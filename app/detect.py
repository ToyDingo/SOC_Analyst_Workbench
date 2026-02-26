""" This module implements detection logic to find suspicious patterns 
in the uploaded event data. Each detection pattern has its own heuristic 
and SQL query to identify potential security issues. The detections are 
run in the background when triggered via the API, and findings are stored 
in the database with calculated confidence scores based on severity and 
evidence strength. 

Accessed by the frontend via main.py
"""

import os
import json
import uuid
import psycopg

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from app.auth import require_user
from app.db import connect_db

router = APIRouter()
DATABASE_URL = os.getenv("DATABASE_URL", "")

#---------------------
# API Endpoints
#---------------------

# API endpoint to trigger detections for a given upload_id; runs in background and returns immediately with status.
@router.post("/detect/{upload_id}")
def start_detect(upload_id: str, bg: BackgroundTasks, user=Depends(require_user)):
    bg.add_task(run_detections, upload_id)
    return {"upload_id": upload_id, "status": "queued"}

# Use this one to troubleshoot
""" @router.post("/detect/{upload_id}")
def start_detect(upload_id: str, user=Depends(require_user)):
    result = run_detections(upload_id)
    return {"status": "done", **result} """

# API endpoint to list findings for a given upload_id
@router.get("/findings/{upload_id}")
def list_findings(upload_id: str, user=Depends(require_user)):
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id, pattern_name, severity, confidence, title, summary, evidence, created_at
                from findings
                where upload_id=%s
                order by created_at desc
                """,
                (upload_id,),
            )
            rows = cur.fetchall()

    return [
        {
            "id": str(r[0]),
            "pattern_name": r[1],
            "severity": r[2],
            "confidence": float(r[3]),
            "title": r[4],
            "summary": r[5],
            "evidence": r[6],
            "created_at": r[7].isoformat() if r[7] else None,
        }
        for r in rows
    ]

def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))

#---------------------
# Detection Logic
#---------------------

# Main function to run all detections for a given upload_id; returns summary of created findings.
def run_detections(upload_id: str) -> Dict[str, Any]:
    created: List[str] = []

    with connect_db() as conn:
        with conn.cursor() as cur:

            # 1) Burst from single client IP in a minute (simple, powerful)
            cur.execute(
                """
                select bucket, client_ip, sum(total) as hits
                from event_rollup_minute
                where upload_id=%s
                  and client_ip is not null
                group by bucket, client_ip
                having sum(total) >= 200
                order by hits desc
                limit 20
                """,
                (upload_id,),
            )
            bursts = cur.fetchall()
            for bucket, client_ip, hits in bursts:
                evidence = {
                    "bucket": bucket.isoformat(),
                    "client_ip": client_ip,
                    "hits_in_minute": int(hits),
                    "how_to_verify": {
                        "sql": "select * from events where upload_id=? and client_ip=? and date_trunc('minute', event_time)=? limit 200",
                        "params": {"upload_id": upload_id, "client_ip": client_ip, "bucket": bucket.isoformat()},
                    },
                }
                created.append(
                    _insert_finding(
                        upload_id=upload_id,
                        pattern_name="BURST_FROM_SINGLE_IP",
                        severity="high",
                        confidence=_calc_confidence("BURST_FROM_SINGLE_IP", "high", evidence),
                        title=f"Burst from {client_ip}",
                        summary=f"{client_ip} generated {int(hits)} events in one minute ({bucket}). This often indicates automation (scan/beacon) or a runaway process.",
                        evidence=evidence,
                    )
                )

            # 2) Repeated blocked threat category (use your normalized fields)
            cur.execute(
                """
                select user_email, client_ip, threat_category, sum(total) as blocked_hits
                from event_rollup_minute
                where upload_id=%s
                  and action ilike 'Blocked'
                  and threat_category is not null
                group by user_email, client_ip, threat_category
                having sum(total) >= 25
                order by blocked_hits desc
                limit 25
                """,
                (upload_id,),
            )
            reps = cur.fetchall()
            for user_email, client_ip, threat_category, blocked_hits in reps:
                evidence = {
                    "user_email": user_email,
                    "client_ip": client_ip,
                    "threat_category": threat_category,
                    "blocked_hits": int(blocked_hits),
                    "how_to_verify": {
                        "sql": "select event_time, user_email, client_ip, url, dest_host, threat_category, threat_name, action, severity from events where upload_id=? and action ilike 'Blocked' and threat_category=? and client_ip=? order by event_time asc limit 200",
                        "params": {"upload_id": upload_id, "threat_category": threat_category, "client_ip": client_ip},
                    },
                }
                created.append(
                    _insert_finding(
                        upload_id=upload_id,
                        pattern_name="REPEATED_BLOCKED_THREAT_CATEGORY",
                        severity="high",
                        confidence=_calc_confidence("REPEATED_BLOCKED_THREAT_CATEGORY", "high", evidence),
                        title=f"Repeated blocked {threat_category}",
                        summary=f"{user_email or '<null>'} / {client_ip or '<null>'} triggered {int(blocked_hits)} blocked events in threat category '{threat_category}'. This is consistent with infection/beaconing or repeated malicious browsing.",
                        evidence=evidence,
                    )
                )

            # 3) Top “threat hosts” (dest_host concentration)
            cur.execute(
                """
                select dest_host, sum(total) as hits
                from event_rollup_minute
                where upload_id=%s
                  and action ilike 'Blocked'
                  and dest_host is not null
                group by dest_host
                having sum(total) >= 15
                order by hits desc
                limit 20
                """,
                (upload_id,),
            )
            hosts = cur.fetchall()
            for dest_host, hits in hosts:
                evidence = {
                    "dest_host": dest_host,
                    "blocked_hits": int(hits),
                    "how_to_verify": {
                        "sql": "select event_time, user_email, client_ip, url, dest_host, threat_category, threat_name, action, severity from events where upload_id=? and action ilike 'Blocked' and dest_host=? order by event_time asc limit 200",
                        "params": {"upload_id": upload_id, "dest_host": dest_host},
                    },
                }
                created.append(
                    _insert_finding(
                        upload_id=upload_id,
                        pattern_name="TOP_BLOCKED_DEST_HOST",
                        severity="medium",
                        confidence=_calc_confidence("TOP_BLOCKED_DEST_HOST", "medium", evidence),
                        title=f"Blocked traffic concentrated to {dest_host}",
                        summary=f"{dest_host} accounts for {int(hits)} blocked events. Worth pivoting into users/IPs and timeline.",
                        evidence=evidence,
                    )
                )

            extra = []
            extra += _detect_endpoint_compromise_multicategory(conn, upload_id)
            extra += _detect_c2_beaconing_suspected(conn, upload_id)
            extra += _detect_phish_to_payload_chain(conn, upload_id)

            for f in extra:
                f["confidence"] = _calc_confidence(f["pattern_name"], f["severity"], f["evidence"])
                _insert_finding(
                    upload_id=upload_id,
                    pattern_name=f["pattern_name"],
                    severity=f["severity"],
                    confidence=f["confidence"],
                    title=f["title"],
                    summary=f["summary"],
                    evidence=f["evidence"],
                )

    return {"upload_id": upload_id, "created_finding_ids": created}

#--------------------
# Confidence Calculation
#--------------------

# Dynamic confidence based on (a) severity prior and (b) strength/quality of evidence.
# Returns 0.10..0.99.
def _calc_confidence(pattern_name: str, severity: str, evidence: Dict[str, Any]) -> float:
    base = _severity_base(severity)

    p = (pattern_name or "").upper()
    boost = 0.0

    # General "evidence quality" boosts (small)
    if evidence.get("user_email") not in (None, "", "<null>"):
        boost += 0.03
    if evidence.get("client_ip") not in (None, "", "<null>"):
        boost += 0.03
    if evidence.get("dest_host") not in (None, "", "<null>"):
        boost += 0.03
    if evidence.get("threat_category") not in (None, "", "<null>"):
        boost += 0.03

    # Pattern-specific evidence strength
    if p == "BURST_FROM_SINGLE_IP":
        hits = float(evidence.get("hits_in_minute") or 0)
        boost += 0.30 * _ratio_score(hits, 200.0, cap_multiple=5.0)  # 200 is the query threshold

    elif p == "REPEATED_BLOCKED_THREAT_CATEGORY":
        hits = float(evidence.get("blocked_hits") or 0)
        boost += 0.28 * _ratio_score(hits, 25.0, cap_multiple=6.0)   # 25 is the query threshold

    elif p == "TOP_BLOCKED_DEST_HOST":
        hits = float(evidence.get("blocked_hits") or 0)
        boost += 0.22 * _ratio_score(hits, 15.0, cap_multiple=6.0)   # 15 is the query threshold

    elif p == "ENDPOINT_COMPROMISE_MULTI_CATEGORY":
        distinct_cats = float(evidence.get("distinct_threat_categories") or 0)
        blocked_hits = float(evidence.get("blocked_hits") or 0)
        boost += 0.20 * _ratio_score(distinct_cats, 3.0, cap_multiple=4.0)   # min_categories default is 3
        boost += 0.22 * _ratio_score(blocked_hits, 12.0, cap_multiple=6.0)   # min_total_blocks default is 12

    elif p == "C2_BEACONING_SUSPECTED":
        active_minutes = float(evidence.get("active_minutes") or 0)
        blocked_hits = float(evidence.get("blocked_hits") or 0)
        boost += 0.18 * _ratio_score(active_minutes, 4.0, cap_multiple=5.0)  # min_minutes default is 4
        boost += 0.18 * _ratio_score(blocked_hits, 8.0, cap_multiple=8.0)    # min_total default is 8
        # Slight bonus because threat category filter is already specific (Botnet/Command/C2)
        boost += 0.04

    elif p == "PHISH_TO_PAYLOAD_CHAIN_SUSPECTED":
        phish_hits = float(evidence.get("phish_hits") or 0)
        payload_hits = float(evidence.get("payload_hits") or 0)
        boost += 0.14 * _ratio_score(phish_hits, 2.0, cap_multiple=8.0)      # min_phish default is 2
        boost += 0.16 * _ratio_score(payload_hits, 2.0, cap_multiple=10.0)   # min_payload default is 2
        # If we have both timestamps, we can reward a tighter chain (smaller delta)
        try:
            fp = evidence.get("first_phish")
            fy = evidence.get("first_payload")
            if fp and fy:
                # fp/fy may be datetime objects; fall back to string parsing via isoformat if needed
                if hasattr(fp, "timestamp") and hasattr(fy, "timestamp"):
                    delta_sec = max(0.0, float(fy.timestamp() - fp.timestamp()))
                else:
                    # Best-effort: if strings, rely on lexical iso parsing not available here; skip
                    delta_sec = None
                if delta_sec is not None:
                    # 0..1800 sec window ~30 minutes => map to bonus where smaller delta => higher bonus
                    t = _clamp(1.0 - (delta_sec / 1800.0), 0.0, 1.0)
                    boost += 0.10 * t
        except Exception:
            pass

    conf = base + boost
    return _clamp(conf, 0.10, 0.99)

# Base confidence by severity level; this is a starting point that can be boosted by evidence quality/strength.
def _severity_base(severity: str) -> float:
    s = (severity or "").lower()
    if s == "critical":
        return 0.72
    if s == "high":
        return 0.62
    if s == "medium":
        return 0.50
    if s == "low":
        return 0.38
    return 0.50

# This function converts a "how far above threshold" metric into a 0..1 score 
def _ratio_score(value: float, threshold: float, cap_multiple: float = 3.0) -> float:
    if threshold <= 0:
        return 0.0
    r = (float(value) - float(threshold)) / (float(threshold) * max(cap_multiple - 1.0, 1e-9))
    return _clamp(r, 0.0, 1.0)

def _detect_endpoint_compromise_multicategory(conn, upload_id: str, min_categories: int = 3, min_total_blocks: int = 12):
    """
    Outcome: SUSPECTED_ENDPOINT_COMPROMISE_MULTI_STAGE
    Heuristic: one client_ip/user has blocked hits across many threat categories.
    """
    sql = """
    WITH x AS (
      SELECT
        COALESCE(user_email, '<null>') AS user_email,
        COALESCE(client_ip::text, '<null>') AS client_ip,
        COUNT(DISTINCT threat_category) AS distinct_cats,
        SUM(total) AS blocked_hits
      FROM event_rollup_minute
      WHERE upload_id = %s
        AND action ILIKE 'Blocked'
        AND threat_category IS NOT NULL
      GROUP BY 1,2
    )
    SELECT user_email, client_ip, distinct_cats, blocked_hits
    FROM x
    WHERE distinct_cats >= %s AND blocked_hits >= %s
    ORDER BY blocked_hits DESC
    LIMIT 10;
    """
    rows = []
    with conn.cursor() as cur:
        cur.execute(sql, (upload_id, min_categories, min_total_blocks))
        rows = cur.fetchall()

    findings = []
    for user_email, client_ip, distinct_cats, blocked_hits in rows:
        evidence = {
            "security_outcome": "SUSPECTED_ENDPOINT_COMPROMISE_MULTI_STAGE",
            "entity": {"user_email": user_email, "client_ip": client_ip},
            "blocked_hits": int(blocked_hits),
            "distinct_threat_categories": int(distinct_cats),
            "how_to_verify_sql": """
                SELECT threat_category, SUM(total) AS hits
                FROM event_rollup_minute
                WHERE upload_id = :upload_id
                AND action ILIKE 'Blocked'
                AND COALESCE(user_email,'<null>') = :user_email
                AND COALESCE(client_ip::text,'<null>') = :client_ip
                GROUP BY threat_category
                ORDER BY hits DESC;
                """,
            "how_to_verify_params": {"upload_id": upload_id, "user_email": user_email, "client_ip": client_ip},
            "mitre": ["TA0001", "TA0011"],  # Initial Access, Command and Control (lightweight mapping)
        }
        severity = "critical" if blocked_hits >= 40 else "high"
        findings.append({
            "pattern_name": "ENDPOINT_COMPROMISE_MULTI_CATEGORY",
            "severity": severity,
            "confidence": _calc_confidence("ENDPOINT_COMPROMISE_MULTI_CATEGORY", severity, evidence),
            "title": "Suspected endpoint compromise (multi-stage) from one host/user",
            "summary": (
                f"Security outcome: SUSPECTED_ENDPOINT_COMPROMISE_MULTI_STAGE. "
                f"{user_email} / {client_ip} generated blocked activity across {int(distinct_cats)} threat categories "
                f"({int(blocked_hits)} total blocked hits). This breadth suggests automated malicious activity "
                f"rather than casual browsing."
            ),
            "evidence": evidence,
        })
    return findings

def _detect_c2_beaconing_suspected(conn, upload_id: str, min_minutes: int = 4, min_total: int = 8):
    """
    Outcome: C2_BEACONING_SUSPECTED
    Heuristic: repeated blocked hits to same dest_host across multiple distinct minutes.
    (We are not calculating perfect periodicity; we’re producing a defendable 'suspected' label.)
    """
    sql = """
    WITH x AS (
      SELECT
        COALESCE(user_email, '<null>') AS user_email,
        COALESCE(client_ip::text, '<null>') AS client_ip,
        dest_host,
        COUNT(DISTINCT bucket) AS active_minutes,
        SUM(total) AS hits
      FROM event_rollup_minute
      WHERE upload_id = %s
        AND action ILIKE 'Blocked'
        AND dest_host IS NOT NULL
        AND (threat_category ILIKE 'Botnet%%' OR threat_category ILIKE 'Command%%' OR threat_category ILIKE 'C2%%')
      GROUP BY 1,2,3
    )
    SELECT user_email, client_ip, dest_host, active_minutes, hits
    FROM x
    WHERE active_minutes >= %s AND hits >= %s
    ORDER BY hits DESC
    LIMIT 15;
    """
    with conn.cursor() as cur:
        cur.execute(sql, (upload_id, min_minutes, min_total))
        rows = cur.fetchall()

    findings = []
    for user_email, client_ip, dest_host, active_minutes, hits in rows:
        evidence = {
            "security_outcome": "C2_BEACONING_SUSPECTED",
            "entity": {"user_email": user_email, "client_ip": client_ip, "dest_host": dest_host},
            "active_minutes": int(active_minutes),
            "blocked_hits": int(hits),
            "how_to_verify_sql": """
                SELECT bucket, SUM(total) AS hits
                FROM event_rollup_minute
                WHERE upload_id = :upload_id
                AND action ILIKE 'Blocked'
                AND COALESCE(user_email,'<null>') = :user_email
                AND COALESCE(client_ip::text,'<null>') = :client_ip
                AND dest_host = :dest_host
                GROUP BY bucket
                ORDER BY bucket;
                """,
            "how_to_verify_params": {"upload_id": upload_id, "user_email": user_email, "client_ip": client_ip, "dest_host": dest_host},
            "mitre": ["TA0011", "T1071"],  # C2, Application Layer Protocol (approx)
        }
        severity = "high"
        findings.append({
            "pattern_name": "C2_BEACONING_SUSPECTED",
            "severity": severity,
            "confidence": _calc_confidence("C2_BEACONING_SUSPECTED", severity, evidence),
            "title": "C2 beaconing suspected (repeated blocked callbacks)",
            "summary": (
                f"Security outcome: C2_BEACONING_SUSPECTED. "
                f"{user_email} / {client_ip} repeatedly attempted to reach {dest_host} "
                f"across {int(active_minutes)} distinct minutes ({int(hits)} total blocked hits). "
                f"Repeated callback attempts are consistent with beaconing behavior."
            ),
            "evidence": evidence,
        })
    return findings

def _detect_phish_to_payload_chain(conn, upload_id: str, window_minutes: int = 30, min_phish: int = 2, min_payload: int = 2):
    """
    Outcome: PHISH_TO_PAYLOAD_CHAIN_SUSPECTED
    Heuristic: same client/user shows phishing activity + later malware/ransomware/exfil categories.
    """
    sql = """
    WITH phish AS (
      SELECT
        COALESCE(user_email,'<null>') AS user_email,
        COALESCE(client_ip::text,'<null>') AS client_ip,
        MIN(bucket) AS first_phish,
        SUM(total) AS phish_hits
      FROM event_rollup_minute
      WHERE upload_id = %s
        AND action ILIKE 'Blocked'
        AND threat_category ILIKE 'Phishing%%'
      GROUP BY 1,2
    ),
    payload AS (
      SELECT
        COALESCE(user_email,'<null>') AS user_email,
        COALESCE(client_ip::text,'<null>') AS client_ip,
        MIN(bucket) AS first_payload,
        SUM(total) AS payload_hits
      FROM event_rollup_minute
      WHERE upload_id = %s
        AND action ILIKE 'Blocked'
        AND (
          threat_category ILIKE 'Malware%%'
          OR threat_category ILIKE 'Ransomware%%'
          OR threat_category ILIKE 'Botnet%%'
          OR threat_category ILIKE 'Cryptomining%%'
          OR threat_category ILIKE 'Data Transfer%%'
          OR threat_category ILIKE 'Data Leakage%%'
        )
      GROUP BY 1,2
    )
    SELECT p.user_email, p.client_ip, p.first_phish, y.first_payload, p.phish_hits, y.payload_hits
    FROM phish p
    JOIN payload y USING (user_email, client_ip)
    WHERE p.phish_hits >= %s AND y.payload_hits >= %s
      AND y.first_payload <= (p.first_phish + (%s || ' minutes')::interval)
    ORDER BY y.payload_hits DESC
    LIMIT 10;
    """
    with conn.cursor() as cur:
        cur.execute(sql, (upload_id, upload_id, min_phish, min_payload, window_minutes))
        rows = cur.fetchall()

    findings = []
    for user_email, client_ip, first_phish, first_payload, phish_hits, payload_hits in rows:
        evidence = {
            "security_outcome": "PHISH_TO_PAYLOAD_CHAIN_SUSPECTED",
            "entity": {"user_email": user_email, "client_ip": client_ip},
            "first_phish": first_phish,
            "first_payload": first_payload,
            "phish_hits": int(phish_hits),
            "payload_hits": int(payload_hits),
            "how_to_verify_sql": """
                SELECT bucket, threat_category, SUM(total) AS hits
                FROM event_rollup_minute
                WHERE upload_id = :upload_id
                AND action ILIKE 'Blocked'
                AND COALESCE(user_email,'<null>') = :user_email
                AND COALESCE(client_ip::text,'<null>') = :client_ip
                AND (
                    threat_category ILIKE 'Phishing%%'
                    OR threat_category ILIKE 'Malware%%'
                    OR threat_category ILIKE 'Ransomware%%'
                    OR threat_category ILIKE 'Botnet%%'
                    OR threat_category ILIKE 'Cryptomining%%'
                    OR threat_category ILIKE 'Data Transfer%%'
                    OR threat_category ILIKE 'Data Leakage%%'
                )
                GROUP BY bucket, threat_category
                ORDER BY bucket;
                """,
            "how_to_verify_params": {"upload_id": upload_id, "user_email": user_email, "client_ip": client_ip},
            "mitre": ["TA0001", "TA0002", "TA0011"],  # Initial Access, Execution, C2 (approx)
        }
        severity = "high"
        findings.append({
            "pattern_name": "PHISH_TO_PAYLOAD_CHAIN_SUSPECTED",
            "severity": severity,
            "confidence": _calc_confidence("PHISH_TO_PAYLOAD_CHAIN_SUSPECTED", severity, evidence),
            "title": "Phish → payload chain suspected",
            "summary": (
                f"Security outcome: PHISH_TO_PAYLOAD_CHAIN_SUSPECTED. "
                f"{user_email} / {client_ip} shows blocked phishing activity followed by blocked "
                f"malware/ransomware/botnet/exfil-related categories within ~{int(window_minutes)} minutes. "
                f"This sequence is consistent with a phish leading to follow-on compromise attempts."
            ),
            "evidence": evidence,
        })
    return findings

#---------------------
# Database Interaction
#---------------------

# This function inserts a finding into the database and returns the new finding ID.
def _insert_finding(
    upload_id: str,
    pattern_name: str,
    severity: str,
    confidence: float,
    title: str,
    summary: str,
    evidence: Dict[str, Any],
) -> str:
    finding_id = str(uuid.uuid4())
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into findings (
                  id, upload_id, pattern_name, severity, confidence, title, summary, evidence
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (finding_id, upload_id, pattern_name, severity, confidence, title, summary, json.dumps(evidence, default=str)),
            )
            conn.commit()
    return finding_id