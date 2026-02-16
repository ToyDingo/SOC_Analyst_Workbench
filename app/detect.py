# app/detect.py
import os
import json
import uuid
import psycopg
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from app.auth import require_user

router = APIRouter()
DATABASE_URL = os.getenv("DATABASE_URL", "")

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
    with psycopg.connect(DATABASE_URL) as conn:
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


def run_detections(upload_id: str) -> Dict[str, Any]:
    created: List[str] = []

    with psycopg.connect(DATABASE_URL) as conn:
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
                        confidence=0.80,
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
                        confidence=0.75,
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
                        confidence=0.65,
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

@router.post("/detect/{upload_id}")
def start_detect(upload_id: str, bg: BackgroundTasks, user=Depends(require_user)):
    bg.add_task(run_detections, upload_id)
    return {"upload_id": upload_id, "status": "queued"}

#--------------------------------------------
# Use this one to troubleshoot
#--------------------------------------------
""" @router.post("/detect/{upload_id}")
def start_detect(upload_id: str, user=Depends(require_user)):
    result = run_detections(upload_id)
    return {"status": "done", **result} """

@router.get("/findings/{upload_id}")
def list_findings(upload_id: str, user=Depends(require_user)):
    with psycopg.connect(DATABASE_URL) as conn:
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
        findings.append({
            "pattern_name": "ENDPOINT_COMPROMISE_MULTI_CATEGORY",
            "severity": "critical" if blocked_hits >= 40 else "high",
            "confidence": 0.85 if distinct_cats >= 5 else 0.7,
            "title": "Suspected endpoint compromise (multi-stage) from one host/user",
            "summary": (
                f"Security outcome: SUSPECTED_ENDPOINT_COMPROMISE_MULTI_STAGE. "
                f"{user_email} / {client_ip} generated blocked activity across {int(distinct_cats)} threat categories "
                f"({int(blocked_hits)} total blocked hits). This breadth suggests automated malicious activity "
                f"rather than casual browsing."
            ),
            "evidence": {
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
            },
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
        findings.append({
            "pattern_name": "C2_BEACONING_SUSPECTED",
            "severity": "high",
            "confidence": 0.7,
            "title": "C2 beaconing suspected (repeated blocked callbacks)",
            "summary": (
                f"Security outcome: C2_BEACONING_SUSPECTED. "
                f"{user_email} / {client_ip} repeatedly attempted to reach {dest_host} "
                f"across {int(active_minutes)} distinct minutes ({int(hits)} total blocked hits). "
                f"Repeated callback attempts are consistent with beaconing behavior."
            ),
            "evidence": {
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
            },
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
        findings.append({
            "pattern_name": "PHISH_TO_PAYLOAD_CHAIN_SUSPECTED",
            "severity": "high",
            "confidence": 0.65,
            "title": "Phish → payload chain suspected",
            "summary": (
                f"Security outcome: PHISH_TO_PAYLOAD_CHAIN_SUSPECTED. "
                f"{user_email} / {client_ip} shows blocked phishing activity followed by blocked "
                f"malware/ransomware/botnet/exfil-related categories within ~{int(window_minutes)} minutes. "
                f"This sequence is consistent with a phish leading to follow-on compromise attempts."
            ),
            "evidence": {
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
            },
        })
    return findings

