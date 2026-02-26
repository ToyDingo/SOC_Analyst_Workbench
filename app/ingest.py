""" This module handles the ingestion of raw event data files into the system. It includes:
- Parsing raw JSONL files line by line to avoid memory issues with large files. 

Accessed by various endpoints in main.py
"""

import json
import os
import psycopg
from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
from app.features import compute_features, build_minute_rollup
from app.db import connect_db

DATABASE_URL = os.getenv("DATABASE_URL", "")
DT_FMT = "%Y-%m-%d %H:%M:%S"
INSERT_SQL = """
    insert into events (
        upload_id,
        event_time, event_id, vendor,
        action, reason, severity, status,
        user_email, department, location,
        client_ip, server_ip, dest_host, url, request_method,
        url_category, threat_category, threat_name, risk_score,
        request_size, response_size, transaction_size,
        raw
    )
    values (
        %(upload_id)s,
        %(event_time)s, %(event_id)s, %(vendor)s,
        %(action)s, %(reason)s, %(severity)s, %(status)s,
        %(user_email)s, %(department)s, %(location)s,
        %(client_ip)s, %(server_ip)s, %(dest_host)s, %(url)s, %(request_method)s,
        %(url_category)s, %(threat_category)s, %(threat_name)s, %(risk_score)s,
        %(request_size)s, %(response_size)s, %(transaction_size)s,
        %(raw)s::jsonb
    )
    """

# Main function to run the ingest job. It processes the file line by line, normalizes records, and batch inserts into Postgres.
# It also updates the ingest job status and stats, and triggers feature computation and rollup building after completion
def run_ingest_job(job_id: str, upload_id: str, file_path: str, batch_size: int = 1000) -> None:
    inserted = 0
    bad_lines = 0
    batch: List[Dict[str, Any]] = []

    try:
        _set_ingest_job(job_id, "running", inserted, bad_lines)

        with connect_db() as conn:
            with conn.cursor() as cur:
                with open(file_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                            row = normalize_zscaler(obj)
                            row["upload_id"] = upload_id
                            row["raw"] = json.dumps(row["raw"])  # jsonb cast
                            batch.append(row)
                        except Exception:
                            bad_lines += 1
                            continue

                        if len(batch) >= batch_size:
                            cur.executemany(INSERT_SQL, batch)
                            conn.commit()
                            inserted += len(batch)
                            batch.clear()
                            _set_ingest_job(job_id, "running", inserted, bad_lines)

                    if batch:
                        cur.executemany(INSERT_SQL, batch)
                        conn.commit()
                        inserted += len(batch)
                        batch.clear()

        _set_ingest_job(job_id, "done", inserted, bad_lines)
        compute_features(upload_id)
        build_minute_rollup(upload_id)

    except Exception as e:
        _set_ingest_job(job_id, "failed", inserted, bad_lines, error=repr(e))

# Update ingest job status and stats in the database.
def _set_ingest_job(job_id: str, status: str, inserted: int, bad: int, error: Optional[str] = None) -> None:
    with connect_db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update ingest_jobs
                set status=%s,
                    inserted_events=%s,
                    bad_lines=%s,
                    error=%s,
                    updated_at=now()
                where id=%s
                """,
                (status, inserted, bad, error, job_id),
            )
            conn.commit()

# Normalize vendor-specific Zscaler record into our internal event schema.
def normalize_zscaler(obj: Dict[str, Any]) -> Dict[str, Any]:
    ev = obj.get("event", {}) if isinstance(obj, dict) else {}
    return {
        "event_time": _parse_dt(ev.get("datetime")),
        "event_id": ev.get("event_id"),
        "vendor": ev.get("vendor"),

        "action": ev.get("action"),
        "reason": ev.get("reason"),
        "severity": ev.get("severity"),
        "status": _to_int(ev.get("status")),

        "user_email": ev.get("user"),
        "department": ev.get("department"),
        "location": ev.get("location"),

        "client_ip": ev.get("ClientIP"),
        "server_ip": ev.get("serverip"),
        "dest_host": ev.get("hostname"),
        "url": ev.get("url"),
        "request_method": ev.get("requestmethod"),

        "url_category": ev.get("urlcategory"),
        "threat_category": ev.get("threatcategory"),
        "threat_name": ev.get("threatname"),
        "risk_score": _to_int(ev.get("riskscore")),

        "request_size": _to_int(ev.get("requestsize")),
        "response_size": _to_int(ev.get("responsesize")),
        "transaction_size": _to_int(ev.get("transactionsize")),

        "raw": obj,
    }

#--------------------
# Helper functions
#--------------------
def _parse_dt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    # Zscaler examples often omit tz; assume UTC for MVP
    return datetime.strptime(s, DT_FMT).replace(tzinfo=timezone.utc)

def _to_int(x: Any) -> Optional[int]:
    try:
        if x is None or x == "":
            return None
        return int(x)
    except Exception:
        return None
