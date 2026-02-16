import json
import os
import re
import uuid
import csv
import psycopg
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from openai import OpenAI
from collections import Counter, defaultdict
from urllib.parse import urlparse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Import your existing auth dependency from main.py
# If your file is app/main.py, then this import path should work.
from app.auth import require_user  # noqa: E402

router = APIRouter()

DATABASE_URL = os.getenv("DATABASE_URL", "")
AI_MODEL = os.getenv("AI_MODEL", "gpt-5")
UPLOAD_DIR = Path("/app/uploads")

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# -----------------------------
# Regex
# -----------------------------
JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
AUTH_HEADER_RE = re.compile(r"(Authorization:\s*Bearer\s+)[^\s]+", re.IGNORECASE)
PASSWORD_KV_RE = re.compile(r"(?i)(password\s*[=:]\s*)(\S+)")
APIKEY_RE = re.compile(r"(?i)\b(api[_-]?key|token|secret)\b\s*[=:]\s*(\S+)")
AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-]{32,}\b")  # conservative

SEVERITY_RE = re.compile(r"\b(ERROR|WARN|WARNING|INFO|DEBUG|TRACE|FATAL)\b", re.IGNORECASE)
TS_RE = re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)")
STACK_TRACE_START_RE = re.compile(r"(Traceback \(most recent call last\):|Exception in thread|^\s*at\s+\S+)", re.IGNORECASE)
ERROR_HINT_RE = re.compile(r"\b(error|exception|failed|failure|stack trace|traceback)\b", re.IGNORECASE)

# -----------------------------
# DB helpers
# -----------------------------
def db_exec(query: str, params: Tuple[Any, ...] = ()) -> None:
    with psycopg.connect(DATABASE_URL) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(query, params)


def db_fetchone(query: str, params: Tuple[Any, ...] = ()) -> Optional[Tuple[Any, ...]]:
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(query, params)
            return cur.fetchone()


def set_job_status(job_id: str, status: str, error: Optional[str] = None, result_json: Any = None) -> None:
    now = datetime.now(timezone.utc)
    db_exec(
        """
        UPDATE analysis_jobs
        SET status = %s,
            error = %s,
            result_json = %s,
            updated_at = %s
        WHERE id = %s
        """,
        (status, error, json.dumps(result_json) if result_json is not None else None, now, job_id),
    )

# -----------------------------
# File helpers
# -----------------------------
def get_upload_row_owned(upload_id: str, user_id: str) -> Tuple[str, str]:
    #Returns (filename, user_id) if upload exists AND belongs to user_id.
    row = db_fetchone(
        "SELECT filename, user_id FROM uploads WHERE id = %s",
        (upload_id,),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Upload not found")

    filename, owner_id = row
    if str(owner_id) != str(user_id):
        raise HTTPException(status_code=403, detail="Not allowed to access this upload")

    return str(filename), str(owner_id)

def get_upload_path(upload_id: str, filename: str) -> Path:
    return UPLOAD_DIR / f"{upload_id}__{filename}"


def read_log_text(path: Path, max_bytes: int = 2_000_000) -> str:
    #Read up to max_bytes from the file (v1 safety). Decode as UTF-8, fall back gracefully.
    if not path.exists():
        raise FileNotFoundError(str(path))

    data = path.read_bytes()
    if len(data) > max_bytes:
        data = data[-max_bytes:]  # keep tail (often most relevant)

    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return data.decode("latin-1", errors="replace")

# -----------------------------
# Hybrid preprocessing
# -----------------------------
def redact(text: str) -> str:
    text = AUTH_HEADER_RE.sub(r"\1[REDACTED]", text)
    text = JWT_RE.sub("[REDACTED_JWT]", text)
    text = PASSWORD_KV_RE.sub(r"\1[REDACTED]", text)
    text = APIKEY_RE.sub(r"\1=[REDACTED]", text)
    text = AWS_KEY_RE.sub("[REDACTED_AWS_KEY]", text)
    text = EMAIL_RE.sub("[REDACTED_EMAIL]", text)
    text = LONG_TOKEN_RE.sub("[REDACTED_TOKEN]", text)
    return text

def split_lines(text: str, max_lines: int = 50_000) -> List[str]:
    lines = text.splitlines()
    if len(lines) > max_lines:
        lines = lines[-max_lines:]  # keep tail
    return lines


def extract_signals(lines: List[str]) -> Dict[str, Any]:
    """
    Pull out:
      - severity counts
      - error-ish lines
      - timestamps (sample)
      - stack traces (up to a few)
    """
    severity_counts = {"ERROR": 0, "WARN": 0, "INFO": 0, "DEBUG": 0, "TRACE": 0, "FATAL": 0}
    error_lines: List[str] = []
    timestamps: List[str] = []
    stack_traces: List[str] = []

    current_trace: List[str] = []
    in_trace = False

    for ln in lines:
        # timestamps
        m_ts = TS_RE.search(ln)
        if m_ts and len(timestamps) < 50:
            timestamps.append(m_ts.group(1))

        # severity
        m_sev = SEVERITY_RE.search(ln)
        if m_sev:
            sev = m_sev.group(1).upper()
            if sev == "WARNING":
                sev = "WARN"
            if sev in severity_counts:
                severity_counts[sev] += 1

        # stack traces (heuristic)
        if STACK_TRACE_START_RE.search(ln):
            in_trace = True
            if current_trace:
                # flush previous trace
                stack_traces.append("\n".join(current_trace))
                current_trace = []
            current_trace.append(ln)
            continue

        if in_trace:
            # end trace when we hit a blank line or a new log line that looks timestamp/severity-ish
            if ln.strip() == "" or TS_RE.search(ln) or SEVERITY_RE.search(ln):
                in_trace = False
                if current_trace:
                    stack_traces.append("\n".join(current_trace))
                    current_trace = []
            else:
                current_trace.append(ln)
            continue

        # error-ish lines
        if ERROR_HINT_RE.search(ln):
            if len(error_lines) < 300:
                error_lines.append(ln)

    if current_trace:
        stack_traces.append("\n".join(current_trace))

    # keep only a few traces (most recent)
    stack_traces = stack_traces[-3:]

    return {
        "severity_counts": severity_counts,
        "timestamps_sample": timestamps[:50],
        "error_lines": error_lines[-200:],  # keep tail
        "stack_traces": stack_traces,
    }


def build_evidence_pack(lines: List[str], signals: Dict[str, Any]) -> Dict[str, Any]:
    """
    Keep LLM input small and high-signal.
    """
    tail = lines[-300:] if len(lines) >= 300 else lines

    return {
        "log_tail_300_lines": tail,
        "severity_counts": signals["severity_counts"],
        "timestamps_sample": signals["timestamps_sample"],
        "error_lines_sample": signals["error_lines"],
        "stack_traces": signals["stack_traces"],
    }

def extract_csv_enrichments(text: str) -> Dict[str, Any]:
    """
    Extract structured insights from CSV-style proxy logs.
    Safe to run even if file is not valid CSV.
    """
    top_domains = Counter()
    top_users = Counter()
    top_categories = Counter()
    action_counts = Counter()
    timeline = defaultdict(int)

    try:
        reader = csv.DictReader(text.splitlines())
        for row in reader:
            user = row.get("user")
            action = row.get("action")
            category = row.get("category")
            url = row.get("url")
            timestamp = row.get("timestamp")

            if user:
                top_users[user] += 1

            if action:
                action_counts[action] += 1

            if category:
                top_categories[category] += 1

            if url:
                parsed = urlparse(url)
                domain = parsed.netloc
                if domain:
                    top_domains[domain] += 1

            if timestamp:
                # bucket by minute
                minute_bucket = timestamp[:16]  # YYYY-MM-DDTHH:MM
                timeline[minute_bucket] += 1

    except Exception:
        # if not CSV, fail silently (we still have generic log parsing)
        pass

    return {
        "top_domains": top_domains.most_common(10),
        "top_users": top_users.most_common(10),
        "top_categories": top_categories.most_common(10),
        "action_counts": dict(action_counts),
        "timeline_buckets": dict(sorted(timeline.items())),
    }

# -----------------------------
# OpenAI call (Structured Outputs)
# -----------------------------
def analyze_with_llm(evidence: Dict[str, Any]) -> Dict[str, Any]:
    instructions = (
        "You are analyzing application log text. "
        "You will receive an evidence pack (tail lines, error samples, stack traces, severity counts). "
        "Return ONLY valid JSON (no markdown) with the following keys:\n"
        "summary (string), top_errors (array of objects {title,evidence,count_estimate}), "
        "probable_root_causes (array of objects {cause,why,confidence}), "
        "recommended_next_steps (array of strings), "
        "notable_indicators (object {severity_counts, time_range_guess})."
        "You will also receive aggregated counts including top domains, users, categories,"
        "action counts, and timeline buckets. Use those aggregates to support your reasoning."
        "If repeated behavior exists (e.g., same domain multiple times), highlight it."
    )

    user_input = {
        "evidence": evidence,
        "task": "Summarize what happened, identify top errors, propose root causes and next steps.",
    }

    resp = client.chat.completions.create(
        model=AI_MODEL,
        messages=[
            {"role": "system", "content": instructions},
            {"role": "user", "content": json.dumps(user_input)},
        ]
    )

    out_text = resp.choices[0].message.content or ""
    try:
        return json.loads(out_text)
    except Exception as e:
        raise RuntimeError(f"Model returned non-JSON: {e}. Raw: {out_text[:500]}")

# -----------------------------
# Background job runner
# -----------------------------
def run_analysis_job(job_id: str, upload_id: str, filename: str) -> None:
    try:
        set_job_status(job_id, "running")

        path = get_upload_path(upload_id, filename)
        raw_text = read_log_text(path)
        redacted = redact(raw_text)

        lines = split_lines(redacted)
        signals = extract_signals(lines)
        csv_enrichments = extract_csv_enrichments(redacted)

        evidence = build_evidence_pack(lines, signals)
        evidence.update(csv_enrichments)

        result = analyze_with_llm(evidence)

        set_job_status(job_id, "done", result_json=result)
    except Exception as e:
        set_job_status(job_id, "failed", error=repr(e))


# -----------------------------
# API endpoints
# -----------------------------
@router.post("/analyze/{upload_id}")
def start_analysis(upload_id: str, bg: BackgroundTasks, user=Depends(require_user)):
    user_id = user["sub"]

    filename, _owner = get_upload_row_owned(upload_id, user_id)
    path = get_upload_path(upload_id, filename)
    if not path.exists():
        raise HTTPException(status_code=404, detail="Upload file not found on disk")

    job_id = str(uuid.uuid4())
    db_exec(
        """
        INSERT INTO analysis_jobs (id, upload_id, user_id, status)
        VALUES (%s, %s, %s, %s)
        """,
        (job_id, upload_id, user_id, "queued"),
    )

    bg.add_task(run_analysis_job, job_id, upload_id, filename)
    return {"job_id": job_id, "status": "queued"}

@router.get("/analysis/{job_id}")
def get_analysis(job_id: str, user=Depends(require_user)):
    user_id = user["sub"]

    row = db_fetchone(
        """
        SELECT id, upload_id, user_id, status, error, result_json, created_at, updated_at
        FROM analysis_jobs
        WHERE id = %s
        """,
        (job_id,),
    )
    if not row:
        raise HTTPException(status_code=404, detail="Job not found")

    (jid, upload_id, owner_id, status, error, result_json, created_at, updated_at) = row
    if str(owner_id) != str(user_id):
        raise HTTPException(status_code=403, detail="Not allowed to access this job")

    return {
        "job_id": str(jid),
        "upload_id": str(upload_id),
        "status": status,
        "error": error,
        "result": result_json,
        "created_at": created_at,
        "updated_at": updated_at,
    }

@router.get("/me/analysis-history")
def analysis_history(limit: int = 50, user=Depends(require_user)):
    user_id = user["sub"]

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  aj.id AS job_id,
                  aj.upload_id,
                  aj.status,
                  aj.error,
                  aj.created_at,
                  aj.updated_at,
                  u.filename,
                  u.content_type,
                  u.size_bytes
                FROM analysis_jobs aj
                JOIN uploads u ON u.id = aj.upload_id
                WHERE aj.user_id = %s
                ORDER BY aj.created_at DESC
                LIMIT %s
                """,
                (user_id, limit),
            )
            rows = cur.fetchall()

    return [
        {
            "job_id": str(r[0]),
            "upload_id": str(r[1]),
            "status": r[2],
            "error": r[3],
            "created_at": r[4],
            "updated_at": r[5],
            "file": {
                "filename": r[6],
                "content_type": r[7],
                "size_bytes": r[8],
            },
        }
        for r in rows
    ]