# app/agent.py
import os
import json
import psycopg
from typing import Any, Dict, List, Optional, Literal

from langchain_core.tools import tool
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_openai import ChatOpenAI
from langchain.agents import create_tool_calling_agent, AgentExecutor

DATABASE_URL = os.getenv("DATABASE_URL", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")  # match what you're using

# -----------------------
# Tools 
# -----------------------

@tool
def get_upload_features(upload_id: str) -> Dict[str, Any]:
    """Fetch precomputed upload_features.stats for an upload_id."""
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute("select stats from upload_features where upload_id=%s", (upload_id,))
            row = cur.fetchone()
    return row[0] if row else {}

@tool
def list_findings(upload_id: str) -> List[Dict[str, Any]]:
    """List findings for an upload_id."""
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

    out = []
    for r in rows:
        out.append({
            "id": str(r[0]),
            "pattern_name": r[1],
            "severity": r[2],
            "confidence": float(r[3]),
            "title": r[4],
            "summary": r[5],
            "evidence": r[6],
            "created_at": r[7].isoformat() if r[7] else None,
        })
    return out

@tool
def get_event_by_id(event_id: int) -> Dict[str, Any]:
    """Fetch a single event by its DB id (events.id)."""
    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select id, upload_id, event_time, user_email, client_ip::text, dest_host, url, action, severity,
                       threat_category, threat_name, status, raw
                from events
                where id=%s
                """,
                (event_id,),
            )
            row = cur.fetchone()
    if not row:
        return {}
    return {
        "id": row[0],
        "upload_id": str(row[1]),
        "event_time": row[2].isoformat() if row[2] else None,
        "user_email": row[3],
        "client_ip": row[4],
        "dest_host": row[5],
        "url": row[6],
        "action": row[7],
        "severity": row[8],
        "threat_category": row[9],
        "threat_name": row[10],
        "status": row[11],
        "raw": row[12],
    }

@tool
def search_events(
    upload_id: str,
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    user_email: Optional[str] = None,
    client_ip: Optional[str] = None,
    dest_host: Optional[str] = None,
    action: Optional[str] = None,
    threat_category: Optional[str] = None,
    limit: int = 200
) -> List[Dict[str, Any]]:
    """
    Search events for an upload_id with optional filters.
    Returns compact rows + ids for citations.
    """
    limit = max(1, min(limit, 500))  # guardrail

    where = ["upload_id=%s"]
    params: List[Any] = [upload_id]

    if start_time:
        where.append("event_time >= %s")
        params.append(start_time)
    if end_time:
        where.append("event_time <= %s")
        params.append(end_time)
    if user_email:
        where.append("user_email=%s")
        params.append(user_email)
    if client_ip:
        where.append("client_ip::text=%s")
        params.append(client_ip)
    if dest_host:
        where.append("dest_host=%s")
        params.append(dest_host)
    if action:
        where.append("action ilike %s")
        params.append(action)
    if threat_category:
        where.append("threat_category=%s")
        params.append(threat_category)

    sql = f"""
        select id, event_time, user_email, client_ip::text, dest_host, url, action, severity, threat_category, threat_name
        from events
        where {" and ".join(where)}
        order by event_time asc nulls last
        limit {limit}
    """

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

    return [{
        "id": r[0],
        "event_time": r[1].isoformat() if r[1] else None,
        "user_email": r[2],
        "client_ip": r[3],
        "dest_host": r[4],
        "url": r[5],
        "action": r[6],
        "severity": r[7],
        "threat_category": r[8],
        "threat_name": r[9],
    } for r in rows]

@tool
def rollup_minute_top(
    upload_id: str,
    group_by: Literal["client_ip", "user_email", "dest_host", "threat_category"] = "client_ip",
    action: Optional[str] = None,
    threat_category: Optional[str] = None,
    dest_host: Optional[str] = None,
    user_email: Optional[str] = None,
    client_ip: Optional[str] = None,
    min_total: int = 1,
    limit: int = 20,
) -> List[Dict[str, Any]]:
    """
    Query the minute rollup table to surface spikes and concentrations quickly.
    Returns top buckets by total count.

    Use this to detect bursty activity, repeated blocked threats, and beacon-like concentrations.
    """
    limit = max(1, min(limit, 100))
    min_total = max(1, min(min_total, 10_000))

    # Map group_by to column
    group_col = {
        "client_ip": "client_ip::text",
        "user_email": "user_email",
        "dest_host": "dest_host",
        "threat_category": "threat_category",
    }[group_by]

    where = ["upload_id=%s"]
    params: List[Any] = [upload_id]

    # Optional filters (all are columns on event_rollup_minute)
    if action:
        where.append("action ilike %s")
        params.append(action)
    if threat_category:
        where.append("threat_category=%s")
        params.append(threat_category)
    if dest_host:
        where.append("dest_host=%s")
        params.append(dest_host)
    if user_email:
        where.append("user_email=%s")
        params.append(user_email)
    if client_ip:
        where.append("client_ip::text=%s")
        params.append(client_ip)

    sql = f"""
      select
        bucket,
        {group_col} as entity,
        sum(total) as hits
      from event_rollup_minute
      where {" and ".join(where)}
      group by bucket, entity
      having sum(total) >= %s
      order by hits desc
      limit {limit}
    """
    params.append(min_total)

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            rows = cur.fetchall()

    return [
        {
            "bucket": r[0].isoformat() if r[0] else None,
            "entity": r[1],
            "hits": int(r[2]),
        }
        for r in rows
    ]

@tool
def entity_profile(
    upload_id: str,
    entity_type: Literal["client_ip", "user_email", "dest_host"] = "client_ip",
    entity_value: str = "",
) -> Dict[str, Any]:
    """
    Quick one-call profile of an entity from raw events:
    totals, blocked ratio, top threat categories, time range.
    Use this to scope blast radius and summarize who/what is impacted.
    """
    if not entity_value:
        return {}

    where = ["upload_id=%s"]
    params: List[Any] = [upload_id]

    if entity_type == "client_ip":
        where.append("client_ip::text=%s")
        params.append(entity_value)
    elif entity_type == "user_email":
        where.append("user_email=%s")
        params.append(entity_value)
    else:
        where.append("dest_host=%s")
        params.append(entity_value)

    w = " and ".join(where)

    with psycopg.connect(DATABASE_URL) as conn:
        with conn.cursor() as cur:
            cur.execute(
                f"""
                select
                  count(*) as total,
                  min(event_time) as start_time,
                  max(event_time) as end_time,
                  sum(case when action ilike 'Blocked' then 1 else 0 end) as blocked,
                  sum(case when action ilike 'Allowed' then 1 else 0 end) as allowed
                from events
                where {w}
                """,
                params,
            )
            total, start_time, end_time, blocked, allowed = cur.fetchone()

            cur.execute(
                f"""
                select coalesce(threat_category,'None') as threat_category, count(*) as c
                from events
                where {w}
                group by 1
                order by c desc
                limit 10
                """,
                params,
            )
            top_threats = [{"threat_category": r[0], "count": int(r[1])} for r in cur.fetchall()]

    return {
        "entity_type": entity_type,
        "entity_value": entity_value,
        "total_events": int(total or 0),
        "time_range": {
            "start": start_time.isoformat() if start_time else None,
            "end": end_time.isoformat() if end_time else None,
        },
        "actions": {"blocked": int(blocked or 0), "allowed": int(allowed or 0)},
        "top_threat_categories": top_threats,
    }

# -----------------------
# Agent factory
# -----------------------

def build_agent():
    llm = ChatOpenAI(model=OPENAI_MODEL)
    tools = [get_upload_features, list_findings, search_events, get_event_by_id, rollup_minute_top, entity_profile]
    system = """
You are a SOC investigation agent. You must behave like an investigator, not a summarizer.

PRIMARY GOAL:
Convert deterministic detections + underlying log evidence into a SOC report focused on SECURITY OUTCOMES.

You have tools to retrieve:
- findings (named patterns) for an upload_id
- rollup summaries (minute buckets)
- sample raw events for specific entities (user/ip/host/category)

MANDATORY TOOL USE:
You MUST call list_findings(upload_id) first.
If you reference any domain/ip/user/category, you MUST be able to cite at least one finding_id or event_id supporting it.
If evidence is insufficient, call search_events(...) or get_rollup_summary(...) to gather it.

SECURITY OUTCOME TAXONOMY (use these labels when supported; otherwise use INSUFFICIENT_EVIDENCE):
- SUSPECTED_ENDPOINT_COMPROMISE_MULTI_STAGE
- C2_BEACONING_SUSPECTED
- PHISH_TO_PAYLOAD_CHAIN_SUSPECTED
- DATA_EXFILTRATION_ATTEMPT_SUSPECTED
- CREDENTIAL_HARVESTING_SUSPECTED
- RANSOMWARE_STAGING_SUSPECTED
- CRYPTOMINING_ACTIVITY_SUSPECTED
- INSUFFICIENT_EVIDENCE

OUTPUT FORMAT (STRICT):
Return ONE valid JSON object and NOTHING ELSE. No prose outside JSON.

The JSON object must contain these top-level keys:
- summary: string (3-6 sentences)
- timeline: array of objects (at least 5 entries if data exists)
    - ts_start: ISO string
    - ts_end: ISO string
    - label: string
    - evidence_finding_ids: array of strings
    - evidence_event_ids: array of strings
- incidents: array of objects (at least 1)
    - title: string
    - severity: low|medium|high|critical
    - confidence: number 0.0-1.0
    - confirmed: boolean
    - security_outcomes: array of taxonomy labels
    - affected_entities: object with optional keys user_emails, client_ips, dest_hosts, threat_categories
    - evidence_finding_ids: array of strings (NON-EMPTY)
    - evidence_event_ids: array of strings
    - why: array of short strings (3-7 bullets)
    - recommended_actions: array of short strings (5-12 bullets)
- iocs: object
    - domains: array of strings
    - urls: array of strings
    - ips: array of strings
    - users: array of strings
- gaps: array of strings
- evidence_queries: array of strings (describe what tools you called + why)
"""

    prompt = ChatPromptTemplate.from_messages([
        ("system", system),
        ("human", "Produce a SOC report for upload_id={upload_id}. Start by calling list_findings(upload_id). Then call get_rollup_summary(upload_id) to construct a timeline. If needed, call search_events(...) to capture 10-25 representative raw events for the top incident. Return only the JSON object."),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])

    agent = create_tool_calling_agent(llm, tools, prompt)
    return AgentExecutor(agent=agent, tools=tools, verbose=True, max_iterations=8)

def run_soc_report(upload_id: str) -> Dict[str, Any]:
    executor = build_agent()
    result = executor.invoke({"upload_id": upload_id})

    # result["output"] is a string; ensure it's JSON
    out = result.get("output", "{}")
    try:
        return json.loads(out)
    except Exception:
        # fallback: wrap raw text
        return {"summary": out, "incidents": [], "iocs": {}, "recommended_actions": [], "citations": [], "gaps": ["Agent output was not valid JSON."]}
