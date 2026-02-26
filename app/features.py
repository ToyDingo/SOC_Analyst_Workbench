""" This module contains the logic for computing features from 
ingested events, as well as building per-minute rollups for 
fast querying. 

Called by ingest.py  """ 
    
import json
import os
import psycopg

from app.db import connect_db

DATABASE_URL = os.getenv("DATABASE_URL", "")

# Compute various features and stats for a given upload ID,
# and store them in the upload_features table. This includes 
# overall stats, top users, top IPs, top hosts, and top threat 
# categories.
def compute_features(upload_id: str, top_n: int = 20) -> dict:
    with connect_db() as conn:
        with conn.cursor() as cur:
            # Overall stats
            cur.execute(
                """
                select
                  count(*) as total,
                  min(event_time) as start_time,
                  max(event_time) as end_time,
                  sum(case when action ilike 'Blocked' then 1 else 0 end) as blocked,
                  sum(case when action ilike 'Allowed' then 1 else 0 end) as allowed
                from events
                where upload_id = %s
                """,
                (upload_id,),
            )
            total, start_time, end_time, blocked, allowed = cur.fetchone()

            # Top users
            cur.execute(
                """
                select coalesce(user_email,'<null>') as user_email, count(*) as c
                from events
                where upload_id=%s
                group by 1
                order by c desc
                limit %s
                """,
                (upload_id, top_n),
            )
            top_users = [{"user": r[0], "count": r[1]} for r in cur.fetchall()]

            # Top client IPs
            cur.execute(
                """
                select coalesce(client_ip::text,'<null>') as client_ip, count(*) as c
                from events
                where upload_id=%s
                group by 1
                order by c desc
                limit %s
                """,
                (upload_id, top_n),
            )
            top_ips = [{"ip": r[0], "count": r[1]} for r in cur.fetchall()]

            # Top destination hosts
            cur.execute(
                """
                select coalesce(dest_host,'<null>') as dest_host, count(*) as c
                from events
                where upload_id=%s
                group by 1
                order by c desc
                limit %s
                """,
                (upload_id, top_n),
            )
            top_hosts = [{"host": r[0], "count": r[1]} for r in cur.fetchall()]

            # Threat categories
            cur.execute(
                """
                select coalesce(threat_category,'None') as threat_category, count(*) as c
                from events
                where upload_id=%s
                group by 1
                order by c desc
                limit %s
                """,
                (upload_id, top_n),
            )
            top_threat_categories = [{"category": r[0], "count": r[1]} for r in cur.fetchall()]

            stats = {
                "total_events": int(total or 0),
                "time_range": {
                    "start": start_time.isoformat() if start_time else None,
                    "end": end_time.isoformat() if end_time else None,
                },
                "actions": {"blocked": int(blocked or 0), "allowed": int(allowed or 0)},
                "top_users": top_users,
                "top_ips": top_ips,
                "top_hosts": top_hosts,
                "top_threat_categories": top_threat_categories,
            }

            # Upsert upload_features
            cur.execute(
                """
                insert into upload_features (upload_id, stats)
                values (%s, %s::jsonb)
                on conflict (upload_id) do update
                set stats = excluded.stats,
                    computed_at = now()
                """,
                (upload_id, json.dumps(stats)),
            )
            conn.commit()

    return stats

# Build per-minute rollups (fast burst / beacon / exfil queries).
def build_minute_rollup(upload_id: str) -> int:
    with connect_db() as conn:
        with conn.cursor() as cur:
            # wipe previous rollups for this upload
            cur.execute("delete from event_rollup_minute where upload_id=%s", (upload_id,))

            cur.execute(
                """
                insert into event_rollup_minute (
                  upload_id, bucket, user_email, client_ip, dest_host, action, threat_category, total
                )
                select
                  upload_id,
                  date_trunc('minute', event_time) as bucket,
                  user_email,
                  client_ip,
                  dest_host,
                  action,
                  threat_category,
                  count(*) as total
                from events
                where upload_id=%s
                  and event_time is not null
                group by upload_id, bucket, user_email, client_ip, dest_host, action, threat_category
                """,
                (upload_id,),
            )
            inserted = cur.rowcount
            conn.commit()
            return inserted
