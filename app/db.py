# app/db.py
import os
import psycopg

def get_db_dsn() -> str:
    """
    Cloud Run + Cloud SQL (Postgres) best practice:
    connect via Unix socket at /cloudsql/<INSTANCE_CONNECTION_NAME>

    Required env vars:
      DB_USER, DB_PASSWORD, DB_NAME, CLOUDSQL_INSTANCE

    Optional:
      DATABASE_URL 
    """
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        return database_url

    user = os.getenv("DB_USER", "")
    password = os.getenv("DB_PASSWORD", "")
    dbname = os.getenv("DB_NAME", "")
    instance = os.getenv("CLOUDSQL_INSTANCE", "")

    if not (user and password and dbname and instance):
        missing = [k for k in ["DB_USER", "DB_PASSWORD", "DB_NAME", "CLOUDSQL_INSTANCE"] if not os.getenv(k)]
        raise RuntimeError(f"Missing DB env vars: {', '.join(missing)}")

    # host points to the Cloud SQL Unix socket directory
    return f"postgresql://{user}:{password}@/{dbname}?host=/cloudsql/{instance}"

def connect_db():
    return psycopg.connect(get_db_dsn())
