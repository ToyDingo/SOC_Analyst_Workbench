-- This is needed for migration to GCS

-- USERS
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- UPLOADS
CREATE TABLE IF NOT EXISTS uploads (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  filename TEXT NOT NULL,
  content_type TEXT,
  size_bytes BIGINT NOT NULL DEFAULT 0,
  stored_path TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- INGEST JOBS
CREATE TABLE IF NOT EXISTS ingest_jobs (
  id UUID PRIMARY KEY,
  upload_id UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  inserted_events INT NOT NULL DEFAULT 0,
  bad_lines INT NOT NULL DEFAULT 0,
  error TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- EVENTS
CREATE TABLE IF NOT EXISTS events (
  id UUID PRIMARY KEY,
  upload_id UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  event_time TIMESTAMPTZ,
  user_email TEXT,
  client_ip TEXT,
  url TEXT,
  dest_host TEXT,
  threat_category TEXT,
  threat_name TEXT,
  action TEXT,
  severity TEXT,
  raw JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_upload_id ON events(upload_id);
CREATE INDEX IF NOT EXISTS idx_events_upload_time ON events(upload_id, event_time);

-- ROLLUP
CREATE TABLE IF NOT EXISTS event_rollup_minute (
  upload_id UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  bucket TIMESTAMPTZ NOT NULL,
  user_email TEXT,
  client_ip TEXT,
  dest_host TEXT,
  action TEXT,
  threat_category TEXT,
  total INT NOT NULL DEFAULT 0,
  PRIMARY KEY (upload_id, bucket, COALESCE(user_email,''), COALESCE(client_ip,''), COALESCE(dest_host,''), COALESCE(action,''), COALESCE(threat_category,''))
);

-- FINDINGS
CREATE TABLE IF NOT EXISTS findings (
  id UUID PRIMARY KEY,
  upload_id UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  pattern_name TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence DOUBLE PRECISION NOT NULL,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  evidence JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_upload_id ON findings(upload_id);

-- ANALYSIS JOBS (used by analysis.py)
CREATE TABLE IF NOT EXISTS analysis_jobs (
  id UUID PRIMARY KEY,
  upload_id UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  error TEXT,
  result_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
