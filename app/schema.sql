-- USERS
CREATE TABLE IF NOT EXISTS users (
  id            UUID PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- UPLOADS
CREATE TABLE IF NOT EXISTS uploads (
  id           UUID PRIMARY KEY,
  filename     TEXT NOT NULL,
  content_type TEXT,
  size_bytes   BIGINT NOT NULL,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ANALYSIS JOBS
CREATE TABLE IF NOT EXISTS analysis_jobs (
  id         UUID PRIMARY KEY,
  upload_id  UUID NOT NULL,
  status     TEXT NOT NULL, -- queued | running | done | failed
  error      TEXT,
  result_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Add user ownership columns
ALTER TABLE uploads
  ADD COLUMN IF NOT EXISTS user_id UUID;

ALTER TABLE analysis_jobs
  ADD COLUMN IF NOT EXISTS user_id UUID;

-- Enforce NOT NULL on ownership columns (will fail if existing rows are null)
ALTER TABLE uploads
  ALTER COLUMN user_id SET NOT NULL;

ALTER TABLE analysis_jobs
  ALTER COLUMN user_id SET NOT NULL;

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_uploads_user_id ON uploads(user_id);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_user_id ON analysis_jobs(user_id);
CREATE INDEX IF NOT EXISTS idx_analysis_jobs_upload_id ON analysis_jobs(upload_id);

-- EVENTS (parsed Zscaler events)
CREATE TABLE IF NOT EXISTS events (
  id bigserial PRIMARY KEY,
  upload_id uuid NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,

  event_time timestamptz NULL,
  event_id text NULL,
  vendor text NULL,

  action text NULL,
  reason text NULL,
  severity text NULL,
  status int NULL,

  user_email text NULL,
  department text NULL,
  location text NULL,

  client_ip inet NULL,
  server_ip inet NULL,
  dest_host text NULL,
  url text NULL,
  request_method text NULL,

  url_category text NULL,
  threat_category text NULL,
  threat_name text NULL,
  risk_score int NULL,

  request_size int NULL,
  response_size int NULL,
  transaction_size int NULL,

  raw jsonb NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_upload_time     ON events(upload_id, event_time);
CREATE INDEX IF NOT EXISTS idx_events_upload_user     ON events(upload_id, user_email);
CREATE INDEX IF NOT EXISTS idx_events_upload_clientip ON events(upload_id, client_ip);
CREATE INDEX IF NOT EXISTS idx_events_upload_desthost ON events(upload_id, dest_host);
CREATE INDEX IF NOT EXISTS idx_events_upload_action   ON events(upload_id, action);

-- INGEST JOBS
CREATE TABLE IF NOT EXISTS ingest_jobs (
  id uuid PRIMARY KEY,
  upload_id uuid NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  user_id uuid NOT NULL,

  status text NOT NULL, -- queued|running|done|failed
  inserted_events bigint NOT NULL DEFAULT 0,
  bad_lines bigint NOT NULL DEFAULT 0,
  error text NULL,

  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- ROLLUP (minute)
CREATE TABLE IF NOT EXISTS event_rollup_minute (
  upload_id uuid NOT NULL,
  bucket timestamptz NOT NULL,
  user_email text NULL,
  client_ip inet NULL,
  dest_host text NULL,
  action text NULL,
  threat_category text NULL,
  total bigint NOT NULL,

  -- NOTE: PK columns cannot contain expressions like COALESCE(...)
  PRIMARY KEY (upload_id, bucket, user_email, client_ip, dest_host, action, threat_category)
);

CREATE INDEX IF NOT EXISTS idx_rollup_minute_upload_bucket
  ON event_rollup_minute(upload_id, bucket);

-- UPLOAD FEATURES
CREATE TABLE IF NOT EXISTS upload_features (
  upload_id uuid PRIMARY KEY,
  computed_at timestamptz NOT NULL DEFAULT now(),
  stats jsonb NOT NULL
);

-- FINDINGS
CREATE TABLE IF NOT EXISTS findings (
  id uuid PRIMARY KEY,
  upload_id uuid NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,

  pattern_name text NOT NULL,    -- e.g. "BURST_FROM_SINGLE_IP"
  severity text NOT NULL,        -- low|medium|high|critical
  confidence numeric NOT NULL,   -- 0..1

  title text NOT NULL,
  summary text NOT NULL,

  evidence jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_upload  ON findings(upload_id);
CREATE INDEX IF NOT EXISTS idx_findings_pattern ON findings(pattern_name);
