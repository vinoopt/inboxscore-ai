-- ============================================================
-- InboxScore: Google Postmaster Tools Integration Tables
-- Run this SQL in Supabase SQL Editor (Dashboard → SQL Editor)
-- ============================================================

-- 1. Postmaster OAuth Connections
CREATE TABLE IF NOT EXISTS postmaster_connections (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    access_token text NOT NULL,
    refresh_token text NOT NULL,
    token_expiry timestamptz NOT NULL,
    google_email text NOT NULL,
    connected_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now(),
    UNIQUE(user_id)
);

-- Index for fast lookup by user
CREATE INDEX IF NOT EXISTS idx_postmaster_connections_user ON postmaster_connections(user_id);

-- 2. Postmaster Daily Metrics
CREATE TABLE IF NOT EXISTS postmaster_metrics (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    domain text NOT NULL,
    date date NOT NULL,
    domain_reputation text,           -- HIGH, MEDIUM, LOW, BAD
    spam_rate float,                   -- 0.0 to 1.0
    ip_reputation jsonb DEFAULT '[]',  -- per-IP reputation
    auth_success_spf float,            -- 0.0 to 1.0
    auth_success_dkim float,           -- 0.0 to 1.0
    auth_success_dmarc float,          -- 0.0 to 1.0
    delivery_errors jsonb DEFAULT '{}', -- error categories
    encrypted_traffic_tls float,       -- 0.0 to 1.0
    raw_data jsonb DEFAULT '{}',       -- full API response
    created_at timestamptz DEFAULT now(),
    UNIQUE(user_id, domain, date)
);

-- Indexes for fast querying
CREATE INDEX IF NOT EXISTS idx_postmaster_metrics_user_domain ON postmaster_metrics(user_id, domain);
CREATE INDEX IF NOT EXISTS idx_postmaster_metrics_date ON postmaster_metrics(date DESC);

-- 3. Postmaster Sync Log
CREATE TABLE IF NOT EXISTS postmaster_sync_log (
    id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    sync_started_at timestamptz DEFAULT now(),
    sync_completed_at timestamptz,
    domains_synced int DEFAULT 0,
    status text DEFAULT 'running',     -- running, success, partial, failed
    error_message text
);

CREATE INDEX IF NOT EXISTS idx_postmaster_sync_log_user ON postmaster_sync_log(user_id);

-- Enable RLS (Row Level Security)
ALTER TABLE postmaster_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE postmaster_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE postmaster_sync_log ENABLE ROW LEVEL SECURITY;

-- RLS Policies: service role can do everything (our backend uses service key)
CREATE POLICY "Service role full access" ON postmaster_connections FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON postmaster_metrics FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON postmaster_sync_log FOR ALL USING (true) WITH CHECK (true);
