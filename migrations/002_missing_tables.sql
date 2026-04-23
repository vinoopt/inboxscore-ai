-- INBOX-32: Schema reconciliation.
-- Creates three tables that exist in prod but have never had a committed migration:
--   * monitoring_logs     — per-monitor-cycle audit log (db.py:664, 692)
--   * snds_connections    — user's SNDS API key + tracked_ips (db.py:972, 1017)
--   * snds_metrics        — per-IP-per-day SNDS reputation rows (db.py:1058, 1075)
--
-- This migration must run BEFORE 004_snds_tracked_ips.sql in a from-scratch
-- replay, because 004 ALTERs snds_connections (adds tracked_ips) — which would
-- fail against an environment that never had the table created. 002 makes
-- the migration chain replayable against an empty Postgres, which is the
-- whole point of INBOX-32.
--
-- Column definitions mirror db/prod-schema-2026-04-22.sql exactly (types,
-- defaults, NOT NULL status). The CI schema-drift-check job compares the
-- column set produced by this file against the prod dump.
--
-- All DDL below is idempotent (CREATE TABLE IF NOT EXISTS, CREATE INDEX IF
-- NOT EXISTS, DROP POLICY IF EXISTS + CREATE POLICY) so this file is safe
-- to re-run against prod (expected to be a no-op there).

-- ============================================================================
-- monitoring_logs
-- ============================================================================
-- Populated by monitor.py every time a scheduled scan produces a score
-- change. Read by /api/monitoring/logs endpoint (app.py:1164) and filtered
-- by user_id for IDOR protection (see INBOX-27 / test_idor.py L8).
--
-- NOTE: domain_id and user_id are NULLABLE in prod (observed in the dump).
-- This is intentional: early rows pre-date the user_id backfill. The
-- get_monitoring_logs() helper always requires a user_id filter, so rows
-- with NULL user_id are effectively orphaned and only visible via
-- service_role.

CREATE TABLE IF NOT EXISTS public.monitoring_logs (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    domain_id UUID,
    user_id UUID,
    domain TEXT NOT NULL,
    old_score INTEGER,
    new_score INTEGER,
    score_change INTEGER DEFAULT 0,
    changes_detected JSONB,
    alerts_created INTEGER DEFAULT 0,
    scan_id UUID,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Primary access pattern is (user_id, domain_id, created_at DESC) — see
-- get_monitoring_logs() in db.py.
CREATE INDEX IF NOT EXISTS idx_monitoring_logs_user_domain_created
    ON public.monitoring_logs(user_id, domain_id, created_at DESC);

-- Secondary: bulk reads by scan_id for the incident post-mortem flow.
CREATE INDEX IF NOT EXISTS idx_monitoring_logs_scan
    ON public.monitoring_logs(scan_id);

ALTER TABLE public.monitoring_logs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view own monitoring logs" ON public.monitoring_logs;
CREATE POLICY "Users can view own monitoring logs"
    ON public.monitoring_logs FOR SELECT
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role full access to monitoring_logs" ON public.monitoring_logs;
CREATE POLICY "Service role full access to monitoring_logs"
    ON public.monitoring_logs FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);


-- ============================================================================
-- snds_connections
-- ============================================================================
-- One row per user — stores their Microsoft SNDS API key plus sync metadata.
-- Used by snds_scheduler.py (daily) and the /api/snds/* endpoints.
--
-- user_id is the PRIMARY KEY (not id) — this matches prod (one-connection-
-- per-user invariant enforced at the DB layer, no app-level UNIQUE needed).
-- The tracked_ips column was added post-launch by 004_snds_tracked_ips.sql;
-- we do NOT add it here, so that 004's ADD COLUMN IF NOT EXISTS remains
-- meaningful when replaying migrations in order.

CREATE TABLE IF NOT EXISTS public.snds_connections (
    user_id UUID PRIMARY KEY,
    snds_key TEXT NOT NULL,
    connected_at TIMESTAMPTZ DEFAULT NOW(),
    last_sync_at TIMESTAMPTZ,
    ip_count INTEGER DEFAULT 0
);

ALTER TABLE public.snds_connections ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view own snds connection" ON public.snds_connections;
CREATE POLICY "Users can view own snds connection"
    ON public.snds_connections FOR SELECT
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Users can manage own snds connection" ON public.snds_connections;
CREATE POLICY "Users can manage own snds connection"
    ON public.snds_connections FOR ALL
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role full access to snds_connections" ON public.snds_connections;
CREATE POLICY "Service role full access to snds_connections"
    ON public.snds_connections FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);


-- ============================================================================
-- snds_metrics
-- ============================================================================
-- One row per (user_id, ip_address, metric_date). Upserted daily from the
-- SNDS feed by snds_scheduler.py (db.py:1058). Read by
-- /api/snds/metrics (app.py:1925).

CREATE TABLE IF NOT EXISTS public.snds_metrics (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL,
    ip_address TEXT NOT NULL,
    metric_date DATE NOT NULL,
    ip_status TEXT,
    complaint_rate DOUBLE PRECISION,
    trap_hits INTEGER DEFAULT 0,
    message_count INTEGER DEFAULT 0,
    filter_results JSONB,
    sample_helos JSONB,
    raw_data TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, ip_address, metric_date)
);

-- Primary access: latest-N-days per user (app.py:1947).
CREATE INDEX IF NOT EXISTS idx_snds_metrics_user_date
    ON public.snds_metrics(user_id, metric_date DESC);

-- Secondary: drill-down into a single IP for the dashboard graph.
CREATE INDEX IF NOT EXISTS idx_snds_metrics_user_ip_date
    ON public.snds_metrics(user_id, ip_address, metric_date DESC);

ALTER TABLE public.snds_metrics ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view own snds metrics" ON public.snds_metrics;
CREATE POLICY "Users can view own snds metrics"
    ON public.snds_metrics FOR SELECT
    USING (auth.uid() = user_id);

DROP POLICY IF EXISTS "Service role full access to snds_metrics" ON public.snds_metrics;
CREATE POLICY "Service role full access to snds_metrics"
    ON public.snds_metrics FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);
