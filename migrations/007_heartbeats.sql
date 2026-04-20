-- INBOX-16: Scheduler heartbeat log.
-- Each scheduler cycle (monitor every 15 min, postmaster_sync/snds_sync daily)
-- inserts one row at the START of a cycle, and UPDATEs it at the END with
-- completion data. A row with NULL cycle_completed_at means either the cycle
-- is still running OR it crashed before reaching the end.
-- The /api/monitoring/heartbeat-status endpoint reads the latest row per
-- cycle_type to detect silent scheduler failures (see INBOX-1 post-mortem).

CREATE TABLE IF NOT EXISTS monitoring_heartbeats (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    cycle_type TEXT NOT NULL,                         -- 'monitor' | 'postmaster_sync' | 'snds_sync'
    cycle_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    cycle_completed_at TIMESTAMPTZ,                   -- NULL until the cycle finishes cleanly
    domains_processed INTEGER DEFAULT 0,
    errors_count INTEGER DEFAULT 0,
    notes TEXT
);

-- Fast lookup of "latest heartbeat for a given cycle type"
CREATE INDEX IF NOT EXISTS idx_heartbeats_type_started
    ON monitoring_heartbeats(cycle_type, cycle_started_at DESC);

-- RLS: this is internal ops data — only the service role touches it.
-- No user-level SELECT policy; the public heartbeat-status endpoint calls this
-- server-side using the service role key.
ALTER TABLE monitoring_heartbeats ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access to monitoring_heartbeats"
    ON monitoring_heartbeats FOR ALL
    TO service_role
    USING (true)
    WITH CHECK (true);
