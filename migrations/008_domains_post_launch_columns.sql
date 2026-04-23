-- INBOX-32: Defensive ADD COLUMN IF NOT EXISTS on domains.
--
-- These three columns were added to prod post-launch without a committed
-- migration:
--   * monitor_interval     — INT, default 24 (hours). Replaces the legacy
--                            text-based monitor_frequency column for all
--                            code paths in monitor.py / db.py.
--   * last_monitored_at    — TIMESTAMPTZ. Written by monitor.py at the end
--                            of each per-domain scan (db.py:555).
--   * previous_score       — INT. Captured before overwriting latest_score
--                            so we can compute score_change without an
--                            extra scans-table lookup (db.py:555).
--
-- 001_base_schema.sql already declares domains with all three columns. This
-- file is a belt-and-braces safety net for any environment that was bootstrapped
-- from the legacy db/supabase-schema.sql BEFORE 001 was introduced, i.e. the
-- same state prod was in on 2026-04-22 before INBOX-32.
--
-- Against a fresh Postgres that ran 001 first, this file is a pure no-op
-- (all three ADD COLUMN IF NOT EXISTS statements find the columns already
-- present). Against prod it is also a no-op for the same reason. Against a
-- hypothetical "legacy base only" environment it forward-patches the schema
-- to match the code.

ALTER TABLE public.domains
    ADD COLUMN IF NOT EXISTS monitor_interval INTEGER DEFAULT 24;

ALTER TABLE public.domains
    ADD COLUMN IF NOT EXISTS last_monitored_at TIMESTAMPTZ;

ALTER TABLE public.domains
    ADD COLUMN IF NOT EXISTS previous_score INTEGER;
