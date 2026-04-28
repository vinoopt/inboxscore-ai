-- INBOX-126: Default auto-monitoring ON for every domain.
--
-- Background: when a user added a domain to InboxScore, our code
-- inserted is_monitored=false and there was no UI to flip it on.
-- Result: nothing was being scanned automatically. Users (including
-- Vinoop) saw a Score Trend chart that never picked up today's scan
-- because today's scan never ran.
--
-- This migration:
--   1. Sets the column DEFAULT to true at the DB level — so even if
--      a future code path inserts without specifying, monitoring is
--      on.
--   2. Backfills every existing row to is_monitored=true.
--
-- Idempotent — safe to re-run.

-- 1) Column default flip
ALTER TABLE domains
    ALTER COLUMN is_monitored SET DEFAULT true;

-- 2) Backfill all existing rows
UPDATE domains
SET is_monitored = true
WHERE is_monitored = false OR is_monitored IS NULL;

-- 3) The legacy monitor_frequency column ('weekly' | 'daily') is dead
-- — get_domains_due_for_scan() reads monitor_interval (hours) instead.
-- Dropping the column to remove the contradiction (rows currently say
-- frequency=weekly + interval=24h, which is contradictory). Safe: no
-- code reads this column anywhere in the app.
ALTER TABLE domains
    DROP COLUMN IF EXISTS monitor_frequency;
