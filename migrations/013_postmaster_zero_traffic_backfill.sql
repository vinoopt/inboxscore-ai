-- INBOX-211 — backfill zero-traffic days in postmaster_metrics.
--
-- The bug:
--   Google Postmaster v2 returns ``floatValue: 0`` for spam_rate,
--   auth_success_*, encrypted_traffic_tls and delivery_error_rate on
--   days where the domain had no Gmail traffic. We were storing those
--   0s verbatim, then rendering them as red "0.00%" failure pills on
--   the Postmaster page (auth chart collapsed, TLS averages dragged
--   down, dashboard cards lit up red on perfectly healthy domains).
--   Vinoop caught this on redrail.redbus.com Apr 25–26 2026 — Google's
--   own UI had hidden those days entirely; ours flagged them red.
--
-- The fix is two-part:
--   1. Ingest path (db.upsert_postmaster_metrics) — going forward,
--      detect zero-traffic days (auth_dmarc + tls both zero/null) and
--      store every rate field as NULL. JSON gets a `_zero_traffic: true`
--      tag so we can audit later.
--   2. This migration — null-out the existing rows that match the same
--      signature, so the UI fixes apply retroactively to the past 30
--      days of cached data without waiting for the daily re-sync.
--
-- Detection signature:
--   auth_success_dmarc IS NOT DISTINCT FROM 0  AND
--   encrypted_traffic_tls IS NOT DISTINCT FROM 0
--
--   Healthy senders never report 0% on both DMARC and TLS at once on
--   real volume — DMARC and TLS are negotiated per-message and run >95%
--   under normal sending. Spam-rate alone is unreliable (0% spam IS
--   healthy on a real-traffic day). This pair is the one combination
--   that's mathematically impossible on a day with delivered mail.
--
-- Safety:
--   • Read-only on auth_success_dmarc + encrypted_traffic_tls. We use
--     them to FIND rows, not to overwrite them — they get nulled too,
--     but only because they were already 0 (the lossless equivalent).
--   • All other fields preserved as-is.
--   • Idempotent: running this twice produces the same result.
--   • Reversible by rolling forward (the next sync will overwrite).
--
-- Run order: AFTER deploying the db.py ingest fix. The ingest fix is
-- the load-bearing change; this is just retroactive cleanup.

UPDATE postmaster_metrics
SET
    spam_rate = NULL,
    auth_success_spf = NULL,
    auth_success_dkim = NULL,
    auth_success_dmarc = NULL,
    encrypted_traffic_tls = NULL,
    -- Tag the JSON so future audits / debugging can identify which rows
    -- were nulled by this backfill vs. genuinely missing data. Replaces
    -- the existing JSON entirely (the only fields it carried for
    -- zero-traffic days were _rate=0 and _count=0, both meaningless).
    delivery_errors = '{"_zero_traffic": true, "_backfilled_2026_05": true}'::jsonb
WHERE
    -- Both signature fields are exactly 0. IS NOT DISTINCT FROM treats
    -- NULL as a value (so NULL=NULL is true) — but for safety we only
    -- want rows where they were genuinely 0 (the bug pattern), not
    -- already null. So compare with `=` to require non-null 0s.
    auth_success_dmarc = 0
    AND encrypted_traffic_tls = 0;

-- Sanity check (run separately to verify):
--   SELECT COUNT(*) FROM postmaster_metrics
--   WHERE auth_success_dmarc IS NULL
--     AND encrypted_traffic_tls IS NULL
--     AND delivery_errors::text LIKE '%_zero_traffic%';
