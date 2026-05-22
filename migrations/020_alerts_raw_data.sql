-- INBOX-144 (2026-05-21) — add raw_data JSONB to alerts table.
--
-- Why:
--   Email notifier (notifier.py) needs structured payload to render
--   dynamic content (which blocklists, what score delta, which checks
--   failed, etc.) — copy and links change based on the underlying
--   event data. The existing `message` text field is human-readable
--   only; not parseable for templating.
--
--   The new raw_data column carries the dict that monitor.compare_scan_results
--   and the alerts_postmaster/alerts_snds modules already produce
--   internally — we just stop dropping it on the floor before
--   create_alert(). Format-free JSONB so we can extend per alert type
--   without further migrations.
--
-- What gets stored (examples):
--   blacklist_added:    {"blacklists_listed": ["Spamhaus ZEN", "Barracuda"],
--                        "blacklists_count": 2, "blacklist_type": "domain"}
--   score_drop:         {"old_score": 62, "new_score": 58,
--                        "score_delta": -4, "failing_checks": ["spf", "gmail_spam_rate"]}
--   dmarc_change:       {"old_policy": "reject", "new_policy": "quarantine",
--                        "old_record": "v=DMARC1; p=reject; ...", "new_record": "..."}
--   reputation_change:  {"old_tier": "HIGH", "new_tier": "BAD",
--                        "affected": "domain"|"ip", "ip": "1.2.3.4"}
--   spam_rate alerts:   {"spam_rate": 0.0038, "yesterday_spam_rate": 0.0005,
--                        "threshold_crossed": 0.003}
--
-- Idempotent + reversible:
--   • ADD COLUMN IF NOT EXISTS is no-op on subsequent runs
--   • Default '{}'::jsonb so existing rows + non-emitting callers stay valid
--   • Reverse: ALTER TABLE public.alerts DROP COLUMN IF EXISTS raw_data;

ALTER TABLE public.alerts
    ADD COLUMN IF NOT EXISTS raw_data JSONB DEFAULT '{}'::jsonb;

COMMENT ON COLUMN public.alerts.raw_data IS
    'INBOX-144: structured event payload used by notifier.py to render dynamic email content. Format-free JSONB — schema varies per alert type. Empty object default for rows created before this migration / for callers that don''t populate it.';
