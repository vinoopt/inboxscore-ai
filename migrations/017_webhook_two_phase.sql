-- INBOX-258 (audit C2 fix, 2026-05-15) — two-phase webhook idempotency.
--
-- Why we need this:
--   Migration 016 created stripe_webhook_events with
--       processed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
--   which means EVERY row is timestamped on insert, even before the
--   handler runs. Combined with the "insert-first, then process"
--   pattern in /api/webhooks/stripe, this caused permanent data loss:
--
--     1. Webhook arrives → insert row (processed_at = NOW)
--     2. Handler throws → return 500 → Stripe retries
--     3. Retry → "already processed" short-circuit → state never repairs
--
--   Fix: make processed_at NULLable. The new two-phase pattern is:
--     Phase 1: INSERT row with processed_at=NULL
--     Phase 2: After handler returns OK, UPDATE row to processed_at=NOW
--   On retry, if processed_at IS NULL we know the previous attempt
--   crashed and the handler is allowed to run again.
--
-- Idempotent + reversible:
--   • ALTER COLUMN DROP NOT NULL is no-op on subsequent runs
--   • ALTER COLUMN DROP DEFAULT removes the eager-timestamp
--   • Reverse: ALTER COLUMN SET NOT NULL + SET DEFAULT NOW()
--     (only safe if no rows currently have processed_at=NULL)

ALTER TABLE public.stripe_webhook_events
    ALTER COLUMN processed_at DROP NOT NULL;

ALTER TABLE public.stripe_webhook_events
    ALTER COLUMN processed_at DROP DEFAULT;

-- Helpful for ops queries — "show me stuck webhooks": rows that came
-- in but never finished. Partial index keeps it small.
CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_stuck
    ON public.stripe_webhook_events (event_type, stripe_event_id)
    WHERE processed_at IS NULL;

COMMENT ON COLUMN public.stripe_webhook_events.processed_at IS
    'When the handler finished successfully. NULL means the row was inserted but the handler crashed or is still running — retries are allowed to re-attempt.';
