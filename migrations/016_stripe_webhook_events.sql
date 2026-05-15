-- INBOX-10d — Stripe webhook idempotency log.
--
-- Why we need this:
--   Stripe replays webhook events on failure (up to 3 days for some
--   event types) and can also deliver the same event multiple times
--   under network partitions. Our handler MUST be idempotent or we'll
--   double-process — e.g., a duplicate checkout.session.completed could
--   re-trigger the "welcome to Pro" email or double-update analytics.
--
--   This table is the idempotency ledger: every event we receive gets
--   inserted FIRST (ON CONFLICT DO NOTHING). If the insert succeeds,
--   we process the event. If the insert is a conflict, we've seen the
--   event before — return 200 to Stripe without re-running side effects.
--
-- Retention:
--   We keep events forever for audit. At 10K events/month a year of
--   data = 120K rows = trivial. We can prune to 90 days later if needed.
--
-- Shape decisions:
--   • stripe_event_id PRIMARY KEY — Stripe guarantees this is unique
--     per event delivery. ON CONFLICT DO NOTHING is the fast path.
--   • payload JSONB — full event body, for replay/debug. We never
--     trust the payload at process time (verify signature first); this
--     is purely audit data.
--   • processed_at — when our handler finished. NULL would mean "we
--     received but didn't finish processing" — currently not used but
--     leaves room for a two-phase pattern later.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.
-- Reversible: DROP TABLE public.stripe_webhook_events.

CREATE TABLE IF NOT EXISTS public.stripe_webhook_events (
    stripe_event_id   TEXT         PRIMARY KEY,
    event_type        TEXT         NOT NULL,
    payload           JSONB        NOT NULL,
    processed_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Type-based reads (e.g., "how many trial_will_end events did we get
-- last week?" for funnel debugging).
CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_type
    ON public.stripe_webhook_events (event_type);

CREATE INDEX IF NOT EXISTS idx_stripe_webhook_events_processed_at
    ON public.stripe_webhook_events (processed_at DESC);

COMMENT ON TABLE public.stripe_webhook_events IS
    'Idempotency ledger for Stripe webhook deliveries. Insert-first-then-process pattern. See PAYMENT-PLAN.md section 3.';
