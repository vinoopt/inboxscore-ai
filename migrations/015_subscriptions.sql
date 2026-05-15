-- INBOX-10b — Stripe billing: subscriptions table.
--
-- Why we need this:
--   Stripe integration (INBOX-10) introduces a paid Pro tier. We need a
--   local subscription record that is the single source of truth for
--   feature-gating ("can this user run a scan? add a domain?"). Without
--   it, every gate check would have to round-trip Stripe — too slow.
--
--   The legacy profiles.plan TEXT column becomes a denormalised cache
--   of this table's `plan` value, kept in sync by the Stripe webhook
--   handler. Any security-relevant decision resolves through this
--   table, not through profiles.plan.
--
-- Plan state machine (3 values, no perpetual Free):
--   trial → first 14 days post-signup, full Pro access, no card collected
--   pro   → active paid subscription
--   stub  → trial expired without conversion, or cancelled/unpaid Pro
--           (account lights-on, severely-limited; 1 scan/week, read-only)
--
-- Status values (mirror Stripe + one local extension):
--   trialing | active | past_due | canceled | incomplete | incomplete_expired
--   stub      ← local: trial that expired with no card, or fully-lapsed sub
--
-- Shape decisions:
--   • UNIQUE(user_id) — one subscription per user. We never run parallel
--     subs for the same account. Reactivation reuses the row.
--   • stripe_subscription_id is UNIQUE but nullable: pre-signup or
--     during the brief window before the trial subscription gets created,
--     a user might exist without one. After signup completes, it's set.
--   • last_webhook_event_id captures the most recent Stripe event that
--     touched this row. Combined with stripe_webhook_events (migration 016)
--     gives us full idempotency observability — "did event X actually
--     mutate this row, or did we no-op?"
--   • CHECK constraints on plan + status to catch typos in webhook
--     handler code at insert time, not at runtime gating.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.
-- Reversible: DROP TABLE public.subscriptions CASCADE.

-- Fresh-install path: create the full table from scratch. On a CI
-- replay there's a legacy 10-column subscriptions table created by
-- db/supabase-schema.sql (the historical pre-Stripe shape: id,
-- user_id, stripe_subscription_id, plan, status, current_period_*,
-- created_at, updated_at) — IF NOT EXISTS makes this a no-op against
-- that legacy table; the ALTER TABLE statements below then add every
-- Stripe-specific column.
CREATE TABLE IF NOT EXISTS public.subscriptions (
    id                       UUID         PRIMARY KEY DEFAULT gen_random_uuid(),

    -- One sub per user. ON DELETE CASCADE so account deletion cleans
    -- up the row; the Stripe customer/sub is canceled separately by
    -- the account-deletion handler before the row goes away.
    user_id                  UUID         NOT NULL UNIQUE
                                          REFERENCES public.profiles(id) ON DELETE CASCADE,

    -- Stripe identifiers. Nullable while the trial sub is being created
    -- (briefly during signup). After that, all three are populated for
    -- trialing/active/canceled rows. For 'stub' rows we keep them — the
    -- Stripe sub still exists in canceled state on Stripe's side.
    stripe_customer_id       TEXT,
    stripe_subscription_id   TEXT         UNIQUE,
    stripe_price_id          TEXT,

    -- Our plan state machine (see header).
    plan                     TEXT         NOT NULL DEFAULT 'stub',

    -- Subscription status mirroring Stripe, plus our 'stub' extension.
    status                   TEXT         NOT NULL DEFAULT 'stub',

    -- Billing period (mirrors Stripe's current_period_*).
    current_period_start     TIMESTAMPTZ,
    current_period_end       TIMESTAMPTZ,

    -- Trial-specific. trial_end is the wall-clock moment Stripe will
    -- attempt the first charge. We index this for the daily reminder
    -- scheduler that sends "trial ends in 3 days" emails.
    trial_end                TIMESTAMPTZ,

    -- User-initiated cancel. cancel_at_period_end = true means "keep
    -- Pro until current_period_end, then drop to stub."
    cancel_at_period_end     BOOLEAN      NOT NULL DEFAULT false,
    canceled_at              TIMESTAMPTZ,

    -- Audit + idempotency observability.
    created_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    last_webhook_event_id    TEXT
);

-- Upgrade path: legacy installs already have a 10-col subscriptions
-- table created by db/supabase-schema.sql. The CREATE TABLE above
-- is a no-op there, so we explicitly add each new column. Idempotent.
ALTER TABLE public.subscriptions
    ADD COLUMN IF NOT EXISTS stripe_customer_id     TEXT,
    ADD COLUMN IF NOT EXISTS stripe_price_id        TEXT,
    ADD COLUMN IF NOT EXISTS trial_end              TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS cancel_at_period_end   BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS canceled_at            TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS last_webhook_event_id  TEXT;

-- Loosen the legacy CHECK constraints. The pre-Stripe shape required
-- plan IN ('pro','growth','enterprise') and status IN
-- ('active','canceled','past_due','trialing','incomplete'). The new
-- model adds 'trial' + 'stub' to plan and 'incomplete_expired' +
-- 'stub' to status. Drop and re-add with the wider whitelist.
ALTER TABLE public.subscriptions
    DROP CONSTRAINT IF EXISTS subscriptions_plan_check;
ALTER TABLE public.subscriptions
    ADD CONSTRAINT subscriptions_plan_check
    CHECK (plan IN ('trial', 'pro', 'stub', 'growth', 'enterprise', 'free'));

ALTER TABLE public.subscriptions
    DROP CONSTRAINT IF EXISTS subscriptions_status_check;
ALTER TABLE public.subscriptions
    ADD CONSTRAINT subscriptions_status_check
    CHECK (status IN (
        'trialing', 'active', 'past_due',
        'canceled', 'incomplete',
        'incomplete_expired', 'stub', 'unpaid', 'paused'
    ));

-- Stripe customer ID is unique where present (one customer per user).
CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_stripe_customer
    ON public.subscriptions (stripe_customer_id)
    WHERE stripe_customer_id IS NOT NULL;

-- Status-based reads (e.g. "all trialing users for the day-11 reminder
-- batch", "all past_due for dunning emails").
CREATE INDEX IF NOT EXISTS idx_subscriptions_status
    ON public.subscriptions (status);

-- Trial-end scheduler — partial index, only relevant rows.
CREATE INDEX IF NOT EXISTS idx_subscriptions_trial_end
    ON public.subscriptions (trial_end)
    WHERE status = 'trialing';

-- updated_at auto-bump on UPDATE. Uses the standard pattern; if a
-- public.set_updated_at() function already exists from a prior migration,
-- CREATE OR REPLACE is a no-op-equivalent.
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS subscriptions_set_updated_at ON public.subscriptions;
CREATE TRIGGER subscriptions_set_updated_at
    BEFORE UPDATE ON public.subscriptions
    FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

COMMENT ON TABLE public.subscriptions IS
    'Single source of truth for billing state. profiles.plan is a cache of this row''s plan column; webhooks keep them in sync. See PAYMENT-PLAN.md sections 4 + 5.';
