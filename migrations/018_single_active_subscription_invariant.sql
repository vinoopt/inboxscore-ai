-- INBOX-267 Layer 5 (2026-05-18) — single-active-subscription invariant.
--
-- Why we need this:
--   Vinoop's test account vinoop@luvia.com ended up with 2 active
--   Stripe subscriptions because /api/billing/checkout had no guard
--   against creating a new Checkout Session when an active sub already
--   existed. Layers 1-4 add UI/API/SDK/webhook protection; Layer 5 is
--   the last-resort safety net at the database layer.
--
--   Our subscriptions table already has UNIQUE(user_id) so one ROW per
--   user is enforced. The remaining risk is at Stripe's side: our row
--   tracks ONE stripe_subscription_id, but Stripe can have many subs
--   on the same customer. We can't enforce Stripe state from Postgres,
--   but we CAN enforce two extra invariants:
--
--   1. A partial UNIQUE index that makes the "one live sub per user"
--      rule explicit and survives any future relaxation of the
--      user_id UNIQUE constraint. Redundant today, explicit always.
--
--   2. An audit table for orphaned subscription IDs. Whenever
--      subscriptions.stripe_subscription_id is mutated in place (the
--      application repointed a row to a new Stripe sub), the previous
--      sub_id is logged for ops cleanup. This catches the case where
--      Stripe-side cleanup didn't happen but our row moved on.
--
-- Idempotent + reversible:
--   • CREATE INDEX IF NOT EXISTS is no-op on subsequent runs
--   • CREATE TABLE IF NOT EXISTS is no-op on subsequent runs
--   • DROP INDEX / DROP TABLE to reverse

-- ─────────────────────────────────────────────────────────────────
-- Part 1: Explicit partial UNIQUE index for "one live sub per user".
-- ─────────────────────────────────────────────────────────────────
--
-- Redundant with the existing UNIQUE(user_id) on subscriptions, but
-- (a) makes the invariant queryable in pg_indexes, (b) survives if a
-- future migration ever relaxes the user_id UNIQUE constraint to
-- support multi-product subscriptions, (c) shows up in EXPLAIN plans
-- when filtering by status.

CREATE UNIQUE INDEX IF NOT EXISTS subscriptions_one_live_per_user_idx
    ON public.subscriptions (user_id)
    WHERE status IN ('active', 'trialing', 'past_due');

COMMENT ON INDEX public.subscriptions_one_live_per_user_idx IS
    'INBOX-267 Layer 5: enforce one live subscription per user. Partial unique index on user_id where status is active/trialing/past_due. Belt + suspenders with the existing UNIQUE(user_id) row constraint.';


-- ─────────────────────────────────────────────────────────────────
-- Part 2: Orphaned-sub audit table.
-- ─────────────────────────────────────────────────────────────────
--
-- When the application repoints subscriptions.stripe_subscription_id
-- from sub_A to sub_B (reactivation, mid-life sub swap, etc.) we want
-- a record of sub_A so ops can verify it was cancelled on Stripe's
-- side. Webhook handlers + reconciler should INSERT here whenever they
-- discover or cancel an orphan.

CREATE TABLE IF NOT EXISTS public.subscriptions_orphan_audit (
    id                       BIGSERIAL    PRIMARY KEY,

    -- The Stripe sub that got orphaned. We keep this NULLable in case
    -- the discovery happened without a known sub_id (e.g., we only had
    -- the customer_id).
    orphaned_sub_id          TEXT,

    -- Customer the orphan lived on.
    stripe_customer_id       TEXT         NOT NULL,

    -- The sub_id we kept (Layer 4 reconciler logs this).
    keeper_sub_id            TEXT,

    -- Internal user, if known.
    user_id                  UUID         REFERENCES public.profiles(id) ON DELETE SET NULL,

    -- Free-text reason: 'reconciler_duplicate', 'manual_cleanup', etc.
    reason                   TEXT         NOT NULL,

    -- When the orphan was detected/recorded.
    detected_at              TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    -- Whether ops has confirmed Stripe-side cleanup. Flip to true via
    -- script or dashboard once verified.
    resolved_at              TIMESTAMPTZ,

    -- The Stripe event that triggered detection, if applicable.
    triggered_by_event_id    TEXT
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_orphan_audit_unresolved
    ON public.subscriptions_orphan_audit (detected_at)
    WHERE resolved_at IS NULL;

CREATE INDEX IF NOT EXISTS idx_subscriptions_orphan_audit_customer
    ON public.subscriptions_orphan_audit (stripe_customer_id);

COMMENT ON TABLE public.subscriptions_orphan_audit IS
    'INBOX-267 Layer 5: records Stripe subscriptions that got orphaned (cancelled by our reconciler, or discovered post-hoc as duplicates). Ops uses idx_subscriptions_orphan_audit_unresolved to find work.';
