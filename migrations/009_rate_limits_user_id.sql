-- INBOX-30: add user_id to rate_limits.
--
-- Closes two bugs that share a root cause (rate_limits has no user_id column):
--
--   Bug 1 — db.delete_user_data did:
--             DELETE FROM rate_limits WHERE ip_address = <user_id UUID>
--           ip_address is INET, user_id is UUID. Postgres rejects the cast,
--           zero rows are deleted, the user's rate-limit data persists.
--
--   Bug 2 — db.check_rate_limit stored the UUID in the ip_address column
--           for authenticated users (same column, same type mismatch).
--           INSERT/UPDATE both failed silently via a bare-except, which
--           meant rate limiting never enforced for logged-in users. The
--           moment paid plans launch, every paid customer has effectively
--           unlimited scans.
--
-- Fix shape:
--   - Add user_id UUID column (nullable — anonymous users will have NULL).
--   - Index on user_id for the authenticated lookup path.
--   - Relax ip_address from NOT NULL to nullable, because authenticated
--     rows will only have user_id populated. Anonymous rows still have
--     ip_address populated.
--   - Code changes in db.py (separate commit) make this operational.

ALTER TABLE public.rate_limits
    ADD COLUMN IF NOT EXISTS user_id UUID;

-- Anonymous rows still key by ip_address; authenticated rows will carry a
-- NULL ip_address and a populated user_id. Relax the NOT NULL so the
-- authenticated-row shape is legal.
ALTER TABLE public.rate_limits
    ALTER COLUMN ip_address DROP NOT NULL;

CREATE INDEX IF NOT EXISTS idx_rate_limits_user_date
    ON public.rate_limits(user_id, date)
    WHERE user_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_date
    ON public.rate_limits(ip_address, date)
    WHERE ip_address IS NOT NULL;

-- Defensive: if a future row somehow has both NULL, it would be
-- indistinguishable from any other. Enforce at least one is populated.
-- Idempotent-safe because IF NOT EXISTS isn't supported for constraints,
-- so we drop+recreate.
ALTER TABLE public.rate_limits
    DROP CONSTRAINT IF EXISTS rate_limits_key_present;
ALTER TABLE public.rate_limits
    ADD CONSTRAINT rate_limits_key_present
    CHECK (ip_address IS NOT NULL OR user_id IS NOT NULL);
