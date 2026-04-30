-- INBOX-171 (F12) — Google Safe Browsing API response cache.
--
-- Why we need this:
--   • Every scan currently calls GSB v4 (checks.py::check_google_safe_browsing).
--   • Free tier = 10,000 lookups/day; we'll exhaust this around 10k
--     scans/day. With auto-monitoring (4 cycles/day × N domains) and
--     manual scans on top, today's portfolio at 5 domains burns
--     ~20 GSB calls/day. At 1k users × 10 domains = 10k domains × 4
--     cycles = 40k GSB calls/day — hard quota wall.
--   • GSB's threat list updates daily (Google's docs). So caching
--     per-domain results for 24h is loss-free: we never miss a fresh
--     flag we couldn't see anyway.
--
-- The cache:
--   • PRIMARY KEY (domain) — one row per domain, upserted on each lookup.
--   • threats: JSONB result of the GSB call. Empty array = "no threats".
--     Storing the full response (not just a status) lets us reconstruct
--     the same CheckResult shape (threat_types, matches count) without
--     re-calling GSB.
--   • checked_at: when this cache row was filled. Cache TTL is enforced
--     in Python (24h). Index on this column powers the nightly
--     cleanup job that prunes anything older than 30 days.
--
-- Idempotent: CREATE TABLE IF NOT EXISTS + CREATE INDEX IF NOT EXISTS.
-- Reversible: DROP TABLE public.gsb_cache.

CREATE TABLE IF NOT EXISTS public.gsb_cache (
    domain      text PRIMARY KEY,
    threats     jsonb NOT NULL DEFAULT '[]'::jsonb,
    checked_at  timestamp with time zone NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_gsb_cache_checked_at
    ON public.gsb_cache (checked_at DESC);
