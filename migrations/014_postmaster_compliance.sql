-- INBOX-226 — Postmaster compliance verdict cache.
--
-- Why we need this:
--   Today the Dashboard's /api/postmaster/compliance-bulk endpoint
--   fan-outs to Google's compliance API live, once per domain. With
--   5+ domains this adds 2-5 seconds to every Dashboard cold load.
--
--   The verdicts themselves are rolling/aggregated multi-day signals
--   that change rarely — perfect for caching. The existing daily
--   Postmaster scheduler (postmaster_scheduler.py @ 6 AM UTC) already
--   pulls metrics from Google; we just need it to ALSO pull compliance
--   verdicts and store them.
--
--   After this lands, /api/postmaster/compliance-bulk becomes a single
--   indexed DB read (<50ms) instead of N parallel Google calls (2-5s).
--
-- Shape:
--   One row per (user, domain). Stores Google's full compliance
--   response as JSONB so the same row works for both:
--     • the bulk endpoint (just reads has_any_verdict + 3 summarised
--       rows for the Dashboard pill row)
--     • the single-domain endpoint (returns the full payload for the
--       Postmaster details page's Compliance Status tab)
--
--   We also denormalise the 3 summarised verdicts (auth / spam /
--   encryption) as TEXT columns so the bulk endpoint can answer
--   without needing JSON-path operators.

CREATE TABLE IF NOT EXISTS postmaster_compliance (
    user_id            UUID         NOT NULL,
    domain             TEXT         NOT NULL,
    -- Denormalised verdicts powering the Dashboard pill row.
    -- Values: 'COMPLIANT' | 'NEEDS_WORK' | NULL (no verdict from Google).
    auth_verdict       TEXT,
    spam_verdict       TEXT,
    encryption_verdict TEXT,
    has_any_verdict    BOOLEAN      NOT NULL DEFAULT false,
    -- Full Google compliance API response. Used by the single-domain
    -- endpoint to render the 8-row Compliance Status table on the
    -- Postmaster details page.
    raw_data           JSONB,
    -- When did the daily scheduler last write this row.
    synced_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, domain)
);

CREATE INDEX IF NOT EXISTS idx_postmaster_compliance_user
    ON postmaster_compliance (user_id);
CREATE INDEX IF NOT EXISTS idx_postmaster_compliance_synced
    ON postmaster_compliance (synced_at);

-- Comment for future maintainers
COMMENT ON TABLE postmaster_compliance IS
    'INBOX-226: cache of Google Postmaster compliance verdicts per (user, domain). Written daily by postmaster_scheduler.py, read by /api/postmaster/compliance-bulk and /api/postmaster/compliance/<domain>.';
