-- INBOX-144 (2026-05-21) — notification_log table for email send tracking.
--
-- Why:
--   notifier.py needs idempotency: the same alert must never produce
--   two emails. The monitor cycle may be retried on transient errors;
--   webhook reconcilers may re-fire; manual replays during ops cleanup
--   shouldn't spam customers.
--
--   notification_log is the ledger. Row inserted BEFORE the MailerCloud
--   API call (pre-flight write); updated with status + message_id AFTER
--   the call returns. The UNIQUE(user_id, alert_id, channel) constraint
--   makes double-sends a database error, not a runtime bug.
--
-- Lifecycle:
--   1. notifier.py decides to send → INSERT row with status='sending'
--      (UNIQUE constraint catches duplicates → existing row returned →
--      skip send entirely)
--   2. MailerCloud API call
--   3. UPDATE row with status='sent' + message_id (success)
--      OR status='failed' + error_code + error_message
--   4. If the user's email_mode == 'off' or no email on file, we still
--      log status='skipped' so the audit trail is complete
--
-- Idempotent + reversible:
--   • CREATE TABLE IF NOT EXISTS — no-op on subsequent runs
--   • Reverse: DROP TABLE public.notification_log;

CREATE TABLE IF NOT EXISTS public.notification_log (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES public.alerts(id) ON DELETE SET NULL,
    domain TEXT,
    channel TEXT NOT NULL CHECK (channel IN ('email', 'slack', 'webhook')),
    status TEXT NOT NULL CHECK (status IN ('sending', 'sent', 'failed', 'skipped')),
    message_id TEXT,
    error_code TEXT,
    error_message TEXT,
    skip_reason TEXT,
    sent_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, alert_id, channel)
);

-- Indexes
-- Primary read pattern: per-user audit + recent sends (Sentry triage,
-- support tickets, ops dashboards).
CREATE INDEX IF NOT EXISTS idx_notification_log_user_sent
    ON public.notification_log(user_id, sent_at DESC);

-- Secondary: drill into a specific alert's notification history.
CREATE INDEX IF NOT EXISTS idx_notification_log_alert
    ON public.notification_log(alert_id);

-- Tertiary: surface recent failures for monitoring dashboards.
CREATE INDEX IF NOT EXISTS idx_notification_log_failed
    ON public.notification_log(sent_at DESC) WHERE status = 'failed';

-- Row-level security — same pattern as alerts table.
ALTER TABLE public.notification_log ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view own notification logs" ON public.notification_log;
CREATE POLICY "Users can view own notification logs"
    ON public.notification_log FOR SELECT
    USING (auth.uid() = user_id);

COMMENT ON TABLE public.notification_log IS
    'INBOX-144: idempotency ledger for external-channel notifications. UNIQUE(user_id, alert_id, channel) prevents double-send. notifier.py inserts before API call and updates after.';
