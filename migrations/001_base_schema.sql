-- ============================================================================
-- INBOX-32 (2026-04-22): base schema — fully idempotent replay.
--
-- This migration is a from-scratch-deployable version of the original
-- `db/supabase-schema.sql` (historical, non-idempotent March 2026 snapshot).
-- It creates the 12 base tables PLUS the post-launch additions to `domains`
-- that were previously made directly in prod via the Supabase dashboard and
-- never captured in a migration (columns: monitor_interval, last_monitored_at,
-- previous_score). All DDL here uses IF NOT EXISTS / CREATE OR REPLACE /
-- DROP…IF EXISTS so re-applying against a populated database is a no-op.
--
-- Reference: docs/SCHEMA-DIFF-2026-04-22.md
--
-- Rollback: `git revert` the commit that introduces this file. All statements
-- are additive + idempotent against prod, so reverting is safe (prod state is
-- not touched by applying this file).
-- ============================================================================

-- ------------------------------------------------
-- Extensions
-- ------------------------------------------------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ------------------------------------------------
-- 1. profiles
-- ------------------------------------------------
CREATE TABLE IF NOT EXISTS public.profiles (
    id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    name TEXT,
    company TEXT,
    plan TEXT NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'pro', 'growth', 'enterprise')),
    stripe_customer_id TEXT,
    scans_today INTEGER NOT NULL DEFAULT 0,
    scans_today_date DATE NOT NULL DEFAULT CURRENT_DATE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- `preferences` column was added post-launch; ensure it exists for fresh installs.
ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS preferences JSONB;

-- Trigger: auto-create profile on auth.users insert.
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, name)
    VALUES (NEW.id, NEW.raw_user_meta_data->>'name')
    ON CONFLICT (id) DO NOTHING;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Trigger: touch updated_at.
CREATE OR REPLACE FUNCTION public.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS profiles_updated_at ON public.profiles;
CREATE TRIGGER profiles_updated_at
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- ------------------------------------------------
-- 2. domains (base columns + post-launch additions)
-- ------------------------------------------------
CREATE TABLE IF NOT EXISTS public.domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    is_monitored BOOLEAN NOT NULL DEFAULT FALSE,
    monitor_frequency TEXT DEFAULT 'weekly' CHECK (monitor_frequency IN ('weekly', 'daily')),
    alert_threshold INTEGER NOT NULL DEFAULT 70 CHECK (alert_threshold BETWEEN 0 AND 100),
    latest_score INTEGER CHECK (latest_score BETWEEN 0 AND 100),
    latest_scan_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Post-launch columns (previously only in prod, now declared in repo).
    monitor_interval INTEGER DEFAULT 24,
    last_monitored_at TIMESTAMPTZ,
    previous_score INTEGER,

    UNIQUE(user_id, domain)
);

-- Idempotent ADD COLUMNs in case this table already existed from the legacy
-- base schema that shipped without the post-launch columns.
ALTER TABLE public.domains ADD COLUMN IF NOT EXISTS monitor_interval INTEGER DEFAULT 24;
ALTER TABLE public.domains ADD COLUMN IF NOT EXISTS last_monitored_at TIMESTAMPTZ;
ALTER TABLE public.domains ADD COLUMN IF NOT EXISTS previous_score INTEGER;

CREATE INDEX IF NOT EXISTS idx_domains_user_id ON public.domains(user_id);
CREATE INDEX IF NOT EXISTS idx_domains_domain ON public.domains(domain);
CREATE INDEX IF NOT EXISTS idx_domains_monitored ON public.domains(is_monitored) WHERE is_monitored = TRUE;

-- ------------------------------------------------
-- 3. scans
-- ------------------------------------------------
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID REFERENCES public.domains(id) ON DELETE SET NULL,
    user_id UUID REFERENCES public.profiles(id) ON DELETE SET NULL,
    domain TEXT NOT NULL,
    score INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
    results JSONB NOT NULL,
    ip_address INET,
    scan_type TEXT NOT NULL DEFAULT 'manual' CHECK (scan_type IN ('manual', 'scheduled', 'api')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_user_id    ON public.scans(user_id);
CREATE INDEX IF NOT EXISTS idx_scans_domain     ON public.scans(domain);
CREATE INDEX IF NOT EXISTS idx_scans_domain_id  ON public.scans(domain_id);
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON public.scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_ip_date    ON public.scans(ip_address, created_at);

-- ------------------------------------------------
-- 4. alerts
-- ------------------------------------------------
CREATE TABLE IF NOT EXISTS public.alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    domain_id UUID NOT NULL REFERENCES public.domains(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK (type IN (
        'score_drop',
        'blacklist_added',
        'blacklist_removed',
        'cert_expiry',
        'reputation_change',
        'dmarc_change',
        'spf_change',
        'dkim_change',
        'dns_change'
    )),
    severity TEXT NOT NULL DEFAULT 'warning' CHECK (severity IN ('critical', 'warning', 'info')),
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_alerts_user_id    ON public.alerts(user_id);
CREATE INDEX IF NOT EXISTS idx_alerts_unread     ON public.alerts(user_id, is_read) WHERE is_read = FALSE;
CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON public.alerts(created_at DESC);

-- ------------------------------------------------
-- 5. subscriptions
-- ------------------------------------------------
CREATE TABLE IF NOT EXISTS public.subscriptions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    stripe_subscription_id TEXT UNIQUE,
    plan TEXT NOT NULL CHECK (plan IN ('pro', 'growth', 'enterprise')),
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'canceled', 'past_due', 'trialing', 'incomplete')),
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id   ON public.subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_stripe_id ON public.subscriptions(stripe_subscription_id);

DROP TRIGGER IF EXISTS subscriptions_updated_at ON public.subscriptions;
CREATE TRIGGER subscriptions_updated_at
    BEFORE UPDATE ON public.subscriptions
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- ------------------------------------------------
-- 6. blacklist_events
-- ------------------------------------------------
CREATE TABLE IF NOT EXISTS public.blacklist_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID NOT NULL REFERENCES public.domains(id) ON DELETE CASCADE,
    blacklist_name TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('listed', 'delisted')),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_blacklist_events_domain   ON public.blacklist_events(domain_id);
CREATE INDEX IF NOT EXISTS idx_blacklist_events_detected ON public.blacklist_events(detected_at DESC);

-- ------------------------------------------------
-- 7. postmaster_data  (legacy; Python code uses postmaster_metrics from 003)
-- ------------------------------------------------
CREATE TABLE IF NOT EXISTS public.postmaster_data (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID NOT NULL REFERENCES public.domains(id) ON DELETE CASCADE,
    date DATE NOT NULL,
    gmail_reputation TEXT CHECK (gmail_reputation IN ('HIGH', 'MEDIUM', 'LOW', 'BAD')),
    spam_rate REAL,
    spf_pass_rate REAL,
    dkim_pass_rate REAL,
    dmarc_pass_rate REAL,
    tls_rate REAL,
    delivery_errors JSONB,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE(domain_id, date)
);

CREATE INDEX IF NOT EXISTS idx_postmaster_domain_date ON public.postmaster_data(domain_id, date DESC);

-- ------------------------------------------------
-- 8. inbox_placement_tests
-- ------------------------------------------------
CREATE TABLE IF NOT EXISTS public.inbox_placement_tests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID NOT NULL REFERENCES public.domains(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    gmail_inbox_rate REAL,
    outlook_inbox_rate REAL,
    yahoo_inbox_rate REAL,
    apple_inbox_rate REAL,
    overall_inbox_rate REAL,
    raw_results JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_placement_domain  ON public.inbox_placement_tests(domain_id);
CREATE INDEX IF NOT EXISTS idx_placement_created ON public.inbox_placement_tests(created_at DESC);

-- ------------------------------------------------
-- 9. dmarc_reports
-- ------------------------------------------------
CREATE TABLE IF NOT EXISTS public.dmarc_reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID NOT NULL REFERENCES public.domains(id) ON DELETE CASCADE,
    report_date DATE NOT NULL,
    source_org TEXT NOT NULL,
    source_ip INET,
    spf_aligned BOOLEAN,
    dkim_aligned BOOLEAN,
    disposition TEXT CHECK (disposition IN ('none', 'quarantine', 'reject')),
    message_count INTEGER NOT NULL DEFAULT 0,
    raw_xml TEXT,
    parsed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_dmarc_domain_date ON public.dmarc_reports(domain_id, report_date DESC);
CREATE INDEX IF NOT EXISTS idx_dmarc_source      ON public.dmarc_reports(source_org);

-- ------------------------------------------------
-- 10. api_keys
-- ------------------------------------------------
CREATE TABLE IF NOT EXISTS public.api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT 'Default',
    calls_this_month INTEGER NOT NULL DEFAULT 0,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user ON public.api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON public.api_keys(key_hash);

-- ------------------------------------------------
-- 11. email_subscribers
-- ------------------------------------------------
CREATE TABLE IF NOT EXISTS public.email_subscribers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT NOT NULL UNIQUE,
    domain TEXT,
    score INTEGER,
    source TEXT DEFAULT 'scan_results',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_subscribers_email ON public.email_subscribers(email);

-- ------------------------------------------------
-- 12. rate_limits
-- ------------------------------------------------
CREATE TABLE IF NOT EXISTS public.rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET NOT NULL,
    scan_count INTEGER NOT NULL DEFAULT 1,
    date DATE NOT NULL DEFAULT CURRENT_DATE,

    UNIQUE(ip_address, date)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_date ON public.rate_limits(ip_address, date);

-- ============================================================================
-- RLS policies — all idempotent via DROP POLICY IF EXISTS + CREATE POLICY.
-- ============================================================================

-- profiles
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users can view own profile"   ON public.profiles;
DROP POLICY IF EXISTS "Users can update own profile" ON public.profiles;
CREATE POLICY "Users can view own profile"
    ON public.profiles FOR SELECT USING (auth.uid() = id);
CREATE POLICY "Users can update own profile"
    ON public.profiles FOR UPDATE USING (auth.uid() = id);

-- domains
ALTER TABLE public.domains ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users can view own domains"   ON public.domains;
DROP POLICY IF EXISTS "Users can insert own domains" ON public.domains;
DROP POLICY IF EXISTS "Users can update own domains" ON public.domains;
DROP POLICY IF EXISTS "Users can delete own domains" ON public.domains;
CREATE POLICY "Users can view own domains"
    ON public.domains FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert own domains"
    ON public.domains FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can update own domains"
    ON public.domains FOR UPDATE USING (auth.uid() = user_id);
CREATE POLICY "Users can delete own domains"
    ON public.domains FOR DELETE USING (auth.uid() = user_id);

-- scans
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users can view own scans"                ON public.scans;
DROP POLICY IF EXISTS "Users can insert scans"                  ON public.scans;
DROP POLICY IF EXISTS "Service role can insert anonymous scans" ON public.scans;
CREATE POLICY "Users can view own scans"
    ON public.scans FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert scans"
    ON public.scans FOR INSERT WITH CHECK (auth.uid() = user_id OR user_id IS NULL);
CREATE POLICY "Service role can insert anonymous scans"
    ON public.scans FOR INSERT WITH CHECK (user_id IS NULL);

-- alerts
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users can view own alerts"   ON public.alerts;
DROP POLICY IF EXISTS "Users can update own alerts" ON public.alerts;
CREATE POLICY "Users can view own alerts"
    ON public.alerts FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can update own alerts"
    ON public.alerts FOR UPDATE USING (auth.uid() = user_id);

-- subscriptions
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users can view own subscription" ON public.subscriptions;
CREATE POLICY "Users can view own subscription"
    ON public.subscriptions FOR SELECT USING (auth.uid() = user_id);

-- blacklist_events
ALTER TABLE public.blacklist_events ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users can view own domain blacklist events" ON public.blacklist_events;
CREATE POLICY "Users can view own domain blacklist events"
    ON public.blacklist_events FOR SELECT
    USING (domain_id IN (SELECT id FROM public.domains WHERE user_id = auth.uid()));

-- postmaster_data
ALTER TABLE public.postmaster_data ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users can view own domain postmaster data" ON public.postmaster_data;
CREATE POLICY "Users can view own domain postmaster data"
    ON public.postmaster_data FOR SELECT
    USING (domain_id IN (SELECT id FROM public.domains WHERE user_id = auth.uid()));

-- inbox_placement_tests
ALTER TABLE public.inbox_placement_tests ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users can view own placement tests" ON public.inbox_placement_tests;
CREATE POLICY "Users can view own placement tests"
    ON public.inbox_placement_tests FOR SELECT USING (auth.uid() = user_id);

-- dmarc_reports
ALTER TABLE public.dmarc_reports ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users can view own domain DMARC reports" ON public.dmarc_reports;
CREATE POLICY "Users can view own domain DMARC reports"
    ON public.dmarc_reports FOR SELECT
    USING (domain_id IN (SELECT id FROM public.domains WHERE user_id = auth.uid()));

-- api_keys
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS "Users can view own API keys"   ON public.api_keys;
DROP POLICY IF EXISTS "Users can insert own API keys" ON public.api_keys;
DROP POLICY IF EXISTS "Users can delete own API keys" ON public.api_keys;
CREATE POLICY "Users can view own API keys"
    ON public.api_keys FOR SELECT USING (auth.uid() = user_id);
CREATE POLICY "Users can insert own API keys"
    ON public.api_keys FOR INSERT WITH CHECK (auth.uid() = user_id);
CREATE POLICY "Users can delete own API keys"
    ON public.api_keys FOR DELETE USING (auth.uid() = user_id);

-- email_subscribers and rate_limits: RLS enabled, service-role-only access.
ALTER TABLE public.email_subscribers ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.rate_limits       ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- End of 001_base_schema.sql
-- ============================================================================
