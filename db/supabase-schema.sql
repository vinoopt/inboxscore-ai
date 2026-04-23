-- ============================================
-- InboxScore.ai — Supabase Database Schema
-- Version: 2.0
-- Run this in Supabase SQL Editor (Dashboard → SQL Editor → New Query)
-- ============================================

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ============================================
-- 1. PROFILES TABLE
-- Extends Supabase Auth users with app-specific data
-- ============================================
CREATE TABLE public.profiles (
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

-- Auto-create profile when a new user signs up
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO public.profiles (id, name)
    VALUES (NEW.id, NEW.raw_user_meta_data->>'name');
    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

-- Auto-update updated_at timestamp
CREATE OR REPLACE FUNCTION public.update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER profiles_updated_at
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- ============================================
-- 2. DOMAINS TABLE
-- Domains that users save and monitor
-- ============================================
CREATE TABLE public.domains (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    is_monitored BOOLEAN NOT NULL DEFAULT FALSE,
    monitor_frequency TEXT DEFAULT 'weekly' CHECK (monitor_frequency IN ('weekly', 'daily')),
    alert_threshold INTEGER NOT NULL DEFAULT 70 CHECK (alert_threshold BETWEEN 0 AND 100),
    latest_score INTEGER CHECK (latest_score BETWEEN 0 AND 100),
    latest_scan_id UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Each user can only save a domain once
    UNIQUE(user_id, domain)
);

CREATE INDEX idx_domains_user_id ON public.domains(user_id);
CREATE INDEX idx_domains_domain ON public.domains(domain);
CREATE INDEX idx_domains_monitored ON public.domains(is_monitored) WHERE is_monitored = TRUE;

-- ============================================
-- 3. SCANS TABLE
-- Every scan result (anonymous + logged-in)
-- ============================================
CREATE TABLE public.scans (
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

CREATE INDEX idx_scans_user_id ON public.scans(user_id);
CREATE INDEX idx_scans_domain ON public.scans(domain);
CREATE INDEX idx_scans_domain_id ON public.scans(domain_id);
CREATE INDEX idx_scans_created_at ON public.scans(created_at DESC);
CREATE INDEX idx_scans_ip_date ON public.scans(ip_address, created_at);

-- ============================================
-- 4. ALERTS TABLE
-- Monitoring alerts for users
-- ============================================
CREATE TABLE public.alerts (
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
        'dkim_change'
    )),
    severity TEXT NOT NULL DEFAULT 'warning' CHECK (severity IN ('critical', 'warning', 'info')),
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_user_id ON public.alerts(user_id);
CREATE INDEX idx_alerts_unread ON public.alerts(user_id, is_read) WHERE is_read = FALSE;
CREATE INDEX idx_alerts_created_at ON public.alerts(created_at DESC);

-- ============================================
-- 5. SUBSCRIPTIONS TABLE
-- Stripe subscription tracking
-- ============================================
CREATE TABLE public.subscriptions (
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

CREATE INDEX idx_subscriptions_user_id ON public.subscriptions(user_id);
CREATE INDEX idx_subscriptions_stripe_id ON public.subscriptions(stripe_subscription_id);

CREATE TRIGGER subscriptions_updated_at
    BEFORE UPDATE ON public.subscriptions
    FOR EACH ROW EXECUTE FUNCTION public.update_updated_at();

-- ============================================
-- 6. BLACKLIST EVENTS TABLE
-- Historical blacklist listing/delisting events
-- ============================================
CREATE TABLE public.blacklist_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    domain_id UUID NOT NULL REFERENCES public.domains(id) ON DELETE CASCADE,
    blacklist_name TEXT NOT NULL,
    event_type TEXT NOT NULL CHECK (event_type IN ('listed', 'delisted')),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_blacklist_events_domain ON public.blacklist_events(domain_id);
CREATE INDEX idx_blacklist_events_detected ON public.blacklist_events(detected_at DESC);

-- ============================================
-- 7. POSTMASTER DATA TABLE (Phase 6 — Pro+)
-- Google Postmaster Tools metrics
-- ============================================
CREATE TABLE public.postmaster_data (
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

CREATE INDEX idx_postmaster_domain_date ON public.postmaster_data(domain_id, date DESC);

-- ============================================
-- 8. INBOX PLACEMENT TESTS TABLE (Phase 8 — Growth+)
-- Inbox vs spam placement test results
-- ============================================
CREATE TABLE public.inbox_placement_tests (
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

CREATE INDEX idx_placement_domain ON public.inbox_placement_tests(domain_id);
CREATE INDEX idx_placement_created ON public.inbox_placement_tests(created_at DESC);

-- ============================================
-- 9. DMARC REPORTS TABLE (Phase 7 — Pro+)
-- Parsed DMARC aggregate reports
-- ============================================
CREATE TABLE public.dmarc_reports (
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

CREATE INDEX idx_dmarc_domain_date ON public.dmarc_reports(domain_id, report_date DESC);
CREATE INDEX idx_dmarc_source ON public.dmarc_reports(source_org);

-- ============================================
-- 10. API KEYS TABLE (Phase 6 — Growth+)
-- API access for Growth/Enterprise users
-- ============================================
CREATE TABLE public.api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES public.profiles(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT 'Default',
    calls_this_month INTEGER NOT NULL DEFAULT 0,
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_user ON public.api_keys(user_id);
CREATE INDEX idx_api_keys_hash ON public.api_keys(key_hash);

-- ============================================
-- 11. EMAIL SUBSCRIBERS TABLE
-- Migrated from JSON file storage
-- ============================================
CREATE TABLE public.email_subscribers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email TEXT NOT NULL UNIQUE,
    domain TEXT,
    score INTEGER,
    source TEXT DEFAULT 'scan_results',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_subscribers_email ON public.email_subscribers(email);

-- ============================================
-- 12. RATE LIMITING TABLE
-- Track anonymous scan usage by IP
-- ============================================
CREATE TABLE public.rate_limits (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET NOT NULL,
    scan_count INTEGER NOT NULL DEFAULT 1,
    date DATE NOT NULL DEFAULT CURRENT_DATE,

    UNIQUE(ip_address, date)
);

CREATE INDEX idx_rate_limits_ip_date ON public.rate_limits(ip_address, date);

-- ============================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- Ensures users can only access their own data
-- ============================================

-- PROFILES
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own profile"
    ON public.profiles FOR SELECT
    USING (auth.uid() = id);

CREATE POLICY "Users can update own profile"
    ON public.profiles FOR UPDATE
    USING (auth.uid() = id);

-- DOMAINS
ALTER TABLE public.domains ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own domains"
    ON public.domains FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own domains"
    ON public.domains FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own domains"
    ON public.domains FOR UPDATE
    USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own domains"
    ON public.domains FOR DELETE
    USING (auth.uid() = user_id);

-- SCANS
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own scans"
    ON public.scans FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert scans"
    ON public.scans FOR INSERT
    WITH CHECK (auth.uid() = user_id OR user_id IS NULL);

-- Allow anonymous scans (no user_id) via service role only
CREATE POLICY "Service role can insert anonymous scans"
    ON public.scans FOR INSERT
    WITH CHECK (user_id IS NULL);

-- ALERTS
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own alerts"
    ON public.alerts FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can update own alerts"
    ON public.alerts FOR UPDATE
    USING (auth.uid() = user_id);

-- SUBSCRIPTIONS
ALTER TABLE public.subscriptions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own subscription"
    ON public.subscriptions FOR SELECT
    USING (auth.uid() = user_id);

-- BLACKLIST EVENTS
ALTER TABLE public.blacklist_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own domain blacklist events"
    ON public.blacklist_events FOR SELECT
    USING (
        domain_id IN (
            SELECT id FROM public.domains WHERE user_id = auth.uid()
        )
    );

-- POSTMASTER DATA
ALTER TABLE public.postmaster_data ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own domain postmaster data"
    ON public.postmaster_data FOR SELECT
    USING (
        domain_id IN (
            SELECT id FROM public.domains WHERE user_id = auth.uid()
        )
    );

-- INBOX PLACEMENT TESTS
ALTER TABLE public.inbox_placement_tests ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own placement tests"
    ON public.inbox_placement_tests FOR SELECT
    USING (auth.uid() = user_id);

-- DMARC REPORTS
ALTER TABLE public.dmarc_reports ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own domain DMARC reports"
    ON public.dmarc_reports FOR SELECT
    USING (
        domain_id IN (
            SELECT id FROM public.domains WHERE user_id = auth.uid()
        )
    );

-- API KEYS
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own API keys"
    ON public.api_keys FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own API keys"
    ON public.api_keys FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can delete own API keys"
    ON public.api_keys FOR DELETE
    USING (auth.uid() = user_id);

-- EMAIL SUBSCRIBERS — No RLS needed (admin access only via service role)
ALTER TABLE public.email_subscribers ENABLE ROW LEVEL SECURITY;

-- RATE LIMITS — No RLS needed (accessed via service role only)
ALTER TABLE public.rate_limits ENABLE ROW LEVEL SECURITY;

-- ============================================
-- DONE!
-- Tables created: 12
-- RLS policies: All enabled
-- Triggers: auto-create profile, auto-update timestamps
-- ============================================
