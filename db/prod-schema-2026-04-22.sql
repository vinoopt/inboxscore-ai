-- ====================================================================
-- InboxScore PROD schema dump — 2026-04-22
-- Source: Supabase PostgREST OpenAPI (service-role introspection)
-- Project: jxqxvexoduynwpywhevr.supabase.co
--
-- This file is a column-level reconciliation target. Column types
-- come from PostgREST's type translation, NOT pg_dump. RLS policies
-- and index DDL are NOT captured here — those are tracked via the
-- migration files under code/inboxscore/migrations/ which we know are
-- applied because the live site functions.
--
-- The CI schema-drift gate compares this file's COLUMN set and
-- types/defaults against what migrations produce.
-- ====================================================================

-- Table: alerts
CREATE TABLE IF NOT EXISTS public.alerts (
    id uuid DEFAULT 'extensions.uuid_generate_v4()' NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    type text NOT NULL,
    severity text DEFAULT 'warning' NOT NULL,
    message text NOT NULL,
    is_read boolean DEFAULT False NOT NULL,
    created_at timestamp with time zone DEFAULT 'now()' NOT NULL
);

-- Table: api_keys
CREATE TABLE IF NOT EXISTS public.api_keys (
    id uuid DEFAULT 'extensions.uuid_generate_v4()' NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL,
    key_hash text NOT NULL,
    name text DEFAULT 'Default' NOT NULL,
    calls_this_month integer DEFAULT 0 NOT NULL,
    last_used_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT 'now()' NOT NULL
);

-- Table: blacklist_events
CREATE TABLE IF NOT EXISTS public.blacklist_events (
    id uuid DEFAULT 'extensions.uuid_generate_v4()' NOT NULL PRIMARY KEY,
    domain_id uuid NOT NULL,
    blacklist_name text NOT NULL,
    event_type text NOT NULL,
    detected_at timestamp with time zone DEFAULT 'now()' NOT NULL
);

-- Table: blacklist_results
CREATE TABLE IF NOT EXISTS public.blacklist_results (
    id uuid DEFAULT 'gen_random_uuid()' NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL,
    domain text NOT NULL,
    results jsonb NOT NULL,
    checked_at timestamp with time zone DEFAULT 'now()'
);

-- Table: dmarc_reports
CREATE TABLE IF NOT EXISTS public.dmarc_reports (
    id uuid DEFAULT 'extensions.uuid_generate_v4()' NOT NULL PRIMARY KEY,
    domain_id uuid NOT NULL,
    report_date date NOT NULL,
    source_org text NOT NULL,
    source_ip inet,
    spf_aligned boolean,
    dkim_aligned boolean,
    disposition text,
    message_count integer DEFAULT 0 NOT NULL,
    raw_xml text,
    parsed_at timestamp with time zone DEFAULT 'now()' NOT NULL
);

-- Table: domains
CREATE TABLE IF NOT EXISTS public.domains (
    id uuid DEFAULT 'extensions.uuid_generate_v4()' NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL,
    domain text NOT NULL,
    is_monitored boolean DEFAULT False NOT NULL,
    monitor_frequency text DEFAULT 'weekly',
    alert_threshold integer DEFAULT 70 NOT NULL,
    latest_score integer,
    latest_scan_id uuid,
    created_at timestamp with time zone DEFAULT 'now()' NOT NULL,
    monitor_interval integer DEFAULT 24,
    last_monitored_at timestamp with time zone,
    previous_score integer
);

-- Table: email_subscribers
CREATE TABLE IF NOT EXISTS public.email_subscribers (
    id uuid DEFAULT 'extensions.uuid_generate_v4()' NOT NULL PRIMARY KEY,
    email text NOT NULL,
    domain text,
    score integer,
    source text DEFAULT 'scan_results',
    created_at timestamp with time zone DEFAULT 'now()' NOT NULL
);

-- Table: inbox_placement_tests
CREATE TABLE IF NOT EXISTS public.inbox_placement_tests (
    id uuid DEFAULT 'extensions.uuid_generate_v4()' NOT NULL PRIMARY KEY,
    domain_id uuid NOT NULL,
    user_id uuid NOT NULL,
    gmail_inbox_rate real,
    outlook_inbox_rate real,
    yahoo_inbox_rate real,
    apple_inbox_rate real,
    overall_inbox_rate real,
    raw_results jsonb,
    created_at timestamp with time zone DEFAULT 'now()' NOT NULL
);

-- Table: monitoring_heartbeats
CREATE TABLE IF NOT EXISTS public.monitoring_heartbeats (
    id uuid DEFAULT 'gen_random_uuid()' NOT NULL PRIMARY KEY,
    cycle_type text NOT NULL,
    cycle_started_at timestamp with time zone DEFAULT 'now()' NOT NULL,
    cycle_completed_at timestamp with time zone,
    domains_processed integer DEFAULT 0,
    errors_count integer DEFAULT 0,
    notes text
);

-- Table: monitoring_logs
CREATE TABLE IF NOT EXISTS public.monitoring_logs (
    id uuid DEFAULT 'gen_random_uuid()' NOT NULL PRIMARY KEY,
    domain_id uuid,
    user_id uuid,
    domain text NOT NULL,
    old_score integer,
    new_score integer,
    score_change integer DEFAULT 0,
    changes_detected jsonb,
    alerts_created integer DEFAULT 0,
    scan_id uuid,
    created_at timestamp with time zone DEFAULT 'now()'
);

-- Table: postmaster_connections
CREATE TABLE IF NOT EXISTS public.postmaster_connections (
    id uuid DEFAULT 'gen_random_uuid()' NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL,
    access_token text NOT NULL,
    refresh_token text NOT NULL,
    token_expiry timestamp with time zone NOT NULL,
    google_email text NOT NULL,
    connected_at timestamp with time zone DEFAULT 'now()',
    updated_at timestamp with time zone DEFAULT 'now()'
);

-- Table: postmaster_data
CREATE TABLE IF NOT EXISTS public.postmaster_data (
    id uuid DEFAULT 'extensions.uuid_generate_v4()' NOT NULL PRIMARY KEY,
    domain_id uuid NOT NULL,
    date date NOT NULL,
    gmail_reputation text,
    spam_rate real,
    spf_pass_rate real,
    dkim_pass_rate real,
    dmarc_pass_rate real,
    tls_rate real,
    delivery_errors jsonb,
    fetched_at timestamp with time zone DEFAULT 'now()' NOT NULL
);

-- Table: postmaster_metrics
CREATE TABLE IF NOT EXISTS public.postmaster_metrics (
    id uuid DEFAULT 'gen_random_uuid()' NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL,
    domain text NOT NULL,
    date date NOT NULL,
    domain_reputation text,
    spam_rate double precision,
    ip_reputation jsonb,
    auth_success_spf double precision,
    auth_success_dkim double precision,
    auth_success_dmarc double precision,
    delivery_errors jsonb,
    encrypted_traffic_tls double precision,
    raw_data jsonb,
    created_at timestamp with time zone DEFAULT 'now()'
);

-- Table: postmaster_sync_log
CREATE TABLE IF NOT EXISTS public.postmaster_sync_log (
    id uuid DEFAULT 'gen_random_uuid()' NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL,
    sync_started_at timestamp with time zone DEFAULT 'now()',
    sync_completed_at timestamp with time zone,
    domains_synced integer DEFAULT 0,
    status text DEFAULT 'running',
    error_message text
);

-- Table: profiles
CREATE TABLE IF NOT EXISTS public.profiles (
    id uuid NOT NULL PRIMARY KEY,
    name text,
    company text,
    plan text DEFAULT 'free' NOT NULL,
    stripe_customer_id text,
    scans_today integer DEFAULT 0 NOT NULL,
    scans_today_date date DEFAULT 'CURRENT_DATE' NOT NULL,
    created_at timestamp with time zone DEFAULT 'now()' NOT NULL,
    updated_at timestamp with time zone DEFAULT 'now()' NOT NULL,
    preferences jsonb
);

-- Table: rate_limits
CREATE TABLE IF NOT EXISTS public.rate_limits (
    id uuid DEFAULT 'extensions.uuid_generate_v4()' NOT NULL PRIMARY KEY,
    ip_address inet NOT NULL,
    scan_count integer DEFAULT 1 NOT NULL,
    date date DEFAULT 'CURRENT_DATE' NOT NULL
);

-- Table: scans
CREATE TABLE IF NOT EXISTS public.scans (
    id uuid DEFAULT 'extensions.uuid_generate_v4()' NOT NULL PRIMARY KEY,
    domain_id uuid,
    user_id uuid,
    domain text NOT NULL,
    score integer NOT NULL,
    results jsonb NOT NULL,
    ip_address inet,
    scan_type text DEFAULT 'manual' NOT NULL,
    created_at timestamp with time zone DEFAULT 'now()' NOT NULL
);

-- Table: snds_connections
CREATE TABLE IF NOT EXISTS public.snds_connections (
    user_id uuid NOT NULL PRIMARY KEY,
    snds_key text NOT NULL,
    connected_at timestamp with time zone DEFAULT 'now()',
    last_sync_at timestamp with time zone,
    ip_count integer DEFAULT 0,
    tracked_ips jsonb
);

-- Table: snds_metrics
CREATE TABLE IF NOT EXISTS public.snds_metrics (
    id uuid DEFAULT 'gen_random_uuid()' NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL,
    ip_address text NOT NULL,
    metric_date date NOT NULL,
    ip_status text,
    complaint_rate double precision,
    trap_hits integer DEFAULT 0,
    message_count integer DEFAULT 0,
    filter_results jsonb,
    sample_helos jsonb,
    raw_data text,
    created_at timestamp with time zone DEFAULT 'now()'
);

-- Table: subscriptions
CREATE TABLE IF NOT EXISTS public.subscriptions (
    id uuid DEFAULT 'extensions.uuid_generate_v4()' NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL,
    stripe_subscription_id text,
    plan text NOT NULL,
    status text DEFAULT 'active' NOT NULL,
    current_period_start timestamp with time zone,
    current_period_end timestamp with time zone,
    created_at timestamp with time zone DEFAULT 'now()' NOT NULL,
    updated_at timestamp with time zone DEFAULT 'now()' NOT NULL
);

-- Table: user_ip_domains
CREATE TABLE IF NOT EXISTS public.user_ip_domains (
    id uuid DEFAULT 'gen_random_uuid()' NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL,
    ip_address text NOT NULL,
    domain text NOT NULL
);

-- Table: user_ips
CREATE TABLE IF NOT EXISTS public.user_ips (
    id uuid DEFAULT 'gen_random_uuid()' NOT NULL PRIMARY KEY,
    user_id uuid NOT NULL,
    ip_address text NOT NULL,
    label text,
    added_at timestamp with time zone DEFAULT 'now()'
);
