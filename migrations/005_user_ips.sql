-- Centralized Sending IPs tables
-- Run this in Supabase SQL Editor

-- 1. Main IPs table (one row per user per IP)
CREATE TABLE IF NOT EXISTS user_ips (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    label TEXT,
    added_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, ip_address)
);

CREATE INDEX IF NOT EXISTS idx_user_ips_user ON user_ips(user_id);

-- Enable RLS
ALTER TABLE user_ips ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own IPs"
    ON user_ips FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Service role full access to user_ips"
    ON user_ips FOR ALL
    USING (true)
    WITH CHECK (true);


-- 2. Junction table: IP <-> Domain (many-to-many)
CREATE TABLE IF NOT EXISTS user_ip_domains (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    ip_address TEXT NOT NULL,
    domain TEXT NOT NULL,
    UNIQUE(user_id, ip_address, domain)
);

CREATE INDEX IF NOT EXISTS idx_user_ip_domains_user_domain ON user_ip_domains(user_id, domain);
CREATE INDEX IF NOT EXISTS idx_user_ip_domains_user_ip ON user_ip_domains(user_id, ip_address);

-- Enable RLS
ALTER TABLE user_ip_domains ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own IP-domain mappings"
    ON user_ip_domains FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Service role full access to user_ip_domains"
    ON user_ip_domains FOR ALL
    USING (true)
    WITH CHECK (true);
