-- Add tracked_ips column to snds_connections
-- Run this in Supabase SQL Editor
-- Allows users to select which IPs to track (null = track all)

ALTER TABLE snds_connections ADD COLUMN IF NOT EXISTS tracked_ips JSONB DEFAULT NULL;

-- tracked_ips stores a JSON array of IP strings, e.g. ["1.2.3.4", "5.6.7.8"]
-- NULL means track all IPs (default behavior)
