-- Stub Supabase auth/extensions objects so migrations can replay cleanly in
-- plain Postgres 15 during CI. Real Supabase provides these out of the box;
-- self-hosted Postgres does not.
--
-- Used by: .github/workflows/ci.yml -> schema-drift-check job.
-- NOT intended for prod use. This file is only ever applied to the ephemeral
-- CI Postgres container, never to a real environment.

-- Schemas Supabase exposes by default.
CREATE SCHEMA IF NOT EXISTS auth;
CREATE SCHEMA IF NOT EXISTS extensions;

-- uuid-ossp in extensions schema so DEFAULT extensions.uuid_generate_v4() works.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" SCHEMA extensions;
-- pgcrypto for gen_random_uuid() (available since Postgres 13 but ensures presence).
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Legacy db/supabase-schema.sql uses the bare form `uuid_generate_v4()` with no
-- schema prefix, relying on Supabase's default search_path which includes
-- `extensions`. Plain Postgres defaults to just `"$user", public`, so mirror
-- Supabase's behaviour here for the CI replay.
ALTER DATABASE inbox_ci SET search_path = "$user", public, extensions;
-- ALTER DATABASE only applies to new sessions, so also set it for this one
-- in case any later statement in this file needs the extensions schema.
SET search_path = "$user", public, extensions;

-- Minimal auth.users shape our triggers touch: id + email + raw_user_meta_data.
-- Enough for handle_new_user() to compile; we never actually INSERT rows here.
CREATE TABLE IF NOT EXISTS auth.users (
    id UUID PRIMARY KEY,
    email TEXT,
    encrypted_password TEXT,
    raw_user_meta_data JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- auth.uid() returns the session user ID in Supabase. In CI there's no session;
-- return NULL so any RLS policy referencing it stays parseable.
CREATE OR REPLACE FUNCTION auth.uid() RETURNS UUID AS $$
    SELECT NULL::UUID;
$$ LANGUAGE SQL STABLE;

-- Roles referenced by RLS policies. Use DO blocks for idempotent role creation.
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'service_role') THEN
        CREATE ROLE service_role NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN
        CREATE ROLE authenticated NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN
        CREATE ROLE anon NOLOGIN;
    END IF;
END$$;
