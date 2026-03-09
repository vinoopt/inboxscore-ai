-- Store last blacklist check results per user+domain
-- So results persist across page navigation and sessions
CREATE TABLE IF NOT EXISTS blacklist_results (
    id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    domain TEXT NOT NULL,
    results JSONB NOT NULL,          -- full API response from HetrixTools
    checked_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(user_id, domain)
);

CREATE INDEX idx_blacklist_results_user ON blacklist_results(user_id);
CREATE INDEX idx_blacklist_results_user_domain ON blacklist_results(user_id, domain);

-- RLS
ALTER TABLE blacklist_results ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own blacklist results"
    ON blacklist_results FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "Users can manage own blacklist results"
    ON blacklist_results FOR ALL
    USING (auth.uid() = user_id);

CREATE POLICY "Service role full access to blacklist results"
    ON blacklist_results FOR ALL
    TO service_role
    USING (true);
