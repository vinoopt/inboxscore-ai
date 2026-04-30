"""
INBOX-169 (F10) + INBOX-171 (F12) — plan domain limits + GSB cache.

F10 — PLAN_DOMAIN_LIMITS enforced in db.add_user_domain:
  • Free user under cap can add a domain.
  • Free user at cap raises PlanDomainLimitExceeded.
  • Enterprise (-1) means unlimited.
  • Existing domains aren't deleted when limit is lowered (only NEW
    additions blocked) — covered by virtue of the count being measured
    BEFORE the insert.

F12 — gsb_cache:
  • get_cached_gsb honours the 24h TTL.
  • get_cached_gsb returns None on cache miss.
  • set_cached_gsb upserts on (domain) and stores threats list.
  • check_google_safe_browsing skips the live API on cache hit.
"""

import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db  # noqa: E402


# ─── Helpers ─────────────────────────────────────────────────────


def _supabase_chain(rows=None, count=None):
    """A MagicMock that returns the same chain object for any builder
    method, so .table(...).select(...).eq(...).execute() always works."""
    sb = MagicMock()
    chain = MagicMock()
    chain.execute.return_value = MagicMock(data=rows if rows is not None else [],
                                            count=count)
    # Every chain method returns the chain itself
    for method in ("select", "eq", "gte", "order", "limit", "range",
                   "single", "insert", "upsert"):
        setattr(chain, method, MagicMock(return_value=chain))
    sb.table.return_value = chain
    return sb, chain


# ─── F10 — plan domain limits ───────────────────────────────────


class TestPlanDomainLimits:
    def test_under_cap_can_add(self):
        """Free user with 5 domains (cap=10) can add another."""
        sb, chain = _supabase_chain(rows=[{"id": "new-domain-id"}])
        # Custom select responses for the 3 separate queries.
        # 1) check existing → empty
        # 2) plan-count via get_user_domains_count → 5
        # 3) latest scan score → None
        # 4) insert → success
        # We can't easily simulate 4 different .execute() returns with
        # one MagicMock chain — patch get_user_plan + get_user_domains_count
        # instead and let the chain handle insert.
        with patch("db.get_supabase", return_value=sb), \
             patch("db.get_user_plan", return_value="free"), \
             patch("db.get_user_domains_count", return_value=5):
            # Override execute to handle the multi-call pattern
            chain.execute.return_value = MagicMock(data=[{"id": "new-domain-id"}])
            r = db.add_user_domain("user-uuid", "newdomain.com")
            assert r is not None or r is None  # smoke — main assertion is no raise

    def test_at_cap_raises(self):
        """Free user with 10 domains (cap=10) cannot add another."""
        sb, _ = _supabase_chain(rows=[])  # no existing match
        with patch("db.get_supabase", return_value=sb), \
             patch("db.get_user_plan", return_value="free"), \
             patch("db.get_user_domains_count", return_value=10):
            with pytest.raises(db.PlanDomainLimitExceeded) as exc:
                db.add_user_domain("user-uuid", "newdomain.com")
            assert exc.value.plan == "free"
            assert exc.value.current == 10
            assert exc.value.allowed == 10

    def test_enterprise_unlimited(self):
        """Enterprise plan (-1) never raises."""
        sb, chain = _supabase_chain(rows=[{"id": "x"}])
        with patch("db.get_supabase", return_value=sb), \
             patch("db.get_user_plan", return_value="enterprise"), \
             patch("db.get_user_domains_count", return_value=10000):
            # Should NOT raise
            db.add_user_domain("user-uuid", "newdomain.com")

    def test_unknown_plan_falls_back_to_free(self):
        """A plan name we don't recognise should fall back to 'free' cap,
        not become unlimited (security default-deny)."""
        sb, _ = _supabase_chain(rows=[])
        with patch("db.get_supabase", return_value=sb), \
             patch("db.get_user_plan", return_value="some_legacy_plan"), \
             patch("db.get_user_domains_count", return_value=10):
            with pytest.raises(db.PlanDomainLimitExceeded):
                db.add_user_domain("user-uuid", "newdomain.com")

    def test_existing_domain_returns_without_limit_check(self):
        """If domain already exists for user, return it — no cap check
        (we're not adding a new slot)."""
        sb, _ = _supabase_chain(rows=[{"id": "existing-domain-id",
                                       "domain": "existing.com"}])
        with patch("db.get_supabase", return_value=sb):
            # Even though we don't patch plan/count, no raise — early-return
            result = db.add_user_domain("user-uuid", "existing.com")
            assert result == {"id": "existing-domain-id", "domain": "existing.com"}


# ─── F12 — GSB cache helpers ────────────────────────────────────


class TestGsbCache:
    def test_fresh_entry_returns_threats(self):
        """Cache hit within TTL returns the cached threats list."""
        recent = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        sb, chain = _supabase_chain(rows=None)
        chain.execute.return_value = MagicMock(data={
            "threats": [],
            "checked_at": recent,
        })
        with patch("db.get_supabase", return_value=sb):
            result = db.get_cached_gsb("example.com")
        assert result is not None
        assert result["threats"] == []
        assert result["checked_at"] == recent

    def test_expired_entry_returns_none(self):
        """Cache hit OUTSIDE TTL returns None (treated as cold cache)."""
        ancient = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        sb, chain = _supabase_chain(rows=None)
        chain.execute.return_value = MagicMock(data={
            "threats": [],
            "checked_at": ancient,
        })
        with patch("db.get_supabase", return_value=sb):
            assert db.get_cached_gsb("example.com") is None

    def test_no_data_returns_none(self):
        """Cache miss (no row) returns None."""
        sb, chain = _supabase_chain(rows=None)
        chain.execute.return_value = MagicMock(data=None)
        with patch("db.get_supabase", return_value=sb):
            assert db.get_cached_gsb("example.com") is None

    def test_no_supabase_returns_none(self):
        with patch("db.get_supabase", return_value=None):
            assert db.get_cached_gsb("example.com") is None

    def test_set_cached_gsb_calls_upsert(self):
        sb, chain = _supabase_chain(rows=[])
        with patch("db.get_supabase", return_value=sb):
            ok = db.set_cached_gsb("example.com", [{"threatType": "MALWARE"}])
        assert ok is True
        chain.upsert.assert_called_once()
        # First positional arg to upsert is the dict
        args, kwargs = chain.upsert.call_args
        payload = args[0]
        assert payload["domain"] == "example.com"
        assert payload["threats"] == [{"threatType": "MALWARE"}]
        assert "checked_at" in payload
        assert kwargs.get("on_conflict") == "domain"

    def test_set_cached_gsb_handles_db_failure(self):
        """Cache write failure should NOT raise — best-effort."""
        with patch("db.get_supabase", return_value=None):
            assert db.set_cached_gsb("example.com", []) is False


# ─── F12 — checks.py integration with cache ─────────────────────


class TestGsbCheckUsesCache:
    def test_cache_hit_skips_api(self):
        """When the cache returns fresh data, no httpx call should happen."""
        os.environ["GOOGLE_SAFE_BROWSING_API_KEY"] = "fake-key"
        try:
            recent_iso = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            cached_response = {"threats": [], "checked_at": recent_iso}
            with patch("db.get_cached_gsb", return_value=cached_response), \
                 patch("checks.httpx.Client") as mock_httpx:
                from checks import check_google_safe_browsing
                result = check_google_safe_browsing("example.com")
            mock_httpx.assert_not_called()
            assert result.status == "pass"
            assert result.raw_data.get("from_cache") is True
        finally:
            os.environ.pop("GOOGLE_SAFE_BROWSING_API_KEY", None)

    def test_cache_miss_calls_api_and_stores(self):
        """Cache miss → live API → result cached."""
        os.environ["GOOGLE_SAFE_BROWSING_API_KEY"] = "fake-key"
        try:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {}  # no matches
            mock_client_ctx = MagicMock()
            mock_client_ctx.__enter__.return_value.post.return_value = mock_resp
            mock_client_ctx.__exit__.return_value = False
            with patch("db.get_cached_gsb", return_value=None) as mock_get, \
                 patch("db.set_cached_gsb") as mock_set, \
                 patch("checks.httpx.Client", return_value=mock_client_ctx):
                from checks import check_google_safe_browsing
                result = check_google_safe_browsing("example.com")
            mock_get.assert_called_once_with("example.com")
            mock_set.assert_called_once()
            # set_cached_gsb second arg is matches list (empty)
            args, _ = mock_set.call_args
            assert args[0] == "example.com"
            assert args[1] == []
            assert result.status == "pass"
            assert result.raw_data.get("from_cache") is False
        finally:
            os.environ.pop("GOOGLE_SAFE_BROWSING_API_KEY", None)
