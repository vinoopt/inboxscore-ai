"""
INBOX-162 (F3) + INBOX-163 (F4) — pagination on /api/user/alerts
and /api/user/domains.

Both endpoints gain optional ``?page=`` + ``?page_size=`` params with
backward-compatible defaults. When neither is set, the response shape
is exactly what it used to be (``{"alerts": [...]}`` /
``{"domains": [...]}``). When both are set, an additional
``pagination`` block is included alongside the array.

Tests:
  • db.get_user_alerts paginates via .range(start, end) when both
    params are set
  • db.get_user_alerts uses .limit(N) (legacy) when neither param is set
  • db.get_user_domains paginates via .range(start, end) when both
    params are set
  • db.get_user_domains skips .limit() entirely (returns ALL) when
    neither param is set — preserves the legacy contract every existing
    page in the app relies on
  • db.get_user_alerts_count + db.get_user_domains_count call the
    count='exact' API
"""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db  # noqa: E402


# ─── Helpers ─────────────────────────────────────────────────────


class _Chain:
    """Chainable Supabase mock that records calls + returns canned data."""

    def __init__(self, rows, count=None):
        self.rows = rows
        self.count = count
        self.calls = []

    def select(self, *a, **kw):
        self.calls.append(("select", a, kw))
        return self

    def eq(self, *a, **kw):
        self.calls.append(("eq", a, kw))
        return self

    def order(self, *a, **kw):
        self.calls.append(("order", a, kw))
        return self

    def limit(self, *a, **kw):
        self.calls.append(("limit", a, kw))
        return self

    def range(self, *a, **kw):
        self.calls.append(("range", a, kw))
        return self

    def execute(self):
        r = MagicMock()
        r.data = self.rows
        r.count = self.count
        return r


def _sb_with(rows=None, count=None):
    rows = rows if rows is not None else []
    sb = MagicMock()
    chain = _Chain(rows, count)
    sb.table.return_value = chain
    return sb, chain


# ─── F3 — alerts pagination ─────────────────────────────────────


class TestAlertsPagination:
    def test_paginated_mode_uses_range(self):
        sb, chain = _sb_with(rows=[])
        with patch("db.get_supabase", return_value=sb):
            db.get_user_alerts("u", page=2, page_size=20)
        names = [c[0] for c in chain.calls]
        assert "range" in names, "paginated mode must call .range(start, end)"
        assert "limit" not in names, "paginated mode must NOT call .limit()"
        # Page 2 with page_size=20 → range(20, 39)
        rcall = next(c for c in chain.calls if c[0] == "range")
        assert rcall[1] == (20, 39), f"expected range(20, 39), got {rcall[1]}"

    def test_legacy_mode_uses_limit(self):
        sb, chain = _sb_with(rows=[])
        with patch("db.get_supabase", return_value=sb):
            db.get_user_alerts("u", limit=50)
        names = [c[0] for c in chain.calls]
        assert "limit" in names, "legacy mode must call .limit()"
        assert "range" not in names, "legacy mode must NOT call .range()"
        lcall = next(c for c in chain.calls if c[0] == "limit")
        assert lcall[1] == (50,), f"expected limit(50), got {lcall[1]}"

    def test_only_page_no_page_size_falls_through_to_legacy(self):
        """Defensive: a half-set request (one param missing) should NOT
        engage pagination. Falls back to legacy LIMIT for safety."""
        sb, chain = _sb_with(rows=[])
        with patch("db.get_supabase", return_value=sb):
            db.get_user_alerts("u", limit=50, page=2)
        names = [c[0] for c in chain.calls]
        assert "range" not in names
        assert "limit" in names

    def test_invalid_page_zero_or_negative_falls_through(self):
        sb, chain = _sb_with(rows=[])
        with patch("db.get_supabase", return_value=sb):
            db.get_user_alerts("u", limit=50, page=0, page_size=20)
        names = [c[0] for c in chain.calls]
        assert "range" not in names, "page<1 should not engage pagination"

    def test_count_query_uses_count_exact(self):
        sb, chain = _sb_with(count=137)
        with patch("db.get_supabase", return_value=sb):
            n = db.get_user_alerts_count("u")
        assert n == 137
        # Confirm select was called with count='exact'
        scall = next(c for c in chain.calls if c[0] == "select")
        assert scall[2].get("count") == "exact"

    def test_count_zero_when_no_supabase(self):
        with patch("db.get_supabase", return_value=None):
            assert db.get_user_alerts_count("u") == 0


# ─── F4 — domains pagination ────────────────────────────────────


class TestDomainsPagination:
    def test_legacy_mode_returns_all_no_limit(self):
        """The most important regression check: when no pagination params
        are passed, the query MUST NOT have a .limit() — every existing
        caller relies on getting the full domain list."""
        sb, chain = _sb_with(rows=[])
        with patch("db.get_supabase", return_value=sb):
            db.get_user_domains("u")
        names = [c[0] for c in chain.calls]
        assert "limit" not in names, "legacy domains query must NOT have a .limit()"
        assert "range" not in names

    def test_paginated_mode_uses_range(self):
        sb, chain = _sb_with(rows=[])
        with patch("db.get_supabase", return_value=sb):
            db.get_user_domains("u", page=3, page_size=50)
        names = [c[0] for c in chain.calls]
        assert "range" in names
        rcall = next(c for c in chain.calls if c[0] == "range")
        assert rcall[1] == (100, 149), f"expected range(100, 149), got {rcall[1]}"

    def test_count_helper(self):
        sb, chain = _sb_with(count=850)
        with patch("db.get_supabase", return_value=sb):
            n = db.get_user_domains_count("u")
        assert n == 850
        scall = next(c for c in chain.calls if c[0] == "select")
        assert scall[2].get("count") == "exact"

    def test_count_zero_when_no_supabase(self):
        with patch("db.get_supabase", return_value=None):
            assert db.get_user_domains_count("u") == 0
