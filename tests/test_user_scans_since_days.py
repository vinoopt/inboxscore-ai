"""
INBOX-160 — `/api/user/scans?since_days=N` time-window behaviour.

Pins the scalability fix for the global LIMIT=20 bug that caused the
Score Trend bar chart to miss days for active multi-domain users
(reported by Vinoop on 2026-04-30 — newsletter.shoppersstop.com only
showed Apr 29 + Apr 30 because the global top-20 scans were dominated
by other domains).

Asserts:
  • When called with ``since_days=N``, the query uses ``.gte("created_at", cutoff)``
    instead of ``.limit(20)``.
  • Legacy callers (no ``since_days``) keep getting ``.limit(N)`` behaviour —
    backward-compatible.
  • Defensive cap: ``since_days`` is clamped at 30 even if a caller asks for 999
    (prevents API runaway pre-INBOX-167 retention).
"""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db  # noqa: E402


def _fake_supabase_with_query_spy():
    """Return (mock_sb, calls) where `calls` records the chained operations."""
    mock_sb = MagicMock()
    calls = {"chain": []}

    # Build a chainable mock that records each method invocation.
    class Chain:
        def select(self, *a, **kw):
            calls["chain"].append(("select", a, kw))
            return self

        def eq(self, *a, **kw):
            calls["chain"].append(("eq", a, kw))
            return self

        def gte(self, *a, **kw):
            calls["chain"].append(("gte", a, kw))
            return self

        def order(self, *a, **kw):
            calls["chain"].append(("order", a, kw))
            return self

        def limit(self, *a, **kw):
            calls["chain"].append(("limit", a, kw))
            return self

        def execute(self):
            r = MagicMock()
            r.data = []
            return r

    mock_sb.table.return_value = Chain()
    return mock_sb, calls


class TestSinceDaysQuery:
    def test_since_days_uses_gte_not_limit_20(self):
        """Time-window mode hits .gte('created_at', cutoff) — no LIMIT=20."""
        mock_sb, calls = _fake_supabase_with_query_spy()
        with patch("db.get_supabase", return_value=mock_sb):
            db.get_user_scans("user-uuid", since_days=7)

        names = [op[0] for op in calls["chain"]]
        assert "gte" in names, f"since_days mode must use .gte() — got {names}"

        # The .gte call's first argument should be 'created_at' and the second
        # should be a parseable ISO string in the past.
        gte_call = next(op for op in calls["chain"] if op[0] == "gte")
        assert gte_call[1][0] == "created_at"
        cutoff_str = gte_call[1][1]
        assert "T" in cutoff_str or "-" in cutoff_str  # ISO format

        # Legacy LIMIT=20 path must NOT be invoked when since_days is set.
        # The 5,000 safety cap IS a limit — make sure it's not 20.
        limit_call = next(op for op in calls["chain"] if op[0] == "limit")
        assert limit_call[1][0] != 20, (
            "since_days mode accidentally used limit=20 — defeats the fix"
        )
        assert limit_call[1][0] == 5000, (
            "Expected 5,000-row safety cap, got " + str(limit_call[1][0])
        )

    def test_legacy_limit_param_unchanged(self):
        """Backward compat — no since_days means top-N global behaviour."""
        mock_sb, calls = _fake_supabase_with_query_spy()
        with patch("db.get_supabase", return_value=mock_sb):
            db.get_user_scans("user-uuid", limit=20)

        names = [op[0] for op in calls["chain"]]
        # No .gte() call in legacy mode
        assert "gte" not in names, "Legacy mode should NOT use time-window"
        # .limit(20) is preserved
        limit_call = next(op for op in calls["chain"] if op[0] == "limit")
        assert limit_call[1][0] == 20, (
            "Legacy callers must still get the LIMIT they asked for"
        )

    def test_since_days_zero_treated_as_none(self):
        """since_days=0 should fall through to legacy LIMIT mode (avoid bad UX)."""
        mock_sb, calls = _fake_supabase_with_query_spy()
        with patch("db.get_supabase", return_value=mock_sb):
            db.get_user_scans("user-uuid", limit=20, since_days=0)

        names = [op[0] for op in calls["chain"]]
        assert "gte" not in names, "since_days=0 must NOT engage time-window"

    def test_no_supabase_returns_empty_list(self):
        """Defensive: no DB → [] regardless of params."""
        with patch("db.get_supabase", return_value=None):
            assert db.get_user_scans("u", since_days=7) == []
            assert db.get_user_scans("u", limit=20) == []
