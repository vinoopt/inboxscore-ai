"""
INBOX-161 (F2) — bulk Dashboard endpoints kill the N+1 fan-out.

The Dashboard previously fired 2 × N parallel fetches per page load
(postmaster + SNDS, one per domain). At ~20 domains, the page made 40+
network requests to the backend on every load.

These tests assert the new bulk endpoints + db helpers produce a single
response keyed per-domain, with the same downstream shape the Microsoft
card render expects.

Tests:
  • db.get_postmaster_metrics_all_domains groups latest row per domain
  • db.get_user_ip_domain_mappings returns the {domain → [ips]} map
  • The SNDS aggregation helper produces the {state, summary, ...} shape
    identical to the single-domain endpoint output

Side-effect goal: NO regression on existing single-domain endpoints.
The single-domain SNDS test (test_snds_dashboard_summary.py) keeps
running and passing — proves the per-domain code path is unchanged.
"""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db  # noqa: E402


# ─── Helpers ─────────────────────────────────────────────────────


class _Chain:
    """Chainable Supabase mock that records its invocations and returns
    a configurable .execute() result. Test code injects this in place of
    sb.table(...) so we can assert the query shape AND the response."""

    def __init__(self, rows):
        self.rows = rows
        self.calls = []

    def select(self, *a, **kw):
        self.calls.append(("select", a, kw))
        return self

    def eq(self, *a, **kw):
        self.calls.append(("eq", a, kw))
        return self

    def gte(self, *a, **kw):
        self.calls.append(("gte", a, kw))
        return self

    def order(self, *a, **kw):
        self.calls.append(("order", a, kw))
        return self

    def limit(self, *a, **kw):
        self.calls.append(("limit", a, kw))
        return self

    def execute(self):
        r = MagicMock()
        r.data = self.rows
        return r


def _supabase_with_rows(rows):
    sb = MagicMock()
    chain = _Chain(rows)
    sb.table.return_value = chain
    return sb, chain


# ─── 1. Postmaster bulk DB helper ───────────────────────────────


class TestPostmasterMetricsAllDomains:
    def test_groups_by_domain_keeping_latest_row(self):
        """One row per domain; rows are ordered desc(date) so first wins."""
        rows = [
            # newer for example.com
            {"domain": "example.com", "date": "2026-04-30", "spam_rate": 0.1},
            # older for example.com — must NOT overwrite the newer one
            {"domain": "example.com", "date": "2026-04-25", "spam_rate": 0.5},
            # one row for other.com
            {"domain": "other.com", "date": "2026-04-29", "spam_rate": 0.0},
        ]
        sb, chain = _supabase_with_rows(rows)
        with patch("db.get_supabase", return_value=sb):
            out = db.get_postmaster_metrics_all_domains("user-uuid", days=7)

        assert set(out.keys()) == {"example.com", "other.com"}
        assert out["example.com"]["date"] == "2026-04-30"  # newest kept
        assert out["other.com"]["date"] == "2026-04-29"

    def test_uses_user_id_filter_and_date_window(self):
        sb, chain = _supabase_with_rows([])
        with patch("db.get_supabase", return_value=sb):
            db.get_postmaster_metrics_all_domains("user-uuid", days=7)
        names = [c[0] for c in chain.calls]
        assert "eq" in names, "must filter by user_id"
        assert "gte" in names, "must apply date cutoff for time-window query"
        assert "order" in names, "must order by date for latest-row-wins"

    def test_no_supabase_returns_empty_dict(self):
        with patch("db.get_supabase", return_value=None):
            assert db.get_postmaster_metrics_all_domains("user-uuid", days=7) == {}

    def test_skips_rows_without_domain_field(self):
        """Defensive: malformed rows shouldn't crash the bulk fetch."""
        rows = [
            {"domain": None, "date": "2026-04-30"},
            {"date": "2026-04-29"},  # missing domain key entirely
            {"domain": "good.com", "date": "2026-04-30", "spam_rate": 0.1},
        ]
        sb, _ = _supabase_with_rows(rows)
        with patch("db.get_supabase", return_value=sb):
            out = db.get_postmaster_metrics_all_domains("user-uuid", days=7)
        assert list(out.keys()) == ["good.com"]


# ─── 2. user_ip_domains bulk DB helper ──────────────────────────


class TestUserIpDomainMappings:
    def test_groups_ips_per_domain(self):
        rows = [
            {"domain": "a.com", "ip_address": "1.1.1.1"},
            {"domain": "a.com", "ip_address": "2.2.2.2"},
            {"domain": "b.com", "ip_address": "3.3.3.3"},
        ]
        sb, _ = _supabase_with_rows(rows)
        with patch("db.get_supabase", return_value=sb):
            out = db.get_user_ip_domain_mappings("user-uuid")
        assert set(out["a.com"]) == {"1.1.1.1", "2.2.2.2"}
        assert out["b.com"] == ["3.3.3.3"]

    def test_skips_malformed_rows(self):
        rows = [
            {"domain": "a.com", "ip_address": None},  # bad
            {"domain": None, "ip_address": "5.5.5.5"},  # bad
            {"domain": "good.com", "ip_address": "9.9.9.9"},  # ok
        ]
        sb, _ = _supabase_with_rows(rows)
        with patch("db.get_supabase", return_value=sb):
            out = db.get_user_ip_domain_mappings("user-uuid")
        assert out == {"good.com": ["9.9.9.9"]}

    def test_no_supabase_returns_empty_dict(self):
        with patch("db.get_supabase", return_value=None):
            assert db.get_user_ip_domain_mappings("user-uuid") == {}


# ─── 3. SNDS summary helper ─────────────────────────────────────
# Imported lazily to avoid pulling FastAPI app graph into the test


class TestSndsSummariseRows:
    def _import_helper(self):
        """app._snds_summarise_rows is module-level. Import only when
        running this test so collection works without touching app.py
        for tests that don't need it."""
        import app  # noqa: WPS433
        return app._snds_summarise_rows, app._snds_complaint_to_float

    def test_no_rows_returns_no_recent_data_state(self):
        summarise, _ = self._import_helper()
        out = summarise([], mapped_count=2, last_sync_at="2026-04-30T00:00:00Z")
        assert out["state"] == "no_recent_data"
        assert out["summary"] is None
        assert out["mapped_ip_count"] == 2
        assert out["last_sync_at"] == "2026-04-30T00:00:00Z"

    def test_green_rows_return_ok_state(self):
        summarise, _ = self._import_helper()
        rows = [
            {"filter_result": "GREEN", "complaint_rate": "0.05%", "trap_hits": 0},
            {"filter_result": "GREEN", "complaint_rate": "< 0.1%", "trap_hits": 0},
        ]
        out = summarise(rows, mapped_count=2, last_sync_at="x")
        assert out["state"] == "ok"
        assert out["summary"]["status_label"] == "GREEN"
        assert out["summary"]["status_color"] == "good"
        assert out["summary"]["trap_hits"] == "0"
        assert out["summary"]["trap_color"] == "none"

    def test_worst_status_wins(self):
        """If any IP is RED, the aggregate must be RED (worst wins)."""
        summarise, _ = self._import_helper()
        rows = [
            {"filter_result": "GREEN", "complaint_rate": "0.05%", "trap_hits": 0},
            {"filter_result": "RED", "complaint_rate": "1.50%", "trap_hits": 3},
        ]
        out = summarise(rows, mapped_count=2, last_sync_at="x")
        assert out["state"] == "ok"
        assert out["summary"]["status_label"] == "RED"
        assert out["summary"]["status_color"] == "bad"

    def test_complaint_parser_handles_lt_and_percent(self):
        _, parse = self._import_helper()
        assert parse("< 0.1%") == 0.1
        assert parse("0.20%") == 0.20
        assert parse(None) is None
        assert parse("garbage") is None
