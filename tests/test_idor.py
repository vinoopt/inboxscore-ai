"""
Regression suite for INBOX-27 — IDOR (Insecure Direct Object Reference) sweep.

Three IDOR bugs were fixed:

  L7  — `db.get_domain_scans` now requires `user_id` and filters by it
        (previously ignored its own user_id kwarg → any user could read
        any other user's scan history for a shared domain name).

  L8  — `db.get_monitoring_logs` now requires `user_id` and filters by it
        (previously the handler took a domain_id from the URL with no
        ownership check → trivial cross-tenant log disclosure).

  L10 — `db.update_domain_score` now requires `user_id` and scopes its
        UPDATE by it (previously `WHERE domain = ?` would overwrite every
        user's latest_score row sharing that domain name — cross-tenant
        WRITE IDOR).

These tests lock in the Supabase query-builder calls each function emits,
so any future refactor that drops the `.eq("user_id", …)` filter will
fail loudly. We do NOT spin up a real Supabase instance — we spy on the
query-builder chain via a MagicMock. The Tier-3 live verification
(cross-tenant curl post-deploy) is the companion check.
"""

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db  # noqa: E402


def _fake_supabase_with_select_chain(returned_rows=None):
    """Return (mock_supabase, select_spy, eq_spies, execute_mock).

    `eq_spies` is a list of every .eq(…, …) call on the chain, in order.
    `select_spy` is the .select(…) call.
    The chain resolves to `.execute()` which returns an object with `.data`.
    """
    mock_sb = MagicMock()
    execute_mock = MagicMock()
    execute_mock.return_value = MagicMock(data=returned_rows or [])

    # Build a chain mock where every method returns itself so we can track
    # all .eq(...) calls, terminating in .execute().
    chain = MagicMock()
    chain.execute = execute_mock
    chain.order.return_value = chain
    chain.limit.return_value = chain
    chain.eq.return_value = chain

    select_spy = MagicMock(return_value=chain)
    mock_sb.table.return_value.select = select_spy
    return mock_sb, select_spy, chain, execute_mock


def _fake_supabase_with_update_chain():
    """Return (mock_supabase, update_spy, chain, execute_mock) for UPDATE ops."""
    mock_sb = MagicMock()
    execute_mock = MagicMock()
    execute_mock.return_value = MagicMock(data=[])

    chain = MagicMock()
    chain.execute = execute_mock
    chain.eq.return_value = chain

    update_spy = MagicMock(return_value=chain)
    mock_sb.table.return_value.update = update_spy
    return mock_sb, update_spy, chain, execute_mock


# ────────────────────────────────────────────────────────────────────
# L7 — get_domain_scans IDOR regression
# ────────────────────────────────────────────────────────────────────

class TestGetDomainScansIDOR:
    def test_filters_by_user_id_in_query(self):
        """The query MUST include .eq('user_id', user_id). If this
        regresses, User A will see User B's scan history."""
        mock_sb, _select_spy, chain, _ = _fake_supabase_with_select_chain(
            returned_rows=[]
        )
        with patch("db.get_supabase", return_value=mock_sb):
            db.get_domain_scans("user-a", "example.com", limit=50)

        # Collect every .eq(...) call made on the chain
        eq_calls = [call.args for call in chain.eq.call_args_list]
        assert ("user_id", "user-a") in eq_calls, (
            "get_domain_scans must filter by user_id (INBOX-27). "
            f"Actual .eq(...) calls: {eq_calls}"
        )
        assert ("domain", "example.com") in eq_calls

    def test_empty_user_id_returns_empty_not_all_rows(self):
        """Defensive guard: missing user_id must NOT run an unscoped query.
        If a future handler forgets to pass user_id, we return [] rather
        than leaking the entire scans table."""
        mock_sb, _select_spy, _chain, execute_mock = (
            _fake_supabase_with_select_chain(returned_rows=[{"id": "leaked"}])
        )
        with patch("db.get_supabase", return_value=mock_sb):
            out = db.get_domain_scans("", "example.com")

        assert out == []
        # The query must never be built when user_id is empty
        assert not execute_mock.called, (
            "get_domain_scans must not execute a query when user_id is empty"
        )

    def test_owner_sees_own_rows_no_regression(self):
        """Parity: the legitimate owner still receives their rows."""
        rows = [{"id": "s1", "domain": "example.com", "score": 90}]
        mock_sb, _select_spy, _chain, _execute_mock = (
            _fake_supabase_with_select_chain(returned_rows=rows)
        )
        with patch("db.get_supabase", return_value=mock_sb):
            out = db.get_domain_scans("user-a", "example.com")

        assert out == rows


# ────────────────────────────────────────────────────────────────────
# L8 — get_monitoring_logs IDOR regression
# ────────────────────────────────────────────────────────────────────

class TestGetMonitoringLogsIDOR:
    def test_filters_by_user_id_and_domain_id(self):
        """Both .eq filters must be present. Dropping the user_id filter
        would re-open the cross-tenant log disclosure bug."""
        mock_sb, _select_spy, chain, _ = _fake_supabase_with_select_chain(
            returned_rows=[]
        )
        with patch("db.get_supabase", return_value=mock_sb):
            db.get_monitoring_logs("user-a", "domain-uuid-123", limit=20)

        eq_calls = [call.args for call in chain.eq.call_args_list]
        assert ("user_id", "user-a") in eq_calls, (
            "get_monitoring_logs must filter by user_id (INBOX-27). "
            f"Actual .eq(...) calls: {eq_calls}"
        )
        assert ("domain_id", "domain-uuid-123") in eq_calls

    def test_empty_user_id_returns_empty(self):
        """Missing user_id → empty result, no query executed."""
        mock_sb, _select_spy, _chain, execute_mock = (
            _fake_supabase_with_select_chain(returned_rows=[{"id": "leaked"}])
        )
        with patch("db.get_supabase", return_value=mock_sb):
            out = db.get_monitoring_logs("", "domain-uuid-123")

        assert out == []
        assert not execute_mock.called

    def test_owner_sees_own_logs_no_regression(self):
        """Parity: the legitimate owner still receives their logs."""
        rows = [{"id": "log1", "domain_id": "d1", "old_score": 80}]
        mock_sb, _select_spy, _chain, _ = _fake_supabase_with_select_chain(
            returned_rows=rows
        )
        with patch("db.get_supabase", return_value=mock_sb):
            out = db.get_monitoring_logs("user-a", "d1")

        assert out == rows


# ────────────────────────────────────────────────────────────────────
# L10 — update_domain_score cross-tenant WRITE regression
# ────────────────────────────────────────────────────────────────────

class TestUpdateDomainScoreIDOR:
    def test_update_scoped_by_user_id(self):
        """The UPDATE must filter by BOTH user_id AND domain. Previously
        only domain was used, so User A's scan overwrote User B's
        latest_score row for the same domain name."""
        mock_sb, update_spy, chain, _ = _fake_supabase_with_update_chain()
        with patch("db.get_supabase", return_value=mock_sb):
            db.update_domain_score("user-a", "example.com", 85, "scan-id-1")

        # Confirm UPDATE payload
        assert update_spy.called
        payload = update_spy.call_args[0][0]
        assert payload == {"latest_score": 85, "latest_scan_id": "scan-id-1"}

        # Both .eq filters must appear in the chain
        eq_calls = [call.args for call in chain.eq.call_args_list]
        assert ("user_id", "user-a") in eq_calls, (
            "update_domain_score must filter UPDATE by user_id (INBOX-27). "
            f"Actual .eq(...) calls: {eq_calls}"
        )
        assert ("domain", "example.com") in eq_calls

    def test_empty_user_id_skips_update(self):
        """Defensive: missing user_id must NOT execute an unscoped UPDATE.
        An unscoped UPDATE would overwrite every user's domain row."""
        mock_sb, update_spy, _chain, execute_mock = (
            _fake_supabase_with_update_chain()
        )
        with patch("db.get_supabase", return_value=mock_sb):
            db.update_domain_score("", "example.com", 85, "scan-id-1")

        # Neither update() nor execute() should have been called
        assert not update_spy.called, (
            "update_domain_score must not call .update() without a user_id — "
            "would overwrite every tenant's row."
        )
        assert not execute_mock.called

    def test_update_does_not_execute_cross_tenant(self):
        """Symbolic: user-a's update must not hit user-b's row. This is
        covered by test_update_scoped_by_user_id above via the .eq chain;
        here we capture it as an explicit invariant for code reviewers."""
        mock_sb, _update_spy, chain, _ = _fake_supabase_with_update_chain()
        with patch("db.get_supabase", return_value=mock_sb):
            db.update_domain_score("user-a", "shared.com", 90, "s1")

        eq_calls = [call.args for call in chain.eq.call_args_list]
        user_ids_filtered = [v for k, v in eq_calls if k == "user_id"]
        assert user_ids_filtered == ["user-a"], (
            "UPDATE must be scoped to exactly one user — "
            f"got user_id filters: {user_ids_filtered}"
        )
