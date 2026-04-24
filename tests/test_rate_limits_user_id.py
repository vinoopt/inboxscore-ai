"""
Regression suite for INBOX-30 — rate_limits + user_id correctness.

Closes TWO bugs that share a root cause (rate_limits had no user_id
column; code tried to store UUIDs in the ip_address INET column):

  Bug 1 — db.delete_user_data ran
            DELETE FROM rate_limits WHERE ip_address = <user_id UUID>
          which deleted zero rows (UUID can't be cast to INET). The
          user's rate-limit rows persisted forever after account
          deletion.

  Bug 2 — db.check_rate_limit stored the UUID in the ip_address column
          for authenticated users. Postgres rejected the INSERT/UPDATE,
          the bare except swallowed the error, and rate limiting was
          silently disabled for every logged-in user. Paid-plan scan
          limits didn't enforce.

Both bugs are closed by migration 009 (adds user_id UUID column) plus
the code changes that route authenticated users through it.

These tests lock the contract in by spying on the Supabase query
builder: we assert the correct column name is used in the .eq() call
chain for each code path.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db  # noqa: E402


def _spy_supabase(select_data=None):
    """Build a Supabase mock whose query-builder chain is observable.

    Returns (mock_sb, insert_spy, delete_spy, eq_spies, update_spy).
    `eq_spies` is a list of (column, value) tuples across the whole chain,
    in order.
    """
    mock_sb = MagicMock()
    eq_calls: list[tuple] = []

    def make_chain():
        chain = MagicMock()
        chain.execute = MagicMock(return_value=MagicMock(data=select_data or []))
        chain.order.return_value = chain
        chain.lt.return_value = chain
        chain.gte.return_value = chain
        chain.limit.return_value = chain

        def _eq(col, val):
            eq_calls.append((col, val))
            return chain

        chain.eq.side_effect = _eq
        return chain

    select_chain = make_chain()
    delete_chain = make_chain()
    insert_chain = make_chain()
    update_chain = make_chain()

    table_mock = MagicMock()
    table_mock.select.return_value = select_chain
    table_mock.delete.return_value = delete_chain
    table_mock.insert.return_value = insert_chain
    table_mock.update.return_value = update_chain

    mock_sb.table.return_value = table_mock

    return mock_sb, eq_calls, table_mock, insert_chain, update_chain


# --------------------------------------------------------------------
# Bug 1 — delete_user_data now filters on user_id, not ip_address
# --------------------------------------------------------------------

class TestDeleteUserData:
    def test_rate_limits_deleted_by_user_id_not_ip_address(self):
        mock_sb, eq_calls, _, _, _ = _spy_supabase()
        with patch.object(db, "get_supabase", return_value=mock_sb):
            result = db.delete_user_data("user-abc-uuid")
        assert result is True

        # Among the .eq() calls made during the delete sequence, there must
        # be one for rate_limits keyed on user_id. There must NOT be one
        # pretending the ip_address column holds a UUID.
        rate_limit_filters = [(c, v) for c, v in eq_calls if v == "user-abc-uuid"]
        assert ("user_id", "user-abc-uuid") in rate_limit_filters, (
            "INBOX-30 regression: delete_user_data must filter rate_limits "
            "on the new user_id column (added in migration 009). "
            f"Actual .eq() calls: {eq_calls}"
        )
        assert ("ip_address", "user-abc-uuid") not in rate_limit_filters, (
            "INBOX-30 regression: the old ip_address=<UUID> filter (which "
            "silently deleted zero rows because INET can't be compared to "
            "a UUID string) has been resurrected."
        )


# --------------------------------------------------------------------
# Bug 2 — check_rate_limit uses the right column per flow
# --------------------------------------------------------------------

class TestCheckRateLimitColumnRouting:

    def test_authenticated_user_selects_and_inserts_by_user_id(self):
        # First-scan-today path for a paid user. Should SELECT by user_id
        # and INSERT with user_id populated (no ip_address).
        mock_sb, eq_calls, table_mock, insert_chain, _ = _spy_supabase(select_data=[])
        with patch.object(db, "get_supabase", return_value=mock_sb), \
             patch.object(db, "get_user_plan", return_value="pro"), \
             patch.dict(db.PLAN_LIMITS, {"pro": 100}, clear=False):
            result = db.check_rate_limit(
                ip_address="203.0.113.5",
                user_id="user-abc-uuid",
            )

        assert result["allowed"] is True
        assert result["scans_used"] == 1
        assert result["plan"] == "pro"

        # SELECT .eq filters must route by user_id, NOT ip_address.
        assert ("user_id", "user-abc-uuid") in eq_calls, (
            "INBOX-30 Bug 2 regression: authenticated check_rate_limit "
            "must .eq('user_id', <uuid>). "
            f"Actual .eq() calls: {eq_calls}"
        )
        assert not any(c == "ip_address" and v == "user-abc-uuid" for c, v in eq_calls), (
            "INBOX-30 Bug 2 regression: we must NOT filter by "
            ".eq('ip_address', <uuid>) — Postgres silently rejects "
            "that cast and disables rate limiting for every paid user."
        )

        # And the INSERT payload must contain user_id (not ip_address with a UUID).
        insert_call = table_mock.insert.call_args
        assert insert_call is not None, "insert() was never called"
        inserted_row = insert_call[0][0]
        assert inserted_row.get("user_id") == "user-abc-uuid"
        assert "ip_address" not in inserted_row, (
            "Authenticated insert must not populate ip_address — that column "
            "is for anonymous rows only."
        )

    def test_anonymous_user_still_keys_by_ip_address(self):
        # Sanity: anonymous flow must continue to work exactly as before.
        mock_sb, eq_calls, table_mock, _, _ = _spy_supabase(select_data=[])
        with patch.object(db, "get_supabase", return_value=mock_sb):
            result = db.check_rate_limit(
                ip_address="203.0.113.5",
                user_id=None,   # anonymous
            )

        assert result["allowed"] is True
        assert result["scans_used"] == 1
        assert result["plan"] == "anonymous"

        assert ("ip_address", "203.0.113.5") in eq_calls, (
            "Anonymous users must still key on ip_address. "
            f"Actual .eq() calls: {eq_calls}"
        )
        insert_call = table_mock.insert.call_args
        inserted_row = insert_call[0][0]
        assert inserted_row.get("ip_address") == "203.0.113.5"
        assert "user_id" not in inserted_row, (
            "Anonymous insert must not populate user_id — that column is "
            "for authenticated rows only."
        )

    def test_authenticated_user_increment_updates_by_user_id(self):
        # User already has a row today with scan_count=4; increment to 5.
        mock_sb, eq_calls, table_mock, _, update_chain = _spy_supabase(
            select_data=[{"scan_count": 4}]
        )
        with patch.object(db, "get_supabase", return_value=mock_sb), \
             patch.object(db, "get_user_plan", return_value="pro"), \
             patch.dict(db.PLAN_LIMITS, {"pro": 100}, clear=False):
            result = db.check_rate_limit(
                ip_address="203.0.113.5",
                user_id="user-abc-uuid",
            )

        assert result["scans_used"] == 5
        # The .eq() chain for the UPDATE must include user_id, not ip_address.
        update_filter_calls = [(c, v) for c, v in eq_calls if v == "user-abc-uuid"]
        assert ("user_id", "user-abc-uuid") in update_filter_calls

    def test_authenticated_user_blocked_at_limit(self):
        # Hit the plan's cap — must be blocked, no insert/update issued.
        mock_sb, eq_calls, table_mock, _, _ = _spy_supabase(
            select_data=[{"scan_count": 100}]
        )
        with patch.object(db, "get_supabase", return_value=mock_sb), \
             patch.object(db, "get_user_plan", return_value="pro"), \
             patch.dict(db.PLAN_LIMITS, {"pro": 100}, clear=False):
            result = db.check_rate_limit(
                ip_address="203.0.113.5",
                user_id="user-abc-uuid",
            )

        assert result["allowed"] is False
        assert result["scans_used"] == 100
        assert result["plan"] == "pro"
