"""
Tests for db.save_scan — the persistence contract consumed by both
app.py::_run_scan and monitor.py::monitor_single_domain (INBOX-22).

Focus: assert that the INSERT payload sent to Supabase carries the correct
scan_type for each code path, and that ip_address=None is correctly omitted
(so the INET column receives NULL, not the string "None" or similar).

This pins the fix for INBOX-1 (monitor never persisted a scan in 42 days
because ip_address="monitor" was silently rejected by the INET type).
"""

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db  # noqa: E402


def _fake_supabase_with_insert_spy():
    """Return (mock_supabase_client, insert_spy).

    insert_spy.call_args[0][0] will be the dict passed to .insert(...).
    """
    mock_sb = MagicMock()
    insert_spy = MagicMock()
    # sb.table("scans").insert(data).execute() → object with .data = [{...}]
    execute_return = MagicMock()
    execute_return.data = [{"id": "fake-uuid-1234"}]
    insert_spy.return_value = MagicMock(execute=MagicMock(return_value=execute_return))
    mock_sb.table.return_value.insert = insert_spy
    return mock_sb, insert_spy


class TestSaveScanScanType:
    """Asserts scan_type travels correctly into the INSERT payload."""

    def test_monitor_path_inserts_scan_type_scheduled(self):
        """INBOX-22: monitor passes scan_type='scheduled' → it lands in INSERT."""
        mock_sb, insert_spy = _fake_supabase_with_insert_spy()
        with patch("db.get_supabase", return_value=mock_sb):
            result = db.save_scan(
                domain="example.com",
                score=75,
                results={"ok": True},
                ip_address=None,
                user_id="user-abc",
                scan_type="scheduled",
            )

        assert result == {"id": "fake-uuid-1234"}
        assert insert_spy.called
        payload = insert_spy.call_args[0][0]
        assert payload["scan_type"] == "scheduled"
        assert payload["domain"] == "example.com"
        assert payload["score"] == 75
        assert payload["user_id"] == "user-abc"

    def test_monitor_path_omits_ip_address_when_none(self):
        """INBOX-22: ip_address=None must NOT be present in INSERT.

        The INET column must receive the SQL default (NULL). Including the key
        with a None value would send the literal None, which the INET type
        would reject. The falsy-guard in save_scan handles this today — this
        test pins that behavior against future refactors.
        """
        mock_sb, insert_spy = _fake_supabase_with_insert_spy()
        with patch("db.get_supabase", return_value=mock_sb):
            db.save_scan(
                domain="example.com",
                score=75,
                results={},
                ip_address=None,
                scan_type="scheduled",
            )

        payload = insert_spy.call_args[0][0]
        assert "ip_address" not in payload, (
            "ip_address=None must be dropped from INSERT so INET column gets NULL"
        )

    def test_api_path_inserts_scan_type_manual_with_ip(self):
        """app.py explicit scan_type='manual' + real IP → both in INSERT."""
        mock_sb, insert_spy = _fake_supabase_with_insert_spy()
        with patch("db.get_supabase", return_value=mock_sb):
            db.save_scan(
                domain="example.com",
                score=88,
                results={},
                ip_address="203.0.113.42",
                user_id="user-xyz",
                scan_type="manual",
            )

        payload = insert_spy.call_args[0][0]
        assert payload["scan_type"] == "manual"
        assert payload["ip_address"] == "203.0.113.42"

    def test_default_scan_type_is_manual(self):
        """Backwards compat: if scan_type omitted, default 'manual' lands."""
        mock_sb, insert_spy = _fake_supabase_with_insert_spy()
        with patch("db.get_supabase", return_value=mock_sb):
            db.save_scan(
                domain="example.com",
                score=50,
                results={},
                ip_address="198.51.100.1",
            )

        payload = insert_spy.call_args[0][0]
        assert payload["scan_type"] == "manual"

    def test_db_unavailable_returns_none(self):
        """If get_supabase() returns None (no creds), save_scan returns None.

        This pins the existing behavior; INBOX-22 does not change it. Note:
        the swallowed-exception path (db.py:75-77) is a separate ticket
        (fail-loud.md violation — see cleanup backlog).
        """
        with patch("db.get_supabase", return_value=None):
            result = db.save_scan(
                domain="example.com",
                score=50,
                results={},
                scan_type="scheduled",
            )
        assert result is None
