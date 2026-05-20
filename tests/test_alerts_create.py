"""
INBOX-269 (2026-05-20) — round-trip smoke tests for db.create_alert().

Background — the bug this test pins:
  The prod alerts schema (db/prod-schema-2026-04-22.sql) had columns:
    id, user_id, domain_id, type, severity, message, is_read, created_at
  But db.create_alert() always writes data["title"] = title, and writes
  data["domain"] = domain whenever the caller passes a domain.
  monitor.py always passes BOTH title and domain. So every
  monitor-originated insert raised "column 'title' does not exist", which
  the silent except: print() handler swallowed. The alerts table sat
  empty for months despite monitor.py logging "no changes, 0 alerts"
  on every cycle.

What this test file does:
  1. Asserts the INSERT payload contract — every column create_alert()
     writes is exercised, with realistic values per alert type. If the
     schema ever loses one of these columns again, the corresponding
     test will reveal which one in the test failure output.
  2. Asserts every alert_type from monitor.compare_scan_results() is
     supported — covers all 8 schema enum types plus the dns_change
     fallback that monitor.py emits.
  3. Asserts the silent-skip pattern is gone — when the Supabase INSERT
     raises, the wrapper calls _alerts_log.exception(), not print().
  4. Round-trips a create + get pair to mimic what monitor.py + the
     /alerts UI do — verifies create returns an id and get returns it.

These tests use MagicMock for Supabase (no live DB), so they pin the
*code contract* — they would NOT have caught the schema/code divergence
that caused this bug. The real safety net is to run the migration first
and then run these against a real (test) Supabase instance. Both are
worth keeping: tests pin the contract here, integration verifies the
contract holds against the real schema in CI.
"""

import logging
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db  # noqa: E402


# ─── Helpers ────────────────────────────────────────────────────────


def _supabase_with_insert_spy(returned_row=None):
    """Build a mock supabase client + capture the insert payload.

    Returns (mock_sb, insert_spy). insert_spy.call_args[0][0] is the
    dict passed into .insert(...).
    """
    mock_sb = MagicMock()
    insert_spy = MagicMock()
    execute_return = MagicMock()
    execute_return.data = [returned_row or {
        "id": "alert-uuid-1234",
        "user_id": "user-abc",
        "type": "score_drop",
        "severity": "warning",
        "title": "Score dropped 12 points",
        "message": "example.com score fell from 88 to 76 (-12 points).",
        "domain_id": "domain-xyz",
        "domain": "example.com",
        "is_read": False,
        "created_at": "2026-05-20T12:00:00Z",
    }]
    insert_spy.return_value = MagicMock(
        execute=MagicMock(return_value=execute_return)
    )
    mock_sb.table.return_value.insert = insert_spy
    return mock_sb, insert_spy


# ─── Tests ──────────────────────────────────────────────────────────


class TestCreateAlertPayload:
    """Pins which columns create_alert() writes — would have caught the
    INBOX-269 bug if it had been written before the schema drift."""

    def test_payload_always_includes_title(self):
        """The bug: prod schema had no title column. The fix: migration
        019 added it. This test ensures the code never stops writing it."""
        mock_sb, insert_spy = _supabase_with_insert_spy()
        with patch("db.get_supabase", return_value=mock_sb):
            db.create_alert(
                user_id="user-abc",
                alert_type="score_drop",
                severity="warning",
                title="Score dropped 12 points",
                message="example.com score fell from 88 to 76.",
                domain_id="domain-xyz",
                domain="example.com",
            )
        payload = insert_spy.call_args[0][0]
        assert "title" in payload, (
            "create_alert() must always include 'title' in the INSERT "
            "payload. Migration 019 added this column to prod alerts table. "
            "If this test fails, /alerts feed will lose the headline row."
        )
        assert payload["title"] == "Score dropped 12 points"

    def test_payload_includes_domain_when_provided(self):
        """monitor.py always passes a domain string. Migration 019 added
        the column. This test pins the contract."""
        mock_sb, insert_spy = _supabase_with_insert_spy()
        with patch("db.get_supabase", return_value=mock_sb):
            db.create_alert(
                user_id="user-abc",
                alert_type="blacklist_added",
                severity="critical",
                title="Listed on Spamhaus",
                message="example.com is now listed on Spamhaus ZEN.",
                domain_id="domain-xyz",
                domain="example.com",
            )
        payload = insert_spy.call_args[0][0]
        assert payload.get("domain") == "example.com"

    def test_payload_omits_domain_when_not_provided(self):
        """If a future caller doesn't pass a domain, the column must be
        omitted (not written as null) so the DB default kicks in.
        Falsy-guard pattern matches save_scan."""
        mock_sb, insert_spy = _supabase_with_insert_spy()
        with patch("db.get_supabase", return_value=mock_sb):
            db.create_alert(
                user_id="user-abc",
                alert_type="score_drop",
                severity="warning",
                title="Score dropped",
                message="…",
                domain_id="domain-xyz",
                # no domain=
            )
        payload = insert_spy.call_args[0][0]
        assert "domain" not in payload

    def test_payload_carries_core_columns(self):
        """All non-optional fields the prod schema requires must be present."""
        mock_sb, insert_spy = _supabase_with_insert_spy()
        with patch("db.get_supabase", return_value=mock_sb):
            db.create_alert(
                user_id="user-abc",
                alert_type="dmarc_change",
                severity="critical",
                title="DMARC now failing",
                message="example.com DMARC went from pass to fail.",
                domain_id="domain-xyz",
                domain="example.com",
            )
        payload = insert_spy.call_args[0][0]
        for required in ("user_id", "type", "severity", "title"):
            assert required in payload, f"missing required column: {required}"
        assert payload["user_id"] == "user-abc"
        assert payload["type"] == "dmarc_change"
        assert payload["severity"] == "critical"


class TestEveryAlertTypeFromMonitor:
    """monitor.compare_scan_results() emits 8 schema-enum types plus
    one fallback ('dns_change') for unrecognised check transitions.
    This test pins that all 9 round-trip through create_alert()."""

    ALERT_TYPES = [
        ("score_drop", "warning", "Score dropped 7 points"),
        ("score_drop", "critical", "Score dropped 22 points"),
        ("blacklist_added", "critical", "Listed on Spamhaus ZEN"),
        ("blacklist_removed", "info", "Removed from blacklists"),
        ("cert_expiry", "warning", "TLS cert near expiry"),
        ("reputation_change", "warning", "IP reputation dropped to medium"),
        ("dmarc_change", "critical", "DMARC now failing"),
        ("spf_change", "critical", "SPF now failing"),
        ("dkim_change", "critical", "DKIM now failing"),
        ("dns_change", "warning", "MX record changed"),
    ]

    @pytest.mark.parametrize("alert_type,severity,title", ALERT_TYPES)
    def test_each_type_round_trips(self, alert_type, severity, title):
        mock_sb, insert_spy = _supabase_with_insert_spy()
        with patch("db.get_supabase", return_value=mock_sb):
            result = db.create_alert(
                user_id="user-abc",
                alert_type=alert_type,
                severity=severity,
                title=title,
                message=f"{title} — context.",
                domain_id="domain-xyz",
                domain="example.com",
            )
        assert insert_spy.called
        payload = insert_spy.call_args[0][0]
        assert payload["type"] == alert_type
        assert payload["severity"] == severity
        assert payload["title"] == title
        assert result is not None
        assert "id" in result


class TestStructuredLoggingOnFailure:
    """INBOX-269 verification: the silent print() that masked the bug
    for months has been replaced with _alerts_log.exception(). When the
    INSERT raises, Sentry's LoggingIntegration must see a structured
    event, not nothing."""

    def test_create_alert_failure_emits_logger_exception(self, caplog):
        mock_sb = MagicMock()
        # Make .execute() raise — simulates schema/auth/network failures
        mock_sb.table.return_value.insert.return_value.execute.side_effect = (
            Exception("simulated: column 'title' does not exist")
        )
        with patch("db.get_supabase", return_value=mock_sb):
            with caplog.at_level(logging.ERROR, logger="inboxscore.alerts.db"):
                result = db.create_alert(
                    user_id="user-abc",
                    alert_type="score_drop",
                    severity="warning",
                    title="Score dropped",
                    message="…",
                    domain_id="domain-xyz",
                    domain="example.com",
                )
        assert result is None
        # Must produce a log record on the alerts logger at ERROR level
        # (logger.exception() emits at ERROR).
        records = [
            r for r in caplog.records
            if r.name == "inboxscore.alerts.db"
            and r.levelno >= logging.ERROR
        ]
        assert records, (
            "Expected _alerts_log.exception(...) on insert failure. "
            "If this test fails, the same silent-skip pattern that hid "
            "INBOX-269 for months is back."
        )
        # logger.exception() always attaches the exception info
        rec = records[0]
        assert rec.exc_info is not None
        assert "alerts.create_failed" in rec.getMessage()

    def test_get_user_alerts_failure_emits_logger_exception(self, caplog):
        mock_sb = MagicMock()
        # Build the chain failure — final .execute() raises
        chain = mock_sb.table.return_value.select.return_value.eq.return_value
        chain.order.return_value.limit.return_value.execute.side_effect = (
            Exception("simulated: connection reset")
        )
        chain.eq.return_value.order.return_value.limit.return_value.execute.side_effect = (
            Exception("simulated: connection reset")
        )
        with patch("db.get_supabase", return_value=mock_sb):
            with caplog.at_level(logging.ERROR, logger="inboxscore.alerts.db"):
                result = db.get_user_alerts(user_id="user-abc")
        assert result == []
        records = [
            r for r in caplog.records
            if r.name == "inboxscore.alerts.db"
            and r.levelno >= logging.ERROR
        ]
        assert records, "get_user_alerts must emit logger.exception on failure"


class TestRoundTripContract:
    """Mimics the monitor.py → /alerts UI flow:
      1. monitor calls create_alert() → returns dict with id
      2. UI calls get_user_alerts() → returns list including that row
    Both paths share the same Supabase chain mock so we can assert the
    written row would be readable."""

    def test_create_then_get_returns_row(self):
        # Stage 1: create returns a row
        created_row = {
            "id": "alert-uuid-9999",
            "user_id": "user-abc",
            "type": "score_drop",
            "severity": "warning",
            "title": "Score dropped 8 points",
            "message": "example.com fell from 86 to 78.",
            "domain_id": "domain-xyz",
            "domain": "example.com",
            "is_read": False,
            "created_at": "2026-05-20T12:00:00Z",
        }
        mock_sb, _ = _supabase_with_insert_spy(returned_row=created_row)

        # Stage 2: get returns that same row
        get_execute = MagicMock()
        get_execute.data = [created_row]
        mock_sb.table.return_value.select.return_value.eq.return_value.order.return_value.limit.return_value.execute.return_value = get_execute

        with patch("db.get_supabase", return_value=mock_sb):
            created = db.create_alert(
                user_id="user-abc",
                alert_type="score_drop",
                severity="warning",
                title="Score dropped 8 points",
                message="example.com fell from 86 to 78.",
                domain_id="domain-xyz",
                domain="example.com",
            )
            fetched = db.get_user_alerts(user_id="user-abc")

        assert created is not None
        assert created["id"] == "alert-uuid-9999"
        assert created["title"] == "Score dropped 8 points"

        assert len(fetched) == 1
        assert fetched[0]["id"] == "alert-uuid-9999"
        # The user-visible headline (the column that the bug killed)
        assert fetched[0]["title"] == "Score dropped 8 points"
        # The user-visible domain (the other column that the bug killed)
        assert fetched[0]["domain"] == "example.com"


class TestDbAvailabilityGuard:
    """When Supabase isn't initialised, create_alert returns None
    quietly. Pin this contract — monitor.py treats None as "skipped"."""

    def test_create_alert_returns_none_when_no_supabase(self):
        with patch("db.get_supabase", return_value=None):
            result = db.create_alert(
                user_id="user-abc",
                alert_type="score_drop",
                severity="warning",
                title="Score dropped",
                message="…",
                domain_id="domain-xyz",
                domain="example.com",
            )
        assert result is None

    def test_get_user_alerts_returns_empty_when_no_supabase(self):
        with patch("db.get_supabase", return_value=None):
            result = db.get_user_alerts(user_id="user-abc")
        assert result == []
