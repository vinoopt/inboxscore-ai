"""
Regression suite for INBOX-29 — timezone hygiene.

Three real bugs fixed in the prior commit. These tests lock each of
them in so a future refactor that drops tz-awareness will fail loudly.

  L12 — db.get_domains_due_for_scan compared naive datetime.utcnow() to
        a tz-stripped last_monitored_at. If the column ever returned
        tz-aware (which it does, Supabase timestamptz), the old
        .replace(tzinfo=None) masked the overdue state — exactly the
        INBOX-1 42-day-silent-monitor pattern.

  L14 — postmaster.ensure_valid_token's 5-minute early-refresh check
        compared naive datetime.utcnow() to a tz-stripped expiry_dt.
        Edge-of-expiry requests could 401 when the OS clock drifted
        from UTC by a handful of seconds.

  L15 — ensure_valid_token returned the raw (possibly already-expired)
        access_token when token_expiry was empty / unparseable. Now it
        refreshes unconditionally in that case.

We do NOT touch a real Supabase or a real Google OAuth endpoint — we
patch the narrow blast radius (get_monitored_domains for L12;
refresh_access_token + update_postmaster_tokens for L14/L15) and
exercise the function under test directly.
"""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import db  # noqa: E402
import postmaster  # noqa: E402


# --------------------------------------------------------------------
# L12 — get_domains_due_for_scan
# --------------------------------------------------------------------

def _domain(monitor_interval: int, last_monitored_at):
    return {
        "id": "d1",
        "user_id": "u1",
        "domain": "example.com",
        "monitor_interval": monitor_interval,
        "last_monitored_at": last_monitored_at,
    }


def _iso_minus(minutes: int) -> str:
    """ISO string (Z suffix) that Supabase would return for a timestamp N minutes ago."""
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}Z"


class TestDomainsDueForScan:
    """L12 — overdue-vs-not-overdue given a tz-aware last_monitored_at."""

    def test_domain_overdue_by_61_minutes_is_returned(self):
        # interval=60min (1h), last scan 61min ago -> must be flagged due.
        domain = _domain(monitor_interval=1, last_monitored_at=_iso_minus(61))
        # Also pass a mock supabase so is_db_available returns truthy.
        with patch.object(db, "get_supabase", return_value=MagicMock()):
            with patch.object(db, "get_monitored_domains", return_value=[domain]):
                due = db.get_domains_due_for_scan()
        assert due == [domain], (
            "L12 regression: tz-aware last_monitored_at 61 minutes ago "
            "against a 1-hour interval must produce a due domain. "
            "Old code silently dropped it because it stripped tz from "
            "last_dt and compared to naive datetime.utcnow()."
        )

    def test_domain_within_interval_is_not_returned(self):
        # Mirror case: interval=60min, last scan 10min ago -> NOT due.
        domain = _domain(monitor_interval=1, last_monitored_at=_iso_minus(10))
        with patch.object(db, "get_supabase", return_value=MagicMock()):
            with patch.object(db, "get_monitored_domains", return_value=[domain]):
                due = db.get_domains_due_for_scan()
        assert due == [], (
            "A domain scanned 10 minutes ago with a 1-hour interval "
            "must NOT be flagged due."
        )

    def test_never_scanned_domain_is_returned_immediately(self):
        domain = _domain(monitor_interval=24, last_monitored_at=None)
        with patch.object(db, "get_supabase", return_value=MagicMock()):
            with patch.object(db, "get_monitored_domains", return_value=[domain]):
                due = db.get_domains_due_for_scan()
        assert due == [domain]

    def test_aware_datetime_object_not_string(self):
        # Some call paths may pass a pre-parsed datetime; tz-aware is the
        # only invariant we guarantee.
        aware_dt = datetime.now(timezone.utc) - timedelta(hours=25)
        domain = _domain(monitor_interval=24, last_monitored_at=aware_dt)
        with patch.object(db, "get_supabase", return_value=MagicMock()):
            with patch.object(db, "get_monitored_domains", return_value=[domain]):
                due = db.get_domains_due_for_scan()
        assert due == [domain]

    def test_naive_datetime_falls_back_to_utc_assumption(self):
        # Defensive: even if a fixture or legacy row produces a naive
        # datetime, we assume UTC rather than crashing on subtraction.
        naive_dt = (datetime.now(timezone.utc) - timedelta(hours=25)).replace(tzinfo=None)
        domain = _domain(monitor_interval=24, last_monitored_at=naive_dt)
        with patch.object(db, "get_supabase", return_value=MagicMock()):
            with patch.object(db, "get_monitored_domains", return_value=[domain]):
                due = db.get_domains_due_for_scan()
        assert due == [domain]


# --------------------------------------------------------------------
# L14 + L15 — ensure_valid_token
# --------------------------------------------------------------------

def _run(coro):
    # Use a fresh event loop per call — asyncio.get_event_loop() picks up
    # whatever loop a previous async test in the suite left behind, and
    # some of those close it, which breaks test order independence.
    return asyncio.new_event_loop().run_until_complete(coro)


def _future_expiry(minutes_from_now: int) -> str:
    ts = datetime.now(timezone.utc) + timedelta(minutes=minutes_from_now)
    return ts.isoformat()


class TestEnsureValidToken:
    """L14: naive/aware mix; L15: missing expiry returned raw token."""

    def test_fresh_token_returns_unchanged(self):
        # Token valid for another 30 minutes — should NOT hit refresh.
        conn = {
            "access_token": "fresh-token",
            "refresh_token": "r",
            "token_expiry": _future_expiry(30),
        }
        with patch.object(postmaster, "refresh_access_token") as m_refresh, \
             patch("db.update_postmaster_tokens"):
            result = _run(postmaster.ensure_valid_token("u1", conn))
        assert result == "fresh-token"
        m_refresh.assert_not_called()

    def test_token_inside_5min_buffer_triggers_refresh(self):
        # L14: within the 5-minute early-refresh window -> refresh.
        conn = {
            "access_token": "expired-soon",
            "refresh_token": "r",
            "token_expiry": _future_expiry(2),   # 2 minutes from now
        }
        with patch.object(postmaster, "refresh_access_token",
                          return_value={"access_token": "new-tok",
                                        "token_expiry": _future_expiry(60)}) as m_refresh, \
             patch("db.update_postmaster_tokens") as m_update:
            result = _run(postmaster.ensure_valid_token("u1", conn))
        assert result == "new-tok"
        m_refresh.assert_called_once_with("r")
        m_update.assert_called_once()

    def test_missing_expiry_forces_refresh_not_raw_token(self):
        # L15: empty token_expiry must refresh, NEVER return raw token.
        conn = {
            "access_token": "raw-possibly-expired",
            "refresh_token": "r",
            "token_expiry": "",
        }
        with patch.object(postmaster, "refresh_access_token",
                          return_value={"access_token": "new-tok",
                                        "token_expiry": _future_expiry(60)}) as m_refresh, \
             patch("db.update_postmaster_tokens"):
            result = _run(postmaster.ensure_valid_token("u1", conn))
        assert result == "new-tok", (
            "L15 regression: when token_expiry is empty, ensure_valid_token "
            "must refresh unconditionally instead of returning the raw "
            "(possibly already-expired) access_token."
        )
        m_refresh.assert_called_once_with("r")

    def test_missing_expiry_key_forces_refresh(self):
        # Same as above but with the key entirely absent.
        conn = {"access_token": "raw", "refresh_token": "r"}
        with patch.object(postmaster, "refresh_access_token",
                          return_value={"access_token": "new-tok",
                                        "token_expiry": _future_expiry(60)}) as m_refresh, \
             patch("db.update_postmaster_tokens"):
            result = _run(postmaster.ensure_valid_token("u1", conn))
        assert result == "new-tok"
        m_refresh.assert_called_once()

    def test_unparseable_expiry_forces_refresh(self):
        conn = {
            "access_token": "raw",
            "refresh_token": "r",
            "token_expiry": "not-a-date",
        }
        with patch.object(postmaster, "refresh_access_token",
                          return_value={"access_token": "new-tok",
                                        "token_expiry": _future_expiry(60)}) as m_refresh, \
             patch("db.update_postmaster_tokens"):
            result = _run(postmaster.ensure_valid_token("u1", conn))
        assert result == "new-tok"
        m_refresh.assert_called_once()

    def test_already_expired_token_triggers_refresh(self):
        conn = {
            "access_token": "dead",
            "refresh_token": "r",
            "token_expiry": _future_expiry(-30),  # 30 minutes in the PAST
        }
        with patch.object(postmaster, "refresh_access_token",
                          return_value={"access_token": "new-tok",
                                        "token_expiry": _future_expiry(60)}) as m_refresh, \
             patch("db.update_postmaster_tokens"):
            result = _run(postmaster.ensure_valid_token("u1", conn))
        assert result == "new-tok"
        m_refresh.assert_called_once()

    def test_refresh_failure_raises(self):
        conn = {
            "access_token": "raw",
            "refresh_token": "r",
            "token_expiry": "",
        }
        with patch.object(postmaster, "refresh_access_token",
                          side_effect=Exception("network boom")), \
             patch("db.update_postmaster_tokens"):
            try:
                _run(postmaster.ensure_valid_token("u1", conn))
                raised = False
            except Exception as e:
                raised = True
                assert "network boom" in str(e) or "Failed to refresh" in str(e)
        assert raised, "Refresh failure must propagate, not silently return raw token"
