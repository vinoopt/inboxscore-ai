"""
INBOX-87 — heartbeat retry + batched-fetch tests.

The original heartbeat helpers logged transient Supabase failures at
error-level, hammering Sentry with 100+ noisy events/day. This regression
suite locks in the new behaviour:

  • _retry runs the supplied fn up to 2 times before giving up
  • _latest_heartbeats fetches ALL cycle types in 1 round-trip
  • fetch failures are warning-level (not error), so Sentry's alert rule
    on errors doesn't fire on recoverable hiccups
  • record_start / record_end use logger.exception so failures that DO
    persist after retries surface a stacktrace in Sentry
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import heartbeat


def test_retry_returns_value_on_first_success():
    fn = MagicMock(return_value="ok")
    assert heartbeat._retry("op", fn) == "ok"
    assert fn.call_count == 1


def test_retry_succeeds_on_second_attempt():
    fn = MagicMock(side_effect=[Exception("transient"), "ok"])
    assert heartbeat._retry("op", fn, attempts=2, backoff=0) == "ok"
    assert fn.call_count == 2


def test_retry_raises_after_exhausting_attempts():
    fn = MagicMock(side_effect=Exception("persistent"))
    import pytest
    with pytest.raises(Exception, match="persistent"):
        heartbeat._retry("op", fn, attempts=2, backoff=0)
    assert fn.call_count == 2


# ─── _latest_heartbeats — batched fetch ─────────────────────────────

def test_latest_heartbeats_returns_one_row_per_cycle_type():
    """Even when the limit-50 window contains many rows, the helper must
    dedupe to the most-recent row per cycle_type."""
    fake_rows = [
        {"cycle_type": "monitor",         "cycle_started_at": "2026-04-27T08:11:44+00:00", "id": "m1"},
        {"cycle_type": "monitor",         "cycle_started_at": "2026-04-27T07:56:44+00:00", "id": "m2"},
        {"cycle_type": "postmaster_sync", "cycle_started_at": "2026-04-27T06:00:00+00:00", "id": "p1"},
        {"cycle_type": "snds_sync",       "cycle_started_at": "2026-04-27T07:00:00+00:00", "id": "s1"},
    ]
    fake_response = MagicMock(data=fake_rows)
    fake_chain = MagicMock()
    fake_chain.execute.return_value = fake_response
    fake_chain.limit.return_value = fake_chain
    fake_chain.order.return_value = fake_chain
    fake_chain.in_.return_value = fake_chain
    fake_chain.select.return_value = fake_chain
    fake_sb = MagicMock()
    fake_sb.table.return_value = fake_chain

    with patch("db.get_supabase", return_value=fake_sb):
        out = heartbeat._latest_heartbeats(["monitor", "postmaster_sync", "snds_sync"])

    assert set(out.keys()) == {"monitor", "postmaster_sync", "snds_sync"}
    # The first 'monitor' row in the (desc) order is the latest one
    assert out["monitor"]["id"] == "m1"
    assert out["postmaster_sync"]["id"] == "p1"
    assert out["snds_sync"]["id"] == "s1"


def test_latest_heartbeats_returns_empty_when_db_unavailable():
    with patch("db.get_supabase", return_value=None):
        assert heartbeat._latest_heartbeats(["monitor"]) == {}


def test_latest_heartbeats_returns_empty_on_persistent_failure(caplog):
    """If retry exhausts and the query still raises, return {} and emit a
    single warning (not error). Critical: no Sentry-error-level event."""
    fake_chain = MagicMock()
    fake_chain.execute.side_effect = Exception("supabase down")
    fake_chain.limit.return_value = fake_chain
    fake_chain.order.return_value = fake_chain
    fake_chain.in_.return_value = fake_chain
    fake_chain.select.return_value = fake_chain
    fake_sb = MagicMock()
    fake_sb.table.return_value = fake_chain

    with caplog.at_level(logging.WARNING, logger="inboxscore.heartbeat"):
        with patch("db.get_supabase", return_value=fake_sb):
            out = heartbeat._latest_heartbeats(["monitor"])

    assert out == {}
    # The failure was logged at WARNING (not ERROR)
    warning_records = [r for r in caplog.records if r.name == "inboxscore.heartbeat"
                       and r.levelno == logging.WARNING
                       and "fetch_failed" in r.message]
    assert warning_records, "Expected a warning-level fetch_failed log; got: " + str([
        (r.levelname, r.message) for r in caplog.records
    ])
    # And no error-level fetch_failed (that would still hit Sentry's alert rule)
    error_records = [r for r in caplog.records if r.name == "inboxscore.heartbeat"
                     and r.levelno == logging.ERROR
                     and "fetch_failed" in r.message]
    assert not error_records, (
        "fetch_failed must NOT log at error-level on transient hiccups "
        "(INBOX-87 regression)."
    )


# ─── heartbeat_status — uses the batched fetch ──────────────────────

def test_heartbeat_status_uses_batch_fetch_one_call():
    """The watchdog runs heartbeat_status() every 5 min. Previously this made
    3 round-trips per tick. INBOX-87 batches them — assert only 1 fetch."""
    sample = {
        "monitor":         {"cycle_started_at": "2026-04-27T08:11:00+00:00",
                            "cycle_completed_at": "2026-04-27T08:11:05+00:00",
                            "domains_processed": 5, "errors_count": 0},
        "postmaster_sync": {"cycle_started_at": "2026-04-27T06:00:00+00:00",
                            "cycle_completed_at": "2026-04-27T06:01:00+00:00",
                            "domains_processed": 3, "errors_count": 0},
        "snds_sync":       {"cycle_started_at": "2026-04-27T07:00:00+00:00",
                            "cycle_completed_at": "2026-04-27T07:01:00+00:00",
                            "domains_processed": 3, "errors_count": 0},
    }
    with patch("heartbeat._latest_heartbeats", return_value=sample) as mock_batch, \
         patch("heartbeat._latest_heartbeat") as mock_single:
        report = heartbeat.heartbeat_status()

    # Exactly one batched call, NO single-row calls
    assert mock_batch.call_count == 1
    assert mock_single.call_count == 0
    assert set(report["cycles"].keys()) == {"monitor", "postmaster_sync", "snds_sync"}


def test_heartbeat_status_unknown_when_batch_empty():
    """If the batched fetch returns nothing (DB down or no rows), every
    cycle must report status=unknown — the watchdog tolerates this for one
    tick before it would escalate."""
    with patch("heartbeat._latest_heartbeats", return_value={}):
        report = heartbeat.heartbeat_status()
    for cycle in report["cycles"].values():
        assert cycle["status"] == "unknown"
    assert report["overall_status"] == "unknown"


# ─── record_start / record_end use logger.exception ─────────────────

def test_record_start_emits_stacktrace_on_persistent_failure(caplog):
    """logger.exception adds exc_info so Sentry receives a stacktrace.
    Previously str(e)[:200] in extra didn't reach Sentry's tag/context
    (INBOX-87 — that was why the error was un-debuggable)."""
    fake_chain = MagicMock()
    fake_chain.execute.side_effect = RuntimeError("connection reset")
    fake_chain.insert.return_value = fake_chain
    fake_sb = MagicMock()
    fake_sb.table.return_value = fake_chain

    with caplog.at_level(logging.ERROR, logger="inboxscore.heartbeat"):
        with patch("db.get_supabase", return_value=fake_sb):
            result = heartbeat.record_start("monitor")

    assert result is None
    # Find the start_failed record
    rec = next((r for r in caplog.records if r.name == "inboxscore.heartbeat"
                and "start_failed" in r.message), None)
    assert rec is not None, "Expected a start_failed log record"
    assert rec.exc_info is not None, (
        "record_start must use logger.exception so Sentry gets a "
        "stacktrace (INBOX-87)."
    )
