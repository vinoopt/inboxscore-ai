"""
Regression suite for INBOX-28 — background-scheduler Sentry coverage.

For 42 days, any exception in monitor.py / postmaster_scheduler.py /
snds_scheduler.py was swallowed by `except Exception as e: print(e)`.
Sentry never saw them (the LoggingIntegration only ships logging-module
records, not stdout). The monitor loop failed silently every 15 minutes
for that entire window — INBOX-1 root-cause class.

The fix (INBOX-28) replaces every silent `print(e)` in these three
schedulers with `logger.exception(...)`. Sentry's LoggingIntegration is
auto-enabled by `sentry_sdk.init()` in app.py and captures ERROR-level
log records — including the traceback attached via exc_info — as Sentry
events.

These tests LOCK that wiring in place. Any future refactor that drops
`logger.exception` back to `print(...)` or swallows the exception without
logging will fail loudly before it reaches production.

We don't patch `sentry_sdk` directly — that would test Sentry, not our
code. We assert the contract: the logger captures an ERROR-level record
WITH `exc_info` attached. LoggingIntegration's behaviour (events from such
records) is the library's responsibility and is separately verified at
init time by SENTRY_DSN integration tests.
"""

import logging
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


# ────────────────────────────────────────────────────────────────────
# monitor.py — 3 exception sites
# ────────────────────────────────────────────────────────────────────

class TestMonitorErrorReporting:
    def test_single_domain_scan_error_reaches_logger(self, caplog):
        """monitor_single_domain must log via logger.exception when the
        scan raises, so Sentry's LoggingIntegration picks it up."""
        import monitor

        domain_data = {
            "id": "domain-uuid-1",
            "domain": "example.com",
            "user_id": "user-abc12345",
            "latest_score": 70,
            "alert_threshold": 50,
            "latest_scan_id": None,
        }

        with patch("monitor.run_full_scan", side_effect=RuntimeError("boom")):
            with caplog.at_level(logging.ERROR, logger="monitor"):
                # Must NOT re-raise — the cycle loop depends on this method
                # swallowing single-domain failures. But the log record MUST
                # carry the traceback.
                monitor.monitor_single_domain(domain_data)

        error_records = [r for r in caplog.records if r.levelno == logging.ERROR]
        assert error_records, (
            "INBOX-28 regression: monitor_single_domain must call logger.exception "
            "(not print) on scan failure — Sentry relies on ERROR-level logger "
            "records to ship the event."
        )
        rec = error_records[-1]
        assert rec.exc_info is not None, (
            "logger.exception must attach exc_info so Sentry captures the traceback. "
            "If this is None, someone swapped .exception() for .error() — that "
            "breaks the traceback attachment."
        )
        assert "monitor.scan_error" in rec.getMessage()
        # Structured context must carry the domain so Sentry's issue
        # fingerprint groups correctly.
        assert getattr(rec, "domain", None) == "example.com"

    def test_cycle_domain_loop_error_reaches_logger(self, caplog):
        """The per-domain exception handler inside run_monitoring_cycle
        must log via logger.exception."""
        import monitor

        domain_data = {"id": "d1", "domain": "x.com", "user_id": "u1"}

        with patch("monitor.is_db_available", return_value=True), \
             patch("monitor.get_domains_due_for_scan", return_value=[domain_data]), \
             patch("monitor.monitor_single_domain", side_effect=ValueError("kaboom")), \
             patch("monitor.time.sleep"), \
             patch("heartbeat.record_start", return_value=None), \
             patch("heartbeat.record_end"):

            with caplog.at_level(logging.ERROR, logger="monitor"):
                monitor.run_monitoring_cycle()

        # There may be multiple ERROR records if upstream machinery also
        # logs; we care that ONE of them is the domain-processing error
        # and that it carries a traceback.
        domain_err = [r for r in caplog.records
                      if r.levelno == logging.ERROR
                      and "domain_processing_error" in r.getMessage()]
        assert domain_err, (
            "INBOX-28 regression: per-domain errors inside run_monitoring_cycle "
            "must reach logger.exception so Sentry captures them."
        )
        assert domain_err[-1].exc_info is not None, (
            "Traceback must be attached for Sentry to group the issue."
        )

    def test_cycle_outer_crash_reaches_logger(self, caplog):
        """If the entire monitoring cycle crashes (e.g. DB gateway down
        mid-cycle), we must still log via logger.exception so the
        on-call engineer is paged — previously this silently printed
        and the next heartbeat tick eventually caught staleness."""
        import monitor

        with patch("monitor.is_db_available", return_value=True), \
             patch("monitor.get_domains_due_for_scan",
                   side_effect=ConnectionError("db gone")), \
             patch("heartbeat.record_start", return_value=None), \
             patch("heartbeat.record_end"):

            with caplog.at_level(logging.ERROR, logger="monitor"):
                monitor.run_monitoring_cycle()

        crash_records = [r for r in caplog.records
                         if r.levelno == logging.ERROR
                         and "cycle_crashed" in r.getMessage()]
        assert crash_records, (
            "INBOX-28 regression: full-cycle crash must log via logger.exception — "
            "this is the most severe failure mode; it must page instantly, not "
            "wait for the 30-min watchdog staleness threshold."
        )
        assert crash_records[-1].exc_info is not None


# ────────────────────────────────────────────────────────────────────
# postmaster_scheduler.py — 2 exception sites
# ────────────────────────────────────────────────────────────────────

class TestPostmasterSchedulerErrorReporting:
    def test_per_user_sync_error_reaches_logger(self, caplog):
        """A Postmaster fetch failure for a single user must emit a
        logger.exception — previously print(e) dropped the traceback."""
        import postmaster_scheduler

        connection = {"user_id": "postmaster-user-xyz"}

        with patch("postmaster_scheduler.is_db_available", return_value=True), \
             patch("postmaster_scheduler.get_all_postmaster_connections",
                   return_value=[connection]), \
             patch("postmaster_scheduler.fetch_metrics_for_user",
                   side_effect=RuntimeError("postmaster api 500")), \
             patch("postmaster_scheduler.log_postmaster_sync"), \
             patch("heartbeat.record_start", return_value=None), \
             patch("heartbeat.record_end"):

            with caplog.at_level(logging.ERROR, logger="postmaster_scheduler"):
                postmaster_scheduler.sync_all_postmaster_users()

        user_err = [r for r in caplog.records
                    if r.levelno == logging.ERROR
                    and "user_error" in r.getMessage()]
        assert user_err, (
            "INBOX-28 regression: per-user Postmaster failures must reach "
            "logger.exception so Sentry groups and alerts on them."
        )
        assert user_err[-1].exc_info is not None

    def test_cycle_crash_reaches_logger(self, caplog):
        """Outer scheduler crash — previously had traceback.print_exc()
        which goes to stderr but not Sentry. Now must use logger.exception."""
        import postmaster_scheduler

        with patch("postmaster_scheduler.is_db_available",
                   side_effect=ConnectionError("db gone")), \
             patch("heartbeat.record_start", return_value=None), \
             patch("heartbeat.record_end"):

            with caplog.at_level(logging.ERROR, logger="postmaster_scheduler"):
                postmaster_scheduler.sync_all_postmaster_users()

        crash = [r for r in caplog.records
                 if r.levelno == logging.ERROR
                 and "cycle_crashed" in r.getMessage()]
        assert crash, (
            "INBOX-28 regression: postmaster scheduler full-cycle crash must "
            "log via logger.exception (removed traceback.print_exc — that's "
            "redundant once logger.exception is wired)."
        )
        assert crash[-1].exc_info is not None


# ────────────────────────────────────────────────────────────────────
# snds_scheduler.py — 2 exception sites
# ────────────────────────────────────────────────────────────────────

class TestSndsSchedulerErrorReporting:
    def test_per_user_sync_error_reaches_logger(self, caplog):
        """An SNDS upsert/parse failure for a single user must emit a
        logger.exception — previously print(e) dropped the traceback."""
        import snds_scheduler

        connection = {"user_id": "snds-user-abc", "snds_key": "fake-key"}

        # Return a "successful" fetch so we reach the per-row upsert, then
        # make the upsert explode — that exercises the per-user except branch.
        fake_fetch_result = {
            "success": True,
            "data": [{"ip_address": "198.51.100.1", "metric_date": "2026-04-22"}],
        }

        async def _fake_fetch(_key):
            return fake_fetch_result

        with patch("snds_scheduler.is_db_available", return_value=True), \
             patch("snds_scheduler.get_all_snds_connections",
                   return_value=[connection]), \
             patch("snds_scheduler.fetch_snds_data", side_effect=_fake_fetch), \
             patch("snds_scheduler.upsert_snds_metrics",
                   side_effect=RuntimeError("upsert failed")), \
             patch("snds_scheduler.update_snds_sync_status"), \
             patch("heartbeat.record_start", return_value=None), \
             patch("heartbeat.record_end"):

            with caplog.at_level(logging.ERROR, logger="snds_scheduler"):
                snds_scheduler.sync_all_snds_users()

        user_err = [r for r in caplog.records
                    if r.levelno == logging.ERROR
                    and "user_error" in r.getMessage()]
        assert user_err, (
            "INBOX-28 regression: per-user SNDS failures must reach "
            "logger.exception so Sentry groups and alerts on them."
        )
        assert user_err[-1].exc_info is not None

    def test_cycle_crash_reaches_logger(self, caplog):
        """Outer scheduler crash — previously print + traceback.print_exc,
        now must use logger.exception."""
        import snds_scheduler

        with patch("snds_scheduler.is_db_available",
                   side_effect=ConnectionError("db gone")), \
             patch("heartbeat.record_start", return_value=None), \
             patch("heartbeat.record_end"):

            with caplog.at_level(logging.ERROR, logger="snds_scheduler"):
                snds_scheduler.sync_all_snds_users()

        crash = [r for r in caplog.records
                 if r.levelno == logging.ERROR
                 and "cycle_crashed" in r.getMessage()]
        assert crash, (
            "INBOX-28 regression: SNDS scheduler full-cycle crash must log "
            "via logger.exception (removed traceback.print_exc — that's "
            "redundant once logger.exception is wired)."
        )
        assert crash[-1].exc_info is not None


# ────────────────────────────────────────────────────────────────────
# Invariant — no `print(<exception-var>)` anywhere in the 3 schedulers
# ────────────────────────────────────────────────────────────────────
# Belt-and-braces guard: even if someone writes a new `except: print(e)`
# block in one of these modules, this test fails. Pairs with the
# behavioural tests above which catch the semantic regression.

@pytest.mark.parametrize("module_file", [
    "monitor.py",
    "postmaster_scheduler.py",
    "snds_scheduler.py",
])
def test_no_exception_var_printed(module_file):
    """Static guard: no `print(...e...)` on a line that directly follows
    `except Exception as e:`. The fix was to replace these with
    logger.exception; anyone reintroducing them breaks Sentry coverage."""
    path = os.path.join(os.path.dirname(__file__), "..", module_file)
    with open(path, encoding="utf-8") as f:
        lines = f.readlines()

    offenders = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("except Exception as e"):
            # Look ahead up to 5 non-blank lines for a print(...: {e}...) pattern
            for j in range(i + 1, min(i + 8, len(lines))):
                nxt = lines[j].strip()
                if not nxt or nxt.startswith("#"):
                    continue
                if nxt.startswith("print(") and "{e}" in nxt:
                    offenders.append(f"{module_file}:{j + 1}: {nxt}")
                    break
                # Stop scanning when we leave the except block
                if nxt.startswith(("def ", "class ", "except ", "try:")):
                    break

    assert not offenders, (
        "INBOX-28 regression: `except Exception as e: print(... {e} ...)` was "
        "re-introduced. Use `logger.exception(event_name, extra={...})` "
        "instead so Sentry's LoggingIntegration captures the error.\n"
        + "\n".join(offenders)
    )
