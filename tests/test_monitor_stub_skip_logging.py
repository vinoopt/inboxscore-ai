"""
INBOX-258 regression — silent stub-skip is now visible in Sentry.

Background
----------
2026-05-13 → 2026-05-15: Vinoop's brand-new Stripe subscription got stuck
in a partial state because the pre-fix ``checkout.session.completed``
handler only logged (didn't upsert). ``get_user_plan()`` resolved to
``"stub"`` for ~44h. ``run_monitoring_cycle`` (INBOX-210) silently skipped
every one of his monitored domains for every 15-min tick over those 44h —
no exception, no Sentry event, just a counter and a print().

The Dashboard's Score Trend chart eventually surfaced this as a missing
day (Thu 2026-05-14 = "—" for all domains). That's a fragile last line
of defence; we should not depend on Vinoop noticing a chart gap to
discover that monitoring is broken for a real user.

Fix
---
``run_monitoring_cycle`` now emits ``logger.warning("monitor.skip_stub",
extra={domain, domain_id, user_id_prefix, resolved_plan})`` for every
domain it skips. Sentry's LoggingIntegration (configured in app.py via
``sentry_sdk.init()``) auto-captures WARNING-level log records as events,
so each cycle that skips a user creates a Sentry signal.

What this test locks in
-----------------------
* The skip emits at WARNING level (not INFO — has to clear Sentry's
  default cutoff).
* The log record carries the structured fields Sentry needs to group
  by user / domain.
* The skip path still ``continue``s — i.e., we don't accidentally drop
  through and try to scan a stub user.
"""

import logging
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class TestMonitorStubSkipLogging:
    def test_stub_user_skip_emits_warning_with_structured_context(self, caplog):
        """A monitored domain owned by a ``stub``-plan user must:
          1. NOT be scanned (monitor_single_domain not called).
          2. Emit a WARNING via ``logger.warning('monitor.skip_stub', …)``
             with the user_id_prefix + domain + resolved_plan attached.
        """
        import monitor

        domain_data = {
            "id": "domain-uuid-stub-1",
            "domain": "stuck-sub.example.com",
            "user_id": "5bef1f36-8ccf-4c1a-8fa7-cbbcbb53135b",
            "latest_score": 91,
        }

        with patch("monitor.is_db_available", return_value=True), \
             patch("monitor.get_domains_due_for_scan",
                   return_value=[domain_data]), \
             patch("db.get_user_plan", return_value="stub"), \
             patch("monitor.monitor_single_domain") as mock_scan, \
             patch("monitor.time.sleep"), \
             patch("heartbeat.record_start", return_value=None), \
             patch("heartbeat.record_end"):

            with caplog.at_level(logging.WARNING, logger="monitor"):
                monitor.run_monitoring_cycle()

        # 1. The domain must NOT have been scanned.
        mock_scan.assert_not_called()

        # 2. A monitor.skip_stub WARNING must be present with full extras.
        skip_records = [
            r for r in caplog.records
            if r.levelno == logging.WARNING
            and "monitor.skip_stub" in r.getMessage()
        ]
        assert skip_records, (
            "INBOX-258 regression: stub-plan skip must emit "
            "logger.warning('monitor.skip_stub', extra={...}) so Sentry's "
            "LoggingIntegration ships an event. Previously the skip was "
            "silent (counter + print only) and the team didn't notice for "
            "~44 hours."
        )
        rec = skip_records[-1]

        # Structured context — Sentry needs these to group by user/domain.
        assert getattr(rec, "domain", None) == "stuck-sub.example.com", (
            "extra={'domain': ...} missing on the skip warning"
        )
        assert getattr(rec, "domain_id", None) == "domain-uuid-stub-1", (
            "extra={'domain_id': ...} missing on the skip warning"
        )
        # user_id_prefix is the first 8 chars only — never log full UUIDs.
        assert getattr(rec, "user_id_prefix", None) == "5bef1f36", (
            "extra={'user_id_prefix': ...} must be set so we can correlate "
            "without leaking full user_ids into Sentry."
        )
        assert getattr(rec, "resolved_plan", None) == "stub", (
            "extra={'resolved_plan': ...} must be set so future debugging "
            "can distinguish stub-skip from other future skip reasons."
        )

    def test_pro_user_does_not_trigger_skip_warning(self, caplog):
        """A pro-plan user's domain must NOT emit monitor.skip_stub.
        This guards against an accidental inversion of the condition
        that would silently drop legitimate monitoring."""
        import monitor

        domain_data = {
            "id": "domain-uuid-pro-1",
            "domain": "healthy.example.com",
            "user_id": "11111111-1111-1111-1111-111111111111",
            "latest_score": 88,
        }

        with patch("monitor.is_db_available", return_value=True), \
             patch("monitor.get_domains_due_for_scan",
                   return_value=[domain_data]), \
             patch("db.get_user_plan", return_value="pro"), \
             patch("monitor.monitor_single_domain") as mock_scan, \
             patch("monitor.time.sleep"), \
             patch("heartbeat.record_start", return_value=None), \
             patch("heartbeat.record_end"):

            with caplog.at_level(logging.WARNING, logger="monitor"):
                monitor.run_monitoring_cycle()

        # Pro user MUST be scanned.
        mock_scan.assert_called_once_with(domain_data)

        # NO skip_stub warning for healthy users.
        skip_records = [
            r for r in caplog.records
            if "monitor.skip_stub" in r.getMessage()
        ]
        assert not skip_records, (
            "INBOX-258 inversion guard: monitor.skip_stub fired for a "
            "pro-plan user. The condition `if plan == 'stub'` must not "
            "be flipped or widened."
        )
