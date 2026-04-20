"""
Tests for scan_service — the unified scan orchestrator (INBOX-21).

These tests assert the contract that both `app.py::_run_scan` and
`monitor.py::monitor_single_domain` now depend on:
- 13 checks are always submitted (including `check_ip_reputation`)
- score is capped at 100
- the returned dict shape matches what `save_scan` + the frontend expect
- a single crashing check does not kill the whole scan (safe_result wrapper)
"""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from checks import CheckResult  # noqa: E402
from scan_service import _safe_result, generate_summary, run_full_scan  # noqa: E402


def _cr(name: str, points: int, max_points: int, status: str = "pass",
        category: str = "infrastructure", title: str = "x") -> CheckResult:
    return CheckResult(
        name=name, category=category, status=status, title=title,
        detail="ok", points=points, max_points=max_points,
    )


# Map each check name → its _cr(...) output so we can patch all 13 at once.
_FAKE_CHECKS = {
    "check_mx_records":       _cr("mx_records", 5, 5, category="infrastructure"),
    "check_spf":              _cr("spf", 15, 15, category="authentication"),
    "check_dkim":             _cr("dkim", 15, 15, category="authentication"),
    "check_dmarc":            _cr("dmarc", 15, 15, category="authentication"),
    "check_blacklists":       _cr("blacklists", 10, 10, category="reputation"),
    "check_tls":              _cr("tls", 5, 5, category="infrastructure"),
    "check_reverse_dns":      _cr("reverse_dns", 5, 5, category="infrastructure"),
    "check_bimi":             _cr("bimi", 5, 5, category="authentication"),
    "check_mta_sts":          _cr("mta_sts", 5, 5, category="infrastructure"),
    "check_tls_rpt":          _cr("tls_rpt", 5, 5, category="infrastructure"),
    "check_sender_detection": _cr("sender_detection", 5, 5, category="infrastructure"),
    "check_domain_age":       _cr("domain_age", 5, 5, category="reputation"),
    "check_ip_reputation":    _cr("ip_reputation", 10, 10, category="reputation"),
}


def _patch_all_checks(**overrides):
    """Patch every scan_service.check_* symbol with a stub returning the given CheckResult."""
    patchers = []
    for name, default in _FAKE_CHECKS.items():
        result = overrides.get(name, default)
        patchers.append(patch(f"scan_service.{name}", return_value=result))
    return patchers


class TestRunFullScan:
    def test_submits_thirteen_checks_including_ip_reputation(self):
        """INBOX-3 regression: monitor path used to be missing ip_reputation."""
        patchers = _patch_all_checks()
        for p in patchers:
            p.start()
        try:
            out = run_full_scan("example.com", source="monitor")
        finally:
            for p in patchers:
                p.stop()

        assert len(out["checks"]) == 13
        names = [c["name"] for c in out["checks"]]
        assert "ip_reputation" in names, "monitor/api must run IP reputation — INBOX-3"
        # Sanity: every expected check is present exactly once
        assert sorted(names) == sorted([
            "mx_records", "spf", "dkim", "dmarc", "blacklists", "tls",
            "reverse_dns", "bimi", "mta_sts", "tls_rpt", "sender_detection",
            "domain_age", "ip_reputation",
        ])

    def test_score_is_capped_at_100(self):
        """All checks max-out → raw ratio could round above 100; result must cap."""
        patchers = _patch_all_checks()
        for p in patchers:
            p.start()
        try:
            out = run_full_scan("perfect.com")
        finally:
            for p in patchers:
                p.stop()

        assert out["score"] == 100
        assert out["score"] <= 100  # invariant — never uncapped

    def test_result_shape_matches_save_contract(self):
        """Keys consumed by save_scan + frontend must be present."""
        patchers = _patch_all_checks()
        for p in patchers:
            p.start()
        try:
            out = run_full_scan("shape.com")
        finally:
            for p in patchers:
                p.stop()

        for key in ("domain", "score", "summary", "checks", "scan_time", "scanned_at"):
            assert key in out, f"missing key: {key}"
        assert out["domain"] == "shape.com"
        assert isinstance(out["checks"], list)
        assert isinstance(out["summary"], dict)
        assert "verdict" in out["summary"]
        assert "stats" in out["summary"]

    def test_zero_max_points_yields_zero_score_not_divzero(self):
        """If every check returns max_points=0, the scan must not crash."""
        zero_check = _cr("zero", 0, 0)
        overrides = {name: zero_check for name in _FAKE_CHECKS}
        patchers = _patch_all_checks(**overrides)
        for p in patchers:
            p.start()
        try:
            out = run_full_scan("empty.com")
        finally:
            for p in patchers:
                p.stop()

        assert out["score"] == 0


class TestSafeResult:
    def test_timeout_returns_warn_zero(self):
        class _FakeFuture:
            def result(self, timeout):
                raise TimeoutError("slow")

        got = _safe_result(_FakeFuture(), "x", "X", "reputation", 1, "ex.com")
        assert got.status == "warn"
        assert got.points == 0
        assert got.max_points == 0
        assert got.name == "x"
        assert got.category == "reputation"

    def test_crash_returns_warn_zero(self):
        class _FakeFuture:
            def result(self, timeout):
                raise RuntimeError("boom")

        got = _safe_result(_FakeFuture(), "x", "X", "reputation", 1, "ex.com")
        assert got.status == "warn"
        assert got.points == 0


class TestGenerateSummary:
    def _checks(self, statuses):
        return [_cr(f"c{i}", 1, 1, status=s) for i, s in enumerate(statuses)]

    def test_excellent_when_score_gte_85(self):
        out = generate_summary("d", 95, self._checks(["pass"] * 10))
        assert out["verdict"] == "Excellent"
        assert out["color"] == "good"

    def test_critical_when_score_lt_40(self):
        out = generate_summary("d", 20, self._checks(["fail"] * 5))
        assert out["verdict"] == "Critical Issues"
        assert out["color"] == "danger"

    def test_stats_count_correctly(self):
        out = generate_summary("d", 70, self._checks(["pass", "pass", "warn", "fail"]))
        assert out["stats"]["passed"] == 2
        assert out["stats"]["warnings"] == 1
        assert out["stats"]["failed"] == 1
