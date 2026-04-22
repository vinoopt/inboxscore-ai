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
from scan_service import (  # noqa: E402
    CANONICAL_MAX_POINTS,
    _safe_result,
    generate_summary,
    run_full_scan,
)


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
    def test_timeout_returns_warn_unknown_name_defaults_to_zero(self):
        class _FakeFuture:
            def result(self, timeout):
                raise TimeoutError("slow")

        # "x" is not in CANONICAL_MAX_POINTS → defaults to 0 (safe fallback).
        got = _safe_result(_FakeFuture(), "x", "X", "reputation", 1, "ex.com")
        assert got.status == "warn"
        assert got.points == 0
        assert got.max_points == 0
        assert got.name == "x"
        assert got.category == "reputation"

    def test_crash_unknown_name_defaults_to_zero(self):
        class _FakeFuture:
            def result(self, timeout):
                raise RuntimeError("boom")

        got = _safe_result(_FakeFuture(), "x", "X", "reputation", 1, "ex.com")
        assert got.status == "warn"
        assert got.points == 0
        assert got.max_points == 0

    def test_crashed_scoring_check_preserves_canonical_max_points(self):
        """INBOX-23: a crashed scoring check must keep its canonical max_points
        so the scan denominator stays honest. Previously this silently returned
        0 and inflated the user's score whenever a scanner had an outage."""
        class _FakeFuture:
            def result(self, timeout):
                raise TimeoutError("blacklist service down")

        got = _safe_result(_FakeFuture(), "blacklists", "Blacklist Check",
                           "reputation", 12, "ex.com")
        assert got.status == "warn"
        assert got.points == 0
        assert got.max_points == 15, (
            "crashed scoring check must return canonical max_points (INBOX-23); "
            "got 0 means the denominator bug is back"
        )

    def test_crashed_informational_check_stays_at_zero(self):
        """INBOX-23 guard: informational-only checks (bimi, mta_sts, tls_rpt,
        sender_detection) legitimately have max_points=0 — they must NOT be
        pushed into the denominator just because they crashed."""
        class _FakeFuture:
            def result(self, timeout):
                raise RuntimeError("bimi lookup failed")

        for name in ("bimi", "mta_sts", "tls_rpt", "sender_detection"):
            got = _safe_result(_FakeFuture(), name, name.upper(),
                               "infrastructure", 8, "ex.com")
            assert got.max_points == 0, (
                f"informational check '{name}' must stay at max_points=0 "
                "even when crashed (INBOX-23 nuance)"
            )


class TestDenominatorCorrectness:
    """INBOX-23 regression suite. A crashed scoring check must REDUCE the
    user's score, not inflate it. Bug was: crashed check returned
    max_points=0, which dropped out of the `if c.max_points > 0` filter,
    shrinking the denominator and giving the user a 'better' score than
    reality."""

    def test_crashed_scoring_check_deflates_score_not_inflates(self):
        """12 checks perfect + blacklists crash → denominator 96, score 84.
        Pre-fix behaviour would have been denominator 81, score 100."""
        # All checks max-out EXCEPT blacklists, which we'll crash via a
        # RuntimeError. The full-scan code path wraps raw check_* calls in
        # _safe_result, so a raising stub triggers the crash branch.
        overrides = {}
        for name, default in _FAKE_CHECKS.items():
            if name == "check_blacklists":
                continue  # handled below
            overrides[name] = default

        # Re-mirror _FAKE_CHECKS but with canonical max_points so the math
        # is deterministic. mx=10, spf=15, dkim=15, dmarc=15, tls=10,
        # reverse_dns=5, domain_age=3, ip_reputation=8 (informational = 0).
        overrides["check_mx_records"]       = _cr("mx_records", 10, 10)
        overrides["check_spf"]              = _cr("spf", 15, 15, category="authentication")
        overrides["check_dkim"]             = _cr("dkim", 15, 15, category="authentication")
        overrides["check_dmarc"]            = _cr("dmarc", 15, 15, category="authentication")
        overrides["check_tls"]              = _cr("tls", 10, 10)
        overrides["check_reverse_dns"]      = _cr("reverse_dns", 5, 5)
        overrides["check_domain_age"]       = _cr("domain_age", 3, 3, category="reputation")
        overrides["check_ip_reputation"]    = _cr("ip_reputation", 8, 8, category="reputation")
        overrides["check_bimi"]             = _cr("bimi", 0, 0, category="authentication")
        overrides["check_mta_sts"]          = _cr("mta_sts", 0, 0)
        overrides["check_tls_rpt"]          = _cr("tls_rpt", 0, 0)
        overrides["check_sender_detection"] = _cr("sender_detection", 0, 0)

        patchers = []
        for name, result in overrides.items():
            patchers.append(patch(f"scan_service.{name}", return_value=result))
        # Crash blacklists: side_effect raises when the ThreadPoolExecutor
        # calls it, which _safe_result catches.
        patchers.append(patch("scan_service.check_blacklists",
                              side_effect=RuntimeError("blacklist service down")))

        for p in patchers:
            p.start()
        try:
            out = run_full_scan("crash-test.com")
        finally:
            for p in patchers:
                p.stop()

        # Points: 10+15+15+15+0(crashed)+10+5+3+8 = 81
        # Denominator (post-fix): 96 (all 9 scoring checks, including crashed blacklists at 15)
        # Expected score: round(81 / 96 * 100) = 84
        assert out["score"] == 84, (
            f"crashed blacklists should deflate score to 84/100, got {out['score']}. "
            "If this is 100, the INBOX-23 denominator bug is back."
        )

        # Sanity: blacklists should still appear in the checks list with
        # max_points=15 (not dropped out).
        blk = next(c for c in out["checks"] if c["name"] == "blacklists")
        assert blk["status"] == "warn"
        assert blk["max_points"] == 15

    def test_canonical_max_points_covers_every_check(self):
        """Guard against drift: every check run by run_full_scan must have
        a canonical max_points entry. Prevents a new check being added in
        checks.py without also being registered for the crash path."""
        patchers = _patch_all_checks()
        for p in patchers:
            p.start()
        try:
            out = run_full_scan("drift-guard.com")
        finally:
            for p in patchers:
                p.stop()

        for c in out["checks"]:
            assert c["name"] in CANONICAL_MAX_POINTS, (
                f"check '{c['name']}' has no entry in CANONICAL_MAX_POINTS — "
                "if this check can crash, its max_points will silently drop to 0 "
                "and inflate users' scores (INBOX-23)"
            )


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
