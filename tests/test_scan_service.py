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


# Map each check name → its _cr(...) output so we can patch all 14 at once.
# INBOX-42 added check_domain_blacklists (14th check).
_FAKE_CHECKS = {
    "check_mx_records":         _cr("mx_records", 5, 5, category="infrastructure"),
    "check_spf":                _cr("spf", 15, 15, category="authentication"),
    "check_dkim":               _cr("dkim", 15, 15, category="authentication"),
    "check_dmarc":              _cr("dmarc", 15, 15, category="authentication"),
    "check_blacklists":         _cr("blacklists", 10, 10, category="reputation"),
    "check_domain_blacklists":  _cr("domain_blacklists", 10, 10, category="reputation"),
    "check_tls":                _cr("tls", 5, 5, category="infrastructure"),
    "check_reverse_dns":        _cr("reverse_dns", 5, 5, category="infrastructure"),
    "check_bimi":               _cr("bimi", 5, 5, category="authentication"),
    "check_mta_sts":            _cr("mta_sts", 5, 5, category="infrastructure"),
    "check_tls_rpt":            _cr("tls_rpt", 5, 5, category="infrastructure"),
    "check_sender_detection":   _cr("sender_detection", 5, 5, category="infrastructure"),
    "check_domain_age":         _cr("domain_age", 5, 5, category="reputation"),
    "check_ip_reputation":      _cr("ip_reputation", 10, 10, category="reputation"),
    "check_google_safe_browsing": _cr("google_safe_browsing", 2, 2, category="reputation"),  # INBOX-95
}


def _patch_all_checks(**overrides):
    """Patch every scan_service.check_* symbol with a stub returning the given CheckResult."""
    patchers = []
    for name, default in _FAKE_CHECKS.items():
        result = overrides.get(name, default)
        patchers.append(patch(f"scan_service.{name}", return_value=result))
    return patchers


class TestRunFullScan:
    def test_submits_all_checks_including_ip_reputation(self):
        """INBOX-3 regression: monitor path used to be missing ip_reputation.
        Also guards the canonical check-name set — if a check is added to
        scan_service without being registered here, this test fails."""
        patchers = _patch_all_checks()
        for p in patchers:
            p.start()
        try:
            out = run_full_scan("example.com", source="monitor")
        finally:
            for p in patchers:
                p.stop()

        # 15 checks as of INBOX-95 (google_safe_browsing added).
        assert len(out["checks"]) == 15
        names = [c["name"] for c in out["checks"]]
        assert "ip_reputation" in names, "monitor/api must run IP reputation — INBOX-3"
        assert "domain_blacklists" in names, "monitor/api must run domain-blacklists — INBOX-42"
        assert "google_safe_browsing" in names, "monitor/api must run GSB — INBOX-95"
        # Sanity: every expected check is present exactly once
        assert sorted(names) == sorted([
            "mx_records", "spf", "dkim", "dmarc", "blacklists",
            "domain_blacklists", "tls",
            "reverse_dns", "bimi", "mta_sts", "tls_rpt", "sender_detection",
            "domain_age", "ip_reputation", "google_safe_browsing",
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


class TestDepthSelector:
    """INBOX-199: depth='public' skips the IP-level checks (check_blacklists
    + check_ip_reputation) so anonymous marketing scans don't try to assess
    IPs we cannot accurately attribute to the user. depth='full' keeps every
    check (the path used by logged-in scans + the monitor cycle)."""

    def test_default_depth_is_full(self):
        """No depth arg → 15 checks (current behaviour preserved)."""
        patchers = _patch_all_checks()
        for p in patchers:
            p.start()
        try:
            out = run_full_scan("example.com")
        finally:
            for p in patchers:
                p.stop()

        assert len(out["checks"]) == 15
        names = {c["name"] for c in out["checks"]}
        assert "blacklists" in names
        assert "ip_reputation" in names
        assert out["depth"] == "full"

    def test_public_depth_omits_ip_level_checks(self):
        """depth='public' must return 13 checks — no blacklists, no ip_reputation."""
        patchers = _patch_all_checks()
        for p in patchers:
            p.start()
        try:
            out = run_full_scan("anon.example", depth="public")
        finally:
            for p in patchers:
                p.stop()

        assert len(out["checks"]) == 13
        names = {c["name"] for c in out["checks"]}
        assert "blacklists" not in names, (
            "INBOX-199: anonymous scan must NOT include IP-based blacklist "
            "check — SPF-derived IPs are mostly shared ESP space and would "
            "show misleading 'your IP is blacklisted' results."
        )
        assert "ip_reputation" not in names, (
            "INBOX-199: same reason — IP reputation needs IPs we can't "
            "accurately attribute to an anonymous user."
        )
        # Domain-level checks MUST still be present.
        assert "domain_blacklists" in names
        assert "spf" in names
        assert "dmarc" in names
        assert out["depth"] == "public"

    def test_public_depth_does_not_call_skipped_check_functions(self):
        """Stronger guarantee: the skipped functions must not be called at
        all on the public path. This protects against accidentally burning
        HetrixTools credits or doing extra DNS work for anonymous scans."""
        patchers = _patch_all_checks()
        for p in patchers:
            p.start()

        # Spy on the two skipped functions to make sure they are NOT called.
        from unittest.mock import patch as _patch
        with _patch("scan_service.check_blacklists") as spy_bl, \
             _patch("scan_service.check_ip_reputation") as spy_ip:
            try:
                run_full_scan("anon.example", depth="public")
            finally:
                for p in patchers:
                    p.stop()

            spy_bl.assert_not_called()
            spy_ip.assert_not_called()

    def test_public_depth_score_is_meaningful(self):
        """With 13 perfect checks (no blacklists/ip_rep), score still maxes
        at 100. The denominator drops along with the numerator so the
        percentage stays honest."""
        patchers = _patch_all_checks()
        for p in patchers:
            p.start()
        try:
            out = run_full_scan("perfect.example", depth="public")
        finally:
            for p in patchers:
                p.stop()

        assert out["score"] == 100, (
            "public depth with all checks max-out must still score 100"
        )

    def test_full_depth_produces_same_checks_as_pre_inbox_199(self):
        """Behavioural lock: depth='full' (explicit) is byte-for-byte the
        same set of checks as the pre-INBOX-199 default."""
        patchers = _patch_all_checks()
        for p in patchers:
            p.start()
        try:
            out = run_full_scan("full.example", depth="full")
        finally:
            for p in patchers:
                p.stop()

        names = sorted(c["name"] for c in out["checks"])
        assert names == sorted([
            "mx_records", "spf", "dkim", "dmarc", "blacklists",
            "domain_blacklists", "tls", "reverse_dns", "bimi",
            "mta_sts", "tls_rpt", "sender_detection", "domain_age",
            "ip_reputation", "google_safe_browsing",
        ])


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
        """INBOX-23 guard: informational-only checks (bimi, sender_detection)
        legitimately have max_points=0 — they must NOT be pushed into the
        denominator just because they crashed.

        INBOX-70 (2026-04-26): mta_sts and tls_rpt are no longer info-only
        (now scored at 5 and 3 respectively), so they're tested under the
        scoring-check guard at TestDenominatorCorrectness instead."""
        class _FakeFuture:
            def result(self, timeout):
                raise RuntimeError("bimi lookup failed")

        for name in ("bimi", "sender_detection"):
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
        """All scoring checks perfect EXCEPT blacklists (crashed) → denominator
        stays at its canonical 106 (INBOX-42 added domain_blacklists at 10),
        score = round(91/106*100) = 86. Pre-INBOX-23 the crashed blacklists
        check would have silently dropped out of the denominator and the
        score would have been 100."""
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
        # reverse_dns=5, domain_age=3, ip_reputation=8,
        # domain_blacklists=10 (INBOX-42). Informational = 0.
        overrides["check_mx_records"]        = _cr("mx_records", 10, 10)
        overrides["check_spf"]               = _cr("spf", 15, 15, category="authentication")
        overrides["check_dkim"]              = _cr("dkim", 15, 15, category="authentication")
        overrides["check_dmarc"]             = _cr("dmarc", 15, 15, category="authentication")
        overrides["check_domain_blacklists"] = _cr("domain_blacklists", 10, 10, category="reputation")
        overrides["check_tls"]               = _cr("tls", 10, 10)
        overrides["check_reverse_dns"]       = _cr("reverse_dns", 5, 5)
        overrides["check_domain_age"]        = _cr("domain_age", 3, 3, category="reputation")
        overrides["check_ip_reputation"]     = _cr("ip_reputation", 8, 8, category="reputation")
        overrides["check_bimi"]              = _cr("bimi", 0, 0, category="authentication")
        overrides["check_mta_sts"]           = _cr("mta_sts", 0, 0)
        overrides["check_tls_rpt"]           = _cr("tls_rpt", 0, 0)
        overrides["check_sender_detection"]  = _cr("sender_detection", 0, 0)

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

        # Points: 10+15+15+15+0(crashed)+10+10+5+3+8 = 91
        # Denominator (post-INBOX-42): 10+15+15+15+15+10+10+5+3+8 = 106
        # Expected score: round(91 / 106 * 100) = 86
        assert out["score"] == 86, (
            f"crashed blacklists should deflate score to 86/100, got {out['score']}. "
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

    # INBOX-265: 5-band scheme. Only 90+ = Excellent (was 85+).
    def test_excellent_when_score_gte_90(self):
        out = generate_summary("d", 95, self._checks(["pass"] * 10))
        assert out["verdict"] == "Excellent"
        assert out["color"] == "good"

    def test_good_when_score_75_to_89(self):
        out = generate_summary("d", 85, self._checks(["pass"] * 8 + ["warn"] * 2))
        assert out["verdict"] == "Good"
        assert out["color"] == "moderate"

    def test_fair_when_score_60_to_74(self):
        out = generate_summary("d", 65, self._checks(["pass"] * 6 + ["warn"] * 4))
        assert out["verdict"] == "Fair"
        assert out["color"] == "moderate"

    def test_needs_work_when_score_40_to_59(self):
        out = generate_summary("d", 50, self._checks(["pass"] * 5 + ["fail"] * 5))
        assert out["verdict"] == "Needs Work"
        assert out["color"] == "danger"

    def test_at_risk_when_score_lt_40(self):
        out = generate_summary("d", 20, self._checks(["fail"] * 5))
        assert out["verdict"] == "At Risk"
        assert out["color"] == "danger"

    def test_stats_count_correctly(self):
        out = generate_summary("d", 70, self._checks(["pass", "pass", "warn", "fail"]))
        assert out["stats"]["passed"] == 2
        assert out["stats"]["warnings"] == 1
        assert out["stats"]["failed"] == 1
