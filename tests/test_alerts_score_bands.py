"""
INBOX-270 (2026-05-20) — tests for the score-band-based alert logic in
monitor.compare_scan_results.

Replaces the old 5-point and 15-point single-cycle delta rule tests
(removed alongside the code change). The new rules:

  1. Score crossed BELOW 90 (Excellent → Good): warning
  2. Score crossed BELOW 75 (Good → Fair): warning
  3. Score crossed BELOW 60 (Fair → Needs Work): critical
  4. Score crossed BELOW 40 (Needs Work → At Risk): critical
  5. Score crossed BACK ABOVE a band threshold: info (positive)
  6. Same band, any small drop: no alert
  7. Trend guard: 15+ pt drop vs 7-day high, no band crossed: warning
  8. DMARC policy weakened (reject → quarantine → none): critical
"""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import monitor  # noqa: E402


# ─── Helpers ────────────────────────────────────────────────────────


def _domain_data(latest_score=None, domain="example.com", domain_id="dom-1"):
    """Build a domain_data dict matching what monitor passes in."""
    d = {"id": domain_id, "domain": domain}
    if latest_score is not None:
        d["latest_score"] = latest_score
    return d


def _scan_result(score, checks=None):
    """Build a new_result dict matching scan_service.run_full_scan output."""
    return {"score": score, "checks": checks or []}


def _old_scan(checks=None):
    """Build an old_scan dict matching get_scan_detail output."""
    return {"results": {"checks": checks or []}}


def _mock_trend_guard_empty():
    """No prior scans in the 7-day window — trend guard never fires."""
    return patch("monitor.get_recent_scan_scores", return_value=[])


# ─── Pure helper tests ──────────────────────────────────────────────


class TestScoreBandHelper:
    """monitor.score_band() must return the right (ordinal, name) for
    every score across all 5 bands plus edge cases."""

    @pytest.mark.parametrize("score,expected", [
        (100, (0, "Excellent")),
        (95,  (0, "Excellent")),
        (90,  (0, "Excellent")),  # boundary
        (89,  (1, "Good")),
        (80,  (1, "Good")),
        (75,  (1, "Good")),       # boundary
        (74,  (2, "Fair")),
        (65,  (2, "Fair")),
        (60,  (2, "Fair")),       # boundary
        (59,  (3, "Needs Work")),
        (45,  (3, "Needs Work")),
        (40,  (3, "Needs Work")), # boundary
        (39,  (4, "At Risk")),
        (10,  (4, "At Risk")),
        (0,   (4, "At Risk")),
    ])
    def test_score_to_band(self, score, expected):
        assert monitor.score_band(score) == expected

    def test_none_score(self):
        assert monitor.score_band(None) == (None, None)


# ─── Band crossing — DOWNWARD (negative) ────────────────────────────


class TestBandCrossingDown:

    def test_excellent_to_good_fires_warning(self):
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(85),
                domain_data=_domain_data(latest_score=92),
            )
        score_changes = [c for c in changes if c["type"] == "score_drop"]
        assert len(score_changes) == 1
        assert score_changes[0]["severity"] == "warning"
        assert "Good" in score_changes[0]["title"]

    def test_good_to_fair_fires_warning(self):
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(72),
                domain_data=_domain_data(latest_score=80),
            )
        score_changes = [c for c in changes if c["type"] == "score_drop"]
        assert len(score_changes) == 1
        assert score_changes[0]["severity"] == "warning"
        assert "Fair" in score_changes[0]["title"]

    def test_fair_to_needs_work_fires_critical(self):
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(55),
                domain_data=_domain_data(latest_score=65),
            )
        score_changes = [c for c in changes if c["type"] == "score_drop"]
        assert len(score_changes) == 1
        assert score_changes[0]["severity"] == "critical"
        assert "Needs Work" in score_changes[0]["title"]

    def test_needs_work_to_at_risk_fires_critical(self):
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(35),
                domain_data=_domain_data(latest_score=45),
            )
        score_changes = [c for c in changes if c["type"] == "score_drop"]
        assert len(score_changes) == 1
        assert score_changes[0]["severity"] == "critical"
        assert "At Risk" in score_changes[0]["title"]

    def test_multi_band_drop_fires_single_alert(self):
        """95 → 38 crosses 3 bands. Should fire ONE alert (worst band
        entered) — not three. Spam protection."""
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(38),
                domain_data=_domain_data(latest_score=95),
            )
        score_changes = [c for c in changes if c["type"] == "score_drop"]
        assert len(score_changes) == 1
        # Lands in At Risk — should be critical
        assert score_changes[0]["severity"] == "critical"
        assert "At Risk" in score_changes[0]["title"]


# ─── Band crossing — UPWARD (recovery) ──────────────────────────────


class TestBandCrossingUp:

    @pytest.mark.parametrize("old_score,new_score,expected_band", [
        (35, 50, "Needs Work"),
        (55, 65, "Fair"),
        (70, 80, "Good"),
        (85, 92, "Excellent"),
        (38, 95, "Excellent"),  # multi-band recovery
    ])
    def test_recovery_fires_info(self, old_score, new_score, expected_band):
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(new_score),
                domain_data=_domain_data(latest_score=old_score),
            )
        score_changes = [c for c in changes if c["type"] == "score_drop"]
        assert len(score_changes) == 1
        assert score_changes[0]["severity"] == "info"
        assert "Recovered" in score_changes[0]["title"]
        assert expected_band in score_changes[0]["title"]


# ─── Same band, no crossing ─────────────────────────────────────────


class TestSameBand:

    @pytest.mark.parametrize("old_score,new_score", [
        (95, 91),   # both Excellent — drop within band
        (89, 76),   # both Good — 13-point drop, still in band
        (74, 60),   # both Fair
        (59, 40),   # both Needs Work
        (39, 10),   # both At Risk
        (95, 92),   # both Excellent — tiny drift
        (50, 50),   # identical
    ])
    def test_no_alert_within_same_band(self, old_score, new_score):
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(new_score),
                domain_data=_domain_data(latest_score=old_score),
            )
        score_changes = [c for c in changes if c["type"] == "score_drop"]
        # No band crossing AND no trend-guard data → zero alerts
        assert score_changes == []


# ─── First scan (no old_score) ──────────────────────────────────────


class TestFirstScan:

    def test_no_alert_when_no_prior_score(self):
        """domain_data lacks `latest_score` — first-ever scan. No band
        crossing alert. (Initial-state alerts could be added later, but
        not in scope for INBOX-270.)"""
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(45),
                domain_data=_domain_data(latest_score=None),
            )
        score_changes = [c for c in changes if c["type"] == "score_drop"]
        assert score_changes == []


# ─── Trend guard (in-band cumulative drop) ──────────────────────────


class TestTrendGuard:

    def test_fires_when_drop_exceeds_15_within_same_band(self):
        """89 (7-day high) → 76 stays in Good but is a 13-pt drop.
        With 7-day high at 95, drop is 19 — warning fires."""
        with patch("monitor.get_recent_scan_scores",
                   return_value=[95, 92, 88, 85, 80]):
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(76),
                domain_data=_domain_data(latest_score=80),
            )
        trend = [
            c for c in changes
            if c["type"] == "score_drop"
            and "7 days" in c["title"]
        ]
        assert len(trend) == 1
        assert trend[0]["severity"] == "warning"
        assert "19 points" in trend[0]["title"]

    def test_no_trend_alert_when_drop_under_15(self):
        with patch("monitor.get_recent_scan_scores",
                   return_value=[90, 88, 85, 83]):
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(78),
                domain_data=_domain_data(latest_score=83),
            )
        trend = [c for c in changes if "7 days" in c.get("title", "")]
        assert trend == []

    def test_no_trend_alert_when_band_crossed(self):
        """If a band crossing already fired this cycle, suppress the
        trend guard — customer would otherwise get two alerts."""
        with patch("monitor.get_recent_scan_scores",
                   return_value=[95, 92, 90]):
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(70),  # crosses 75 → Fair
                domain_data=_domain_data(latest_score=92),
            )
        # Should have exactly ONE score_drop alert (the band crossing)
        score_alerts = [c for c in changes if c["type"] == "score_drop"]
        assert len(score_alerts) == 1
        # And it should be the band-crossing title, not the trend title
        assert "7 days" not in score_alerts[0]["title"]
        assert "Fair" in score_alerts[0]["title"]


# ─── DMARC policy weakening ─────────────────────────────────────────


def _dmarc_check(policy, status="pass"):
    """Build a DMARC check result with the given policy in raw_data."""
    return {
        "name": "dmarc",
        "status": status,
        "title": "DMARC Policy",
        "detail": f"p={policy}",
        "raw_data": {"record": f"v=DMARC1; p={policy}", "policy": policy},
    }


class TestDmarcPolicyWeakening:

    def test_reject_to_quarantine_fires_critical(self):
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=_old_scan(checks=[_dmarc_check("reject")]),
                new_result=_scan_result(80, checks=[_dmarc_check("quarantine")]),
                domain_data=_domain_data(latest_score=80),
            )
        weak = [
            c for c in changes
            if c["type"] == "dmarc_change"
            and "weakened" in c["title"]
        ]
        assert len(weak) == 1
        assert weak[0]["severity"] == "critical"
        assert "reject" in weak[0]["title"]
        assert "quarantine" in weak[0]["title"]

    def test_quarantine_to_none_fires_critical(self):
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=_old_scan(checks=[_dmarc_check("quarantine")]),
                new_result=_scan_result(80, checks=[_dmarc_check("none", status="warn")]),
                domain_data=_domain_data(latest_score=80),
            )
        weak = [
            c for c in changes
            if c["type"] == "dmarc_change"
            and "weakened" in c["title"]
        ]
        assert len(weak) == 1
        assert weak[0]["severity"] == "critical"

    def test_reject_to_none_fires_critical(self):
        """Big drop straight through — still one alert."""
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=_old_scan(checks=[_dmarc_check("reject")]),
                new_result=_scan_result(80, checks=[_dmarc_check("none", status="warn")]),
                domain_data=_domain_data(latest_score=80),
            )
        weak = [
            c for c in changes
            if c["type"] == "dmarc_change"
            and "weakened" in c["title"]
        ]
        assert len(weak) == 1

    @pytest.mark.parametrize("old_policy,new_policy", [
        ("none", "quarantine"),    # strengthening
        ("quarantine", "reject"),  # strengthening
        ("none", "reject"),        # strengthening
        ("reject", "reject"),      # same
        ("quarantine", "quarantine"),  # same
    ])
    def test_no_alert_when_policy_same_or_strengthened(
        self, old_policy, new_policy
    ):
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=_old_scan(checks=[_dmarc_check(old_policy)]),
                new_result=_scan_result(80, checks=[_dmarc_check(new_policy)]),
                domain_data=_domain_data(latest_score=80),
            )
        weak = [
            c for c in changes
            if c["type"] == "dmarc_change"
            and "weakened" in c.get("title", "")
        ]
        assert weak == []

    def test_no_dmarc_check_present(self):
        """Scan result has no DMARC check at all — no false alert."""
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=_old_scan(checks=[]),
                new_result=_scan_result(80, checks=[]),
                domain_data=_domain_data(latest_score=80),
            )
        weak = [c for c in changes if "weakened" in c.get("title", "")]
        assert weak == []


# ─── Per-check transitions still work (regression for existing logic) ──


class TestExistingTransitionsStillWork:

    def test_blacklist_added_still_fires(self):
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=_old_scan(checks=[
                    {"name": "blacklist_domain", "status": "pass",
                     "title": "Domain blacklist", "detail": "Clean"}
                ]),
                new_result=_scan_result(80, checks=[
                    {"name": "blacklist_domain", "status": "fail",
                     "title": "Domain blacklist", "detail": "Listed on Spamhaus"}
                ]),
                domain_data=_domain_data(latest_score=80),
            )
        bl = [c for c in changes if c["type"] == "blacklist_added"]
        assert len(bl) == 1
        assert bl[0]["severity"] == "critical"

    def test_blacklist_removed_still_fires(self):
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=_old_scan(checks=[
                    {"name": "blacklist_domain", "status": "fail",
                     "title": "Domain blacklist", "detail": "Listed"}
                ]),
                new_result=_scan_result(80, checks=[
                    {"name": "blacklist_domain", "status": "pass",
                     "title": "Domain blacklist", "detail": "Clean"}
                ]),
                domain_data=_domain_data(latest_score=80),
            )
        bl = [c for c in changes if c["type"] == "blacklist_removed"]
        assert len(bl) == 1
        assert bl[0]["severity"] == "info"

    def test_spf_change_pass_to_fail_fires(self):
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=_old_scan(checks=[
                    {"name": "spf", "status": "pass",
                     "title": "SPF", "detail": "OK"}
                ]),
                new_result=_scan_result(80, checks=[
                    {"name": "spf", "status": "fail",
                     "title": "SPF", "detail": "No SPF record"}
                ]),
                domain_data=_domain_data(latest_score=80),
            )
        spf = [c for c in changes if c["type"] == "spf_change"]
        assert len(spf) == 1
        assert spf[0]["severity"] == "critical"


# ─── Old delta rules are GONE — pin the regression ──────────────────


class TestOldDeltaRulesAreGone:
    """The previous 5-point and 15-point single-cycle drop rules + the
    user-configurable alert_threshold field are removed. These tests
    pin that absence — if someone tries to re-add them, these break."""

    def test_5_point_drop_within_band_does_not_fire(self):
        """OLD rule: any 5+ drop fires warning. NEW rule: no alert
        because both 95 and 90 are Excellent."""
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(90),
                domain_data=_domain_data(latest_score=95),
            )
        score_changes = [c for c in changes if c["type"] == "score_drop"]
        assert score_changes == []

    def test_15_point_drop_within_band_no_history_no_alert(self):
        """OLD rule: any 15+ drop fires critical regardless of band.
        NEW rule: no alert if both old + new are in the same band AND
        no past-7d history shows a higher score (trend guard quiet).
        58 → 41 is a 17-pt drop but both fall in "Needs Work" (40-59)."""
        with _mock_trend_guard_empty():
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(41),
                domain_data=_domain_data(latest_score=58),
            )
        # Both Needs Work — no band crossing. No history → trend guard skip.
        score_changes = [c for c in changes if c["type"] == "score_drop"]
        assert score_changes == []

    def test_alert_threshold_field_is_ignored(self):
        """OLD rule: score crossing the user's alert_threshold (default
        70) fires critical. NEW rule: that field is ignored. Score
        going from 75 → 65 should fire because it crossed band 75
        (entered Fair), NOT because it crossed the legacy threshold."""
        with _mock_trend_guard_empty():
            # Pass alert_threshold=80 in domain_data — old code would
            # have fired "below threshold". New code ignores it.
            dd = _domain_data(latest_score=82)
            dd["alert_threshold"] = 50  # would suppress in old code
            changes = monitor.compare_scan_results(
                old_scan=None,
                new_result=_scan_result(72),  # crossed 75 → entered Fair
                domain_data=dd,
            )
        score_changes = [c for c in changes if c["type"] == "score_drop"]
        # Should fire the BAND alert (Fair), regardless of threshold field
        assert len(score_changes) == 1
        assert "Fair" in score_changes[0]["title"]
