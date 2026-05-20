"""
INBOX-270 (2026-05-20) — tests for alerts_snds.compare_and_alert_snds.

Per-IP comparison of yesterday vs today's snds_metrics row. Triggers
on status transitions (green/yellow/red) and new trap hits.
"""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import alerts_snds  # noqa: E402


def _row(date="2026-05-20", ip_status=None, trap_hits=0, message_count=0):
    return {
        "metric_date": date,
        "ip_status": ip_status,
        "trap_hits": trap_hits,
        "message_count": message_count,
    }


def _run_compare(yesterday, today, ip="1.2.3.4", user_id="user-abc"):
    created = []
    def fake_create_alert(**kwargs):
        created.append(kwargs)
        return {"id": "alert-fake"}
    def fake_get_metrics(uid, ip_arg, days=2):
        return [yesterday, today]
    with patch("alerts_snds.create_alert", side_effect=fake_create_alert), \
         patch("alerts_snds.get_snds_metrics_for_ip", side_effect=fake_get_metrics):
        count = alerts_snds.compare_and_alert_snds(user_id, [ip])
    return created, count


# ─── Status transitions ─────────────────────────────────────────────


class TestStatusTransitions:

    def test_green_to_yellow_fires_warning(self):
        y = _row(ip_status="green")
        t = _row(ip_status="yellow", date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        st = [a for a in alerts if "SNDS status" in a["title"]]
        assert len(st) == 1
        assert st[0]["severity"] == "warning"
        assert "GREEN" in st[0]["title"]
        assert "YELLOW" in st[0]["title"]

    def test_yellow_to_red_fires_critical(self):
        y = _row(ip_status="yellow")
        t = _row(ip_status="red", date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        st = [a for a in alerts if "SNDS status" in a["title"]]
        assert len(st) == 1
        assert st[0]["severity"] == "critical"

    def test_green_to_red_fires_critical_with_urgency(self):
        """Skipping yellow is a major degradation."""
        y = _row(ip_status="green")
        t = _row(ip_status="red", date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        st = [a for a in alerts if "SNDS status" in a["title"]]
        assert len(st) == 1
        assert st[0]["severity"] == "critical"
        assert "major degradation" in st[0]["title"].lower()

    @pytest.mark.parametrize("from_tier,to_tier", [
        ("red", "yellow"),
        ("red", "green"),
        ("yellow", "green"),
    ])
    def test_recovery_fires_info(self, from_tier, to_tier):
        y = _row(ip_status=from_tier)
        t = _row(ip_status=to_tier, date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        st = [a for a in alerts if "SNDS status" in a["title"]]
        assert len(st) == 1
        assert st[0]["severity"] == "info"
        assert "recovered" in st[0]["title"].lower()

    @pytest.mark.parametrize("tier", ["green", "yellow", "red"])
    def test_same_tier_no_alert(self, tier):
        y = _row(ip_status=tier)
        t = _row(ip_status=tier, date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        st = [a for a in alerts if "SNDS status" in a["title"]]
        assert st == []

    def test_unknown_tier_no_alert(self):
        y = _row(ip_status="purple")
        t = _row(ip_status="red", date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        st = [a for a in alerts if "SNDS status" in a["title"]]
        assert st == []


# ─── Trap hits ──────────────────────────────────────────────────────


class TestTrapHits:

    def test_first_trap_hit_fires_critical(self):
        y = _row(ip_status="green", trap_hits=0)
        t = _row(ip_status="green", trap_hits=3, date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        traps = [a for a in alerts if "trap" in a["title"].lower()]
        assert len(traps) == 1
        assert traps[0]["severity"] == "critical"
        assert "3" in traps[0]["title"]

    def test_zero_to_zero_no_alert(self):
        y = _row(ip_status="green", trap_hits=0)
        t = _row(ip_status="green", trap_hits=0, date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        traps = [a for a in alerts if "trap" in a["title"].lower()]
        assert traps == []

    def test_persistent_traps_no_new_alert(self):
        """Yesterday had traps, today also has traps — already alerted
        yesterday, don't re-fire."""
        y = _row(trap_hits=2)
        t = _row(trap_hits=5, date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        traps = [a for a in alerts if "trap" in a["title"].lower()]
        assert traps == []


# ─── Insufficient data ──────────────────────────────────────────────


class TestInsufficientData:

    def test_single_row(self):
        def fake_get_metrics(uid, ip, days=2):
            return [_row(ip_status="red")]
        with patch("alerts_snds.create_alert"), \
             patch("alerts_snds.get_snds_metrics_for_ip",
                   side_effect=fake_get_metrics):
            count = alerts_snds.compare_and_alert_snds("user-abc", ["1.2.3.4"])
        assert count == 0

    def test_same_date_skip(self):
        y = _row(ip_status="green", date="2026-05-20")
        t = _row(ip_status="red", date="2026-05-20")
        alerts, count = _run_compare(y, t)
        # No alerts because same date — defensive skip
        assert count == 0


# ─── Failure isolation ──────────────────────────────────────────────


class TestFailureIsolation:

    def test_db_failure_does_not_raise(self):
        def fake_get_metrics_raise(uid, ip, days=2):
            raise RuntimeError("simulated DB down")
        with patch("alerts_snds.create_alert"), \
             patch("alerts_snds.get_snds_metrics_for_ip",
                   side_effect=fake_get_metrics_raise):
            count = alerts_snds.compare_and_alert_snds("user-abc", ["1.2.3.4"])
        assert count == 0  # No exception escaped


# ─── Pure helper tests ──────────────────────────────────────────────


class TestTierRank:

    def test_tier_rank(self):
        assert alerts_snds._tier_rank("green") == 0
        assert alerts_snds._tier_rank("yellow") == 1
        assert alerts_snds._tier_rank("red") == 2
        assert alerts_snds._tier_rank("GREEN") == 0  # case-insensitive
        assert alerts_snds._tier_rank("purple") is None
        assert alerts_snds._tier_rank(None) is None
        assert alerts_snds._tier_rank("") is None
