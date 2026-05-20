"""
INBOX-270 (2026-05-20) — tests for alerts_postmaster.compare_and_alert_postmaster.

Each test injects a fake (yesterday, today) row pair and asserts the
expected alert(s) are created. We mock create_alert + get_postmaster_metrics
so no real Supabase is involved.
"""

import os
import sys
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import alerts_postmaster  # noqa: E402


# ─── Helpers ────────────────────────────────────────────────────────


def _row(
    date="2026-05-20",
    domain_reputation=None,
    spam_rate=None,
    ip_reputation=None,
    auth_spf=None,
    auth_dkim=None,
    auth_dmarc=None,
):
    """Build a postmaster_metrics row for tests."""
    return {
        "date": date,
        "domain_reputation": domain_reputation,
        "spam_rate": spam_rate,
        "ip_reputation": ip_reputation,
        "auth_success_spf": auth_spf,
        "auth_success_dkim": auth_dkim,
        "auth_success_dmarc": auth_dmarc,
    }


def _run_compare(yesterday, today, domain="example.com", user_id="user-abc"):
    """Run compare_and_alert_postmaster with mocked db + create_alert.
    Returns the list of alert dicts that would have been written."""
    created_alerts = []

    def fake_create_alert(**kwargs):
        created_alerts.append(kwargs)
        return {"id": "alert-fake"}

    def fake_get_metrics(uid, dom, days=2):
        return [yesterday, today]

    with patch("alerts_postmaster.create_alert", side_effect=fake_create_alert), \
         patch("alerts_postmaster.get_postmaster_metrics", side_effect=fake_get_metrics):
        count = alerts_postmaster.compare_and_alert_postmaster(
            user_id, [domain]
        )
    return created_alerts, count


# ─── Spam rate tests ────────────────────────────────────────────────


class TestSpamRate:

    def test_crossed_warning_threshold(self):
        y = _row(spam_rate=0.0005)   # 0.05% — below 0.1%
        t = _row(spam_rate=0.0015, date="2026-05-21")  # 0.15% — above
        alerts, _ = _run_compare(y, t)
        sr = [a for a in alerts if "spam rate" in a["title"].lower()]
        assert len(sr) == 1
        assert sr[0]["severity"] == "warning"
        assert "0.1%" in sr[0]["title"]

    def test_crossed_critical_threshold(self):
        y = _row(spam_rate=0.0015)   # 0.15% — between thresholds
        t = _row(spam_rate=0.004, date="2026-05-21")  # 0.4% — critical
        alerts, _ = _run_compare(y, t)
        sr = [a for a in alerts if "spam rate" in a["title"].lower()]
        assert len(sr) == 1
        assert sr[0]["severity"] == "critical"
        assert "0.3%" in sr[0]["title"]

    def test_jumped_straight_to_critical(self):
        """From 0% straight to 0.5% — should fire ONE critical alert,
        not both warning and critical."""
        y = _row(spam_rate=0.0)
        t = _row(spam_rate=0.005, date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        sr = [a for a in alerts if "spam rate" in a["title"].lower()]
        assert len(sr) == 1
        assert sr[0]["severity"] == "critical"

    def test_recovered_below_warning(self):
        y = _row(spam_rate=0.002)    # 0.2% — above warning
        t = _row(spam_rate=0.0005, date="2026-05-21")  # 0.05% — below
        alerts, _ = _run_compare(y, t)
        sr = [a for a in alerts if "spam rate" in a["title"].lower()]
        assert len(sr) == 1
        assert sr[0]["severity"] == "info"
        assert "recovered" in sr[0]["title"].lower()

    def test_no_alert_when_unchanged(self):
        y = _row(spam_rate=0.0005)
        t = _row(spam_rate=0.0005, date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        sr = [a for a in alerts if "spam rate" in a["title"].lower()]
        assert sr == []

    def test_no_alert_when_today_missing(self):
        y = _row(spam_rate=0.001)
        t = _row(spam_rate=None, date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        sr = [a for a in alerts if "spam rate" in a["title"].lower()]
        assert sr == []


# ─── Domain reputation tier transitions ─────────────────────────────


class TestDomainReputation:

    @pytest.mark.parametrize("from_tier,to_tier,severity", [
        ("HIGH", "MEDIUM", "warning"),
        ("HIGH", "LOW", "warning"),
        ("MEDIUM", "LOW", "warning"),
        ("HIGH", "BAD", "critical"),
        ("MEDIUM", "BAD", "critical"),
        ("LOW", "BAD", "critical"),
    ])
    def test_tier_drop(self, from_tier, to_tier, severity):
        y = _row(domain_reputation=from_tier)
        t = _row(domain_reputation=to_tier, date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        rep = [a for a in alerts if "domain reputation" in a["title"].lower()]
        assert len(rep) == 1
        assert rep[0]["severity"] == severity
        assert from_tier in rep[0]["title"]
        assert to_tier in rep[0]["title"]

    def test_recovery_fires_info(self):
        y = _row(domain_reputation="LOW")
        t = _row(domain_reputation="HIGH", date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        rep = [a for a in alerts if "domain reputation" in a["title"].lower()]
        assert len(rep) == 1
        assert rep[0]["severity"] == "info"

    def test_unchanged_no_alert(self):
        y = _row(domain_reputation="HIGH")
        t = _row(domain_reputation="HIGH", date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        rep = [a for a in alerts if "reputation" in a["title"].lower()]
        assert rep == []


# ─── IP reputation tier transitions ─────────────────────────────────


class TestIpReputation:

    def test_single_ip_dropped(self):
        y = _row(ip_reputation=[{"ip": "1.2.3.4", "reputation": "HIGH"}])
        t = _row(ip_reputation=[{"ip": "1.2.3.4", "reputation": "LOW"}],
                 date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        ip_alerts = [
            a for a in alerts
            if "IP reputation" in a["title"] and "1.2.3.4" in a["title"]
        ]
        assert len(ip_alerts) == 1
        assert ip_alerts[0]["severity"] == "warning"

    def test_single_ip_to_bad(self):
        y = _row(ip_reputation=[{"ip": "1.2.3.4", "reputation": "HIGH"}])
        t = _row(ip_reputation=[{"ip": "1.2.3.4", "reputation": "BAD"}],
                 date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        ip_alerts = [a for a in alerts if "1.2.3.4" in a["title"]]
        assert len(ip_alerts) == 1
        assert ip_alerts[0]["severity"] == "critical"

    def test_multiple_ips_multiple_alerts(self):
        y = _row(ip_reputation=[
            {"ip": "1.1.1.1", "reputation": "HIGH"},
            {"ip": "2.2.2.2", "reputation": "HIGH"},
        ])
        t = _row(ip_reputation=[
            {"ip": "1.1.1.1", "reputation": "MEDIUM"},
            {"ip": "2.2.2.2", "reputation": "BAD"},
        ], date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        ip_alerts = [a for a in alerts if "IP reputation" in a["title"]]
        assert len(ip_alerts) == 2

    def test_ip_reputation_as_json_string(self):
        """upsert_postmaster_metrics dumps ip_reputation to a JSON
        string. The compare code must handle both list and str."""
        import json
        y = _row(ip_reputation=json.dumps([
            {"ip": "1.2.3.4", "reputation": "HIGH"}
        ]))
        t = _row(ip_reputation=json.dumps([
            {"ip": "1.2.3.4", "reputation": "LOW"}
        ]), date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        ip_alerts = [a for a in alerts if "1.2.3.4" in a["title"]]
        assert len(ip_alerts) == 1


# ─── Auth pass rate transitions ─────────────────────────────────────


class TestAuthPassRate:

    @pytest.mark.parametrize("column,label", [
        ("auth_spf", "SPF"),
        ("auth_dkim", "DKIM"),
        ("auth_dmarc", "DMARC"),
    ])
    def test_crossed_warning(self, column, label):
        y = _row(**{column: 0.995})  # 99.5% — OK
        t = _row(**{column: 0.985, "date": "2026-05-21"})  # 98.5% — warn
        alerts, _ = _run_compare(y, t)
        auth = [a for a in alerts if label in a["title"]]
        assert len(auth) == 1
        assert auth[0]["severity"] == "warning"

    @pytest.mark.parametrize("column,label", [
        ("auth_spf", "SPF"),
        ("auth_dkim", "DKIM"),
        ("auth_dmarc", "DMARC"),
    ])
    def test_crossed_critical(self, column, label):
        y = _row(**{column: 0.99})
        t = _row(**{column: 0.92, "date": "2026-05-21"})  # below 95%
        alerts, _ = _run_compare(y, t)
        auth = [a for a in alerts if label in a["title"]]
        assert len(auth) == 1
        assert auth[0]["severity"] == "critical"

    def test_recovered_to_ok(self):
        y = _row(auth_spf=0.92)
        t = _row(auth_spf=0.995, date="2026-05-21")
        alerts, _ = _run_compare(y, t)
        auth = [a for a in alerts if "SPF" in a["title"]]
        assert len(auth) == 1
        assert auth[0]["severity"] == "info"


# ─── Insufficient data ──────────────────────────────────────────────


class TestInsufficientData:

    def test_only_one_day_of_data(self):
        """Need 2+ rows to detect a transition. With only 1 row, no
        alerts fire."""
        def fake_get_metrics(uid, dom, days=2):
            return [_row(spam_rate=0.005)]  # just one row
        with patch("alerts_postmaster.create_alert"), \
             patch("alerts_postmaster.get_postmaster_metrics",
                   side_effect=fake_get_metrics):
            count = alerts_postmaster.compare_and_alert_postmaster(
                "user-abc", ["example.com"]
            )
        assert count == 0

    def test_two_rows_same_date(self):
        """Defensive: if somehow both rows are for the same date, skip."""
        y = _row(spam_rate=0.0001, date="2026-05-20")
        t = _row(spam_rate=0.005, date="2026-05-20")  # same date
        alerts, count = _run_compare(y, t)
        assert count == 0


# ─── Failure isolation ──────────────────────────────────────────────


class TestFailureIsolation:

    def test_db_failure_does_not_raise(self):
        """If get_postmaster_metrics raises, the function logs +
        returns 0, never propagates."""
        def fake_get_metrics_raise(uid, dom, days=2):
            raise RuntimeError("simulated DB down")
        with patch("alerts_postmaster.create_alert"), \
             patch("alerts_postmaster.get_postmaster_metrics",
                   side_effect=fake_get_metrics_raise):
            count = alerts_postmaster.compare_and_alert_postmaster(
                "user-abc", ["example.com"]
            )
        assert count == 0  # No alerts, no exception escaped

    def test_create_alert_failure_continues(self):
        """If one create_alert call fails (returns None), the rest of
        the alerts still try."""
        y = _row(domain_reputation="HIGH")
        t = _row(domain_reputation="BAD", date="2026-05-21")

        call_count = {"n": 0}
        def fake_create_alert(**kwargs):
            call_count["n"] += 1
            return {"id": "ok"}

        def fake_get_metrics(uid, dom, days=2):
            return [y, t]

        with patch("alerts_postmaster.create_alert", side_effect=fake_create_alert), \
             patch("alerts_postmaster.get_postmaster_metrics",
                   side_effect=fake_get_metrics):
            count = alerts_postmaster.compare_and_alert_postmaster(
                "user-abc", ["example.com"]
            )
        assert count >= 1
