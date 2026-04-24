"""
Regression suite for INBOX-25 — check_blacklists correctness.

Two real bugs fixed:

  L2 — a domain with NO MX records AND NO A record used to score a
       perfect 15/15 "clean blacklist" with bogus detail text about
       a cloud provider. Now: status="fail", points=0, max_points=15,
       with honest detail text and fix_steps pointing at the DNS
       config problem.

  L5 — the check loop only queried the first 2 IPs while the display
       summary claimed "checked 3 IPs" (inconsistent) and anything
       listed on IPs 3+ was invisible. Now: both the loop AND the
       summary use a cap of 5, and when a domain has more than 5 IPs
       the detail text makes the cap visible with a "(checked 5 of N
       IPs)" phrasing.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import checks  # noqa: E402


# --------------------------------------------------------------------
# L2 — no infrastructure must not score 15/15
# --------------------------------------------------------------------

class TestNoMailInfrastructure:
    """Parked / dead domains score fail, not pass."""

    def test_no_mx_no_a_returns_fail_with_zero_points(self):
        # Simulate a domain with neither MX nor A records — i.e. no mail
        # infrastructure of any kind.
        def dns_stub(query: str, record_type: str):
            return []

        with patch.object(checks, "safe_dns_query", side_effect=dns_stub):
            result = checks.check_blacklists("parked.example")

        assert result.status == "fail", (
            "INBOX-25 L2 regression: no MX and no A must return status='fail', "
            f"not {result.status!r}. A domain with zero mail infrastructure "
            "cannot score a perfect blacklist result — that's the exact "
            "over-credit the ticket was filed to close."
        )
        assert result.points == 0
        assert result.max_points == 15
        assert "no mail infrastructure" in (result.detail or "").lower()
        # fix_steps must suggest something actionable
        assert result.fix_steps is not None and len(result.fix_steps) > 0
        # raw_data must reflect the reason so downstream dashboards can
        # distinguish this from a "checked, nothing listed" pass.
        raw = result.raw_data or {}
        assert raw.get("reason") == "no_mail_infrastructure"
        assert raw.get("checked") == 0


# --------------------------------------------------------------------
# L5 — IP cap parity + 5-IP coverage
# --------------------------------------------------------------------

class TestIPCoverage:
    """IPs checked must match IPs displayed; cap is 5, not 2."""

    def _resolve_stub(self, mx_ip_map: dict[str, list[str]]):
        """Build a safe_dns_query stub that returns canned MX/A records.

        mx_ip_map: dict mapping MX host -> list of IPs for that host.
        """
        def stub(query: str, record_type: str):
            if record_type == "MX" and query == "example.com":
                # Return one MX per host in the map, with arbitrary preference.
                return [f"10 {host}" for host in mx_ip_map.keys()]
            if record_type == "A":
                return mx_ip_map.get(query, [])
            return []
        return stub

    def _nxdomain_resolver(self):
        """Make every inner blacklist DNS lookup 'fail' (NXDOMAIN = clean)."""
        mock_resolver = MagicMock()
        mock_resolver.resolve.side_effect = Exception("NXDOMAIN")
        return mock_resolver

    def test_checks_and_displays_same_5_ips(self):
        # 6 MX hosts, one IP each = 6 candidate IPs. Cap is 5.
        mx_ip_map = {
            f"mx{i}.example.com": [f"192.0.2.{i}"]
            for i in range(1, 7)
        }
        with patch.object(checks, "safe_dns_query",
                          side_effect=self._resolve_stub(mx_ip_map)), \
             patch("checks.dns.resolver.Resolver",
                   return_value=self._nxdomain_resolver()):
            result = checks.check_blacklists("example.com")

        raw = result.raw_data or {}
        ips_summary = raw.get("ips_checked", [])
        ips_shown = [item["ip"] for item in ips_summary]

        assert len(ips_shown) == 5, (
            "INBOX-25 L5 regression: with 6 candidate IPs, the summary must "
            f"show exactly 5 IPs (the cap), got {len(ips_shown)}. Previous "
            "code showed 3 here while checking only 2 — that's the lie the "
            "ticket was filed to close."
        )
        # Detail text must be explicit about the cap ("5 of 6 IPs").
        assert "5 of 6" in (result.detail or ""), (
            "Detail text must say 'checked 5 of 6 IPs' when the cap is hit "
            "— hiding the cap is the same kind of dishonesty as L5."
        )

    def test_single_ip_domain_still_works(self):
        # Sanity: the happy-path (1 IP, clean) still produces a pass.
        mx_ip_map = {"mx.example.com": ["192.0.2.1"]}
        with patch.object(checks, "safe_dns_query",
                          side_effect=self._resolve_stub(mx_ip_map)), \
             patch("checks.dns.resolver.Resolver",
                   return_value=self._nxdomain_resolver()):
            result = checks.check_blacklists("example.com")

        assert result.status == "pass"
        assert result.points == 15
        assert result.max_points == 15
        raw = result.raw_data or {}
        assert len(raw.get("ips_checked", [])) == 1

    def test_three_ips_within_cap_shows_all_three(self):
        # 3 IPs is under the cap of 5 — all three must be shown, detail
        # must NOT include the "of N" capped phrasing.
        mx_ip_map = {f"mx{i}.example.com": [f"192.0.2.{i}"] for i in range(1, 4)}
        with patch.object(checks, "safe_dns_query",
                          side_effect=self._resolve_stub(mx_ip_map)), \
             patch("checks.dns.resolver.Resolver",
                   return_value=self._nxdomain_resolver()):
            result = checks.check_blacklists("example.com")

        raw = result.raw_data or {}
        assert len(raw.get("ips_checked", [])) == 3
        # No "N of M" cap phrasing because we didn't cap.
        assert " of " not in (result.detail or "") or "of 5" not in (result.detail or "")
