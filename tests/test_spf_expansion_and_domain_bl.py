"""
Regression suite for INBOX-42 (domain blacklists) and INBOX-43 (SPF sending IPs).

Two related improvements:

  INBOX-43 — check_blacklists now includes SPF-derived sending IPs as
             candidates alongside MX IPs. Google/Microsoft MX IPs are
             essentially never on public blacklists, so the MX-only check
             was low-signal. SPF expansion surfaces the customer's ACTUAL
             sending IPs (which DO land on blacklists when misused).

  INBOX-42 — new check_domain_blacklists function. Domain-based blacklists
             (Spamhaus DBL, SURBL, URIBL) flag the DOMAIN regardless of
             IP. Major mailbox providers consult these during inbox-vs-spam
             decisions; missing this check was a real coverage gap.

Tests use targeted patching so nothing hits the network.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import checks  # noqa: E402


# --------------------------------------------------------------------
# INBOX-43 — expand_spf_ips helper
# --------------------------------------------------------------------

class TestSPFExpansion:
    """Unit tests for the expand_spf_ips helper."""

    def _make_dns_stub(self, spf_by_domain: dict, a_by_host: dict | None = None,
                       mx_by_domain: dict | None = None):
        """Return a safe_dns_query stub serving canned SPF / A / MX records."""
        a_by_host = a_by_host or {}
        mx_by_domain = mx_by_domain or {}

        def stub(query: str, record_type: str):
            if record_type == "TXT":
                if query in spf_by_domain:
                    return [f'"{spf_by_domain[query]}"']
                return []
            if record_type == "A":
                return list(a_by_host.get(query, []))
            if record_type == "MX":
                return list(mx_by_domain.get(query, []))
            return []
        return stub

    def test_simple_ip4_mechanisms(self):
        spf = {"example.com": "v=spf1 ip4:1.2.3.4 ip4:5.6.7.8 -all"}
        with patch.object(checks, "safe_dns_query",
                          side_effect=self._make_dns_stub(spf)):
            ips, warnings = checks.expand_spf_ips("example.com")
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips
        assert warnings == []

    def test_ip4_cidr_samples_network_address(self):
        spf = {"example.com": "v=spf1 ip4:192.0.2.0/24 -all"}
        with patch.object(checks, "safe_dns_query",
                          side_effect=self._make_dns_stub(spf)):
            ips, _ = checks.expand_spf_ips("example.com")
        # /24 → sample is the network address
        assert "192.0.2.0" in ips

    def test_include_mechanism_recurses(self):
        spf = {
            "example.com": "v=spf1 include:_spf.provider.test -all",
            "_spf.provider.test": "v=spf1 ip4:10.0.0.1 ip4:10.0.0.2 -all",
        }
        with patch.object(checks, "safe_dns_query",
                          side_effect=self._make_dns_stub(spf)):
            ips, warnings = checks.expand_spf_ips("example.com")
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    def test_nested_includes_within_lookup_budget(self):
        spf = {
            "example.com": "v=spf1 include:_spf.a.test -all",
            "_spf.a.test": "v=spf1 include:_spf.b.test -all",
            "_spf.b.test": "v=spf1 ip4:172.16.0.1 -all",
        }
        with patch.object(checks, "safe_dns_query",
                          side_effect=self._make_dns_stub(spf)):
            ips, _ = checks.expand_spf_ips("example.com")
        assert "172.16.0.1" in ips

    def test_10_lookup_limit_enforced(self):
        # Build 12 nested includes — should stop at 10 and warn.
        spf = {"domain0.test": "v=spf1 include:domain1.test -all"}
        for i in range(1, 12):
            spf[f"domain{i}.test"] = f"v=spf1 include:domain{i+1}.test -all"
        spf["domain12.test"] = "v=spf1 ip4:1.1.1.1 -all"

        with patch.object(checks, "safe_dns_query",
                          side_effect=self._make_dns_stub(spf)):
            ips, warnings = checks.expand_spf_ips("domain0.test", max_lookups=10)

        # Deep IP shouldn't be reached.
        assert "1.1.1.1" not in ips
        assert any("10-lookup limit" in w for w in warnings)

    def test_circular_include_does_not_loop_forever(self):
        spf = {
            "a.test": "v=spf1 include:b.test -all",
            "b.test": "v=spf1 include:a.test ip4:9.9.9.9 -all",
        }
        with patch.object(checks, "safe_dns_query",
                          side_effect=self._make_dns_stub(spf)):
            ips, _ = checks.expand_spf_ips("a.test")
        # We collected 9.9.9.9 once; the a.test→b.test→a.test cycle
        # is detected and short-circuited.
        assert "9.9.9.9" in ips

    def test_a_mechanism_resolves_domain_a_record(self):
        spf = {"example.com": "v=spf1 a -all"}
        a = {"example.com": ["203.0.113.5"]}
        with patch.object(checks, "safe_dns_query",
                          side_effect=self._make_dns_stub(spf, a_by_host=a)):
            ips, _ = checks.expand_spf_ips("example.com")
        assert "203.0.113.5" in ips

    def test_no_spf_returns_empty(self):
        with patch.object(checks, "safe_dns_query",
                          side_effect=self._make_dns_stub({})):
            ips, _ = checks.expand_spf_ips("no-spf.test")
        assert ips == set()

    def test_ipv6_mechanism_ignored(self):
        # ip6: should not add anything — DNSBLs don't support IPv6 widely.
        spf = {"example.com": "v=spf1 ip4:1.1.1.1 ip6:2001:db8::1 -all"}
        with patch.object(checks, "safe_dns_query",
                          side_effect=self._make_dns_stub(spf)):
            ips, _ = checks.expand_spf_ips("example.com")
        assert "1.1.1.1" in ips
        # No IPv6 addrs in output
        assert all(":" not in ip for ip in ips)

    def test_cap_limits_ip_set_size(self):
        # SPF with many ip4: entries — ensure cap kicks in.
        ip_list = " ".join(f"ip4:10.0.{i}.1" for i in range(30))
        spf = {"example.com": f"v=spf1 {ip_list} -all"}
        with patch.object(checks, "safe_dns_query",
                          side_effect=self._make_dns_stub(spf)):
            ips, warnings = checks.expand_spf_ips("example.com", cap=20)
        assert len(ips) <= 20
        assert any("sampled first 20" in w for w in warnings)


# --------------------------------------------------------------------
# INBOX-43 — check_blacklists now includes SPF-sending IPs as candidates
# --------------------------------------------------------------------

class TestBlacklistsUsesSpfSendingIps:
    """The real test: SPF IPs appear in the ips_checked list alongside MX IPs."""

    def test_spf_ips_and_mx_ips_both_checked(self):
        # Domain with MX at Google but SPF authorizing a specific IP too.
        def dns_stub(query: str, record_type: str):
            if record_type == "MX" and query == "acme.test":
                return ["10 aspmx.l.google.com"]
            if record_type == "A" and query == "aspmx.l.google.com":
                return ["142.250.101.27"]
            if record_type == "TXT" and query == "acme.test":
                # SPF authorizes a specific ip4 + Google
                return ['"v=spf1 ip4:203.0.113.99 include:_spf.google.com -all"']
            if record_type == "TXT" and query == "_spf.google.com":
                return ['"v=spf1 ip4:35.190.247.0/24 -all"']
            return []

        # Every DNSBL returns NXDOMAIN.
        class CleanResolver:
            def __init__(self): self.timeout = 2; self.lifetime = 2
            def resolve(self, *a, **kw): raise Exception("NXDOMAIN")

        with patch.object(checks, "safe_dns_query", side_effect=dns_stub), \
             patch.object(checks.dns.resolver, "Resolver", CleanResolver):
            result = checks.check_blacklists("acme.test")

        raw = result.raw_data or {}
        ips_checked = [item["ip"] for item in (raw.get("ips_checked") or [])]
        # MX-derived IP — still checked.
        assert "142.250.101.27" in ips_checked
        # SPF-derived sending IP — new, thanks to INBOX-43.
        assert "203.0.113.99" in ips_checked, (
            "INBOX-43 regression: SPF-derived sending IP must appear in "
            "ips_checked. Got: " + str(ips_checked)
        )
        # SPF-included Google block — network address sampled.
        assert "35.190.247.0" in ips_checked


# --------------------------------------------------------------------
# INBOX-42 — check_domain_blacklists
# --------------------------------------------------------------------

class TestCheckDomainBlacklists:
    """New domain-based blacklist check (DBL, SURBL, URIBL)."""

    def _dnsbl_stub(self, listings: dict):
        """Build a Resolver stub. listings: {bl_name: [codes]}."""
        class StubResolver:
            def __init__(self):
                self.timeout = 2
                self.lifetime = 2
            def resolve(self, query, rtype):
                # Query shape: "domain.blacklist.com"
                # Find which blacklist we're hitting
                for bl in listings:
                    if query.endswith("." + bl) or query == bl:
                        codes = listings[bl]
                        if not codes:
                            raise Exception("NXDOMAIN")
                        return [MagicMock(__str__=lambda self, c=c: c) for c in codes]
                raise Exception("NXDOMAIN")
        return StubResolver

    def test_clean_domain_returns_pass(self):
        with patch.object(checks.dns.resolver, "Resolver",
                          self._dnsbl_stub({})):  # empty = all NXDOMAIN
            result = checks.check_domain_blacklists("example.com")

        assert result.status == "pass"
        assert result.points == 10
        raw = result.raw_data or {}
        assert raw.get("listed") == []

    def test_listed_on_dbl_returns_fail(self):
        with patch.object(checks.dns.resolver, "Resolver",
                          self._dnsbl_stub({"dbl.spamhaus.org": ["127.0.1.2"]})):
            result = checks.check_domain_blacklists("listed.example")

        assert result.status == "fail"
        assert result.points == 0
        assert result.max_points == 10
        assert "dbl.spamhaus.org" in (result.detail or "")
        raw = result.raw_data or {}
        assert len(raw.get("listed") or []) == 1
        # fix_steps must point at delisting flow
        assert result.fix_steps is not None
        assert any("spamhaus.org" in s for s in result.fix_steps)

    def test_error_code_does_not_flip_status(self):
        # INBOX-39 code range — treat as "couldn't query" not "listed".
        with patch.object(checks.dns.resolver, "Resolver",
                          self._dnsbl_stub({"dbl.spamhaus.org": ["127.255.255.254"]})):
            result = checks.check_domain_blacklists("example.com")

        assert result.status == "pass", (
            "INBOX-39 applies here too: 127.255.255.254 (public resolver "
            "block) is NOT a listing. Must not flip status to fail."
        )
        assert result.points == 10
        raw = result.raw_data or {}
        assert (raw.get("listed") or []) == []
        assert "dbl.spamhaus.org" in (raw.get("fully_errored_blacklists") or [])
        assert "could not be queried" in (result.detail or "")

    def test_multiple_dbls_different_outcomes(self):
        # Listed on DBL, errored on SURBL, clean on URIBL.
        listings = {
            "dbl.spamhaus.org": ["127.0.1.2"],         # real listing
            "multi.surbl.org": ["127.255.255.254"],    # error
            # URIBL not in map → NXDOMAIN (clean)
        }
        with patch.object(checks.dns.resolver, "Resolver",
                          self._dnsbl_stub(listings)):
            result = checks.check_domain_blacklists("bad.example")

        assert result.status == "fail"
        raw = result.raw_data or {}
        assert len(raw.get("listed") or []) == 1
        assert "multi.surbl.org" in (raw.get("fully_errored_blacklists") or [])


# --------------------------------------------------------------------
# INBOX-50 — URIBL 127.0.0.1 "Query Refused" sentinel handling
# --------------------------------------------------------------------

class TestCheckDomainBlacklistsUriblRefusal:
    """URIBL (and SURBL in some configs) return 127.0.0.1 with a TXT record
    to refuse public-resolver queries. We must NOT treat those as listings.

    Pinned evidence — URIBL live TXT record (2026-04-24):
        "127.0.0.1 -> Query Refused. See http://uribl.com/refused.shtml for
         more information [Your DNS IP: 162.158.215.32]"
    """

    def _stub_with_txt(self, a_map: dict, txt_map: dict | None = None):
        """Build a Resolver stub returning A + TXT per blacklist."""
        txt_map = txt_map or {}
        class StubResolver:
            def __init__(self):
                self.timeout = 2
                self.lifetime = 2
            def resolve(self, query, rtype):
                for bl, codes in a_map.items():
                    if query.endswith("." + bl) or query == bl:
                        if rtype == "A":
                            if not codes:
                                raise Exception("NXDOMAIN")
                            return [MagicMock(__str__=lambda self, c=c: c)
                                    for c in codes]
                        if rtype == "TXT":
                            txt = txt_map.get(bl)
                            if not txt:
                                raise Exception("NXDOMAIN")
                            return [MagicMock(__str__=lambda self, t=txt: t)]
                raise Exception("NXDOMAIN")
        return StubResolver

    def test_uribl_127_0_0_1_with_refused_txt_is_not_a_listing(self):
        """The voicenotes.com scenario — URIBL returns 127.0.0.1 with a TXT
        record documenting the refusal. Before INBOX-50 this produced a
        false FAIL ('listed on black.uribl.com')."""
        a_map = {
            "black.uribl.com": ["127.0.0.1"],
            # Other two DBLs don't answer
        }
        txt_map = {
            "black.uribl.com": '"127.0.0.1 -> Query Refused. See '
                               'http://uribl.com/refused.shtml for more "'
                               '"information [Your DNS IP: 1.2.3.4]"',
        }
        with patch.object(checks.dns.resolver, "Resolver",
                          self._stub_with_txt(a_map, txt_map)):
            result = checks.check_domain_blacklists("voicenotes.com")

        assert result.status != "fail", (
            "INBOX-50: a URIBL 127.0.0.1 refusal must NOT be treated as a "
            "listing. This was the exact voicenotes.com false positive."
        )
        raw = result.raw_data or {}
        assert (raw.get("listed") or []) == []
        assert "black.uribl.com" in (raw.get("fully_errored_blacklists") or [])

    def test_all_dbls_refuse_returns_info_not_pass(self):
        """When every DBL refuses, we literally cannot verify. Must report
        info-only (0/0 max_points) — NOT a false pass with 10/10."""
        a_map = {
            "dbl.spamhaus.org": ["127.255.255.254"],   # Spamhaus sentinel
            "multi.surbl.org": ["127.0.0.1"],           # refusal
            "black.uribl.com": ["127.0.0.1"],           # refusal
        }
        txt_map = {
            "multi.surbl.org": '"query blocked from public resolver"',
            "black.uribl.com": '"Query Refused. See uribl.com/refused.shtml"',
        }
        with patch.object(checks.dns.resolver, "Resolver",
                          self._stub_with_txt(a_map, txt_map)):
            result = checks.check_domain_blacklists("voicenotes.com")

        assert result.status == "info", (
            "All 3 DBLs refused → cannot verify → info-only, NOT pass."
        )
        assert result.max_points == 0, (
            "Info-only check must not contribute to the denominator — "
            "consistent with BIMI / Domain Age / MTA-STS."
        )
        assert result.points == 0
        raw = result.raw_data or {}
        assert raw.get("effectively_checked") == 0
        # External verification link — matches what the UI surfaces
        assert "hetrixtools" in (result.detail or "").lower()
        assert raw.get("external_verification_url", "").startswith(
            "https://hetrixtools.com/blacklist-check/"
        )

    def test_uribl_127_0_0_2_is_still_a_real_listing(self):
        """Spam listing codes (127.0.0.2/4/8/14) must NOT be overridden by
        the new 127.0.0.1 refusal logic."""
        a_map = {"black.uribl.com": ["127.0.0.2"]}  # URIBL black listing
        with patch.object(checks.dns.resolver, "Resolver",
                          self._stub_with_txt(a_map, {})):
            result = checks.check_domain_blacklists("actually-spammy.example")

        assert result.status == "fail"
        assert result.points == 0
        assert result.max_points == 10
        assert "black.uribl.com" in (result.detail or "")

    def test_127_0_0_1_without_txt_is_conservative_error(self):
        """If a DBL returns 127.0.0.1 but has no TXT to confirm the
        refusal, we still treat it as error — 127.0.0.1 is not a valid
        listing code on any major DBL, so assuming a real listing would
        generate false positives."""
        a_map = {
            "black.uribl.com": ["127.0.0.1"],
            "dbl.spamhaus.org": [],   # NXDOMAIN
            "multi.surbl.org": [],    # NXDOMAIN
        }
        with patch.object(checks.dns.resolver, "Resolver",
                          self._stub_with_txt(a_map, {})):  # no TXT
            result = checks.check_domain_blacklists("example.com")

        assert result.status != "fail"
        raw = result.raw_data or {}
        assert (raw.get("listed") or []) == []
        assert "black.uribl.com" in (raw.get("fully_errored_blacklists") or [])
