"""
Tests for InboxScore core check functions
Tests DNS-based checks (SPF, DKIM, DMARC, MX, blacklists) with mocked DNS
"""

import sys
import os
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from tests.conftest import mock_safe_dns_query


# ─── SPF CHECK TESTS ────────────────────────────────────────────

class TestCheckSPF:
    """Test SPF record checking logic"""

    @patch("checks.safe_dns_query", side_effect=mock_safe_dns_query)
    def test_spf_pass_hard_fail(self, mock_dns):
        from checks import check_spf
        result = check_spf("good.com")
        assert result.status == "pass"
        assert result.points == 15
        assert result.name == "spf"
        assert result.category == "authentication"

    @patch("checks.safe_dns_query", side_effect=mock_safe_dns_query)
    def test_spf_soft_fail_still_passes(self, mock_dns):
        """INBOX-73 (2026-04-26): ~all no longer docks 1 point. Google,
        Microsoft, Apple, Stripe all use ~all by design — DMARC p=reject
        does the heavy lifting for actual mail rejection. Industry tools
        (MXToolbox, Dmarcian, Google Postmaster) treat ~all as PASS."""
        from checks import check_spf
        result = check_spf("partial.com")
        assert result.status == "pass"
        assert result.points == 15  # INBOX-73: was 14, now full credit

    @patch("checks.safe_dns_query", return_value=None)
    def test_spf_missing(self, mock_dns):
        from checks import check_spf
        result = check_spf("bad.com")
        assert result.status == "fail"
        assert result.points == 0
        assert result.fix_steps is not None
        assert len(result.fix_steps) > 0

    @patch("checks.safe_dns_query", return_value=['"v=spf1 +all"'])
    def test_spf_plus_all_is_critical_fail(self, mock_dns):
        from checks import check_spf
        result = check_spf("dangerous.com")
        assert result.status == "fail"
        assert result.points == 0

    @patch("checks.safe_dns_query", return_value=['"v=spf1 ?all"'])
    def test_spf_neutral_is_warning(self, mock_dns):
        from checks import check_spf
        result = check_spf("neutral.com")
        assert result.status == "warn"
        assert result.points == 5


# ─── DMARC CHECK TESTS ──────────────────────────────────────────

class TestCheckDMARC:
    """Test DMARC policy checking logic"""

    @patch("checks.safe_dns_query")
    def test_dmarc_reject_full_score(self, mock_dns):
        mock_dns.return_value = ['"v=DMARC1; p=reject; rua=mailto:dmarc@good.com"']
        from checks import check_dmarc
        result = check_dmarc("good.com")
        assert result.status == "pass"
        assert result.points == 15
        assert result.raw_data["policy"] == "reject"

    @patch("checks.safe_dns_query")
    def test_dmarc_quarantine(self, mock_dns):
        mock_dns.return_value = ['"v=DMARC1; p=quarantine; rua=mailto:d@x.com"']
        from checks import check_dmarc
        result = check_dmarc("quarantine.com")
        assert result.status == "pass"
        assert result.points == 14
        assert result.raw_data["policy"] == "quarantine"

    @patch("checks.safe_dns_query")
    def test_dmarc_none_is_warning(self, mock_dns):
        mock_dns.return_value = ['"v=DMARC1; p=none; rua=mailto:d@x.com"']
        from checks import check_dmarc
        result = check_dmarc("weak.com")
        assert result.status == "warn"
        assert result.points == 10
        assert result.fix_steps is not None

    @patch("checks.safe_dns_query", return_value=None)
    def test_dmarc_missing(self, mock_dns):
        from checks import check_dmarc
        result = check_dmarc("nodmarc.com")
        assert result.status == "fail"
        assert result.points == 0

    @patch("checks.safe_dns_query")
    def test_dmarc_no_rua_deducts_points(self, mock_dns):
        mock_dns.return_value = ['"v=DMARC1; p=reject"']
        from checks import check_dmarc
        result = check_dmarc("norua.com")
        assert result.points == 13  # 15 - 2 for missing rua
        assert result.raw_data["has_rua"] is False


class TestCheckDMARCNuance:
    """INBOX-56 — full DMARC nuance: sp=, pct=, aspf=, adkim=, fo=.

    Pre-INBOX-56 every `p=reject` was 15/15 PASS. Two domains with
    identical p=reject can have very different real-world protection:
    one fully locked down, one with most mail unenforced and every
    subdomain wide open. This class covers each combination.

    Pinned to real-world records observed 2026-04-25:
      voicenotes.com — p=reject; pct=100, no sp= (inherits)  → 15/15
      mailercloud.com — p=reject; sp=reject; pct=100; fo=1   → 15/15
      microsoft.com  — p=reject; pct=100; fo=1               → 15/15
    """

    @patch("checks.safe_dns_query")
    def test_reject_pct_100_sp_reject_full_credit(self, mock_dns):
        """The mailercloud.com profile — fully locked down."""
        mock_dns.return_value = [
            '"v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@x.com; ruf=mailto:dmarc@x.com; fo=1"'
        ]
        from checks import check_dmarc
        result = check_dmarc("mailercloud-style.com")
        assert result.status == "pass"
        assert result.points == 15
        raw = result.raw_data or {}
        assert raw["policy"] == "reject"
        assert raw["sp"] == "reject"
        assert raw["pct"] == 100
        assert raw["fo"] == "1"
        # Detail must surface sp=reject and fo=1 — the differentiators
        d = result.detail or ""
        assert "subdomains protected" in d
        assert "fo=1" in d
        assert "100%" in d

    @patch("checks.safe_dns_query")
    def test_reject_pct_100_sp_inherited_full_credit(self, mock_dns):
        """The voicenotes.com profile — no explicit sp= (inherits p=reject
        per RFC). Must NOT be penalised — RFC says missing sp= inherits p=."""
        mock_dns.return_value = ['"v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@x.com"']
        from checks import check_dmarc
        result = check_dmarc("voicenotes-style.com")
        assert result.status == "pass"
        assert result.points == 15, (
            "Missing sp= must NOT be penalised — RFC 7489 §6.3 says sp= "
            "inherits p= when absent. voicenotes.com profile."
        )
        raw = result.raw_data or {}
        assert raw["sp"] is None
        assert "subdomains inherit" in (result.detail or "").lower()

    @patch("checks.safe_dns_query")
    def test_reject_sp_none_subdomain_takeover_risk(self, mock_dns):
        """Headline gap — p=reject; sp=none. Root protected, subdomains
        wide open. Must lose points and surface a clear warning."""
        mock_dns.return_value = ['"v=DMARC1; p=reject; sp=none; pct=100; rua=mailto:dmarc@x.com"']
        from checks import check_dmarc
        result = check_dmarc("subdomain-open.com")
        assert result.points == 13, (
            f"p=reject + sp=none must lose 2pts. Got {result.points}/15."
        )
        raw = result.raw_data or {}
        assert raw["sp"] == "none"
        assert "no DMARC policy" in (result.detail or "")
        # Fix steps must explain the subdomain risk
        fix = result.fix_steps or []
        assert any("subdomain" in s.lower() for s in fix)
        assert any("sp=" in s for s in fix)

    @patch("checks.safe_dns_query")
    def test_reject_pct_50_partial_enforcement_warning(self, mock_dns):
        """p=reject; pct=50 — 50% of mail unenforced. -3pts. Must surface
        the percentage warning explicitly."""
        mock_dns.return_value = ['"v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@x.com"']
        from checks import check_dmarc
        result = check_dmarc("half-enforced.com")
        assert result.points == 12, f"pct=50 → 15-3 = 12. Got {result.points}/15."
        raw = result.raw_data or {}
        assert raw["pct"] == 50
        d = result.detail or ""
        assert "50%" in d
        assert "unprotected" in d.lower()

    @patch("checks.safe_dns_query")
    def test_reject_pct_20_steep_penalty(self, mock_dns):
        """p=reject; pct=20 — most mail wide open. -5pts."""
        mock_dns.return_value = ['"v=DMARC1; p=reject; pct=20; rua=mailto:dmarc@x.com"']
        from checks import check_dmarc
        result = check_dmarc("mostly-unenforced.com")
        assert result.points == 10, f"pct=20 → 15-5 = 10. Got {result.points}/15."
        d = result.detail or ""
        assert "20%" in d

    @patch("checks.safe_dns_query")
    def test_combined_pct_and_sp_gaps_stack(self, mock_dns):
        """p=reject; pct=20; sp=none — both gaps present, both penalties stack.
        15 - 5 (pct) - 2 (sp) = 8."""
        mock_dns.return_value = [
            '"v=DMARC1; p=reject; pct=20; sp=none; rua=mailto:dmarc@x.com"'
        ]
        from checks import check_dmarc
        result = check_dmarc("very-broken.com")
        assert result.points == 8, (
            f"pct=20 + sp=none stacks penalties: 15-5-2=8. Got {result.points}."
        )
        # Status promotes to warn (8-11 range)
        assert result.status == "warn"

    @patch("checks.safe_dns_query")
    def test_strict_alignment_surfaced_in_detail(self, mock_dns):
        """aspf=s + adkim=s should be surfaced in the detail. No extra
        points (we're already at 15) but it's a visibility win."""
        mock_dns.return_value = [
            '"v=DMARC1; p=reject; pct=100; aspf=s; adkim=s; rua=mailto:dmarc@x.com"'
        ]
        from checks import check_dmarc
        result = check_dmarc("strict-aligned.com")
        assert result.points == 15
        raw = result.raw_data or {}
        assert raw["strict_alignment"] is True
        assert "strict alignment" in (result.detail or "").lower()

    @patch("checks.safe_dns_query")
    def test_quarantine_subdomain_protected(self, mock_dns):
        """p=quarantine; sp=quarantine — quarantine baseline (14) with
        sp= surfaced."""
        mock_dns.return_value = [
            '"v=DMARC1; p=quarantine; sp=quarantine; pct=100; rua=mailto:dmarc@x.com"'
        ]
        from checks import check_dmarc
        result = check_dmarc("quarantine-secured.com")
        assert result.points == 14
        d = result.detail or ""
        assert "quarantine" in d.lower()
        assert "subdomains quarantined" in d.lower()

    @patch("checks.safe_dns_query")
    def test_multistring_dmarc_record_parses(self, mock_dns):
        """INBOX-52 reuse — DMARC records can also span multiple TXT
        strings (rare but possible). Must parse correctly."""
        mock_dns.return_value = [
            '"v=DMARC1; p=reject;" " sp=reject; pct=100; rua=mailto:dmarc@x.com"'
        ]
        from checks import check_dmarc
        result = check_dmarc("multistring-dmarc.com")
        assert result.points == 15
        raw = result.raw_data or {}
        assert raw["policy"] == "reject"
        assert raw["sp"] == "reject"
        assert raw["pct"] == 100

    @patch("checks.safe_dns_query")
    def test_voicenotes_comma_separator_typo_tolerated(self, mock_dns):
        """voicenotes.com's actual record has `pct=100, rua=...` (comma
        instead of semicolon between tags). RFC says semicolon-separated
        but real-world records use commas. Be tolerant — parse anyway."""
        mock_dns.return_value = [
            '"v=DMARC1; p=reject; pct=100, rua=mailto:dmarc@mlrcloud.com; ruf=mailto:dmarc@mlrcloud.com"'
        ]
        from checks import check_dmarc
        result = check_dmarc("voicenotes.com")
        # rua MUST still be detected even though the typo separates pct,rua
        # with a comma. Otherwise we'd lose 2pts incorrectly.
        assert result.raw_data["has_rua"] is True
        assert result.points == 15

    @patch("checks.safe_dns_query")
    def test_fo_1_surfaced(self, mock_dns):
        """fo=1 (forensic on any failure) — mature DMARC posture, surface."""
        mock_dns.return_value = [
            '"v=DMARC1; p=reject; pct=100; fo=1; rua=mailto:dmarc@x.com; ruf=mailto:dmarc@x.com"'
        ]
        from checks import check_dmarc
        result = check_dmarc("mature.com")
        assert result.points == 15
        assert "fo=1" in (result.detail or "")


# ─── MX RECORDS TESTS ───────────────────────────────────────────

class TestCheckMX:
    """Test MX record checking"""

    def test_mx_multiple_records_pass(self):
        """Two MX records should get full score"""
        from checks import check_mx_records

        with patch("dns.resolver.Resolver") as MockResolver:
            mock_resolver = MagicMock()
            MockResolver.return_value = mock_resolver

            # Create mock MX answers
            mx1 = MagicMock()
            mx1.preference = 10
            mx1.exchange = MagicMock()
            mx1.exchange.__str__ = lambda self: "mail1.good.com."

            mx2 = MagicMock()
            mx2.preference = 20
            mx2.exchange = MagicMock()
            mx2.exchange.__str__ = lambda self: "mail2.good.com."

            mock_resolver.resolve.return_value = [mx1, mx2]

            result = check_mx_records("good.com")
            assert result.status == "pass"
            assert result.points == 10

    def test_mx_single_record(self):
        """One MX record (non-load-balanced) should pass but with redundancy note."""
        from checks import check_mx_records

        with patch("dns.resolver.Resolver") as MockResolver:
            mock_resolver = MagicMock()
            MockResolver.return_value = mock_resolver

            mx1 = MagicMock()
            mx1.preference = 10
            mx1.exchange = MagicMock()
            mx1.exchange.__str__ = lambda self: "mail.single.com."

            mock_resolver.resolve.return_value = [mx1]

            result = check_mx_records("single.com")
            assert result.status == "pass"
            assert result.points == 9
            assert "backup" in result.detail.lower() or "redundancy" in result.detail.lower()


class TestCheckMXLoadBalancedProvider:
    """INBOX-72 (2026-04-26) — single MX resolving to a known load-balanced
    provider pool (Google, Microsoft, Proofpoint, Mimecast) gets full
    10/10. The redundancy is at the IP layer — `smtp.google.com` resolves
    to dozens of mail servers behind one DNS name. Pre-INBOX-72 we docked
    1 point at the DNS layer when redundancy actually existed."""

    def _mx_check_with_single_host(self, mx_host_value):
        """Helper — patches dns.resolver to return a single MX with the
        given host. The MX-resolution check is patched separately to
        return True so we hit the all_resolved branch."""
        from checks import check_mx_records

        with patch("dns.resolver.Resolver") as MockResolver, \
             patch("checks.safe_dns_query", return_value=["1.2.3.4"]):
            mock_resolver = MagicMock()
            MockResolver.return_value = mock_resolver
            mx1 = MagicMock()
            mx1.preference = 10
            mx1.exchange = MagicMock()
            mx1.exchange.__str__ = lambda self: mx_host_value
            mock_resolver.resolve.return_value = [mx1]
            return check_mx_records("test.example")

    def test_google_smtp_single_mx_gets_full_credit(self):
        """smtp.google.com is Google's load-balanced pool — IP-layer redundancy."""
        result = self._mx_check_with_single_host("smtp.google.com.")
        assert result.status == "pass"
        assert result.points == 10, (
            "INBOX-72: was 9/10 (docked for 'no backup'), now 10/10 "
            "because smtp.google.com is load-balanced across many IPs"
        )
        assert "provider pool" in (result.detail or "").lower() or \
               "ip-layer" in (result.detail or "").lower()

    def test_microsoft_outlook_single_mx_gets_full_credit(self):
        """*.protection.outlook.com is Microsoft 365's load-balanced pool."""
        result = self._mx_check_with_single_host("acme-com.mail.protection.outlook.com.")
        assert result.status == "pass"
        assert result.points == 10

    def test_proofpoint_single_mx_gets_full_credit(self):
        """*.pphosted.com is Proofpoint's load-balanced pool."""
        result = self._mx_check_with_single_host("mx0a-001.pphosted.com.")
        assert result.status == "pass"
        assert result.points == 10

    def test_self_hosted_single_mx_still_docked(self):
        """Non-load-balanced single MX still gets 9/10 with backup advice.
        Preserves the original behaviour for genuine single-server setups."""
        result = self._mx_check_with_single_host("mail.selfhosted.example.")
        assert result.status == "pass"
        assert result.points == 9
        assert "backup" in (result.detail or "").lower() or \
               "redundancy" in (result.detail or "").lower()


class TestCheckMXReachability:
    """INBOX-58 — MX hostname resolution check.

    Pre-INBOX-58 the MX check was structural-only: 10/10 PASS for any
    domain with ≥2 MX records, even if every MX host pointed at a
    non-existent server. INBOX-44 audit flagged this as a false-PASS
    risk. We now verify each MX host has an A or AAAA record.

    L1 only — DNS resolution. SMTP-banner check (L2) is deferred since
    Render blocks outbound port 25.
    """

    def _build_mx_resolver_mock(self, mx_hosts: list, resolves_map: dict):
        """Helper: mock dns.resolver.Resolver such that
        resolve(domain, 'MX') returns the given hosts, and
        safe_dns_query(host, 'A'/'AAAA') returns truthy iff
        resolves_map[host] is True.
        """
        from unittest.mock import patch, MagicMock

        # Build MX answer objects (priority + exchange)
        mx_answers = []
        for i, host in enumerate(mx_hosts):
            mx = MagicMock()
            mx.preference = 10 * (i + 1)
            mx.exchange = MagicMock()
            mx.exchange.__str__ = lambda self, h=host: h + "."
            mx_answers.append(mx)
        return mx_answers

    def test_all_mx_resolve_returns_10_of_10(self):
        """Happy path: ≥2 MX records, all resolve → 10/10 PASS."""
        from unittest.mock import patch, MagicMock

        with patch("dns.resolver.Resolver") as MockResolver, \
             patch("checks.safe_dns_query") as mock_sdq:

            mock_resolver = MagicMock()
            MockResolver.return_value = mock_resolver
            mock_resolver.resolve.return_value = self._build_mx_resolver_mock(
                ["aspmx.l.google.com", "alt1.aspmx.l.google.com"], {}
            )
            # All A/AAAA queries return a truthy result
            mock_sdq.return_value = ["1.2.3.4"]

            from checks import check_mx_records
            result = check_mx_records("good.com")
            assert result.status == "pass"
            assert result.points == 10
            assert (result.raw_data or {}).get("all_resolved") is True
            assert (result.raw_data or {}).get("unresolved_count") == 0

    def test_some_mx_unresolvable_returns_warn_7(self):
        """≥2 MX, some don't resolve → 7/10 WARN — partial reachability,
        identifies the broken host(s) by name."""
        from unittest.mock import patch, MagicMock

        hosts = ["good.example.com", "broken.example.com"]

        def sdq_side_effect(qname, rdtype, timeout=2):
            if rdtype in ("A", "AAAA") and qname == "good.example.com":
                return ["1.2.3.4"]
            return None  # broken.example.com → NXDOMAIN-equivalent

        with patch("dns.resolver.Resolver") as MockResolver, \
             patch("checks.safe_dns_query", side_effect=sdq_side_effect):

            mock_resolver = MagicMock()
            MockResolver.return_value = mock_resolver
            mock_resolver.resolve.return_value = self._build_mx_resolver_mock(hosts, {})

            from checks import check_mx_records
            result = check_mx_records("partial.com")
            assert result.status == "warn"
            assert result.points == 7
            assert "broken.example.com" in (result.detail or "")
            assert (result.raw_data or {}).get("unresolved_count") == 1
            assert (result.raw_data or {}).get("all_resolved") is False
            assert result.fix_steps is not None

    def test_all_mx_unresolvable_returns_fail_3(self):
        """≥2 MX, NONE resolve → 3/10 FAIL — domain can't accept mail.
        This is the headline false-PASS case INBOX-58 closes."""
        from unittest.mock import patch, MagicMock

        hosts = ["mail1.dead.example", "mail2.dead.example"]

        with patch("dns.resolver.Resolver") as MockResolver, \
             patch("checks.safe_dns_query", return_value=None):

            mock_resolver = MagicMock()
            MockResolver.return_value = mock_resolver
            mock_resolver.resolve.return_value = self._build_mx_resolver_mock(hosts, {})

            from checks import check_mx_records
            result = check_mx_records("dead.example")
            assert result.status == "fail"
            assert result.points == 3
            assert "NONE resolve" in (result.detail or "") or "none resolve" in (result.detail or "").lower()
            assert (result.raw_data or {}).get("all_resolved") is False
            assert result.fix_steps is not None

    def test_single_mx_resolves_returns_9(self):
        """1 MX that resolves → 9/10 PASS (regression — backup suggestion)."""
        from unittest.mock import patch, MagicMock

        with patch("dns.resolver.Resolver") as MockResolver, \
             patch("checks.safe_dns_query", return_value=["1.2.3.4"]):

            mock_resolver = MagicMock()
            MockResolver.return_value = mock_resolver
            mock_resolver.resolve.return_value = self._build_mx_resolver_mock(
                ["mail.single.com"], {}
            )

            from checks import check_mx_records
            result = check_mx_records("single-good.com")
            assert result.status == "pass"
            assert result.points == 9
            assert "backup" in (result.detail or "").lower() or "redundancy" in (result.detail or "").lower()

    def test_single_mx_unresolvable_returns_fail_3(self):
        """1 MX that doesn't resolve → 3/10 FAIL (new INBOX-58 behavior)."""
        from unittest.mock import patch, MagicMock

        with patch("dns.resolver.Resolver") as MockResolver, \
             patch("checks.safe_dns_query", return_value=None):

            mock_resolver = MagicMock()
            MockResolver.return_value = mock_resolver
            mock_resolver.resolve.return_value = self._build_mx_resolver_mock(
                ["mail.broken.example"], {}
            )

            from checks import check_mx_records
            result = check_mx_records("single-broken.com")
            assert result.status == "fail"
            assert result.points == 3
            assert "mail.broken.example" in (result.detail or "")

    def test_mx_resolves_via_aaaa_only(self):
        """An MX host with only AAAA (IPv6) but no A still counts as
        resolvable. Some modern providers are IPv6-only."""
        from unittest.mock import patch, MagicMock

        def sdq_side_effect(qname, rdtype, timeout=2):
            if rdtype == "AAAA":
                return ["2001:db8::1"]
            return None  # No A record

        with patch("dns.resolver.Resolver") as MockResolver, \
             patch("checks.safe_dns_query", side_effect=sdq_side_effect):

            mock_resolver = MagicMock()
            MockResolver.return_value = mock_resolver
            mock_resolver.resolve.return_value = self._build_mx_resolver_mock(
                ["v6only.example", "v6-also.example"], {}
            )

            from checks import check_mx_records
            result = check_mx_records("ipv6-only.example")
            assert result.status == "pass"
            assert result.points == 10


# ─── DKIM CHECK TESTS ───────────────────────────────────────────

class TestCheckDKIM:
    """Test DKIM selector probing"""

    @patch("checks.safe_dns_query")
    def test_dkim_found_2048bit(self, mock_dns):
        def dns_side_effect(qname, rdtype, timeout=2):
            if "default._domainkey" in qname and rdtype == "TXT":
                # Return a long enough key to be detected as 2048-bit
                return ['"v=DKIM1; k=rsa; p=' + 'A' * 400 + '"']
            return None

        mock_dns.side_effect = dns_side_effect
        from checks import check_dkim
        result = check_dkim("good.com")
        assert result.status == "pass"
        assert result.points == 15
        assert len(result.raw_data["selectors"]) >= 1

    @patch("checks.safe_dns_query", return_value=None)
    def test_dkim_not_found(self, mock_dns):
        from checks import check_dkim
        result = check_dkim("nodkim.com")
        assert result.status == "fail"
        assert result.points == 0
        assert result.fix_steps is not None


class TestCheckDKIMMultiStringTxt:
    """INBOX-52 regression — DKIM key-size detection across multi-string TXT
    records. dnspython renders a multi-string TXT as `"PART1" "PART2"`. Real
    2048-bit DKIM keys are commonly split this way because each TXT string is
    capped at 255 bytes. Before INBOX-52, our regex stopped at the
    quote-space-quote junction and miscounted the key as 1024-bit.

    Pinned evidence — voicenotes.com k1 selector (2026-04-25):
    A real 2048-bit RSA DKIM key returned by dnspython as
    `'"v=DKIM1; k=rsa; p=MIIBIj...DGm" "zOXf...QAB"'` (415 chars, junction
    at offset 254). Pre-fix → reported as 1024-bit; post-fix → 2048-bit.
    """

    @patch("checks.safe_dns_query")
    def test_multistring_2048bit_key_correctly_identified(self, mock_dns):
        """Multi-string TXT containing a 2048-bit key must score 15/15
        with key_length='2048-bit', not 14/15 with false 1024-bit warning."""
        # Build a realistic multi-string TXT: enough base64 chars total to
        # exceed 2000 (2048-bit boundary), but split across two strings.
        part1_b64 = "A" * 230   # 230 chars × 6 = 1380 bits — falls in 1024 bucket
        part2_b64 = "B" * 170   # combined 400 chars × 6 = 2400 bits — 2048-bit
        multistring = f'"v=DKIM1; k=rsa; p={part1_b64}" "{part2_b64}"'

        def dns_side_effect(qname, rdtype, timeout=2):
            if "default._domainkey" in qname and rdtype == "TXT":
                return [multistring]
            return None

        mock_dns.side_effect = dns_side_effect
        from checks import check_dkim
        result = check_dkim("voicenotes-style.com")

        assert result.status == "pass"
        assert result.points == 15, (
            f"INBOX-52: multi-string 2048-bit DKIM must score 15/15, "
            f"got {result.points}/15. Did the regex stop at the "
            f"quote-space-quote junction again?"
        )
        assert result.max_points == 15
        # Key length must be reported correctly
        sels = (result.raw_data or {}).get("selectors", [])
        assert sels
        assert sels[0].get("key_length") == "2048-bit"
        # No '1024-bit' upgrade warning in the detail
        assert "1024-bit" not in (result.detail or "")

    @patch("checks.safe_dns_query")
    def test_singlestring_1024bit_still_warns_correctly(self, mock_dns):
        """Regression: a real 1024-bit key (single-string, ~216 chars b64)
        must still trigger the 14/15 upgrade warning."""
        single_1024 = '"v=DKIM1; k=rsa; p=' + "A" * 200 + '"'  # 200 × 6 = 1200 bits

        def dns_side_effect(qname, rdtype, timeout=2):
            if "default._domainkey" in qname and rdtype == "TXT":
                return [single_1024]
            return None

        mock_dns.side_effect = dns_side_effect
        from checks import check_dkim
        result = check_dkim("legacy-1024.com")

        assert result.status == "pass"
        assert result.points == 14, (
            "1024-bit single-string DKIM must still warn (14/15)"
        )
        # INBOX-77: technical detail moved to raw_data — user-facing
        # message uses plain English ("older weaker encryption").
        d = (result.detail or "").lower()
        assert "older" in d or "weaker" in d or "weak" in d, (
            "Detail must signal weak encryption in plain language"
        )
        sels = (result.raw_data or {}).get("selectors", [])
        assert sels and sels[0].get("key_length") == "1024-bit"
        # Technical detail still available for support staff
        tech = (result.raw_data or {}).get("technical_detail", "")
        assert "1024" in tech, (
            "raw_data.technical_detail must preserve bit count for support"
        )

    @patch("checks.safe_dns_query")
    def test_singlestring_2048bit_unchanged(self, mock_dns):
        """Regression: a single-string 2048-bit key (rare in practice but
        possible if the b64 fits in 255 bytes) must continue to score 15/15."""
        # ~410 chars b64, single-string (right at the TXT byte limit edge)
        single_2048 = '"v=DKIM1; k=rsa; p=' + "A" * 380 + '"'

        def dns_side_effect(qname, rdtype, timeout=2):
            if "default._domainkey" in qname and rdtype == "TXT":
                return [single_2048]
            return None

        mock_dns.side_effect = dns_side_effect
        from checks import check_dkim
        result = check_dkim("modern-2048.com")
        assert result.status == "pass"
        assert result.points == 15
        sels = (result.raw_data or {}).get("selectors", [])
        assert sels and sels[0].get("key_length") == "2048-bit"

    @patch("checks.safe_dns_query")
    def test_revoked_key_handled(self, mock_dns):
        """A revoked DKIM key (p=;) must not crash. Reports as revoked,
        not as a real key. Detail should make this clear."""
        revoked = '"v=DKIM1; k=rsa; p="'

        def dns_side_effect(qname, rdtype, timeout=2):
            if "default._domainkey" in qname and rdtype == "TXT":
                return [revoked]
            return None

        mock_dns.side_effect = dns_side_effect
        from checks import check_dkim
        # Should not crash. Behavior — selector found but key empty —
        # acceptable so long as it doesn't false-PASS as 2048-bit.
        result = check_dkim("revoked-key.com")
        sels = (result.raw_data or {}).get("selectors", [])
        if sels:
            kl = sels[0].get("key_length", "")
            assert kl in ("revoked (p=;)", "unknown", "~0-bit"), (
                f"Revoked key should not be classified as 2048/1024-bit, got {kl!r}"
            )


class TestCheckDKIMSelectorExpansion:
    """INBOX-57 — expanded selector dictionary (17 → ~50) covering common
    transactional providers that were producing false-FAILs.

    Pre-INBOX-57 we probed only 17 selectors. Real senders using Mandrill
    (mte1-mte5), Postmark (pm), Resend (resend), Klaviyo (klaviyo), Brevo
    (sib), or Zoho (zoho) hit a flat 0/15 FAIL even when DKIM was working.
    """

    @patch("checks.safe_dns_query")
    def test_postmark_selector_pm_now_found(self, mock_dns):
        """Postmark's `pm` selector — was missing pre-INBOX-57."""
        good_2048 = '"v=DKIM1; k=rsa; p=' + "A" * 380 + '"'

        def side(qname, rdtype, timeout=2):
            if qname == "pm._domainkey.postmark-user.com" and rdtype == "TXT":
                return [good_2048]
            return None

        mock_dns.side_effect = side
        from checks import check_dkim
        r = check_dkim("postmark-user.com")
        assert r.status == "pass"
        sels = (r.raw_data or {}).get("selectors", [])
        assert any(s.get("selector") == "pm" for s in sels)

    @patch("checks.safe_dns_query")
    def test_resend_selector_now_found(self, mock_dns):
        """Resend's `resend` selector — was missing pre-INBOX-57.
        Voicenotes.com actually has this selector live (audited 2026-04-25)."""
        good_2048 = '"v=DKIM1; k=rsa; p=' + "A" * 380 + '"'

        def side(qname, rdtype, timeout=2):
            if qname == "resend._domainkey.resend-user.com" and rdtype == "TXT":
                return [good_2048]
            return None

        mock_dns.side_effect = side
        from checks import check_dkim
        r = check_dkim("resend-user.com")
        assert r.status == "pass"
        sels = (r.raw_data or {}).get("selectors", [])
        assert any(s.get("selector") == "resend" for s in sels)

    @patch("checks.safe_dns_query")
    def test_mandrill_mte_selectors_now_found(self, mock_dns):
        """Mandrill rotates mte1-mte9. Pre-INBOX-57 we only had `mandrill`
        which doesn't catch the actual signing selector."""
        good_2048 = '"v=DKIM1; k=rsa; p=' + "A" * 380 + '"'

        def side(qname, rdtype, timeout=2):
            if qname == "mte1._domainkey.mandrill-user.com" and rdtype == "TXT":
                return [good_2048]
            return None

        mock_dns.side_effect = side
        from checks import check_dkim
        r = check_dkim("mandrill-user.com")
        assert r.status == "pass"
        sels = (r.raw_data or {}).get("selectors", [])
        assert any(s.get("selector") == "mte1" for s in sels)

    @patch("checks.safe_dns_query")
    def test_klaviyo_selector_now_found(self, mock_dns):
        """Klaviyo (B2C marketing) — `klaviyo`/`klaviyo1`/`klaviyo2`."""
        good_2048 = '"v=DKIM1; k=rsa; p=' + "A" * 380 + '"'

        def side(qname, rdtype, timeout=2):
            if qname == "klaviyo1._domainkey.b2c-shop.com" and rdtype == "TXT":
                return [good_2048]
            return None

        mock_dns.side_effect = side
        from checks import check_dkim
        r = check_dkim("b2c-shop.com")
        assert r.status == "pass"
        sels = (r.raw_data or {}).get("selectors", [])
        assert any(s.get("selector") == "klaviyo1" for s in sels)

    @patch("checks.safe_dns_query")
    def test_zoho_selector_now_found(self, mock_dns):
        """Zoho's `zoho`/`zohomail` selectors."""
        good_2048 = '"v=DKIM1; k=rsa; p=' + "A" * 380 + '"'

        def side(qname, rdtype, timeout=2):
            if qname == "zoho._domainkey.zoho-shop.com" and rdtype == "TXT":
                return [good_2048]
            return None

        mock_dns.side_effect = side
        from checks import check_dkim
        r = check_dkim("zoho-shop.com")
        assert r.status == "pass"
        sels = (r.raw_data or {}).get("selectors", [])
        assert any(s.get("selector") == "zoho" for s in sels)

    @patch("checks.safe_dns_query")
    def test_no_dkim_messaging_includes_external_verifier(self, mock_dns):
        """When no selector matches, the fix_steps must point users to an
        external verifier — many senders use random/rotating selectors
        (AWS SES, HubSpot, Salesforce MC) that we genuinely can't probe.

        INBOX-77: detail is now plain English ("Your emails aren't signed");
        the dkimvalidator.com / port25.com pointer moved to fix_steps
        (which is where actionable advice lives)."""
        mock_dns.return_value = None
        from checks import check_dkim
        r = check_dkim("rotating-selector.com")
        assert r.status == "fail"
        assert r.points == 0
        # External-verifier reference moved from detail to fix_steps
        fix_text = " ".join(r.fix_steps or []).lower()
        assert "dkimvalidator" in fix_text or "port25" in fix_text, (
            "No-DKIM fix_steps must point to an external verifier — many "
            "real senders use random selectors we can't probe."
        )
        # raw_data should expose the count of probed selectors. INBOX-69
        # expanded the probe list from DKIM_SELECTORS (~47) to
        # DKIM_PROBE_SELECTORS (~102 = static + known-rotating + last
        # 24 months of YYYYMM01/15 candidates). The test now asserts on
        # the broader probe list and that we surface a representative
        # sample for transparency.
        raw = r.raw_data or {}
        assert raw.get("checked_count") == len(__import__("checks").DKIM_PROBE_SELECTORS)
        assert len(raw.get("checked_selectors_sample", [])) >= 10

    def test_dkim_selectors_list_has_expected_providers(self):
        """Sanity check — the canonical providers must be in the list.
        If someone removes one of these, this test fails."""
        from checks import DKIM_SELECTORS
        required = {
            "default", "selector1", "selector2", "google",
            "k1", "k2", "s1", "s2",
            "mandrill", "mte1", "mte2",
            "pm", "postmark",
            "resend",
            "klaviyo", "klaviyo1",
            "zoho",
            "smtpapi", "m1",  # SendGrid
            "krs", "mxvault",  # Mailgun
            "sib",  # Brevo
            "amazonses",
            "mlrcloud",  # Mailercloud's own
        }
        actual = set(DKIM_SELECTORS)
        missing = required - actual
        assert not missing, f"Required DKIM selectors missing from list: {missing}"
        assert len(DKIM_SELECTORS) >= 40, (
            f"DKIM_SELECTORS should be ~50 after INBOX-57 expansion, "
            f"got only {len(DKIM_SELECTORS)}"
        )


class TestCheckDKIMMixedKeyMessaging:
    """INBOX-62 — when multiple DKIM selectors are found with mixed key
    sizes, the detail must name the WEAK selector specifically rather
    than implying the main key is weak.

    Pinned to voicenotes.com Tier-3 finding (2026-04-25): selectors k1
    (2048-bit) + resend (1024-bit) was producing the misleading message
    "DKIM configured for selectors: k1, resend — using 1024-bit key".
    Now reads "selector `resend` uses a legacy 1024-bit key".
    """

    @patch("checks.safe_dns_query")
    def test_mixed_keys_names_the_weak_selector(self, mock_dns):
        """The voicenotes.com case — k1 strong + resend weak.
        INBOX-77: detail is now plain English; per-selector bit info
        moved to raw_data.technical_detail for support visibility."""
        strong_2048 = '"v=DKIM1; k=rsa; p=' + "A" * 380 + '"'
        weak_1024 = '"v=DKIM1; k=rsa; p=' + "A" * 200 + '"'

        def side(qname, rdtype, timeout=2):
            if qname == "k1._domainkey.mixed-keys.com" and rdtype == "TXT":
                return [strong_2048]
            if qname == "resend._domainkey.mixed-keys.com" and rdtype == "TXT":
                return [weak_1024]
            return None

        mock_dns.side_effect = side
        from checks import check_dkim
        r = check_dkim("mixed-keys.com")
        assert r.points == 14, "Mixed keys: still 14/15"
        assert r.status == "pass"
        d = r.detail or ""
        # Must name `resend` as the weak one (in plain-English detail or fix_steps)
        fix_text = " ".join(r.fix_steps or [])
        assert "`resend`" in d or "`resend`" in fix_text, (
            "Detail or fix_steps must name the weak selector `resend`."
        )
        # Plain English signalling
        assert "older" in d.lower() or "weaker" in d.lower(), (
            "INBOX-77: detail must use plain language ('older'/'weaker'), "
            "not bit counts"
        )
        # raw_data must distinguish weak vs strong selectors
        raw = r.raw_data or {}
        assert "resend" in (raw.get("weak_selectors") or [])
        assert "k1" in (raw.get("strong_selectors") or [])
        # Technical detail with bit counts preserved for support
        tech = raw.get("technical_detail", "")
        assert "1024-bit" in tech and "2048-bit" in tech, (
            "raw_data.technical_detail must preserve bit counts for support"
        )
        # Fix steps must guide to the specific selector
        assert "`resend`" in fix_text or "resend" in fix_text
        # Fix steps must reassure user that the strong selectors are fine
        assert "already strong" in fix_text or "already 2048-bit" in fix_text or \
               "Don't touch your other" in fix_text, (
            "Fix steps must reassure user that the strong selectors are fine"
        )

    @patch("checks.safe_dns_query")
    def test_all_weak_keeps_existing_behavior(self, mock_dns):
        """All selectors 1024-bit — INBOX-77 plain-English wording.
        Score stays 14/15 but message uses 'older weaker encryption' not
        '1024-bit'."""
        weak = '"v=DKIM1; k=rsa; p=' + "A" * 200 + '"'

        def side(qname, rdtype, timeout=2):
            if qname == "default._domainkey.all-weak.com" and rdtype == "TXT":
                return [weak]
            if qname == "selector1._domainkey.all-weak.com" and rdtype == "TXT":
                return [weak]
            return None

        mock_dns.side_effect = side
        from checks import check_dkim
        r = check_dkim("all-weak.com")
        assert r.points == 14
        d = (r.detail or "").lower()
        # Plain English signal that keys are weak
        assert "older" in d or "weaker" in d or "older weaker" in d
        # No "your other selectors are 2048-bit" language — they aren't
        fix = " ".join(r.fix_steps or [])
        assert "already strong" not in fix and "already 2048-bit" not in fix
        # Technical detail still in raw_data
        raw = r.raw_data or {}
        assert "1024" in raw.get("technical_detail", "")

    @patch("checks.safe_dns_query")
    def test_all_strong_unchanged(self, mock_dns):
        """All selectors 2048-bit — perfect score, INBOX-77 plain English.
        Detail leads with the user-positive framing ('signed with strong,
        modern encryption') and includes the selector names. Bit counts
        moved to raw_data.technical_detail for support."""
        strong = '"v=DKIM1; k=rsa; p=' + "A" * 380 + '"'

        def side(qname, rdtype, timeout=2):
            if qname == "default._domainkey.all-strong.com" and rdtype == "TXT":
                return [strong]
            if qname == "selector1._domainkey.all-strong.com" and rdtype == "TXT":
                return [strong]
            return None

        mock_dns.side_effect = side
        from checks import check_dkim
        r = check_dkim("all-strong.com")
        assert r.points == 15
        d = r.detail or ""
        # No warning language for all-strong
        assert "older" not in d.lower() and "weaker" not in d.lower()
        # Plain-English positive framing
        d_lower = d.lower()
        assert "signed" in d_lower or "modern" in d_lower or "strong" in d_lower
        # Selector names still surfaced (in backticks per INBOX-77)
        assert "`default`" in d or "`selector1`" in d
        # Bit counts moved to technical_detail
        tech = (r.raw_data or {}).get("technical_detail", "")
        assert "2048-bit" in tech


# ─── SCORE CALCULATION TESTS ────────────────────────────────────

class TestScoreCalculation:
    """Test that overall scores calculate correctly"""

    def test_score_is_percentage_of_points(self):
        """Score should be total_points / max_points * 100"""
        from checks import CheckResult

        checks = [
            CheckResult(name="a", category="auth", status="pass", title="A", detail="ok", points=10, max_points=10),
            CheckResult(name="b", category="auth", status="pass", title="B", detail="ok", points=5, max_points=10),
            CheckResult(name="c", category="rep", status="fail", title="C", detail="bad", points=0, max_points=10),
        ]

        total_points = sum(c.points for c in checks)
        max_points = sum(c.max_points for c in checks if c.max_points > 0)
        score = min(100, round((total_points / max_points * 100))) if max_points > 0 else 0

        assert total_points == 15
        assert max_points == 30
        assert score == 50

    def test_perfect_score(self):
        from checks import CheckResult
        checks = [
            CheckResult(name="a", category="auth", status="pass", title="A", detail="ok", points=15, max_points=15),
            CheckResult(name="b", category="rep", status="pass", title="B", detail="ok", points=10, max_points=10),
        ]
        total = sum(c.points for c in checks)
        maximum = sum(c.max_points for c in checks if c.max_points > 0)
        score = min(100, round((total / maximum * 100)))
        assert score == 100

    def test_zero_score(self):
        from checks import CheckResult
        checks = [
            CheckResult(name="a", category="auth", status="fail", title="A", detail="bad", points=0, max_points=15),
            CheckResult(name="b", category="rep", status="fail", title="B", detail="bad", points=0, max_points=10),
        ]
        total = sum(c.points for c in checks)
        maximum = sum(c.max_points for c in checks if c.max_points > 0)
        score = min(100, round((total / maximum * 100)))
        assert score == 0


class TestCheckDKIMRotatingSelectors:
    """INBOX-69 — date-based rotating DKIM selectors (Google, Apple,
    Stripe, AWS, Cloudflare). google.com publishes selectors in
    YYYYMMDD format with frequent rotation. Without probing date-based
    candidates we returned FAIL 0/15 for the entire major-sender class.

    Pinned to google.com finding (2026-04-26):
      - 20221208._domainkey.google.com → revoked (p=;)
      - 20210112._domainkey.google.com → revoked (p=;)
      - 20230601._domainkey.google.com → likely current active
    """

    def test_probe_list_includes_known_rotating(self):
        """KNOWN_ROTATING_SELECTORS must appear in DKIM_PROBE_SELECTORS."""
        from checks import DKIM_PROBE_SELECTORS
        for known in ["20230601", "20221208", "20210112", "s2048"]:
            assert known in DKIM_PROBE_SELECTORS, (
                f"INBOX-69: rotating selector `{known}` must be probed"
            )

    def test_probe_list_includes_recent_monthly_dates(self):
        """The last 24 months of YYYYMM01 / YYYYMM15 must be probed."""
        from checks import DKIM_PROBE_SELECTORS, _generate_monthly_selectors
        recent = _generate_monthly_selectors(months_back=24)
        assert len(recent) >= 40, (
            "Should generate ~48 monthly candidates (24 months × 2 days)"
        )
        for sel in recent[:5]:
            assert sel in DKIM_PROBE_SELECTORS, (
                f"INBOX-69: monthly candidate `{sel}` must be in probe list"
            )

    def test_probe_list_size_in_expected_range(self):
        """Probe list should be ~95-110 selectors (47 static + 7 known +
        ~48 monthly). Catches accidental over- or under-expansion."""
        from checks import DKIM_PROBE_SELECTORS
        size = len(DKIM_PROBE_SELECTORS)
        assert 90 <= size <= 130, (
            f"DKIM_PROBE_SELECTORS size {size} outside expected 90-130 range"
        )

    @patch("checks.safe_dns_query")
    def test_revoked_only_returns_info_not_fail(self, mock_dns):
        """The google.com case — only revoked selectors found.
        Must return INFO 5/15, not FAIL 0/15. Revoked selectors are
        rotation breadcrumbs; the active key likely uses a format we
        don't probe yet, but DKIM IS configured."""
        revoked = '"v=DKIM1; k=rsa; p="'  # empty p = revoked

        def side(qname, rdtype, timeout=2):
            # Match a couple of known historical Google selectors
            if "20221208._domainkey." in qname and rdtype == "TXT":
                return [revoked]
            if "20210112._domainkey." in qname and rdtype == "TXT":
                return [revoked]
            return None

        mock_dns.side_effect = side
        from checks import check_dkim
        r = check_dkim("rotating-sender.example")

        assert r.status == "info", "Revoked-only must be INFO, not FAIL"
        assert r.points == 5, "Revoked-only must score 5/15 (don't torpedo)"
        assert r.max_points == 15
        # raw_data must surface the revoked selectors for transparency
        assert "revoked_selectors" in (r.raw_data or {})
        assert len(r.raw_data["revoked_selectors"]) >= 1
        # Detail must mention rotating-sender pattern
        detail = (r.detail or "").lower()
        assert "rotat" in detail or "revoked" in detail

    @patch("checks.safe_dns_query")
    def test_active_plus_revoked_drops_revoked_from_pass_message(self, mock_dns):
        """If at least one ACTIVE selector found, revoked ones must NOT
        appear in the PASS detail message — they're noise from history."""
        active_2048 = '"v=DKIM1; k=rsa; p=' + "A" * 380 + '"'
        revoked = '"v=DKIM1; k=rsa; p="'

        def side(qname, rdtype, timeout=2):
            if "default._domainkey." in qname and rdtype == "TXT":
                return [active_2048]
            if "20221208._domainkey." in qname and rdtype == "TXT":
                return [revoked]
            return None

        mock_dns.side_effect = side
        from checks import check_dkim
        r = check_dkim("mixed-active-revoked.example")

        assert r.status == "pass"
        assert r.points == 15
        # Detail names `default` (active), not `20221208` (revoked)
        assert "default" in (r.detail or "")
        assert "20221208" not in (r.detail or ""), (
            "Revoked selector must not appear in the PASS detail — "
            "it's historical noise, the active key is what matters"
        )

    @patch("checks.safe_dns_query")
    def test_truly_no_dkim_still_fails(self, mock_dns):
        """If neither active NOR revoked selectors found, keep the
        FAIL 0/15 — this is genuinely no DKIM, not a rotation case.

        INBOX-77: detail is now plain English ("Your emails aren't
        signed"); the dkimvalidator.com pointer is in fix_steps."""
        mock_dns.return_value = None
        from checks import check_dkim
        r = check_dkim("no-dkim-at-all.example")
        assert r.status == "fail"
        assert r.points == 0
        # Plain-English detail (no protocol jargon up front)
        d = (r.detail or "").lower()
        assert "aren't signed" in d or "not signed" in d or "no dkim" in d, (
            "INBOX-77: detail must lead with plain-English impact"
        )
        # External-verifier pointer moved to fix_steps
        fix_text = " ".join(r.fix_steps or []).lower()
        assert "dkimvalidator" in fix_text or "port25" in fix_text


class TestCheckMTASTSScoring:
    """INBOX-70 — MTA-STS now scored (max_points=5), was info-only.
    Properly configured MTA-STS in enforce mode is a strong
    deliverability signal (Google's bulk-sender requirements). Pre-
    INBOX-70 we showed PASS with max_points=0, leaving 5 points off
    the table for every well-configured sender."""

    @patch("checks.httpx")
    @patch("checks.safe_dns_query")
    def test_enforce_mode_scores_full_5(self, mock_dns, mock_httpx):
        """Enforce mode + valid policy = 5/5."""
        mock_dns.return_value = ['"v=STSv1; id=20240101"']
        mock_resp = MagicMock(status_code=200, text="version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 86400")
        mock_httpx.Client.return_value.__enter__.return_value.get.return_value = mock_resp

        from checks import check_mta_sts
        r = check_mta_sts("enforce-mode.example")
        assert r.status == "pass"
        assert r.points == 5
        assert r.max_points == 5

    @patch("checks.httpx")
    @patch("checks.safe_dns_query")
    def test_testing_mode_scores_3_of_5(self, mock_dns, mock_httpx):
        """Testing mode = 3/5 (good but not full enforce)."""
        mock_dns.return_value = ['"v=STSv1; id=20240101"']
        mock_resp = MagicMock(status_code=200, text="version: STSv1\nmode: testing\nmx: *.example.com\nmax_age: 86400")
        mock_httpx.Client.return_value.__enter__.return_value.get.return_value = mock_resp

        from checks import check_mta_sts
        r = check_mta_sts("testing-mode.example")
        assert r.status == "pass"
        assert r.points == 3
        assert r.max_points == 5

    @patch("checks.httpx")
    @patch("checks.safe_dns_query")
    def test_none_mode_scores_1_of_5(self, mock_dns, mock_httpx):
        """Mode 'none' = effectively disabled; minimal credit."""
        mock_dns.return_value = ['"v=STSv1; id=20240101"']
        mock_resp = MagicMock(status_code=200, text="version: STSv1\nmode: none\nmx: *.example.com\nmax_age: 86400")
        mock_httpx.Client.return_value.__enter__.return_value.get.return_value = mock_resp

        from checks import check_mta_sts
        r = check_mta_sts("none-mode.example")
        assert r.status == "info"
        assert r.points == 1
        assert r.max_points == 5

    @patch("checks.safe_dns_query")
    def test_no_mta_sts_max_points_5_not_zero(self, mock_dns):
        """Not configured = 0/5 INFO (was 0/0 info-only).
        max_points must be 5 so the denominator includes MTA-STS."""
        mock_dns.return_value = None
        from checks import check_mta_sts
        r = check_mta_sts("no-mta-sts.example")
        assert r.status == "info"
        assert r.points == 0
        assert r.max_points == 5  # INBOX-70: was 0, must now be 5


class TestCheckTLSRPTScoring:
    """INBOX-70 — TLS-RPT now scored (max_points=3), was info-only.
    Pairs with MTA-STS for visibility into TLS enforcement failures."""

    @patch("checks.safe_dns_query")
    def test_valid_rua_mailto_scores_full_3(self, mock_dns):
        """Configured with valid mailto rua = 3/3."""
        mock_dns.return_value = ['"v=TLSRPTv1; rua=mailto:tls-reports@example.com"']
        from checks import check_tls_rpt
        r = check_tls_rpt("good-tls-rpt.example")
        assert r.status == "pass"
        assert r.points == 3
        assert r.max_points == 3

    @patch("checks.safe_dns_query")
    def test_valid_rua_https_scores_full_3(self, mock_dns):
        """HTTPS endpoint rua also valid."""
        mock_dns.return_value = ['"v=TLSRPTv1; rua=https://reports.example.com/tlsrpt"']
        from checks import check_tls_rpt
        r = check_tls_rpt("https-rpt.example")
        assert r.status == "pass"
        assert r.points == 3
        assert r.max_points == 3

    @patch("checks.safe_dns_query")
    def test_malformed_rua_scores_1_of_3_warn(self, mock_dns):
        """v=TLSRPTv1 found but rua tag missing → warn at 1/3."""
        mock_dns.return_value = ['"v=TLSRPTv1"']
        from checks import check_tls_rpt
        r = check_tls_rpt("malformed-rpt.example")
        assert r.status == "warn"
        assert r.points == 1
        assert r.max_points == 3

    @patch("checks.safe_dns_query")
    def test_no_tls_rpt_max_points_3_not_zero(self, mock_dns):
        """Not configured = 0/3 INFO. max_points must be 3."""
        mock_dns.return_value = None
        from checks import check_tls_rpt
        r = check_tls_rpt("no-tls-rpt.example")
        assert r.status == "info"
        assert r.points == 0
        assert r.max_points == 3  # INBOX-70: was 0, must now be 3


class TestCanonicalMaxPointsAlignment:
    """INBOX-70 — scan_service.CANONICAL_MAX_POINTS must agree with
    the dynamic max_points returned by the check functions on the
    happy path. Otherwise the score denominator drifts and crash
    reporting becomes inconsistent."""

    def test_mta_sts_canonical_5(self):
        from scan_service import CANONICAL_MAX_POINTS
        assert CANONICAL_MAX_POINTS["mta_sts"] == 5

    def test_tls_rpt_canonical_3(self):
        from scan_service import CANONICAL_MAX_POINTS
        assert CANONICAL_MAX_POINTS["tls_rpt"] == 3


class TestReputationDNSBLParsers:
    """INBOX-74 — reputation DNSBL response code parsing.

    Pre-INBOX-74 we treated any successful resolve as 'listed', which
    caused false positives on Google/Microsoft scans because:
      - ScrolloutF1 returns reputation scores (127.2.X.2 where X = 0-100,
        higher = better) — a 'listing' there means 'we have a score for
        you', not 'you're flagged'
      - HostKarma returns multi-valued codes including refusal sentinels

    Pinned to google.com finding (2026-04-26): 173.194.203.26 was flagged
    on ScrolloutF1 with score 60 (good reputation) but reported as
    'Flagged on ScrolloutF1', losing 4/8 points.
    """

    def test_scrollout_high_score_is_good_reputation(self):
        """127.2.60.2 = reputation 60 = good (Google's IP)."""
        from checks import _parse_scrollout_response
        assert _parse_scrollout_response("127.2.60.2") == "good_reputation"
        assert _parse_scrollout_response("127.2.50.2") == "good_reputation"
        assert _parse_scrollout_response("127.2.99.2") == "good_reputation"

    def test_scrollout_mid_score_is_neutral(self):
        """30-49 = mid-range, no signal."""
        from checks import _parse_scrollout_response
        assert _parse_scrollout_response("127.2.30.2") == "neutral"
        assert _parse_scrollout_response("127.2.45.2") == "neutral"

    def test_scrollout_low_score_is_listed(self):
        """< 30 = real concerning reputation."""
        from checks import _parse_scrollout_response
        assert _parse_scrollout_response("127.2.10.2") == "listed"
        assert _parse_scrollout_response("127.2.0.2") == "listed"
        assert _parse_scrollout_response("127.2.29.2") == "listed"

    def test_scrollout_unknown_format_returns_unknown(self):
        """Defensive: response that doesn't match the 127.2.X.2 pattern."""
        from checks import _parse_scrollout_response
        assert _parse_scrollout_response("127.0.0.2") == "unknown"
        assert _parse_scrollout_response("garbage") == "unknown"

    def test_hostkarma_whitelist_is_whitelisted(self):
        """127.0.0.1 = whitelist."""
        from checks import _parse_hostkarma_response
        assert _parse_hostkarma_response("127.0.0.1") == "whitelisted"

    def test_hostkarma_blacklist_is_listed(self):
        """127.0.0.2 = blacklist; 0.3 yellow, 0.4 brown — all 'listed'."""
        from checks import _parse_hostkarma_response
        assert _parse_hostkarma_response("127.0.0.2") == "listed"
        assert _parse_hostkarma_response("127.0.0.3") == "listed"
        assert _parse_hostkarma_response("127.0.0.4") == "listed"

    def test_hostkarma_refused_is_refused(self):
        """127.0.0.5 = no-op / refused. Must NOT count as listed."""
        from checks import _parse_hostkarma_response
        assert _parse_hostkarma_response("127.0.0.5") == "refused"

    def test_check_reputation_dnsbl_returns_categorical(self):
        """Function returns string category, not bool. Backward-compat
        check: every public path that previously expected a bool needs
        to be updated."""
        import checks
        # not_found case (no DNS record at all)
        with patch("dns.resolver.Resolver") as MockResolver:
            mock_resolver = MagicMock()
            MockResolver.return_value = mock_resolver
            mock_resolver.resolve.side_effect = Exception("NXDOMAIN")
            result = checks._check_reputation_dnsbl(
                "1.2.3.4", "reputation-ip.rbl.scrolloutf1.com"
            )
            assert result == "not_found"
            assert isinstance(result, str), "must return str, not bool (INBOX-74)"


class TestCheckIPReputationGoogleNotFalseFlagged:
    """INBOX-74 — google.com IP must NOT show 'Flagged on ScrolloutF1'
    when ScrolloutF1 returns a high reputation score."""

    def test_google_high_scrollout_score_does_not_flag(self):
        """ScrolloutF1 returns 127.2.60.2 (score 60) for Google.
        Pre-INBOX-74 this was treated as 'listed' (false positive).
        Now it must be treated as 'good_reputation' → whitelisted."""
        import checks

        # Mock _check_reputation_dnsbl to simulate ScrolloutF1 returning
        # good_reputation for Google's IP (the actual category our parser
        # returns for 127.2.60.2)
        def fake_dnsbl(ip, zone):
            if zone == "reputation-ip.rbl.scrolloutf1.com":
                return "good_reputation"
            if zone == "list.dnswl.org":
                return "listed"   # whitelist hit
            return "not_found"

        # Mock everything else needed for check_ip_reputation
        with patch("checks._check_reputation_dnsbl", side_effect=fake_dnsbl), \
             patch("checks.safe_dns_query") as mock_dns, \
             patch("checks._cymru_asn_lookup", return_value={"asn": "15169", "asn_name": "Google", "country": "US"}), \
             patch("checks._sender_score_lookup", return_value=None):

            def dns_side(qname, rdtype="A"):
                if rdtype == "MX":
                    return ["10 smtp.google.com"]
                if rdtype == "A":
                    return ["173.194.203.26"]
                return None
            mock_dns.side_effect = dns_side

            from checks import check_ip_reputation
            r = check_ip_reputation("google.com")

        # ScrolloutF1 must NOT appear in reputation_flags
        # (it should be in whitelisted via good_reputation)
        flag_text = " ".join(r.detail.split()).lower()
        assert "flagged on scrolloutf1" not in flag_text, (
            "INBOX-74 regression: ScrolloutF1 with good_reputation must "
            "NOT appear as a flag. Pre-fix this caused false positives "
            "on every Google/Microsoft/Apple scan."
        )
        # Status should be pass (no warn/fail) when only good_reputation
        assert r.status == "pass"


# ─── CHECK RESULT MODEL TESTS ───────────────────────────────────

class TestCheckResultModel:
    """Test the CheckResult Pydantic model"""

    def test_basic_creation(self):
        from checks import CheckResult
        result = CheckResult(
            name="test",
            category="authentication",
            status="pass",
            title="Test Check",
            detail="Everything is fine",
            points=10,
            max_points=10,
        )
        assert result.name == "test"
        assert result.fix_steps is None
        assert result.raw_data is None

    def test_with_fix_steps(self):
        from checks import CheckResult
        result = CheckResult(
            name="test",
            category="authentication",
            status="fail",
            title="Test Check",
            detail="Something wrong",
            points=0,
            max_points=10,
            fix_steps=["Step 1", "Step 2"],
        )
        assert len(result.fix_steps) == 2

    def test_dict_serialization(self):
        from checks import CheckResult
        result = CheckResult(
            name="test", category="auth", status="pass",
            title="T", detail="D", points=5, max_points=10,
        )
        d = result.dict()
        assert d["name"] == "test"
        assert d["points"] == 5
        assert "raw_data" in d
