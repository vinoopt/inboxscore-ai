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
        from checks import check_spf
        result = check_spf("partial.com")
        assert result.status == "pass"
        assert result.points == 14  # ~all gets 14/15

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
        """One MX record should pass but with note about redundancy"""
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
        assert "1024-bit" in (result.detail or "")
        sels = (result.raw_data or {}).get("selectors", [])
        assert sels and sels[0].get("key_length") == "1024-bit"

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
        """When no selector matches, the message must NOT just say 'fail'.
        It must point users to dkimvalidator.com or port25.com — many
        senders use random/rotating selectors (AWS SES, HubSpot,
        Salesforce MC) that we genuinely can't enumerate."""
        mock_dns.return_value = None
        from checks import check_dkim
        r = check_dkim("rotating-selector.com")
        assert r.status == "fail"
        assert r.points == 0
        d = (r.detail or "").lower()
        assert "dkimvalidator" in d or "port25" in d, (
            "No-DKIM detail must point to an external verifier — many "
            "real senders use random selectors we can't probe."
        )
        # raw_data should expose the full checked list (not just first 10)
        raw = r.raw_data or {}
        assert raw.get("checked_count") == len(__import__("checks").DKIM_SELECTORS)
        assert len(raw.get("checked_selectors", [])) >= 40

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
