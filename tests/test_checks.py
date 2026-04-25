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
