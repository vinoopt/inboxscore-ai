"""
Regression suite for check_blacklists correctness.

INBOX-229 phase 3 (2026-05-11): blacklist queries now go through
HetrixTools, not direct DNSBL DNS lookups. Tests in this file have
been split into:

  ✅ KEPT + UPDATED — tests for behaviours we still guarantee:
        clean → pass, listed → warn/fail, IP candidate scope (INBOX-36).
        These now mock `hetrix.check_ip` instead of `dns.resolver`.

  ⏭️  SKIPPED — tests for inline-DNSBL response-code semantics that no
        longer apply: PBL policy listings (INBOX-35), 127.255.255.*
        refusal codes (INBOX-39). HetrixTools' private resolvers give
        us the ground truth — those refusal-code false-positives
        cannot occur. Kept as skip-marked so the history is preserved
        in case we ever bring inline DNSBL back.
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import checks  # noqa: E402


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------

def _dns_stub(mx_map: dict[str, list[str]] | None, a_records: list[str] | None,
              mx_records: list[str] | None = None):
    """Build a safe_dns_query stub that returns canned MX + A record data.

    Used for testing IP discovery (which still happens locally via DNS,
    before the hetrix call).
    """
    def stub(query: str, record_type: str):
        if record_type == "MX":
            return list(mx_records or [])
        if record_type == "A":
            if mx_map and query in mx_map:
                return list(mx_map[query])
            return list(a_records or [])
        return []
    return stub


def _hetrix_stub(listings_by_ip: dict[str, list[dict]] | None = None):
    """Build a hetrix.check_ip stub.

    listings_by_ip: {ip: [listing_dict, ...]}. Missing IPs return
                    a clean (zero-listing) response.
    """
    listings_by_ip = listings_by_ip or {}

    def stub(ip: str) -> dict:
        listings = listings_by_ip.get(ip, [])
        return {
            "ip": ip,
            "blacklisted_count": len(listings),
            "blacklisted_on": listings,
            "checked_count": 1000,
            "error": None,
        }
    return stub


# --------------------------------------------------------------------
# Still-relevant: clean → pass
# --------------------------------------------------------------------

class TestCleanResult:
    """A truly clean domain (no listings) must return status='pass' with
    full points. This is the most common path and the most important to
    keep working through the migration."""

    def test_clean_ip_returns_pass(self):
        mx_map = {"mail.clean.example": ["5.6.7.8"]}
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=["10 mail.clean.example"],
                              mx_map=mx_map, a_records=None)), \
             patch("hetrix.check_ip", side_effect=_hetrix_stub({})):
            result = checks.check_blacklists("clean.example")

        assert result.status == "pass"
        assert result.points == 15
        raw = result.raw_data or {}
        assert raw.get("listed") == []
        assert raw.get("provider") == "hetrix"


# --------------------------------------------------------------------
# Still-relevant: listed → fail
# --------------------------------------------------------------------

class TestListedResult:
    """A real spam listing must trigger warn/fail and dock points."""

    def test_sbl_listing_counts_as_real_spam_and_fails(self):
        mx_map = {"mail.bad.example": ["1.2.3.4"]}
        listing = {
            "rbl": "Spamhaus ZEN", "name": "Spamhaus ZEN",
            "severity": "high", "operator": "Spamhaus",
            "delist": "https://www.spamhaus.org/lookup/", "codes": ["127.0.0.2"],
        }
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=["10 mail.bad.example"],
                              mx_map=mx_map, a_records=None)), \
             patch("hetrix.check_ip",
                   side_effect=_hetrix_stub({"1.2.3.4": [listing]})):
            result = checks.check_blacklists("bad.example")

        assert result.status in ("warn", "fail"), (
            f"Real listing must trigger warn/fail, got {result.status!r}"
        )
        raw = result.raw_data or {}
        assert len(raw.get("listed") or []) >= 1
        # Listing carries the data the UI needs
        listed = raw.get("listed", [])
        assert listed[0]["ip"] == "1.2.3.4"
        assert "Spamhaus" in listed[0]["blacklist"]

    def test_multiple_listings_aggregate(self):
        """Two IPs each on a different blacklist → 2 total listings."""
        mx_map = {"mail.bad.example": ["1.2.3.4", "5.6.7.8"]}
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=["10 mail.bad.example"],
                              mx_map=mx_map, a_records=None)), \
             patch("hetrix.check_ip", side_effect=_hetrix_stub({
                 "1.2.3.4": [{"rbl": "Spamhaus ZEN", "name": "Spamhaus ZEN",
                              "severity": "high", "operator": "Spamhaus",
                              "delist": "", "codes": []}],
                 "5.6.7.8": [{"rbl": "Barracuda BBL", "name": "Barracuda BBL",
                              "severity": "high", "operator": "Barracuda",
                              "delist": "", "codes": []}],
             })):
            result = checks.check_blacklists("bad.example")

        assert result.status == "fail"
        raw = result.raw_data or {}
        assert len(raw.get("listed") or []) == 2
        # Both IPs grouped into listings_by_ip
        lbi = raw.get("listings_by_ip", {})
        assert "1.2.3.4" in lbi and "5.6.7.8" in lbi


# --------------------------------------------------------------------
# Still-relevant: IP candidate scope (INBOX-36)
# --------------------------------------------------------------------

class TestIPCandidateScope:
    """A-record IPs (website host) must not appear in the email blacklist
    check when MX records exist. The voicenotes.com Cloudflare false
    positive must stay fixed.
    """

    def test_cloudflare_a_records_excluded_when_mx_exists(self):
        mx_map = {"aspmx.l.google.com": ["142.250.101.27"]}
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=["10 aspmx.l.google.com"],
                              mx_map=mx_map,
                              a_records=["104.26.4.96", "104.26.5.96"])), \
             patch("hetrix.check_ip", side_effect=_hetrix_stub({})):
            result = checks.check_blacklists("example.com")

        raw = result.raw_data or {}
        ips_checked = [item["ip"] for item in raw.get("ips_checked") or []]
        assert "142.250.101.27" in ips_checked, (
            "MX-derived IPs must still be checked"
        )
        assert "104.26.4.96" not in ips_checked, (
            "INBOX-36 regression: Cloudflare A-record IP was included in the "
            "email blacklist check. Previous code scored the domain's website "
            "host as if it were a mail server — category error."
        )
        assert "104.26.5.96" not in ips_checked

    def test_no_mx_falls_back_to_a_record(self):
        """Legitimate pre-RFC-7505 edge case: no MX, A record present.
        We still check the A-record IP — that niche is valid for old
        domains that accept mail on the apex."""
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=[], mx_map={},
                              a_records=["10.0.0.1"])), \
             patch("hetrix.check_ip", side_effect=_hetrix_stub({})):
            result = checks.check_blacklists("no-mx.example")

        raw = result.raw_data or {}
        ips_checked = [item["ip"] for item in raw.get("ips_checked") or []]
        assert "10.0.0.1" in ips_checked
        sources = [item["source"] for item in raw.get("ips_checked") or []]
        assert any("no MX" in s or "A record" in s for s in sources)

    def test_no_mx_no_a_returns_fail(self):
        """Dead domain → fail with 0/15 (INBOX-25 L2)."""
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=[], mx_map={}, a_records=None)):
            result = checks.check_blacklists("parked.example")

        assert result.status == "fail"
        assert result.points == 0
        assert result.max_points == 15


# --------------------------------------------------------------------
# Obsolete: PBL semantics — kept skip-marked for history
# --------------------------------------------------------------------

class TestDNSBLCodeParsing:
    """INBOX-35 fixed inline-DNSBL classification of 127.0.0.10/11 (PBL)
    vs spam codes. With HetrixTools, response codes are abstracted —
    we get listings or we don't, the provider handles classification.
    """

    @pytest.mark.skip(reason=(
        "INBOX-229 phase 3: HetrixTools abstracts DNSBL response codes. "
        "PBL classification is no longer a concern at the call-site. "
        "Skip-kept for history."
    ))
    def test_pbl_only_listing_does_not_fail_or_dock_points(self):
        pass

    @pytest.mark.skip(reason="Superseded by TestListedResult above.")
    def test_sbl_listing_counts_as_real_spam_and_fails(self):
        pass

    @pytest.mark.skip(reason=(
        "INBOX-229 phase 3: HetrixTools abstracts mixed-code parsing. "
        "If hetrix returns a listing, it's a real listing."
    ))
    def test_mixed_pbl_and_sbl_counts_as_spam(self):
        pass

    @pytest.mark.skip(reason="Superseded by TestCleanResult above.")
    def test_clean_ip_returns_pass_no_policy_note(self):
        pass


# --------------------------------------------------------------------
# Obsolete: 127.255.255.* refusal codes — kept skip-marked for history
# --------------------------------------------------------------------

class TestDNSBLErrorCodes:
    """INBOX-39 fixed misclassification of Spamhaus's 127.255.255.* error
    range as listings. With HetrixTools we never see those codes —
    they're hit by HetrixTools' private resolvers, which DON'T get the
    public-resolver block (HetrixTools is a commercial DBL customer).
    """

    @pytest.mark.skip(reason=(
        "INBOX-229 phase 3: HetrixTools queries DBLs from licensed "
        "infrastructure, not public resolvers. 127.255.255.* refusal "
        "codes don't reach us."
    ))
    def test_public_resolver_blocked_code_does_not_flip_status(self):
        pass

    @pytest.mark.skip(reason="See test_public_resolver_blocked_code_does_not_flip_status.")
    def test_mixed_error_and_real_listing_still_fails(self):
        pass

    @pytest.mark.skip(reason="See test_public_resolver_blocked_code_does_not_flip_status.")
    def test_other_error_codes_in_255_range_all_ignored(self):
        pass
