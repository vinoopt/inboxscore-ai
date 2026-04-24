"""
Regression suite for INBOX-35 and INBOX-36 — check_blacklists correctness.

Two real bugs, same function:

  INBOX-35 — DNSBL response-code parsing. The previous code treated ANY
             A-record response from a DNSBL query as a spam listing. But
             Spamhaus ZEN returns 127.0.0.10 / 127.0.0.11 for PBL policy
             hits (e.g. "this IP shouldn't send direct mail" — common for
             ESP-managed IPs), and that's semantically NOT a spam listing.
             Google Workspace MX IPs routinely appear on PBL, which is why
             the voicenotes.com scan reported them as "listed on Spamhaus
             + CBL" when they are not actually blacklisted for spam.

  INBOX-36 — Scope of IPs checked. The previous code added the domain's
             A-record IPs to the email-blacklist scan even when MX
             records existed. For modern domains behind Cloudflare /
             Vercel / Netlify, those A-record IPs are the WEBSITE host
             (Cloudflare: 104.26.x.x) — not a mail server. Including them
             in an email-blacklist check is a category error and was the
             root cause of the "Cloudflare IPs listed" false positive.

These tests lock both behaviours in by patching safe_dns_query (to
control which IPs get resolved) and dns.resolver.Resolver.resolve (to
control what the DNSBL lookup returns per IP + blacklist combination).
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import checks  # noqa: E402


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------

def _dns_stub(mx_map: dict[str, list[str]] | None, a_records: list[str] | None,
              mx_records: list[str] | None = None):
    """Build a safe_dns_query stub that returns canned MX + A record data.

    mx_records:   list of 'priority host' strings the domain's MX lookup returns.
    mx_map:       dict of mx_host -> list of IPs that A-lookup of the host returns.
    a_records:    list of IPs the domain's own A record returns.
    """
    def stub(query: str, record_type: str):
        if record_type == "MX":
            return list(mx_records or [])
        if record_type == "A":
            if mx_map and query in mx_map:
                return list(mx_map[query])
            # Domain's own A record
            return list(a_records or [])
        return []
    return stub


def _dnsbl_stub(ip_to_codes: dict[str, dict[str, list[str]]]):
    """Build a dns.resolver.Resolver stub.

    ip_to_codes:  {ip: {blacklist_name: [A_record_values]}} — if the ip is
                  not on a given blacklist, omit that blacklist from its dict
                  (lookup raises to simulate NXDOMAIN).
    """
    class StubResolver:
        def __init__(self):
            self.timeout = 2
            self.lifetime = 2

        def resolve(self, query, rtype):
            # query looks like '96.5.26.104.zen.spamhaus.org'
            # Reverse the first 4 octets to get the IP.
            parts = query.split(".")
            if len(parts) < 5:
                raise Exception("NXDOMAIN")
            ip = ".".join(reversed(parts[:4]))
            bl = ".".join(parts[4:])
            codes = ip_to_codes.get(ip, {}).get(bl)
            if not codes:
                raise Exception("NXDOMAIN")
            # Return a list of mock RRset items; str() yields the A record.
            return [MagicMock(__str__=lambda self, c=c: c) for c in codes]
    return StubResolver


# --------------------------------------------------------------------
# INBOX-35 — PBL policy listings must NOT count as spam
# --------------------------------------------------------------------

class TestDNSBLCodeParsing:
    """The key invariant: 127.0.0.10/11 => policy, not spam; everything else => spam."""

    def test_pbl_only_listing_does_not_fail_or_dock_points(self):
        # Mimics the voicenotes.com situation: Google MX IP is on Spamhaus
        # ZEN, but ONLY for PBL codes (127.0.0.10). It should be scored
        # as a pass with an informational note, not a FAIL.
        mx_map = {"aspmx.l.google.com": ["142.250.101.27"]}
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=["10 aspmx.l.google.com"],
                              mx_map=mx_map, a_records=None)), \
             patch.object(checks.dns.resolver, "Resolver",
                          _dnsbl_stub({"142.250.101.27": {"zen.spamhaus.org": ["127.0.0.10"]}})):
            result = checks.check_blacklists("example.com")

        assert result.status == "pass", (
            f"INBOX-35 regression: PBL-only listing must return status='pass', "
            f"not {result.status!r}. Previous code treated any DNSBL response "
            "as a spam listing and flipped status to warn/fail. "
            "Detail: " + (result.detail or "")
        )
        assert result.points == 15, (
            "PBL-only listings must NOT dock points from the score. Google Workspace "
            "IPs appear on PBL routinely; they're not spam sources."
        )
        raw = result.raw_data or {}
        # The listed array should be empty (zero spam listings).
        assert raw.get("listed") == []
        # But the policy listing should be exposed so the UI can show it as INFO.
        pol = raw.get("policy_listings") or []
        assert any(p["blacklist"] == "zen.spamhaus.org" and p["ip"] == "142.250.101.27"
                   for p in pol), (
            "Policy listings must be captured in raw_data.policy_listings so the "
            "UI can display them as informational context without counting toward FAIL."
        )
        # The detail text should mention the policy note (not hide it).
        assert "PBL" in (result.detail or "") or "policy" in (result.detail or "").lower()

    def test_sbl_listing_counts_as_real_spam_and_fails(self):
        # A real SBL spam listing (127.0.0.2) must still trigger the FAIL path.
        mx_map = {"mail.bad.example": ["1.2.3.4"]}
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=["10 mail.bad.example"],
                              mx_map=mx_map, a_records=None)), \
             patch.object(checks.dns.resolver, "Resolver",
                          _dnsbl_stub({"1.2.3.4": {"zen.spamhaus.org": ["127.0.0.2"]}})):
            result = checks.check_blacklists("bad.example")

        assert result.status in ("warn", "fail"), (
            f"SBL listing must trigger warn/fail, got {result.status!r}"
        )
        raw = result.raw_data or {}
        assert len(raw.get("listed") or []) >= 1, (
            "Real spam listings must appear in raw_data.listed"
        )

    def test_mixed_pbl_and_sbl_counts_as_spam(self):
        # If an IP is on BOTH SBL (127.0.0.2) and PBL (127.0.0.10), it's
        # a spam listing — the spam code takes precedence.
        mx_map = {"mail.bad.example": ["1.2.3.4"]}
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=["10 mail.bad.example"],
                              mx_map=mx_map, a_records=None)), \
             patch.object(checks.dns.resolver, "Resolver",
                          _dnsbl_stub({
                              "1.2.3.4": {"zen.spamhaus.org": ["127.0.0.2", "127.0.0.10"]}
                          })):
            result = checks.check_blacklists("bad.example")

        assert result.status in ("warn", "fail")
        raw = result.raw_data or {}
        assert len(raw.get("listed") or []) == 1

    def test_clean_ip_returns_pass_no_policy_note(self):
        # Baseline sanity: a truly clean IP produces a clean pass, no policy note.
        mx_map = {"mail.clean.example": ["5.6.7.8"]}
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=["10 mail.clean.example"],
                              mx_map=mx_map, a_records=None)), \
             patch.object(checks.dns.resolver, "Resolver",
                          _dnsbl_stub({})):   # empty = every lookup NXDOMAINs
            result = checks.check_blacklists("clean.example")

        assert result.status == "pass"
        assert result.points == 15
        assert "PBL" not in (result.detail or "")
        raw = result.raw_data or {}
        assert raw.get("policy_listings") == []


# --------------------------------------------------------------------
# INBOX-39 — 127.255.255.* error codes must NOT be treated as listings
# --------------------------------------------------------------------

class TestDNSBLErrorCodes:
    """Spamhaus's 127.255.255.* error range is NOT a listing. Never.

    These tests pin the exact voicenotes.com / mailercloud.co failure mode:
    Render's shared DNS resolver hits Spamhaus, Spamhaus returns
    127.255.255.254 ("public-resolver block"), and our code MUST treat
    that as "couldn't check" — not as a spam listing. The previous
    behaviour flagged Google's MX IPs as listed on Spamhaus + CBL,
    which was a false-positive FAIL.
    """

    def test_public_resolver_blocked_code_does_not_flip_status(self):
        # Exact shape of the live bug. 1 IP, both Spamhaus ZEN and CBL
        # return 127.255.255.254 ("public resolver blocked").
        mx_map = {"mail.example": ["1.2.3.4"]}
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=["10 mail.example"],
                              mx_map=mx_map, a_records=None)), \
             patch.object(checks.dns.resolver, "Resolver",
                          _dnsbl_stub({
                              "1.2.3.4": {
                                  "zen.spamhaus.org": ["127.255.255.254"],
                                  "cbl.abuseat.org":  ["127.255.255.254"],
                              }
                          })):
            result = checks.check_blacklists("example.com")

        assert result.status == "pass", (
            "INBOX-39 regression: 127.255.255.254 is a Spamhaus ERROR code "
            "(public resolver blocked). It is NOT a listing. Must not flip "
            f"the blacklist check to warn/fail. Got: {result.status!r}."
        )
        assert result.points == 15
        raw = result.raw_data or {}
        assert len(raw.get("listed") or []) == 0, (
            "No real listings must appear in raw_data.listed when only "
            "error codes were returned."
        )
        # The errored DNSBLs must appear in the diagnostics bucket.
        assert "zen.spamhaus.org" in (raw.get("fully_errored_blacklists") or [])
        assert "cbl.abuseat.org" in (raw.get("fully_errored_blacklists") or [])
        # Detail text must honestly flag the limitation.
        detail = result.detail or ""
        assert "could not be queried" in detail or "public-resolver block" in detail

    def test_mixed_error_and_real_listing_still_fails(self):
        # If Spamhaus returns real SBL (127.0.0.2) AND another BL returns
        # an error code, we should still FAIL on the real listing.
        mx_map = {"mail.bad.example": ["1.2.3.4"]}
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=["10 mail.bad.example"],
                              mx_map=mx_map, a_records=None)), \
             patch.object(checks.dns.resolver, "Resolver",
                          _dnsbl_stub({
                              "1.2.3.4": {
                                  "zen.spamhaus.org": ["127.0.0.2"],   # real SBL
                                  "cbl.abuseat.org":  ["127.255.255.254"],  # error
                              }
                          })):
            result = checks.check_blacklists("bad.example")

        assert result.status in ("warn", "fail")
        raw = result.raw_data or {}
        assert len(raw.get("listed") or []) == 1   # only SBL counted
        assert "cbl.abuseat.org" in (raw.get("fully_errored_blacklists") or [])

    def test_other_error_codes_in_255_range_all_ignored(self):
        # 252 (typo), 253 (discontinued), 254 (public resolver blocked),
        # 255 (rate-limited) are all error codes. None should count as
        # a listing.
        mx_map = {"mail.example": ["5.5.5.5"]}
        for code in ["127.255.255.252", "127.255.255.253",
                     "127.255.255.254", "127.255.255.255"]:
            with patch.object(checks, "safe_dns_query",
                              side_effect=_dns_stub(
                                  mx_records=["10 mail.example"],
                                  mx_map=mx_map, a_records=None)), \
                 patch.object(checks.dns.resolver, "Resolver",
                              _dnsbl_stub({
                                  "5.5.5.5": {"zen.spamhaus.org": [code]}
                              })):
                result = checks.check_blacklists("example.com")
            assert result.status == "pass", (
                f"Code {code} must be treated as error, not listing. "
                f"Got status={result.status!r}"
            )
            raw = result.raw_data or {}
            assert (raw.get("listed") or []) == []


# --------------------------------------------------------------------
# INBOX-36 — A-record IPs must NOT be included when MX exists
# --------------------------------------------------------------------

class TestIPCandidateScope:
    """A-record IPs (website host) must not appear in the email blacklist check
    when MX records exist."""

    def test_cloudflare_a_records_excluded_when_mx_exists(self):
        # Voicenotes.com scenario: MX at Google, A record at Cloudflare.
        # The A record IPs (104.26.x.x) are Cloudflare; they must NOT be
        # queried against email blacklists.
        mx_map = {"aspmx.l.google.com": ["142.250.101.27"]}
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=["10 aspmx.l.google.com"],
                              mx_map=mx_map,
                              a_records=["104.26.4.96", "104.26.5.96"])), \
             patch.object(checks.dns.resolver, "Resolver", _dnsbl_stub({})):
            result = checks.check_blacklists("example.com")

        raw = result.raw_data or {}
        ips_checked = [item["ip"] for item in raw.get("ips_checked") or []]
        # Only the MX IP must appear.
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
        # Legitimate edge case: domain has no MX but has an A record.
        # Pre-RFC-7505 that meant "mail can be accepted on the A record IP"
        # — and that niche is still worth checking.
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=[],   # no MX
                              mx_map={},
                              a_records=["10.0.0.1"])), \
             patch.object(checks.dns.resolver, "Resolver", _dnsbl_stub({})):
            result = checks.check_blacklists("no-mx.example")

        raw = result.raw_data or {}
        ips_checked = [item["ip"] for item in raw.get("ips_checked") or []]
        assert "10.0.0.1" in ips_checked, (
            "When MX is absent, the A-record fallback still applies — that "
            "case is legitimate (pre-RFC-7505 implicit MX)."
        )
        # Source label should indicate this is the no-MX fallback.
        sources = [item["source"] for item in raw.get("ips_checked") or []]
        assert any("no MX" in s or "A record" in s for s in sources)

    def test_no_mx_no_a_returns_fail(self):
        # Regression: INBOX-25 L2 — dead domain still fails with 0/15.
        # Ensures INBOX-36 refactor didn't break the no-infra path.
        with patch.object(checks, "safe_dns_query",
                          side_effect=_dns_stub(
                              mx_records=[], mx_map={}, a_records=None)):
            result = checks.check_blacklists("parked.example")

        assert result.status == "fail"
        assert result.points == 0
        assert result.max_points == 15
