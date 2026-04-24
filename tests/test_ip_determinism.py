"""
Regression suite for INBOX-26 — deterministic IP ordering across the scan.

Python's hash randomization means list(set(ip_strings)) returns elements
in a different order every time the Python process starts. Several code
paths did `list(ips)[0]` or `list(ips)[:5]` where `ips` was a set —
silently producing different scan results on the same input.

These tests pin the behaviour: identical DNS responses MUST produce
identical scan outputs, today and on every future Python version.

Strategy:
 - Patch `safe_dns_query` and the other network-touching functions so
   each test is fully synchronous and fast.
 - Shuffle DNS return orders between the two runs to simulate the
   real-world non-determinism — if the code paths had any residual
   `list(set)` → `[0]` / `[:N]` the two runs would diverge.
"""

from __future__ import annotations

import os
import random
import sys
from typing import Iterable
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import checks  # noqa: E402


# --------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------

# A domain with 6 sending IPs spread across 2 MX hosts. Enough to expose
# both the "pick primary" and the "first 5" codepaths.
_MX_RESPONSE = ["10 mx1.example.com", "20 mx2.example.com"]
_MX1_IPS = ["192.0.2.11", "192.0.2.12", "192.0.2.13"]
_MX2_IPS = ["192.0.2.21", "192.0.2.22", "192.0.2.23"]
_A_RECORD = ["192.0.2.99"]


def _dns_stub(shuffled: bool = False):
    """Return a safe_dns_query stub that serves canned DNS answers.

    If shuffled=True, each answer list is returned in a randomised order
    to simulate real-world DNS round-robin / resolver variation.
    """
    def _maybe_shuffle(items: Iterable[str]) -> list[str]:
        lst = list(items)
        if shuffled:
            random.shuffle(lst)
        return lst

    def stub(query: str, record_type: str):
        if record_type == "MX":
            return _maybe_shuffle(_MX_RESPONSE) if query == "example.com" else []
        if record_type == "A":
            if query == "mx1.example.com":
                return _maybe_shuffle(_MX1_IPS)
            if query == "mx2.example.com":
                return _maybe_shuffle(_MX2_IPS)
            if query == "example.com":
                return _maybe_shuffle(_A_RECORD)
        return []
    return stub


# --------------------------------------------------------------------
# check_ip_reputation — primary_ip and all_ips
# --------------------------------------------------------------------

class TestCheckIPReputationDeterminism:
    """primary_ip (checks.py:1478) and all_ips (checks.py:1617) must be stable."""

    def _run_once(self, seed: int):
        """Run check_ip_reputation with a fully mocked dependency surface."""
        random.seed(seed)
        with patch.object(checks, "safe_dns_query", side_effect=_dns_stub(shuffled=True)), \
             patch.object(checks, "_cymru_asn_lookup", return_value={}), \
             patch.object(checks, "_sender_score_lookup", return_value=None), \
             patch.object(checks, "_check_reputation_dnsbl", return_value=False):
            return checks.check_ip_reputation("example.com")

    def test_primary_ip_is_identical_across_runs(self):
        r1 = self._run_once(seed=1)
        r2 = self._run_once(seed=42)   # different shuffle seed
        r3 = self._run_once(seed=9999)

        raw1 = r1.raw_data or {}
        raw2 = r2.raw_data or {}
        raw3 = r3.raw_data or {}

        assert raw1.get("primary_ip") == raw2.get("primary_ip") == raw3.get("primary_ip"), (
            "INBOX-26 regression: check_ip_reputation picked a different "
            "primary_ip across runs. Expected lexicographic-minimum IP "
            "regardless of DNS response ordering."
        )
        # Lexicographic min of all known IPs (excluding the A-record
        # fallback which only fires if MX lookup fails) is 192.0.2.11.
        assert raw1.get("primary_ip") == "192.0.2.11"

    def test_all_ips_slice_is_identical_across_runs(self):
        r1 = self._run_once(seed=1).raw_data.get("all_ips")
        r2 = self._run_once(seed=42).raw_data.get("all_ips")
        assert r1 == r2, (
            "INBOX-26 regression: all_ips (the 5-IP slice shipped in the "
            "scan payload) differed between runs with equal DNS state."
        )
        # Should be the 5 lexicographically-lowest IPs, sorted.
        assert r1 == ["192.0.2.11", "192.0.2.12", "192.0.2.13",
                      "192.0.2.21", "192.0.2.22"]


# --------------------------------------------------------------------
# check_blacklists — sorted ips = stable slice
# --------------------------------------------------------------------

class TestCheckBlacklistsDeterminism:
    """The `ips[:2]` and `ips[:3]` slices must always hit the same IPs."""

    def _run_once(self, seed: int):
        random.seed(seed)
        # The real check uses dnspython via check_single_bl's inner
        # resolver. Patch that out so no network traffic happens and so
        # the result deterministically reports "clean" for every IP.
        with patch.object(checks, "safe_dns_query", side_effect=_dns_stub(shuffled=True)), \
             patch("checks.dns.resolver.Resolver") as MockResolver:
            # Make every .resolve() call raise — simulating "not on any
            # blacklist". The inner try/except returns None on failure.
            mock_resolver = MagicMock()
            mock_resolver.resolve.side_effect = Exception("NXDOMAIN")
            MockResolver.return_value = mock_resolver
            return checks.check_blacklists("example.com")

    def test_ips_checked_is_identical_across_runs(self):
        r1 = self._run_once(seed=1).raw_data
        r2 = self._run_once(seed=42).raw_data

        ips1 = sorted(item["ip"] for item in r1.get("ips_checked", []))
        ips2 = sorted(item["ip"] for item in r2.get("ips_checked", []))

        assert ips1 == ips2, (
            "INBOX-26 regression: check_blacklists selected a different "
            "subset of IPs to check in run-2 vs run-1. The ips[:3] slice "
            "must pick the same 3 IPs every time."
        )
        # With 6 candidate IPs sorted lexicographically, the first 3 are
        # 192.0.2.11, 192.0.2.12, 192.0.2.13. raw_data["ips_checked"]
        # reports up to 3 (see checks.py:538).
        assert ips1 == ["192.0.2.11", "192.0.2.12", "192.0.2.13"]
