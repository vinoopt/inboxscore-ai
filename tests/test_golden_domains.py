"""Golden-domain regression suite (INBOX-53).

Pins the scan output for a small set of well-known domains. Any change
to scoring logic, check functions, or scoring constants that breaks
these expectations fails CI.

Why this matters
----------------
Two cross-cutting bugs in 2026-04 (INBOX-39 Spamhaus sentinel, INBOX-50
URIBL sentinel) only surfaced via live testing. Both were the same
class — DNSBL refusal codes treated as listings. A golden-domain test
would have caught them immediately because voicenotes.com (which we
now pin) was producing the false-positive output.

How to update
-------------
1. If a check function's behavior intentionally changes, the golden
   test will fail. Re-run the capture script to regenerate fixtures:
       python3 -c "from tests.test_golden_domains import recapture; recapture()"
   Then commit the updated fixture along with the code change. The
   diff in the fixture file is the audit trail of what changed.

2. If a real domain's DNS changes (eg they add a new DKIM selector),
   re-capture just that fixture. The diff shows what changed at the
   DNS layer, which is part of why this suite exists.

3. To add a new golden domain: add to GOLDEN_DOMAINS, run the capture
   script, commit. Pick domains that exercise edge cases (mixed-bit
   DKIM, sp=reject, BIMI, port-25-blocked TLS fallback, etc).

What this catches
-----------------
* Scoring logic changes (intentional or accidental)
* Check function regressions
* Output shape changes
* Score weighting drift

What it doesn't catch
---------------------
* A live customer's DNS changing — they'd see it on their dashboard
* Actual network-level bugs (eg DBL sentinel handling) — you need
  real DNS to catch those, but the *fix* gets pinned here once
  applied (eg the URIBL 127.0.0.1 sentinel is captured in the
  voicenotes.com fixture).

What's NOT covered (yet)
------------------------
* check_tls — needs SMTP banner mocking, deferred
* check_domain_age — needs WHOIS mocking, deferred
* check_ip_reputation — needs DNSWL/Talos API mocking, deferred
"""
import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import dns.resolver
import pytest


# Path to the fixture directory (sibling of this file)
GOLDEN_DIR = Path(__file__).parent / "golden_data"

# The set of golden domains to test. Each entry must have a fixture file
# at GOLDEN_DIR/<domain_with_underscores>.json.
GOLDEN_DOMAINS = [
    "voicenotes.com",       # Customer-grade, mixed-bit DKIM (k1+resend), DBL refusal
    "mailercloud.com",      # Mailercloud's own infra: BIMI configured, sp=reject, fo=1
    "microsoft.com",        # Enterprise reference: MTA-STS, TLS-RPT, multi-sender
]


# Checks covered by the golden suite. Each must be importable as
# checks.check_<name> (with one alias for sender_detection -> senders).
GOLDEN_CHECKS = [
    "mx_records", "spf", "dkim", "dmarc", "blacklists", "domain_blacklists",
    "bimi", "mta_sts", "tls_rpt", "senders", "reverse_dns",
]


def _load_fixture(domain: str) -> dict:
    """Load the JSON fixture for a domain."""
    path = GOLDEN_DIR / f"{domain.replace('.', '_')}.json"
    if not path.exists():
        pytest.fail(
            f"Missing golden fixture: {path}\n"
            f"Run the capture script to regenerate it:\n"
            f"  python3 -c 'from tests.test_golden_domains import recapture; recapture()'"
        )
    with path.open() as f:
        return json.load(f)


def _make_replay(dns_data: dict):
    """Return a fake safe_dns_query that returns fixture data."""
    def replay(qname, rdtype, timeout=5):
        return dns_data.get(f"{qname}:{rdtype}")
    return replay


def _make_resolver_class(dns_data: dict):
    """Return a fake dns.resolver.Resolver class that returns fixture data.
    Used by check functions that call dns.resolver.Resolver() directly."""
    class FixtureResolver:
        def __init__(self):
            self.timeout = 5
            self.lifetime = 5
            self.nameservers = []

        def resolve(self, qname, rdtype):
            key = f"{qname}:{rdtype}"
            data = dns_data.get(key)
            if data is None:
                raise dns.resolver.NXDOMAIN(qnames=[qname])
            results = []
            for s in data:
                m = MagicMock()
                m.__str__ = lambda self, s=s: s
                if rdtype == "MX":
                    parts = s.split()
                    if len(parts) >= 2:
                        m.preference = int(parts[0])
                        host = parts[1]
                        m.exchange = MagicMock()
                        m.exchange.__str__ = lambda self, h=host: h
                results.append(m)
            return results
    return FixtureResolver


def _check_function(name: str):
    """Return the check function for a given check name."""
    import checks
    fn_name = "check_" + ("sender_detection" if name == "senders" else name)
    return getattr(checks, fn_name)


@pytest.fixture(autouse=False)
def fixture_dns(request):
    """Patch checks.safe_dns_query and checks.dns.resolver.Resolver to
    replay from the supplied dns_data dict (request.param)."""
    import checks
    dns_data = request.param
    orig_safe = checks.safe_dns_query
    orig_resolver = checks.dns.resolver.Resolver
    checks.safe_dns_query = _make_replay(dns_data)
    checks.dns.resolver.Resolver = _make_resolver_class(dns_data)
    yield
    checks.safe_dns_query = orig_safe
    checks.dns.resolver.Resolver = orig_resolver


# ─── PARAMETRIZED TESTS ──────────────────────────────────────────

def _build_test_cases():
    """Yield (domain, check_name, expected) tuples for each golden cell."""
    cases = []
    for domain in GOLDEN_DOMAINS:
        fx = _load_fixture(domain)
        expected = (fx.get("expected") or {}).get("checks") or {}
        for cname in GOLDEN_CHECKS:
            # The check name in the result might differ from the input
            # — sender_detection's CheckResult uses name="senders".
            # We look up by the GOLDEN_CHECKS canonical name.
            exp = expected.get(cname)
            if exp is None:
                continue
            cases.append((domain, cname, exp, fx["dns"]))
    return cases


@pytest.mark.parametrize(
    "domain,check_name,expected,dns_data",
    _build_test_cases(),
    ids=lambda v: (v if isinstance(v, str) else "").replace(":", "_"),
)
def test_golden_check(domain, check_name, expected, dns_data, monkeypatch):
    """Run a single check against fixture DNS, assert pinned output."""
    import checks

    # Patch DNS access
    monkeypatch.setattr(checks, "safe_dns_query", _make_replay(dns_data))
    monkeypatch.setattr(
        checks.dns.resolver, "Resolver",
        _make_resolver_class(dns_data),
    )

    fn = _check_function(check_name)
    result = fn(domain)

    # Assert exact match on status (any drift = scoring change worth notice)
    assert result.status == expected["status"], (
        f"\n[{domain} :: {check_name}] status changed:\n"
        f"  expected: {expected['status']}\n"
        f"  actual  : {result.status}\n"
        f"\nIf intentional, re-run capture and commit the updated fixture."
    )
    # Assert exact match on points
    assert result.points == expected["points"], (
        f"\n[{domain} :: {check_name}] points changed:\n"
        f"  expected: {expected['points']}\n"
        f"  actual  : {result.points}\n"
        f"\nIf intentional, re-run capture and commit the updated fixture."
    )
    # Assert exact match on max_points
    assert result.max_points == expected["max_points"], (
        f"\n[{domain} :: {check_name}] max_points changed:\n"
        f"  expected: {expected['max_points']}\n"
        f"  actual  : {result.max_points}\n"
        f"\nThis usually signals a CANONICAL_MAX_POINTS edit. If "
        f"intentional, re-run capture and commit the updated fixture."
    )


# ─── HELPER: RECAPTURE FIXTURES ──────────────────────────────────

def recapture():
    """Re-run live DNS captures for every GOLDEN_DOMAIN and update the
    fixture files. Use this when scoring logic intentionally changes
    or when a real domain's DNS changes.

    Run from the project root:
        python3 -c "from tests.test_golden_domains import recapture; recapture()"
    """
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent))
    import checks
    import dns.reversename

    def resolver_factory():
        r = dns.resolver.Resolver()
        r.nameservers = ["1.1.1.1", "8.8.8.8"]
        r.timeout = 4
        r.lifetime = 5
        return r

    def safe(qname, rdtype):
        try:
            ans = resolver_factory().resolve(qname, rdtype)
            return [str(rdata) for rdata in ans]
        except Exception:
            return None

    # Selectors we expect to find on at least one of our golden domains
    SELECTORS = ["default", "selector1", "selector2", "google",
                  "k1", "k2", "s1", "s2", "mandrill", "mte1",
                  "pm", "postmark", "resend", "klaviyo",
                  "smtpapi", "m1", "amazonses", "mxvault",
                  "mlrcloud"]

    for domain in GOLDEN_DOMAINS:
        fx = {
            "domain": domain,
            "captured_at": "RUN_DATE",
            "dns": {},
        }

        def record(q, t):
            ans = safe(q, t)
            if ans is not None:
                fx["dns"][f"{q}:{t}"] = ans

        record(domain, "TXT")
        record(domain, "MX")
        record(domain, "A")
        for sel in SELECTORS:
            record(f"{sel}._domainkey.{domain}", "TXT")
            record(f"{sel}._domainkey.{domain}", "CNAME")
        record(f"_dmarc.{domain}", "TXT")
        record(f"default._bimi.{domain}", "TXT")
        record(f"_mta-sts.{domain}", "TXT")
        record(f"_smtp._tls.{domain}", "TXT")

        # Resolve MX hosts to A/AAAA + their PTR
        for mx_str in fx["dns"].get(f"{domain}:MX", []):
            parts = mx_str.split()
            if len(parts) >= 2:
                host = parts[1].rstrip(".")
                record(host, "A")
                record(host, "AAAA")
                a_records = fx["dns"].get(f"{host}:A", [])
                for ip in a_records:
                    rev = str(dns.reversename.from_address(ip))  # has trailing dot
                    record(rev, "PTR")

        # Compute expected outputs by replaying against the captured DNS
        orig_safe = checks.safe_dns_query
        orig_resolver = checks.dns.resolver.Resolver
        checks.safe_dns_query = _make_replay(fx["dns"])
        checks.dns.resolver.Resolver = _make_resolver_class(fx["dns"])
        expected = {}
        try:
            for cname in GOLDEN_CHECKS:
                fn = _check_function(cname)
                r = fn(domain)
                expected[r.name] = {
                    "status": r.status,
                    "points": r.points,
                    "max_points": r.max_points,
                }
        finally:
            checks.safe_dns_query = orig_safe
            checks.dns.resolver.Resolver = orig_resolver
        fx["expected"] = {"checks": expected}

        path = GOLDEN_DIR / f"{domain.replace('.', '_')}.json"
        with path.open("w") as f:
            json.dump(fx, f, indent=2)
        print(f"recaptured {domain} → {path}")


# ─── SANITY: FIXTURE FILES PRESENT ────────────────────────────────

def test_all_golden_fixtures_exist():
    """Every domain in GOLDEN_DOMAINS must have a fixture file."""
    for domain in GOLDEN_DOMAINS:
        path = GOLDEN_DIR / f"{domain.replace('.', '_')}.json"
        assert path.exists(), f"Missing fixture: {path}"


def test_all_fixtures_have_expected_section():
    """Every fixture must have an 'expected.checks' dict."""
    for domain in GOLDEN_DOMAINS:
        fx = _load_fixture(domain)
        assert "expected" in fx, f"{domain} missing 'expected' key"
        assert "checks" in fx["expected"], f"{domain} missing 'expected.checks'"
        assert len(fx["expected"]["checks"]) > 0, f"{domain} has no expected check pins"
