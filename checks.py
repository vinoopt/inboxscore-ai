"""
InboxScore - Email deliverability diagnostic checks.

This module holds the 14 domain-health `check_*` functions that were previously
inside `app.py`. Extracted in INBOX-20 (Phase 1 Foundation Audit) so that the
scan orchestrator in `app.py` can import them from a single place, and so that
`app.py` is no longer ~3.7k lines.

Nothing in here knows about FastAPI, the database, Sentry, or the scheduler.
Each `check_*` function takes a domain string and returns a `CheckResult`.

All behaviour is preserved byte-for-byte — this module is a mechanical extract,
not a rewrite. See `docs/DECISIONS.md` for the boundary decisions.
"""

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

import concurrent.futures
import dns.resolver
import dns.reversename
import httpx
import whois
from pydantic import BaseModel


# ─── BLACKLISTS TO CHECK ───────────────────────────────────────────
# Trimmed to the 20 most reliable/authoritative blacklists for speed
# (removed slow/redundant/niche lists — these 20 cover all major providers)
BLACKLISTS = [
    "zen.spamhaus.org",          # Most authoritative — covers SBL, XBL, PBL
    "b.barracudacentral.org",    # Widely used by enterprises
    "bl.spamcop.net",            # Auto-expiring, complaint-based
    "cbl.abuseat.org",           # Composite Blocking List
    "dnsbl.sorbs.net",           # Combined SORBS
    "dnsbl-1.uceprotect.net",    # Level 1 — single IP
    "psbl.surriel.com",          # Passive Spam Block List
    "bl.mailspike.net",          # Mailspike
    "dyna.spamrats.com",         # Dynamic IP detection
    "spam.spamrats.com",         # Known spam sources
    "bl.blocklist.de",           # Attack detection
    "dnsbl.dronebl.org",         # Drone/botnet detection
    "ix.dnsbl.manitu.net",       # German blocklist
    "truncate.gbudb.net",        # Global Blacklist UDP
    "all.s5h.net",               # Comprehensive
    "combined.abuse.ch",         # Malware/spam combined
    "rbl.interserver.net",       # Hosting provider list
    "bl.nordspam.com",           # Nordic spam list
    "combined.mail.abusix.zone", # Abusix combined
    "bogons.cymru.com",          # Bogon/unallocated IPs
]

# Common DKIM selectors to check
DKIM_SELECTORS = [
    "google", "default", "selector1", "selector2",
    "dkim", "mail", "k1", "k2", "s1", "s2",
    "mandrill", "amazonses", "smtp", "cm",
    "mailchimp", "mailo", "mxvault",
]

# ─── DOMAIN BLACKLISTS (INBOX-42) ──────────────────────────────────
# DBL / SURBL / URIBL — domain-based reputation lists. These flag the
# DOMAIN itself (regardless of IP), which major mailbox providers
# consult when deciding inbox-vs-spam. A listing here means "mail from
# this domain will land in spam regardless of authentication setup."
DOMAIN_BLACKLISTS = [
    "dbl.spamhaus.org",   # Spamhaus Domain Block List — the authoritative one
    "multi.surbl.org",    # SURBL combined
    "black.uribl.com",    # URIBL
]


# ─── MODEL ─────────────────────────────────────────────────────────
class CheckResult(BaseModel):
    name: str
    category: str  # "authentication", "reputation", "infrastructure"
    status: str  # "pass", "warn", "fail", "info"
    title: str
    detail: str
    raw_data: Optional[dict] = None
    fix_steps: Optional[list] = None
    points: int = 0
    max_points: int = 0

# ─── DNS HELPERS ────────────────────────────────────────────────────
def safe_dns_query(qname, rdtype, timeout=5):
    """Safe DNS query with timeout and error handling"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        answers = resolver.resolve(qname, rdtype)
        return [str(rdata) for rdata in answers]
    except dns.resolver.NXDOMAIN:
        return None
    except dns.resolver.NoAnswer:
        return None
    except dns.resolver.NoNameservers:
        return None
    except dns.resolver.Timeout:
        return None
    except Exception:
        return None


# ─── SPF EXPANSION (INBOX-43) ──────────────────────────────────────
# Expand a domain's SPF record to concrete sending IPs. The set of IPs
# authorized to send mail as a domain is what actually matters for
# blacklist-checking deliverability — MX IPs are receiving-side and are
# almost always provider IPs (Google, Microsoft) that are never blacklisted.
#
# RFC 7208 caps "DNS lookups" at 10 to prevent runaway recursion via
# include: / redirect= / a / mx / exists: / ptr mechanisms. We enforce
# that limit here and warn when hit.
#
# IPv6 is ignored — virtually no DNSBL supports IPv6 queries today.
# `ptr` / `exists:` / `+all` / `~all` / `?all` / `-all` are also skipped
# (they don't contribute concrete IPs).

def _sample_cidr(cidr: str) -> list[str]:
    """For a CIDR range, return up to 3 IPs (first / middle / last)
    that represent the block. Small ranges return fewer — /32 returns 1.
    Keeps scan blast radius bounded for e.g. `ip4:52.0.0.0/8`.
    """
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return []
    if not isinstance(net, ipaddress.IPv4Network):
        return []   # skip IPv6 — most DNSBLs don't support it
    if net.prefixlen >= 30:
        # /30, /31, /32 — small enough to sample all
        return [str(h) for h in net.hosts()][:3] or [str(net.network_address)]
    if net.prefixlen >= 24:
        return [str(net.network_address)]
    # Larger ranges — take first, middle, last
    addrs = list(net.hosts())
    if len(addrs) <= 3:
        return [str(a) for a in addrs]
    return [str(addrs[0]), str(addrs[len(addrs) // 2]), str(addrs[-1])]


def _expand_spf_inner(domain: str, visited: set, lookup_budget: list, warnings: list) -> set:
    """Internal recursive SPF expander.

    `lookup_budget` is a 1-element list so we can decrement it by reference
    across the recursion. Stops at 0.
    """
    if lookup_budget[0] <= 0:
        if "10-lookup limit" not in "|".join(warnings):
            warnings.append(f"RFC 7208 10-lookup limit reached while expanding {domain}'s SPF")
        return set()
    if domain in visited:
        return set()
    visited.add(domain)
    lookup_budget[0] -= 1

    txt_records = safe_dns_query(domain, "TXT")
    if not txt_records:
        return set()

    spf = None
    for record in txt_records:
        clean = record.strip('"').strip()
        # Some TXT records arrive as concatenated quoted strings — strip inner quotes.
        clean = clean.replace('" "', '').replace('""', '')
        if clean.lower().startswith("v=spf1"):
            spf = clean
            break

    if not spf:
        return set()

    ips: set[str] = set()
    for raw_token in spf.split():
        token = raw_token.strip().lstrip("+")   # default qualifier is "+"
        tok = token.lower()

        if tok.startswith("ip4:"):
            cidr = token[4:]
            ips.update(_sample_cidr(cidr))
        elif tok.startswith("include:"):
            inc = token[8:]
            ips |= _expand_spf_inner(inc, visited, lookup_budget, warnings)
        elif tok.startswith("redirect="):
            redir = token.split("=", 1)[1]
            # redirect= replaces the current SPF per RFC 7208.
            ips |= _expand_spf_inner(redir, visited, lookup_budget, warnings)
        elif tok == "a" or tok.startswith("a:") or tok.startswith("a/"):
            a_target = token[2:] if tok.startswith("a:") else (domain if tok == "a" else token[2:])
            if "/" in a_target:
                a_target, cidr_suffix = a_target.split("/", 1)
            else:
                cidr_suffix = None
            if lookup_budget[0] <= 0:
                continue
            lookup_budget[0] -= 1
            a_records = safe_dns_query(a_target, "A")
            if a_records:
                for ip in a_records:
                    if cidr_suffix:
                        ips.update(_sample_cidr(f"{ip}/{cidr_suffix}"))
                    else:
                        ips.add(ip)
        elif tok == "mx" or tok.startswith("mx:") or tok.startswith("mx/"):
            mx_target = token[3:] if tok.startswith("mx:") else (domain if tok == "mx" else token[3:])
            if lookup_budget[0] <= 0:
                continue
            lookup_budget[0] -= 1
            mx_records = safe_dns_query(mx_target, "MX")
            if mx_records:
                for mx in mx_records[:5]:
                    mx_host = mx.split()[-1].rstrip(".")
                    if lookup_budget[0] <= 0:
                        break
                    lookup_budget[0] -= 1
                    a_recs = safe_dns_query(mx_host, "A")
                    if a_recs:
                        ips.update(a_recs)
        # else: ip6: / ptr / exists: / all / -all / ~all / ?all — no IP contribution.

    return ips


def expand_spf_ips(domain: str, max_lookups: int = 10, cap: int = 20) -> tuple[set, list]:
    """Public API: given a domain, return (ip_set, warnings).

    ip_set     — set of IPv4 strings authorized to send as this domain
                 via its SPF record. Empty if no SPF or only IPv6/-all.
                 Capped at `cap` entries (sorted lexicographically) to
                 bound blacklist-query blast radius.
    warnings   — human-readable notes about limits hit during expansion.
    """
    visited: set[str] = set()
    lookup_budget = [max_lookups]
    warnings: list[str] = []
    ips = _expand_spf_inner(domain, visited, lookup_budget, warnings)
    if len(ips) > cap:
        warnings.append(
            f"SPF expanded to {len(ips)} IPs; sampled first {cap} (sorted) for blacklist check"
        )
        ips = set(sorted(ips)[:cap])
    return ips, warnings


# ─── CHECK FUNCTIONS ────────────────────────────────────────────────

def check_mx_records(domain: str) -> CheckResult:
    """Check MX records for the domain"""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5
        answers = resolver.resolve(domain, "MX")
        mx_records = []
        for rdata in answers:
            mx_records.append({
                "priority": rdata.preference,
                "host": str(rdata.exchange).rstrip(".")
            })
        mx_records.sort(key=lambda x: x["priority"])

        if len(mx_records) >= 2:
            detail = f"{len(mx_records)} MX records found with proper priority configuration"
            points = 10
            status = "pass"
        elif len(mx_records) == 1:
            detail = f"1 MX record found — consider adding a backup mail server for redundancy"
            points = 9
            status = "pass"
        else:
            detail = "No MX records found"
            points = 0
            status = "fail"

        return CheckResult(
            name="mx_records",
            category="infrastructure",
            status=status,
            title="MX Records",
            detail=detail,
            raw_data={"records": mx_records},
            points=points,
            max_points=10,
            fix_steps=None if status == "pass" else [
                "Add at least 2 MX records in your DNS settings",
                "Set different priorities (e.g., 10 for primary, 20 for backup)",
                "Ensure both mail servers are reachable and accepting connections"
            ]
        )
    except Exception as e:
        return CheckResult(
            name="mx_records",
            category="infrastructure",
            status="fail",
            title="MX Records",
            detail=f"Could not find MX records for {domain}",
            points=0,
            max_points=10,
            fix_steps=[
                "Verify the domain exists and DNS is properly configured",
                "Add MX records pointing to your email provider's mail servers",
                "Check with your domain registrar if DNS propagation is complete"
            ]
        )


def check_spf(domain: str) -> CheckResult:
    """Check SPF record"""
    txt_records = safe_dns_query(domain, "TXT")
    if txt_records is None:
        return CheckResult(
            name="spf",
            category="authentication",
            status="fail",
            title="SPF Record",
            detail="No TXT records found — SPF is not configured",
            points=0,
            max_points=15,
            fix_steps=[
                "Add a TXT record to your DNS with your SPF policy",
                "Example: v=spf1 include:_spf.google.com -all (for Google Workspace)",
                "Use -all (hard fail) instead of ~all (soft fail) for better security",
                "Keep the number of DNS lookups under 10 to avoid SPF permerror"
            ]
        )

    spf_record = None
    for record in txt_records:
        cleaned = record.strip('"')
        if cleaned.startswith("v=spf1"):
            spf_record = cleaned
            break

    if not spf_record:
        return CheckResult(
            name="spf",
            category="authentication",
            status="fail",
            title="SPF Record",
            detail="No SPF record found in DNS TXT records",
            points=0,
            max_points=15,
            fix_steps=[
                "Add a TXT record starting with 'v=spf1' to your domain's DNS",
                "Include your email provider's SPF directive (e.g., include:_spf.google.com)",
                "End with -all to reject unauthorized senders"
            ]
        )

    # Analyze SPF quality
    issues = []
    points = 15

    if "~all" in spf_record:
        issues.append("Uses ~all (soft fail) — widely accepted; -all (hard fail) offers stricter enforcement")
        points = 14
        status = "pass"
    elif "+all" in spf_record:
        issues.append("CRITICAL: Uses +all which allows ANYONE to send as your domain")
        points = 0
        status = "fail"
    elif "?all" in spf_record:
        issues.append("Uses ?all (neutral) — this provides no protection. Change to -all")
        points = 5
        status = "warn"
    elif "-all" in spf_record:
        status = "pass"
    else:
        status = "warn"
        points = 10
        issues.append("No 'all' mechanism found — add -all at the end")

    # Check for too many includes (DNS lookup limit is 10)
    include_count = spf_record.count("include:")
    if include_count > 7:
        issues.append(f"High number of includes ({include_count}) — close to the 10 DNS lookup limit")
        points = min(points, 10)

    detail = f"SPF record found: {spf_record[:80]}{'...' if len(spf_record) > 80 else ''}"
    if issues:
        detail += " — " + issues[0]

    return CheckResult(
        name="spf",
        category="authentication",
        status=status,
        title="SPF Record",
        detail=detail,
        raw_data={"record": spf_record, "issues": issues},
        points=points,
        max_points=15,
        fix_steps=issues if issues else None
    )


def check_dkim(domain: str) -> CheckResult:
    """Check DKIM by testing common selectors — parallelized for speed"""
    found_selectors = []

    def _probe_selector(selector):
        """Check one selector for DKIM TXT or CNAME — returns dict or None"""
        dkim_domain = f"{selector}._domainkey.{domain}"
        # Try TXT first
        result = safe_dns_query(dkim_domain, "TXT", timeout=2)
        if result:
            for record in result:
                # INBOX-52: dnspython renders a multi-string TXT record as
                # `"PART1" "PART2"`. 2048-bit DKIM keys are commonly split
                # across multiple strings because each TXT string is capped
                # at 255 bytes. We must concatenate before regex extraction
                # — otherwise the `p=([A-Za-z0-9+/=]+)` capture stops at
                # the quote-space-quote junction and we miscount the key
                # length (eg report 2048-bit as 1024-bit, the voicenotes.com
                # k1 case).
                cleaned = re.sub(r'"\s+"', '', record).strip('"')
                if "v=DKIM1" in cleaned or "p=" in cleaned:
                    key_length = "unknown"
                    p_match = re.search(r'p=([A-Za-z0-9+/=]+)', cleaned)
                    if p_match:
                        key_b64 = p_match.group(1)
                        # Heuristic: base64 encodes ~6 bits/char of the
                        # SPKI envelope; an SPKI-wrapped 2048-bit RSA key
                        # is ~294 bytes ≈ 392 chars × 6 = 2352 bits;
                        # 1024-bit is ~162 bytes ≈ 216 chars × 6 = 1296.
                        # Any p=; (revoked) yields 0 chars and falls into
                        # the unknown bucket (status handled below).
                        key_bits = len(key_b64) * 6
                        if key_bits == 0:
                            key_length = "revoked (p=;)"
                        elif key_bits > 2000:
                            key_length = "2048-bit"
                        elif key_bits > 1000:
                            key_length = "1024-bit"
                        else:
                            key_length = f"~{key_bits}-bit"
                    return {
                        "selector": selector,
                        "key_length": key_length,
                        "record_preview": cleaned[:100]
                    }
        # Fallback: check CNAME
        cname_result = safe_dns_query(dkim_domain, "CNAME", timeout=2)
        if cname_result:
            return {
                "selector": selector,
                "key_length": "CNAME redirect",
                "record_preview": f"CNAME -> {cname_result[0]}"
            }
        return None

    # Probe all selectors in parallel (each is a single DNS query)
    with concurrent.futures.ThreadPoolExecutor(max_workers=17) as executor:
        future_map = {executor.submit(_probe_selector, s): s for s in DKIM_SELECTORS}
        for future in concurrent.futures.as_completed(future_map, timeout=5):
            try:
                hit = future.result()
                if hit:
                    found_selectors.append(hit)
            except Exception:
                pass

    if found_selectors:
        selector_names = [s["selector"] for s in found_selectors]
        detail = f"DKIM configured for selector{'s' if len(found_selectors) > 1 else ''}: {', '.join(selector_names)}"

        # Check key strength
        has_weak_key = any(
            "1024" in s.get("key_length", "") for s in found_selectors
        )
        if has_weak_key:
            return CheckResult(
                name="dkim",
                category="authentication",
                status="pass",
                title="DKIM",
                detail=detail + " — using 1024-bit key; 2048-bit recommended for stronger security",
                raw_data={"selectors": found_selectors},
                points=14,
                max_points=15,
                fix_steps=[
                    "Your DKIM key is 1024-bit which is becoming outdated",
                    "Generate a new 2048-bit DKIM key through your email provider",
                    "Update the DNS TXT record with the new key",
                    "Most providers (Google, Microsoft) support 2048-bit keys"
                ]
            )

        return CheckResult(
            name="dkim",
            category="authentication",
            status="pass",
            title="DKIM",
            detail=detail,
            raw_data={"selectors": found_selectors},
            points=15,
            max_points=15
        )
    else:
        return CheckResult(
            name="dkim",
            category="authentication",
            status="fail",
            title="DKIM",
            detail="No DKIM records found for common selectors",
            raw_data={"checked_selectors": DKIM_SELECTORS[:10]},
            points=0,
            max_points=15,
            fix_steps=[
                "Enable DKIM signing in your email provider settings",
                "For Google Workspace: Admin Console → Apps → Google Workspace → Gmail → Authenticate email",
                "For Microsoft 365: Exchange Admin → Protection → DKIM",
                "Add the generated TXT record to your DNS",
                "Note: We checked selectors: " + ", ".join(DKIM_SELECTORS[:8]) + " — your provider may use a different selector"
            ]
        )


def check_dmarc(domain: str) -> CheckResult:
    """Check DMARC record"""
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = safe_dns_query(dmarc_domain, "TXT")

    if not txt_records:
        return CheckResult(
            name="dmarc",
            category="authentication",
            status="fail",
            title="DMARC Policy",
            detail="No DMARC record found — your domain is vulnerable to email spoofing",
            points=0,
            max_points=15,
            fix_steps=[
                "Add a TXT record at _dmarc.yourdomain.com",
                "Start with: v=DMARC1; p=none; rua=mailto:dmarc-reports@yourdomain.com",
                "Monitor reports for 2-4 weeks to ensure legitimate emails pass",
                "Then upgrade to p=quarantine, and eventually p=reject",
                "The rua tag tells ISPs where to send DMARC aggregate reports"
            ]
        )

    dmarc_record = None
    for record in txt_records:
        cleaned = record.strip('"')
        if cleaned.startswith("v=DMARC1"):
            dmarc_record = cleaned
            break

    if not dmarc_record:
        return CheckResult(
            name="dmarc",
            category="authentication",
            status="fail",
            title="DMARC Policy",
            detail="TXT record found at _dmarc but no valid DMARC policy",
            points=0,
            max_points=15,
            fix_steps=[
                "Your _dmarc record exists but doesn't contain a valid DMARC policy",
                "Ensure the record starts with 'v=DMARC1;'",
                "Example: v=DMARC1; p=reject; rua=mailto:dmarc@yourdomain.com"
            ]
        )

    # Parse DMARC policy
    policy = "none"
    if "p=reject" in dmarc_record:
        policy = "reject"
    elif "p=quarantine" in dmarc_record:
        policy = "quarantine"
    elif "p=none" in dmarc_record:
        policy = "none"

    has_rua = "rua=" in dmarc_record
    has_ruf = "ruf=" in dmarc_record

    if policy == "reject":
        points = 15
        status = "pass"
        detail = f"DMARC policy set to reject — maximum protection enabled"
    elif policy == "quarantine":
        points = 14
        status = "pass"
        detail = f"DMARC policy set to quarantine — strong protection"
    else:
        points = 10
        status = "warn"
        detail = f"DMARC exists with p=none — monitoring mode, consider upgrading to quarantine/reject"

    if not has_rua:
        detail += ". No rua tag — you're not receiving DMARC reports"
        points = max(points - 2, 0)

    fix_steps = None
    if policy == "none":
        fix_steps = [
            "Your DMARC policy (p=none) only monitors — it doesn't protect against spoofing",
            "Step 1: Keep p=none for 2 weeks while reviewing DMARC reports",
            "Step 2: Change to p=quarantine to send failed emails to spam",
            "Step 3: After confirming no legitimate emails are affected, upgrade to p=reject",
            "This gradual approach prevents accidentally blocking your own emails"
        ]
    elif not has_rua:
        fix_steps = [
            "Add a rua tag to receive DMARC aggregate reports",
            "Example: rua=mailto:dmarc-reports@yourdomain.com",
            "These reports show who is sending email as your domain"
        ]

    return CheckResult(
        name="dmarc",
        category="authentication",
        status=status,
        title="DMARC Policy",
        detail=detail,
        raw_data={
            "record": dmarc_record,
            "policy": policy,
            "has_rua": has_rua,
            "has_ruf": has_ruf
        },
        points=points,
        max_points=15,
        fix_steps=fix_steps
    )


def check_blacklists(domain: str) -> CheckResult:
    """Check domain against multiple blacklists — tracks IP source for transparency"""
    # Resolve domain IPs and track WHERE each IP came from
    ip_sources = {}  # ip -> list of sources like "MX: aspmx.l.google.com" or "A record"

    # INBOX-43: primary signal — SPF-derived sending IPs. These are the IPs
    # the domain AUTHORIZES to send mail as itself, and therefore the IPs
    # whose reputation actually drives deliverability. MX IPs (below) are
    # receiving-side; they're always provider IPs (Google, Microsoft, etc.)
    # and are essentially never on public blacklists — low signal value.
    # SPF-derived IPs, by contrast, include the customer's own sending
    # infrastructure + any ESPs they've authorized (Mailgun, SendGrid, SES,
    # Mailercloud, etc.) — those DO land on blacklists when misused.
    spf_ips, spf_warnings = expand_spf_ips(domain)
    for ip in spf_ips:
        ip_sources.setdefault(ip, []).append(f"SPF: sending IP for {domain}")

    mx_records = safe_dns_query(domain, "MX")
    if mx_records:
        for mx in mx_records:
            mx_host = mx.split()[-1].rstrip(".")
            a_records = safe_dns_query(mx_host, "A")
            if a_records:
                for ip in a_records:
                    ip_sources.setdefault(ip, []).append(f"MX: {mx_host}")

    # INBOX-36: the domain's A record is the WEBSITE host (Cloudflare, Vercel,
    # Netlify, etc.) when MX is properly configured. It does NOT send email.
    # Including it in an email-blacklist check was the root cause of the
    # false-positive "104.26.x.x listed on blacklists" observations — those
    # are Cloudflare IPs, not mail IPs. We now only fall back to the A record
    # if NEITHER SPF NOR MX produced usable IPs (null-MX or DNS misconfig).
    if not ip_sources:
        a_records = safe_dns_query(domain, "A")
        if a_records:
            for ip in a_records:
                ip_sources.setdefault(ip, []).append("A record (no MX)")

    if not ip_sources:
        # INBOX-25 (L2): a domain with zero mail infrastructure (parked,
        # abandoned, typo-squatted) must NOT score a perfect blacklist
        # result. The previous implementation returned status="pass",
        # points=15, max_points=15 with a bogus "cloud provider" detail —
        # handing out a gold star for doing nothing. Now we fail loudly
        # so the denominator still says /15 (honest score) but the
        # numerator reflects that we have no evidence of any mail setup.
        return CheckResult(
            name="blacklists",
            category="reputation",
            status="fail",
            title="Blacklist Status",
            detail=(
                "No mail infrastructure detected — cannot evaluate blacklist "
                "exposure. Domain has no MX records and no A record, which "
                "means it cannot receive or send email."
            ),
            points=0,
            max_points=15,
            raw_data={"checked": 0, "listed": [], "reason": "no_mail_infrastructure"},
            fix_steps=[
                "Publish MX records pointing to your email provider (e.g., aspmx.l.google.com for Google Workspace)",
                "If this domain is intentionally not used for email, add an MX record of \".\" (null MX, RFC 7505) to make that explicit",
                "Verify DNS propagation by running: dig MX yourdomain.com",
            ],
        )

    # INBOX-26: sort deterministically so slices at :518, :538, and downstream
    # callers (hetrix, app) see the same IPs in the same order between runs.
    # Order here is insertion-order-from-DNS, which is NOT stable across
    # scans even with identical upstream state.
    ips = sorted(ip_sources.keys())

    # Check each IP against blacklists.
    # Three categories of non-clean result, all tracked separately:
    #   listed_on — real spam/botnet listings (SBL/CBL/XBL; 127.0.0.2-9).
    #               Count toward FAIL status + dock points.
    #   policy_on — Spamhaus PBL policy listings (INBOX-35; 127.0.0.10/11).
    #               DO NOT count — ESP-managed IPs routinely land on PBL.
    #   error_on  — DNSBL query refused/rate-limited (INBOX-39; 127.255.255.*).
    #               DO NOT count — we literally couldn't get a real answer.
    listed_on = []
    policy_on = []
    error_on = []
    clean_on = 0
    checked = 0

    # Spamhaus PBL codes — policy listings, NOT spam/botnet listings.
    # See https://www.spamhaus.org/faq/section/DNSBL%20Usage
    PBL_CODES = frozenset(["127.0.0.10", "127.0.0.11"])

    def check_single_bl(ip, bl):
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.{bl}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            ans = resolver.resolve(query, "A")
            codes = sorted({str(rr) for rr in ans})
        except Exception:
            # NXDOMAIN (not listed) or network error — treat as clean.
            # Note: conflating NXDOMAIN with network failure is a separate
            # fail-loud concern, flagged in INBOX-25's close-out.
            return None

        source = ", ".join(ip_sources.get(ip, ["unknown"]))

        # INBOX-39: Spamhaus return codes in the 127.255.255.0/24 range are
        # ERROR responses, NOT listings. They mean the DNSBL refused to
        # serve the query — typically because our scan server is using a
        # shared/public DNS resolver (Render-side infra). Examples:
        #   127.255.255.252 — typo in DNSBL name
        #   127.255.255.253 — DNSBL discontinued
        #   127.255.255.254 — query via public resolver blocked  ← common
        #   127.255.255.255 — excessive queries / rate-limited
        # Previously we misread these as spam listings, producing false-
        # positive FAILs on Google Workspace / Microsoft 365 MX IPs.
        if codes and all(c.startswith("127.255.255.") for c in codes):
            return {
                "blacklist": bl, "ip": ip, "source": source,
                "listing_type": "error", "codes": codes,
            }

        # Only-PBL codes → policy listing. Any other code → spam listing.
        if codes and set(codes).issubset(PBL_CODES):
            return {
                "blacklist": bl, "ip": ip, "source": source,
                "listing_type": "policy", "codes": codes,
            }
        return {
            "blacklist": bl, "ip": ip, "source": source,
            "listing_type": "spam", "codes": codes,
        }

    # INBOX-25 (L5): check up to 5 IPs (was: 2). A domain with many sending
    # IPs (Google Workspace, Office 365, SendGrid, SES, etc.) routinely
    # exposes 4+ IPs at the MX layer. Checking only the first 2 meant
    # listings on IPs 3+ were invisible to the customer.
    #
    # The cap stays (rather than checking ALL IPs) because:
    #   - 20 blacklists × N IPs = 20N parallel DNS queries.
    #   - With 25 workers and the 8s outer timeout, ~100 queries = safe.
    #   - Raising N without bound would push queries past the timeout and
    #     they'd be silently discarded (i.e. counted neither clean nor
    #     listed) — a worse outcome than capping honestly.
    # 5 matches the cap we ship in `all_ips` for ip_reputation (INBOX-26)
    # and the cap in hetrix.py, keeping the three surfaces consistent.
    IP_CHECK_CAP = 5
    ips_to_check = ips[:IP_CHECK_CAP]

    # Use thread pool for parallel blacklist checks
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        futures = []
        for ip in ips_to_check:
            for bl in BLACKLISTS:
                futures.append(executor.submit(check_single_bl, ip, bl))

        for future in concurrent.futures.as_completed(futures, timeout=8):
            checked += 1
            try:
                result = future.result()
                if result is None:
                    clean_on += 1
                elif result.get("listing_type") == "policy":
                    policy_on.append(result)
                elif result.get("listing_type") == "error":
                    error_on.append(result)
                else:
                    listed_on.append(result)
            except Exception:
                pass

    total_lists = len(BLACKLISTS)
    listings = len(listed_on)
    policy_count = len(policy_on)
    error_count = len(error_on)

    # INBOX-25: display the SAME IPs we actually checked.
    ip_summary = []
    for ip in ips_to_check:
        sources = ", ".join(ip_sources.get(ip, []))
        ip_summary.append({"ip": ip, "source": sources})

    # INBOX-35: group policy listings by IP so the UI can show them as
    # informational context (without counting them toward the FAIL).
    policy_by_ip = {}
    for item in policy_on:
        policy_by_ip.setdefault(item["ip"], []).append(item["blacklist"])

    # INBOX-39: which DNSBLs returned error responses for EVERY IP we
    # queried? If Spamhaus ZEN refused all 5 IP lookups with
    # 127.255.255.254, that's a complete failure of the ZEN check — not
    # noise we can ignore. A BL is fully-errored only if we got errors for
    # all of the IPs we checked against it.
    errors_by_bl: dict[str, int] = {}
    for item in error_on:
        errors_by_bl[item["blacklist"]] = errors_by_bl.get(item["blacklist"], 0) + 1
    fully_errored_bls = sorted(
        bl for bl, n in errors_by_bl.items() if n >= len(ips_to_check)
    )

    # Zero real listings — PASS. Optionally mention policy listings as INFO.
    if listings == 0:
        # INBOX-39: compute how many blacklists we actually managed to query
        # cleanly — `total_lists` minus any that refused every IP.
        effectively_checked = total_lists - len(fully_errored_bls)
        detail = f"Not listed on any of {effectively_checked} blacklists checked"
        if len(ips) == 1:
            detail += f" (checked IP: {ips[0]} via {ip_sources[ips[0]][0]})"
        elif len(ips) > IP_CHECK_CAP:
            detail += f" (checked {len(ips_to_check)} of {len(ips)} IPs)"
        else:
            detail += f" (checked {len(ips_to_check)} IPs)"
        if policy_count:
            # Don't dock points — just let the user know.
            unique_policy_ips = len(policy_by_ip)
            detail += (
                f". Note: {unique_policy_ips} IP{'s' if unique_policy_ips != 1 else ''} "
                "appear on Spamhaus PBL — a policy indicator (common for "
                "ESP-managed IPs), not a spam listing."
            )
        # INBOX-39: honestly surface when DNSBLs refused our queries.
        # For scans from cloud hosts (Render, AWS), Spamhaus returns
        # 127.255.255.254 to block public-resolver queries. We report
        # PASS because we have no evidence of a listing — but we should
        # NOT pretend the check was comprehensive when part of it failed.
        if fully_errored_bls:
            bl_list = ", ".join(fully_errored_bls)
            detail += (
                f". Note: {len(fully_errored_bls)} blacklist{'s' if len(fully_errored_bls) != 1 else ''} "
                f"({bl_list}) could not be queried from our scan server (public-resolver block) — "
                "re-verify externally if needed."
            )
        return CheckResult(
            name="blacklists",
            category="reputation",
            status="pass",
            title="Blacklist Status",
            detail=detail,
            raw_data={
                "checked": total_lists,
                "effectively_checked": effectively_checked,
                "listed": [],
                "ips_checked": ip_summary,
                "policy_listings": policy_on,
                "policy_by_ip": policy_by_ip,
                # INBOX-39: expose error details so a future UI can show them
                # in a "diagnostics" section without affecting the top-line verdict.
                "error_listings": error_on,
                "fully_errored_blacklists": fully_errored_bls,
            },
            points=15,
            max_points=15
        )

    # Group listings by IP for clear display
    listings_by_ip = {}
    for item in listed_on:
        ip = item["ip"]
        listings_by_ip.setdefault(ip, []).append(item["blacklist"])

    if listings <= 2:
        fix_steps = []
        for item in listed_on:
            bl_name = item["blacklist"]
            ip = item["ip"]
            source = item.get("source", "unknown")
            step = f"IP {ip} ({source}) listed on {bl_name}: "
            if "spamhaus" in bl_name:
                step += "Visit spamhaus.org/lookup and submit a removal request"
            elif "barracuda" in bl_name:
                step += "Go to barracudacentral.org/rbl/removal-request"
            elif "spamcop" in bl_name:
                step += "Listings auto-expire in 24-48 hours once spam stops"
            elif "sorbs" in bl_name:
                step += "Visit sorbs.net and request delisting"
            else:
                step += f"Search for '{bl_name} removal request' to find the delisting form"
            fix_steps.append(step)
        fix_steps.append("Before requesting removal, identify and fix the root cause (high bounces, spam complaints, compromised account)")

        return CheckResult(
            name="blacklists",
            category="reputation",
            status="warn" if listings == 1 else "fail",
            title="Blacklist Status",
            detail=f"Listed on {listings} blacklist{'s' if listings > 1 else ''} out of {total_lists} checked",
            raw_data={
                "checked": total_lists,
                "listed": listed_on,
                "ips_checked": ip_summary,
                "listings_by_ip": listings_by_ip,
                # INBOX-35: also expose any policy listings for context.
                "policy_listings": policy_on,
                "policy_by_ip": policy_by_ip,
                # INBOX-39: error diagnostics.
                "error_listings": error_on,
                "fully_errored_blacklists": fully_errored_bls,
            },
            points=max(15 - (listings * 7), 0),
            max_points=15,
            fix_steps=fix_steps
        )
    else:
        # Build IP-aware detail text so the user can see which IPs are listed
        ip_detail_parts = []
        for ip, bls in listings_by_ip.items():
            source = ", ".join(ip_sources.get(ip, ["unknown"]))
            ip_detail_parts.append(f"{ip} ({source}) on {len(bls)}")

        detail = f"Listed on {listings} blacklists across {len(listings_by_ip)} IP{'s' if len(listings_by_ip) > 1 else ''}: " + "; ".join(ip_detail_parts)

        # Build detailed fix steps showing which IPs are listed where
        fix_steps = []
        for ip, bls in listings_by_ip.items():
            source = ", ".join(ip_sources.get(ip, ["unknown"]))
            fix_steps.append(f"IP {ip} ({source}) — listed on {len(bls)} blacklist{'s' if len(bls) > 1 else ''}: {', '.join(bls[:5])}{'...' if len(bls) > 5 else ''}")
        fix_steps.append("Immediately check for compromised accounts or open relays on your mail server")
        fix_steps.append("Review recent bounce-back messages for patterns")
        fix_steps.append("Contact your email hosting provider — they may need to assign you a clean IP")
        fix_steps.append("After fixing the root cause, submit removal requests to each blacklist individually")
        fix_steps.append("Consider using a dedicated IP or a reputable email service provider")

        return CheckResult(
            name="blacklists",
            category="reputation",
            status="fail",
            title="Blacklist Status",
            detail=detail,
            raw_data={
                "checked": total_lists,
                "listed": listed_on,
                "ips_checked": ip_summary,
                "listings_by_ip": listings_by_ip,
                # INBOX-35: also expose any policy listings for context.
                "policy_listings": policy_on,
                "policy_by_ip": policy_by_ip,
                # INBOX-39: error diagnostics.
                "error_listings": error_on,
                "fully_errored_blacklists": fully_errored_bls,
            },
            points=0,
            max_points=15,
            fix_steps=fix_steps
        )


def check_domain_blacklists(domain: str) -> CheckResult:
    """Check the DOMAIN itself against domain-based blacklists (DBL/SURBL/URIBL).

    INBOX-42: separate reputation signal from the IP-based blacklist check.
    Domain blacklists (Spamhaus DBL, SURBL, URIBL) flag domains that have
    been observed in spam campaigns, phishing, or malware hosting — regardless
    of which IP they currently use. Major mailbox providers consult these
    lists during inbox-vs-spam decisions; a listing here effectively means
    "this domain's mail goes to spam regardless of authentication setup."

    Same DNSBL-error-code handling as INBOX-39: 127.255.255.* codes are
    Spamhaus's "query blocked / rate-limited" response range, NOT actual
    listings. Treated as "could not verify" rather than spam.
    """
    listed_on = []
    error_on = []

    # INBOX-50: refusal keywords observed in live TXT responses from URIBL
    # (and SURBL/Spamhaus fall-through cases). When a DBL returns an A record
    # of 127.0.0.1, it's almost always a "query refused" sentinel — URIBL
    # explicitly returns this with a TXT record pointing to uribl.com/refused.
    # We check the TXT record to disambiguate a real listing from a refusal.
    REFUSAL_TXT_MARKERS = ("refused", "blocked", "query", "public", "rate-limit",
                            "denied", "not authorized", "refused.shtml")

    def _query_domain_bl(bl: str):
        query = f"{domain}.{bl}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            ans = resolver.resolve(query, "A")
            codes = sorted({str(rr) for rr in ans})
        except Exception:
            return None  # NXDOMAIN / timeout — treat as clean

        # INBOX-39: 127.255.255.* is the Spamhaus error/rate-limit range.
        if codes and all(c.startswith("127.255.255.") for c in codes):
            return {"blacklist": bl, "listing_type": "error",
                    "codes": codes, "error_reason": "spamhaus_sentinel"}

        # INBOX-50: URIBL returns 127.0.0.1 with a TXT record when refusing
        # queries from public resolvers. Confirm via TXT before classifying
        # as a real listing. (URIBL's real listings are 127.0.0.2/4/8/14.)
        if codes == ["127.0.0.1"]:
            txt_text = ""
            try:
                txt_ans = resolver.resolve(query, "TXT")
                txt_text = " ".join(str(rr) for rr in txt_ans).lower()
            except Exception:
                txt_text = ""
            if any(marker in txt_text for marker in REFUSAL_TXT_MARKERS):
                return {"blacklist": bl, "listing_type": "error",
                        "codes": codes, "error_reason": "public_resolver_refused",
                        "txt": txt_text[:200]}
            # No TXT — conservative: treat as error anyway since 127.0.0.1 is
            # not a standard listing code on any major DBL. Spam listings are
            # 127.0.0.2-9 (Spamhaus/URIBL) or 127.0.1.* (Spamhaus DBL scoped).
            return {"blacklist": bl, "listing_type": "error",
                    "codes": codes, "error_reason": "nonstandard_127.0.0.1_response"}

        return {"blacklist": bl, "listing_type": "spam", "codes": codes}

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(_query_domain_bl, bl) for bl in DOMAIN_BLACKLISTS]
        for future in concurrent.futures.as_completed(futures, timeout=6):
            try:
                result = future.result()
                if result is None:
                    continue  # clean
                if result["listing_type"] == "error":
                    error_on.append(result)
                else:
                    listed_on.append(result)
            except Exception:
                pass

    listings = len(listed_on)
    errored_bls = sorted(r["blacklist"] for r in error_on)
    total_bls = len(DOMAIN_BLACKLISTS)

    if listings == 0:
        effectively_checked = total_bls - len(errored_bls)

        # INBOX-50: when every DBL refuses the query (Render's outbound DNS
        # goes through cloud resolvers, which most DBLs block), we literally
        # cannot verify listing status. Report this honestly as info-only
        # (max_points=0, points=0) and point the user to an external tool —
        # consistent with TLS fallback (INBOX-24) and the info-only treatment
        # of BIMI / Domain Age / MTA-STS.
        if effectively_checked == 0:
            hetrix_url = f"https://hetrixtools.com/blacklist-check/{domain}"
            return CheckResult(
                name="domain_blacklists",
                category="reputation",
                status="info",
                title="Domain Blacklists",
                detail=(
                    f"Could not verify domain blacklist status for {domain} from our "
                    f"scan server — all {total_bls} blacklists ({', '.join(errored_bls)}) "
                    "refused the query because we're hitting them from a public-DNS "
                    f"resolver IP. Verify externally at: {hetrix_url}"
                ),
                raw_data={
                    "checked": total_bls,
                    "effectively_checked": 0,
                    "listed": [],
                    "error_listings": error_on,
                    "fully_errored_blacklists": errored_bls,
                    "external_verification_url": hetrix_url,
                },
                fix_steps=[
                    f"Our scan server could not query domain blacklists directly. Verify on HetrixTools: {hetrix_url}",
                    "If you see a real listing there, use the DBL-specific removal process "
                    "(Spamhaus DBL: https://www.spamhaus.org/dbl/removal/  •  URIBL: "
                    "https://uribl.com/lookup.shtml  •  SURBL: https://www.surbl.org/surbl-analysis).",
                    "We're working on integrating HetrixTools' API to give you real-time data "
                    "directly in your InboxScore report (tracked in INBOX-51).",
                ],
                points=0,
                max_points=0,
            )

        # At least one DBL answered and none showed a listing.
        detail = f"{domain} not listed on any of {effectively_checked} domain blacklists checked"
        if errored_bls:
            detail += (
                f". Note: {len(errored_bls)} blacklist{'s' if len(errored_bls) != 1 else ''} "
                f"({', '.join(errored_bls)}) could not be queried from our scan server — "
                "re-verify externally if needed."
            )
        return CheckResult(
            name="domain_blacklists",
            category="reputation",
            status="pass",
            title="Domain Blacklists",
            detail=detail,
            raw_data={
                "checked": total_bls,
                "effectively_checked": effectively_checked,
                "listed": [],
                "error_listings": error_on,
                "fully_errored_blacklists": errored_bls,
            },
            points=10,
            max_points=10,
        )

    # Listed on one or more DBLs — serious. Domain blacklistings drive
    # spam-folder placement directly at Gmail / Yahoo / Microsoft.
    bl_names = sorted(r["blacklist"] for r in listed_on)
    return CheckResult(
        name="domain_blacklists",
        category="reputation",
        status="fail",
        title="Domain Blacklists",
        detail=(
            f"{domain} is listed on {listings} domain blacklist"
            f"{'s' if listings != 1 else ''}: {', '.join(bl_names)}. "
            "Mail from this domain will land in spam at most major mailbox providers "
            "until the listing is resolved."
        ),
        raw_data={
            "checked": total_bls,
            "listed": listed_on,
            "error_listings": error_on,
            "fully_errored_blacklists": errored_bls,
        },
        points=0,
        max_points=10,
        fix_steps=[
            f"Your domain ({domain}) is listed on one or more domain-based blacklists. "
            "This is a reputation signal that directly affects inbox placement at Gmail, "
            "Microsoft, Yahoo, and Apple Mail.",
            "Common causes: (a) the domain was used in spam campaigns, (b) pages on "
            "the domain were flagged as malicious, (c) the domain was recently acquired "
            "from a previous spammer, (d) an email you linked to lists spammy content.",
            "Check listing details and request removal:",
            "  • Spamhaus DBL:  https://www.spamhaus.org/dbl/removal/",
            "  • SURBL:         https://www.surbl.org/surbl-analysis",
            "  • URIBL:         https://uribl.com/lookup.shtml",
            "Before requesting removal, identify and fix the root cause. Delisting "
            "before cleanup usually results in being re-listed within hours.",
            "Expect 24–72 hours for removal after the cause is resolved.",
        ],
    )


def check_tls(domain: str) -> CheckResult:
    """Check if mail server supports TLS — tries all MX hosts.

    INBOX-24: scoring is now based on what we actually verified, not on
    what the hostname looked like. Three outcomes:

      1. Real STARTTLS handshake completes AND the certificate verifies
         (valid chain, hostname match, not expired). Full credit — up
         to 10/10 for TLSv1.3 with >30d of expiry headroom.

      2. Real STARTTLS handshake completes but cert verification fails
         (expired, hostname mismatch, self-signed, untrusted root).
         TLS is advertised but it's broken — warn at 4/10.

      3. Port 25 blocked from our scan server (common; Render and most
         cloud hosts block outbound SMTP). We CANNOT verify TLS from
         here. Return info at 5/10 if the MX resolves to a known mail
         provider (Google/Microsoft/Proofpoint/etc.) — acknowledges
         likely-good-but-unverified — or info at 3/10 otherwise. The
         old pattern-match 10/10 was a lie (L3 in audit).
    """
    mx_records = safe_dns_query(domain, "MX")
    if not mx_records:
        return CheckResult(
            name="tls",
            category="infrastructure",
            status="info",
            title="TLS Encryption",
            detail="No MX records found — cannot test TLS",
            points=0,
            max_points=10
        )

    # Try each MX host in priority order until one connects
    mx_hosts = [mx.split()[-1].rstrip(".") for mx in mx_records]
    last_error = None

    for mx_host in mx_hosts[:3]:  # Try up to 3 MX hosts
        try:
            # INBOX-45: 3s connect timeout (was 4s). Budget arithmetic:
            #   3 MX × 3s = 9s, fits in scan_service's 10s TLS budget with
            #   1s headroom for the pattern-match fallback pass. Previously
            #   3 × 4s = 12s overran the budget by 2s, causing the whole
            #   check to fall through to the generic crash-warn and the
            #   intended "port 25 blocked + known provider → INFO 5/10"
            #   branch never ran.
            sock = socket.create_connection((mx_host, 25), timeout=3)
            sock.recv(1024)  # consume banner

            # Send EHLO
            sock.sendall(b"EHLO inboxscore.test\r\n")
            ehlo_response = sock.recv(4096).decode("utf-8", errors="ignore")
            supports_starttls = "STARTTLS" in ehlo_response.upper()

            if supports_starttls:
                # Request STARTTLS
                sock.sendall(b"STARTTLS\r\n")
                starttls_response = sock.recv(1024).decode("utf-8", errors="ignore")

                if starttls_response.startswith("220"):
                    result = _tls_handshake_with_cert_check(sock, mx_host)
                    # Socket is closed inside _tls_handshake_with_cert_check
                    return result

            # If we got here, the EHLO/STARTTLS exchange didn't reach a 220.
            try:
                sock.close()
            except Exception:
                pass

            if supports_starttls:
                # STARTTLS advertised but the server rejected our request
                return CheckResult(
                    name="tls",
                    category="infrastructure",
                    status="warn",
                    title="TLS Encryption",
                    detail=f"STARTTLS advertised on {mx_host} but the server did not accept the upgrade",
                    raw_data={"mx_host": mx_host, "starttls_response": starttls_response[:200]},
                    points=2,
                    max_points=10,
                    fix_steps=[
                        f"Mail server {mx_host} advertises STARTTLS but rejects the upgrade",
                        "Check mail-server logs for TLS-related errors during the STARTTLS phase",
                        "Verify the SMTP daemon's TLS config (cert path, key path, permissions)",
                    ],
                )
            else:
                # No STARTTLS capability at all — plain-text SMTP only
                return CheckResult(
                    name="tls",
                    category="infrastructure",
                    status="fail",
                    title="TLS Encryption",
                    detail=f"Mail server {mx_host} does not support STARTTLS — emails sent in plain text",
                    raw_data={"mx_host": mx_host},
                    points=0,
                    max_points=10,
                    fix_steps=[
                        f"Mail server {mx_host} doesn't support TLS encryption",
                        "Gmail and other providers flag unencrypted emails with a red padlock icon",
                        "Enable STARTTLS on your mail server or switch to a provider that supports it",
                        "Most modern email providers (Google, Microsoft, etc.) support TLS by default",
                    ],
                )
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            last_error = str(e)
            continue  # Try next MX host
        except Exception as e:
            last_error = str(e)
            continue  # Try next MX host

    # None of the MX hosts were reachable on port 25 — almost always because
    # our scan server is hosted on a cloud provider that blocks outbound :25.
    # We CANNOT verify TLS from here. The old code pattern-matched the MX
    # hostname against a provider list and awarded 10/10 — that was the L3
    # lie this ticket closes. Now we return info with partial credit,
    # clearly labelled as unverified.
    provider_tls = {
        "google.com": "Google Workspace",
        "googlemail.com": "Google Workspace",
        "outlook.com": "Microsoft 365",
        "protection.outlook.com": "Microsoft 365",
        "pphosted.com": "Proofpoint",
        "mimecast.com": "Mimecast",
    }
    inferred_provider = None
    inferred_mx = None
    for mx_host in mx_hosts:
        mx_lower = mx_host.lower()
        for provider_domain, provider_name in provider_tls.items():
            if provider_domain in mx_lower:
                inferred_provider = provider_name
                inferred_mx = mx_host
                break
        if inferred_provider:
            break

    if inferred_provider:
        return CheckResult(
            name="tls",
            category="infrastructure",
            status="info",
            title="TLS Encryption",
            detail=(
                f"Mail handled by {inferred_provider} ({inferred_mx}) — "
                "TLS could not be verified directly from this scan server (port 25 blocked), "
                "but this provider typically supports TLS. Score is partial credit pending verification."
            ),
            raw_data={
                "mx_host": inferred_mx,
                "inferred_provider": inferred_provider,
                "verification": "unverified_port_25_blocked",
                "error": last_error,
            },
            points=5,
            max_points=10,
        )

    return CheckResult(
        name="tls",
        category="infrastructure",
        status="info",
        title="TLS Encryption",
        detail=(
            "Could not verify TLS — port 25 not reachable from the scan server, "
            "and the MX doesn't match a known major provider. "
            "Run a TLS test from a network that permits outbound SMTP (e.g. smtptls-test.example)."
        ),
        raw_data={
            "mx_hosts_tried": mx_hosts[:5],
            "verification": "unverified_unknown_provider",
            "error": last_error,
        },
        points=3,
        max_points=10,
    )


def _tls_handshake_with_cert_check(sock, mx_host: str) -> CheckResult:
    """Complete STARTTLS with full certificate verification.

    INBOX-24 (L4): the previous implementation set check_hostname=False
    and verify_mode=CERT_NONE, so an expired or hostname-mismatched cert
    would produce a pass. Now we run with CERT_REQUIRED + hostname
    verification, and on SSLCertVerificationError we attempt a second
    handshake with verification relaxed so we can still tell the user
    WHY their cert is broken (expired? mismatched? self-signed?).
    """
    import ssl as _ssl
    # Phase 1 — strict verification
    strict_ctx = _ssl.create_default_context()
    strict_ctx.check_hostname = True
    strict_ctx.verify_mode = _ssl.CERT_REQUIRED

    try:
        ssl_sock = strict_ctx.wrap_socket(sock, server_hostname=mx_host)
        tls_version = str(ssl_sock.version())
        cert = ssl_sock.getpeercert()
        try:
            ssl_sock.close()
        except Exception:
            pass
        return _score_valid_cert(mx_host, tls_version, cert)
    except _ssl.SSLCertVerificationError as e:
        try:
            sock.close()
        except Exception:
            pass
        return _diagnose_bad_cert(mx_host, e)
    except Exception as e:
        try:
            sock.close()
        except Exception:
            pass
        return CheckResult(
            name="tls",
            category="infrastructure",
            status="warn",
            title="TLS Encryption",
            detail=f"STARTTLS handshake failed on {mx_host}: {e}",
            raw_data={"mx_host": mx_host, "error": str(e)},
            points=2,
            max_points=10,
            fix_steps=[
                f"TLS handshake with {mx_host} failed after STARTTLS accepted",
                "Check mail-server TLS configuration, supported protocol versions, and cipher suites",
            ],
        )


def _score_valid_cert(mx_host: str, tls_version: str, cert) -> CheckResult:
    """Score a successful strict-verify handshake.

    Captures cert expiry and subject/issuer details. Expiry within 30
    days degrades the score to a 'warn' because renewal lead-time is
    critical for mail infrastructure.
    """
    from datetime import datetime, timezone, timedelta
    subject = _flatten_cert_name(cert.get("subject", []))
    issuer = _flatten_cert_name(cert.get("issuer", []))
    expiry_raw = cert.get("notAfter")
    expiry_dt = None
    days_left = None
    if expiry_raw:
        try:
            expiry_dt = datetime.strptime(expiry_raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry_dt - datetime.now(timezone.utc)).days
        except Exception:
            pass

    raw = {
        "mx_host": mx_host,
        "tls_version": tls_version,
        "cert_subject": subject,
        "cert_issuer": issuer,
        "cert_not_after": expiry_raw,
        "days_until_expiry": days_left,
        "verification": "strict_verified",
    }

    # Expiring within 30 days → warn even if everything else is fine.
    if days_left is not None and days_left < 30:
        return CheckResult(
            name="tls",
            category="infrastructure",
            status="warn",
            title="TLS Encryption",
            detail=(
                f"Mail server {mx_host} supports {tls_version} with a valid cert, "
                f"but the certificate expires in {days_left} day{'s' if days_left != 1 else ''}"
            ),
            raw_data=raw,
            points=7,
            max_points=10,
            fix_steps=[
                f"Renew the TLS certificate for {mx_host} before it expires",
                "Automate renewal (Let's Encrypt + certbot, or your provider's auto-renewal)",
                "Monitor cert expiry with an alert 30 days out",
            ],
        )

    if "TLSv1.3" in tls_version:
        return CheckResult(
            name="tls",
            category="infrastructure",
            status="pass",
            title="TLS Encryption",
            detail=f"Mail server {mx_host} supports {tls_version} with a valid certificate — excellent encryption",
            raw_data=raw,
            points=10,
            max_points=10,
        )

    return CheckResult(
        name="tls",
        category="infrastructure",
        status="pass",
        title="TLS Encryption",
        detail=f"Mail server {mx_host} supports {tls_version} with a valid certificate",
        raw_data=raw,
        points=8,
        max_points=10,
    )


def _diagnose_bad_cert(mx_host: str, err) -> CheckResult:
    """A strict verification failure — extract what went wrong.

    Common cases: hostname mismatch, expired, self-signed, unknown CA.
    """
    msg = str(err).lower()
    if "hostname mismatch" in msg or "doesn't match" in msg or "subjectaltname" in msg:
        reason = "hostname_mismatch"
        detail = f"Mail server {mx_host} has a TLS certificate but it does not match the hostname"
        fix = [
            f"The certificate on {mx_host} doesn't cover that hostname",
            "Reissue the cert with the MX hostname in the Subject or SAN",
            "Many receiving servers reject mail over a hostname-mismatched cert",
        ]
    elif "certificate has expired" in msg or "certificate expired" in msg:
        reason = "expired"
        detail = f"Mail server {mx_host}'s TLS certificate has expired"
        fix = [
            f"Renew the TLS certificate for {mx_host} immediately",
            "Expired certs cause inbound TLS connections to fail or downgrade to plain text",
        ]
    elif "self-signed" in msg or "self signed" in msg:
        reason = "self_signed"
        detail = f"Mail server {mx_host} uses a self-signed TLS certificate"
        fix = [
            f"Install a certificate from a trusted CA on {mx_host} (Let's Encrypt is free)",
            "Self-signed certs are rejected by most receiving mail servers",
        ]
    elif "unable to get local issuer" in msg or "unknown ca" in msg:
        reason = "unknown_ca"
        detail = f"Mail server {mx_host}'s TLS certificate chain is incomplete or uses an unknown issuer"
        fix = [
            f"Install the full certificate chain on {mx_host} (leaf + intermediate)",
            "Verify with openssl s_client -connect <mx>:25 -starttls smtp -showcerts",
        ]
    else:
        reason = "verification_failed"
        detail = f"Mail server {mx_host}'s TLS certificate failed verification: {err}"
        fix = [
            f"Inspect the certificate on {mx_host} — it failed trust verification",
            f"Details: {err}",
        ]

    return CheckResult(
        name="tls",
        category="infrastructure",
        status="warn",
        title="TLS Encryption",
        detail=detail,
        raw_data={
            "mx_host": mx_host,
            "verification": "failed",
            "failure_reason": reason,
            "error": str(err),
        },
        points=4,
        max_points=10,
        fix_steps=fix,
    )


def _flatten_cert_name(name_tuple):
    """Turn the weird ((('commonName', 'foo'),),) cert shape into a dict."""
    out = {}
    for rdn in name_tuple:
        for key, value in rdn:
            out[key] = value
    return out


def check_reverse_dns(domain: str) -> CheckResult:
    """Check reverse DNS (PTR records) for mail server IPs"""
    mx_records = safe_dns_query(domain, "MX")
    if not mx_records:
        return CheckResult(
            name="reverse_dns",
            category="infrastructure",
            status="info",
            title="Reverse DNS (PTR)",
            detail="No MX records — cannot check reverse DNS",
            points=0,
            max_points=5
        )

    mx_host = mx_records[0].split()[-1].rstrip(".")
    a_records = safe_dns_query(mx_host, "A")
    if not a_records:
        return CheckResult(
            name="reverse_dns",
            category="infrastructure",
            status="warn",
            title="Reverse DNS (PTR)",
            detail=f"Could not resolve IP for {mx_host}",
            points=0,
            max_points=5
        )

    ip = a_records[0]
    try:
        rev_name = dns.reversename.from_address(ip)
        ptr_records = safe_dns_query(str(rev_name), "PTR")

        if ptr_records:
            ptr_host = ptr_records[0].rstrip(".")
            # Check if PTR matches or is related to MX
            if mx_host.lower() in ptr_host.lower() or ptr_host.lower() in mx_host.lower():
                return CheckResult(
                    name="reverse_dns",
                    category="infrastructure",
                    status="pass",
                    title="Reverse DNS (PTR)",
                    detail=f"PTR record matches — {ip} resolves to {ptr_host}",
                    raw_data={"ip": ip, "ptr": ptr_host, "mx": mx_host},
                    points=5,
                    max_points=5
                )
            else:
                return CheckResult(
                    name="reverse_dns",
                    category="infrastructure",
                    status="pass",
                    title="Reverse DNS (PTR)",
                    detail=f"PTR record exists — {ip} resolves to {ptr_host}",
                    raw_data={"ip": ip, "ptr": ptr_host, "mx": mx_host},
                    points=4,
                    max_points=5
                )
        else:
            return CheckResult(
                name="reverse_dns",
                category="infrastructure",
                status="warn",
                title="Reverse DNS (PTR)",
                detail=f"No PTR record found for {ip}",
                raw_data={"ip": ip},
                points=0,
                max_points=5,
                fix_steps=[
                    "Contact your hosting provider to set up a PTR record for your mail server IP",
                    f"The PTR record for {ip} should point back to {mx_host}",
                    "Many email providers check reverse DNS and may reject emails without it"
                ]
            )
    except Exception:
        return CheckResult(
            name="reverse_dns",
            category="infrastructure",
            status="info",
            title="Reverse DNS (PTR)",
            detail="Could not perform reverse DNS lookup",
            points=3,
            max_points=5
        )


def check_bimi(domain: str) -> CheckResult:
    """Check BIMI (Brand Indicators for Message Identification) record"""
    bimi_domain = f"default._bimi.{domain}"
    txt_records = safe_dns_query(bimi_domain, "TXT")

    if txt_records:
        bimi_record = None
        for record in txt_records:
            cleaned = record.strip('"')
            if "v=BIMI1" in cleaned:
                bimi_record = cleaned
                break

        if bimi_record:
            has_logo = "l=" in bimi_record and "l=;" not in bimi_record
            has_vmc = "a=" in bimi_record and "a=;" not in bimi_record

            if has_logo and has_vmc:
                detail = "BIMI configured with logo and Verified Mark Certificate"
                status = "pass"
            elif has_logo:
                detail = "BIMI configured with logo — consider adding a VMC for Gmail support"
                status = "pass"
            else:
                detail = "BIMI record found but no logo URL specified"
                status = "warn"

            return CheckResult(
                name="bimi",
                category="authentication",
                status=status,
                title="BIMI (Brand Logo)",
                detail=detail,
                raw_data={"record": bimi_record},
                points=0,  # Bonus, doesn't affect score
                max_points=0
            )

    return CheckResult(
        name="bimi",
        category="authentication",
        status="info",
        title="BIMI (Brand Logo)",
        detail="No BIMI record — optional but helps brand visibility in supported email clients",
        points=0,
        max_points=0,
        fix_steps=[
            "BIMI lets you display your brand logo next to emails in Gmail and other clients",
            "Create an SVG logo in the required format (square, Tiny PS profile)",
            "Add a TXT record at default._bimi.yourdomain.com",
            "Example: v=BIMI1; l=https://yourdomain.com/bimi-logo.svg;",
            "For Gmail display, you'll also need a Verified Mark Certificate (VMC)"
        ]
    )


# ─── ENHANCED CHECKS (Phase 2) ─────────────────────────────────────

def check_mta_sts(domain: str) -> CheckResult:
    """Check MTA-STS policy (DNS record + /.well-known/mta-sts.txt)"""
    try:
        # Step 1: Check DNS record _mta-sts.{domain} TXT
        sts_domain = f"_mta-sts.{domain}"
        txt_records = safe_dns_query(sts_domain, "TXT")

        dns_found = False
        sts_record = None
        if txt_records:
            for record in txt_records:
                cleaned = record.strip('"')
                if cleaned.startswith("v=STSv1"):
                    dns_found = True
                    sts_record = cleaned
                    break

        if not dns_found:
            return CheckResult(
                name="mta_sts",
                category="infrastructure",
                status="info",
                title="MTA-STS (Strict Transport Security)",
                detail="No MTA-STS record — optional advanced feature for enforcing TLS on incoming mail",
                points=0,
                max_points=0,
                fix_steps=[
                    "MTA-STS enforces TLS encryption for incoming emails, preventing man-in-the-middle attacks",
                    "Add a TXT record at _mta-sts.yourdomain.com with: v=STSv1; id=20240101",
                    "Host a policy file at https://mta-sts.yourdomain.com/.well-known/mta-sts.txt",
                    "Policy file should contain: version: STSv1, mode: enforce, mx: *.yourdomain.com, max_age: 86400"
                ]
            )

        # Step 2: Fetch the policy file
        policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        policy_content = None
        policy_ok = False
        try:
            with httpx.Client(timeout=8, follow_redirects=True) as client:
                resp = client.get(policy_url)
                if resp.status_code == 200:
                    policy_content = resp.text.strip()
                    policy_ok = True
        except Exception:
            pass

        if not policy_ok:
            return CheckResult(
                name="mta_sts",
                category="infrastructure",
                status="warn",
                title="MTA-STS (Strict Transport Security)",
                detail=f"MTA-STS DNS record found but policy file not accessible at {policy_url}",
                raw_data={"dns_record": sts_record},
                points=1,
                max_points=0,
                fix_steps=[
                    "Your DNS record is set up, but the policy file is missing or unreachable",
                    f"Host a text file at {policy_url}",
                    "Content should include: version: STSv1\\nmode: enforce\\nmx: mail.yourdomain.com\\nmax_age: 86400",
                    "The file must be served over HTTPS with a valid certificate"
                ]
            )

        # Step 3: Validate policy content
        mode = "unknown"
        if "mode:" in policy_content:
            for line in policy_content.split("\n"):
                if line.strip().startswith("mode:"):
                    mode = line.split(":", 1)[1].strip().lower()

        if mode == "enforce":
            return CheckResult(
                name="mta_sts",
                category="infrastructure",
                status="pass",
                title="MTA-STS (Strict Transport Security)",
                detail="MTA-STS is fully configured with enforce mode — excellent protection against downgrade attacks",
                raw_data={"dns_record": sts_record, "policy_mode": mode},
                points=3,
                max_points=0
            )
        elif mode == "testing":
            return CheckResult(
                name="mta_sts",
                category="infrastructure",
                status="pass",
                title="MTA-STS (Strict Transport Security)",
                detail="MTA-STS configured in testing mode — switch to enforce mode when ready for full protection",
                raw_data={"dns_record": sts_record, "policy_mode": mode},
                points=2,
                max_points=0
            )
        else:
            return CheckResult(
                name="mta_sts",
                category="infrastructure",
                status="warn",
                title="MTA-STS (Strict Transport Security)",
                detail=f"MTA-STS policy found but mode is '{mode}' — use 'enforce' or 'testing'",
                raw_data={"dns_record": sts_record, "policy_mode": mode},
                points=1,
                max_points=0,
                fix_steps=["Update the mode line in your policy file to: mode: enforce"]
            )

    except Exception as e:
        return CheckResult(
            name="mta_sts",
            category="infrastructure",
            status="info",
            title="MTA-STS (Strict Transport Security)",
            detail="Could not complete MTA-STS check",
            points=0,
            max_points=0
        )


def check_tls_rpt(domain: str) -> CheckResult:
    """Check TLS-RPT (TLS Reporting) record"""
    try:
        rpt_domain = f"_smtp._tls.{domain}"
        txt_records = safe_dns_query(rpt_domain, "TXT")

        if txt_records:
            for record in txt_records:
                cleaned = record.strip('"')
                if "v=TLSRPTv1" in cleaned:
                    # Parse reporting URI
                    rua = ""
                    if "rua=" in cleaned:
                        rua = cleaned.split("rua=", 1)[1].strip().rstrip(";")

                    return CheckResult(
                        name="tls_rpt",
                        category="infrastructure",
                        status="pass",
                        title="TLS-RPT (TLS Reporting)",
                        detail=f"TLS-RPT configured — reports sent to {rua[:60]}{'...' if len(rua) > 60 else ''}" if rua else "TLS-RPT record found",
                        raw_data={"record": cleaned, "rua": rua},
                        points=2,
                        max_points=0
                    )

        return CheckResult(
            name="tls_rpt",
            category="infrastructure",
            status="info",
            title="TLS-RPT (TLS Reporting)",
            detail="No TLS-RPT record — optional feature for receiving TLS delivery failure reports",
            points=0,
            max_points=0,
            fix_steps=[
                "TLS-RPT lets you receive reports when emails can't be delivered securely",
                "Add a TXT record at _smtp._tls.yourdomain.com",
                "Example: v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.com",
                "Works best alongside MTA-STS to monitor TLS enforcement"
            ]
        )

    except Exception:
        return CheckResult(
            name="tls_rpt",
            category="infrastructure",
            status="info",
            title="TLS-RPT (TLS Reporting)",
            detail="Could not complete TLS-RPT check",
            points=0,
            max_points=0
        )


# Known third-party email senders mapped by SPF include pattern
KNOWN_SENDERS = {
    "_spf.google.com": "Google Workspace",
    "spf.protection.outlook.com": "Microsoft 365",
    "amazonses.com": "Amazon SES",
    "sendgrid.net": "SendGrid",
    "servers.mcsv.net": "Mailchimp",
    "mandrillapp.com": "Mandrill (Mailchimp)",
    "spf.sendinblue.com": "Brevo (Sendinblue)",
    "spf.brevo.com": "Brevo",
    "mail.zendesk.com": "Zendesk",
    "mktomail.com": "Marketo",
    "spf.mailjet.com": "Mailjet",
    "hubspot.com": "HubSpot",
    "spf1.hubspot.com": "HubSpot",
    "postmarkapp.com": "Postmark",
    "mailgun.org": "Mailgun",
    "freshdesk.com": "Freshdesk",
    "intercom.io": "Intercom",
    "helpscoutemail.com": "Help Scout",
    "sparkpostmail.com": "SparkPost",
    "zoho.com": "Zoho Mail",
    "zoho.eu": "Zoho Mail (EU)",
    "mailercloud.com": "Mailercloud",
    "cust-spf.exacttarget.com": "Salesforce Marketing Cloud",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "calendly.com": "Calendly",
    "outreach.io": "Outreach",
    "salesloft.com": "SalesLoft",
    "constantcontact.com": "Constant Contact",
    "getresponse.com": "GetResponse",
    "activecampaign.com": "ActiveCampaign",
    "klaviyo.com": "Klaviyo",
    "convertkit.com": "ConvertKit",
    "aweber.com": "AWeber",
}


def check_sender_detection(domain: str) -> CheckResult:
    """Detect third-party email senders from SPF includes"""
    try:
        txt_records = safe_dns_query(domain, "TXT")
        if not txt_records:
            return CheckResult(
                name="senders",
                category="infrastructure",
                status="info",
                title="Third-Party Senders",
                detail="No SPF record found — cannot detect authorized senders",
                points=0,
                max_points=0
            )

        spf_record = None
        for record in txt_records:
            cleaned = record.strip('"')
            if cleaned.startswith("v=spf1"):
                spf_record = cleaned
                break

        if not spf_record:
            return CheckResult(
                name="senders",
                category="infrastructure",
                status="info",
                title="Third-Party Senders",
                detail="No SPF record — cannot detect authorized senders",
                points=0,
                max_points=0
            )

        # Extract includes from SPF
        includes = re.findall(r'include:([^\s]+)', spf_record)

        detected = []
        unknown_includes = []

        for inc in includes:
            matched = False
            for pattern, name in KNOWN_SENDERS.items():
                if pattern in inc:
                    detected.append({"include": inc, "sender": name})
                    matched = True
                    break
            if not matched:
                unknown_includes.append(inc)

        sender_names = [d["sender"] for d in detected]

        if detected:
            detail = f"Detected {len(detected)} authorized sender{'s' if len(detected) != 1 else ''}: {', '.join(sender_names)}"
            if unknown_includes:
                detail += f" (+{len(unknown_includes)} custom)"
        else:
            detail = "No known third-party email senders detected in SPF record"
            if unknown_includes:
                detail += f" — {len(unknown_includes)} custom include{'s' if len(unknown_includes) != 1 else ''} found"

        return CheckResult(
            name="senders",
            category="infrastructure",
            status="info",
            title="Third-Party Senders",
            detail=detail,
            raw_data={
                "detected_senders": detected,
                "unknown_includes": unknown_includes,
                "total_includes": len(includes)
            },
            points=0,  # Informational — doesn't affect score
            max_points=0
        )

    except Exception:
        return CheckResult(
            name="senders",
            category="infrastructure",
            status="info",
            title="Third-Party Senders",
            detail="Could not analyze third-party senders",
            points=0,
            max_points=0
        )


def check_domain_age(domain: str) -> CheckResult:
    """Check domain age via WHOIS/RDAP — newer domains have lower reputation"""
    try:
        creation_date = None
        lookup_method = None

        # Method 1: RDAP (fast HTTP call, preferred for speed)
        try:
            rdap_url = f"https://rdap.org/domain/{domain}"
            with httpx.Client(timeout=5, follow_redirects=True) as client:
                resp = client.get(rdap_url, headers={"Accept": "application/rdap+json"})
                if resp.status_code == 200:
                    data = resp.json()
                    events = data.get("events", [])
                    for event in events:
                        if event.get("eventAction") == "registration":
                            date_str = event.get("eventDate", "")
                            if date_str:
                                creation_date = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                                lookup_method = "RDAP"
                                break
        except Exception:
            pass

        # Method 2: python-whois fallback (slower — can take 5-10s)
        if not creation_date:
            try:
                w = whois.whois(domain)
                if w and w.creation_date:
                    cd = w.creation_date
                    # whois sometimes returns a list of dates
                    if isinstance(cd, list):
                        cd = cd[0]
                    if cd:
                        if cd.tzinfo is None:
                            from datetime import timezone
                            cd = cd.replace(tzinfo=timezone.utc)
                        creation_date = cd
                        lookup_method = "WHOIS"
            except Exception:
                pass

        if not creation_date:
            return CheckResult(
                name="domain_age",
                category="reputation",
                status="info",
                title="Domain Age",
                detail="Could not determine domain registration date — RDAP and WHOIS lookups both failed for this domain",
                points=0,
                max_points=0
            )

        # Calculate age — INBOX-29: always tz-aware (naive creation_date is
        # treated as UTC, matching how Supabase/whois consumers behave).
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        age_days = (now - creation_date).days
        age_years = age_days / 365.25

        created_str = creation_date.strftime("%B %d, %Y")

        if age_years >= 2:
            detail = f"Domain registered on {created_str} ({age_years:.1f} years) — well-established domain"
            status = "pass"
            points = 3
        elif age_years >= 1:
            detail = f"Domain registered on {created_str} ({age_years:.1f} years) — established domain"
            status = "pass"
            points = 3
        elif age_days >= 90:
            detail = f"Domain registered on {created_str} ({age_days} days ago) — domain age is fine, reputation still building"
            status = "pass"
            points = 2
        elif age_days >= 30:
            detail = f"Domain registered on {created_str} ({age_days} days ago) — relatively new domain, warm up sending gradually"
            status = "warn"
            points = 1
        else:
            detail = f"Domain registered on {created_str} ({age_days} days ago) — brand new domains often face spam filtering"
            status = "warn"
            points = 0

        return CheckResult(
            name="domain_age",
            category="reputation",
            status=status,
            title="Domain Age",
            detail=detail,
            raw_data={"created": created_str, "age_days": age_days, "age_years": round(age_years, 1)},
            points=points,
            max_points=3,
            fix_steps=[
                "Newer domains have lower sender reputation by default",
                "Warm up your domain gradually — start with low volume to trusted recipients",
                "Set up all authentication records (SPF, DKIM, DMARC) immediately",
                "Avoid sending bulk emails until domain is at least 30 days old"
            ] if age_days < 90 else None
        )

    except Exception:
        return CheckResult(
            name="domain_age",
            category="reputation",
            status="info",
            title="Domain Age",
            detail="Could not determine domain age",
            points=0,
            max_points=0
        )


# ─── PHASE 5: IP REPUTATION CHECK ──────────────────────────────────

# Known ESP/cloud mail networks (ASN → provider name) — INFORMATIONAL ONLY, not scored
KNOWN_ESP_ASNS = {
    "15169": "Google (Gmail/Workspace)",
    "396982": "Google Cloud",
    "8075": "Microsoft (Outlook/365)",
    "14618": "Amazon (SES)",
    "16509": "Amazon AWS",
    "13335": "Cloudflare",
    "36351": "SoftLayer (IBM)",
    "20940": "Akamai",
    "14061": "DigitalOcean",
    "16276": "OVH",
    "24940": "Hetzner",
    "63949": "Linode (Akamai)",
    "46606": "Unified Layer",
    "26496": "GoDaddy",
    "22612": "Namecheap",
    "398101": "SendGrid (Twilio)",
    "46562": "Mailchimp",
    "394254": "Mailgun",
    "32244": "Liquid Web",
    "19551": "Incapsula",
    "54113": "Fastly",
    "209242": "Postmark",
}

# Reputation-focused DNSBLs (beyond the main blacklists already checked)
REPUTATION_DNSBLS = [
    {"zone": "reputation-ip.rbl.scrolloutf1.com", "name": "ScrolloutF1 Reputation", "severity": "medium"},
    {"zone": "wl.mailspike.net", "name": "Mailspike Whitelist", "type": "whitelist"},
    {"zone": "list.dnswl.org", "name": "DNSWL.org Whitelist", "type": "whitelist"},
    {"zone": "hostkarma.junkemailfilter.com", "name": "HostKarma", "severity": "medium"},
]


def _cymru_asn_lookup(ip: str) -> dict:
    """Look up ASN info via Team Cymru DNS (free, no API key needed)"""
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(query, "TXT")
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            # Format: "ASN | IP/prefix | CC | registry | date"
            parts = [p.strip() for p in txt.split("|")]
            if len(parts) >= 3:
                asn = parts[0]
                prefix = parts[1]
                country = parts[2]

                # Look up ASN name
                asn_name = KNOWN_ESP_ASNS.get(asn, None)
                if not asn_name:
                    try:
                        name_query = f"AS{asn}.asn.cymru.com"
                        name_answers = resolver.resolve(name_query, "TXT")
                        for nr in name_answers:
                            ntxt = nr.to_text().strip('"')
                            nparts = [p.strip() for p in ntxt.split("|")]
                            if len(nparts) >= 5:
                                asn_name = nparts[4]
                    except Exception:
                        asn_name = f"AS{asn}"

                return {
                    "asn": asn,
                    "prefix": prefix,
                    "country": country,
                    "asn_name": asn_name or f"AS{asn}",
                    "is_known_esp": asn in KNOWN_ESP_ASNS
                }
    except Exception:
        pass
    return {}


def _check_reputation_dnsbl(ip: str, zone: str) -> bool:
    """Check a single reputation DNSBL — returns True if listed/found"""
    reversed_ip = ".".join(reversed(ip.split(".")))
    query = f"{reversed_ip}.{zone}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        resolver.resolve(query, "A")
        return True
    except Exception:
        return False


def _sender_score_lookup(ip: str) -> Optional[int]:
    """Attempt Sender Score DNS lookup — returns 0-100 score or None if unavailable.
    This is informational only (not scored) since the DNS service may be deprecated."""
    try:
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.score.senderscore.com"
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(query, "A")
        for rdata in answers:
            # Response is 127.0.0.X where X is the score (0-100)
            ip_str = rdata.to_text()
            if ip_str.startswith("127.0.0."):
                score = int(ip_str.split(".")[-1])
                if 0 <= score <= 100:
                    return score
    except Exception:
        pass
    return None


def check_ip_reputation(domain: str) -> CheckResult:
    """Phase 5: IP reputation — scored on proven behavior (whitelists, reputation flags),
    with ASN identity and Sender Score shown as informational context only."""

    # Step 1: Resolve MX → IPs
    ips = set()
    mx_records = safe_dns_query(domain, "MX")
    if mx_records:
        for mx in mx_records:
            mx_host = mx.split()[-1].rstrip(".")
            a_records = safe_dns_query(mx_host, "A")
            if a_records:
                ips.update(a_records)

    if not ips:
        a_records = safe_dns_query(domain, "A")
        if a_records:
            ips.update(a_records)

    if not ips:
        return CheckResult(
            name="ip_reputation",
            category="reputation",
            status="info",
            title="IP Reputation",
            detail="Could not resolve mail server IPs for reputation check",
            points=0,
            max_points=0
        )

    # INBOX-26: sorted(), not list(). `ips` is a set — list(set) order is not
    # stable across Python processes (hash randomization). Picking the
    # lexicographically-lowest IP gives a reproducible "primary" pick.
    primary_ip = sorted(ips)[0]

    # Step 2: Run all lookups in parallel — ASN, whitelists, reputation flags, Sender Score
    asn_info = {}
    whitelisted = []
    reputation_flags = []
    sender_score = None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        # ASN lookup
        future_asn = executor.submit(_cymru_asn_lookup, primary_ip)
        # Sender Score (informational)
        future_ss = executor.submit(_sender_score_lookup, primary_ip)
        # Reputation DNSBLs
        rbl_futures = {}
        for rbl in REPUTATION_DNSBLS:
            f = executor.submit(_check_reputation_dnsbl, primary_ip, rbl["zone"])
            rbl_futures[f] = rbl

        # Collect ASN result
        try:
            asn_info = future_asn.result(timeout=5) or {}
        except Exception:
            pass

        # Collect Sender Score result
        try:
            sender_score = future_ss.result(timeout=5)
        except Exception:
            pass

        # Collect reputation DNSBL results
        for future in concurrent.futures.as_completed(rbl_futures, timeout=10):
            rbl = rbl_futures[future]
            try:
                listed = future.result()
                if listed and rbl.get("type") == "whitelist":
                    whitelisted.append(rbl["name"])
                elif listed and rbl.get("type") != "whitelist":
                    reputation_flags.append(rbl["name"])
            except Exception:
                pass

    # Step 3: Build assessment
    # ─── Scoring: only whitelist presence and reputation flags matter ───
    # ASN and Sender Score are INFORMATIONAL ONLY — shown but not scored
    # Rationale: A known ESP IP (e.g. SendGrid) can still have bad reputation,
    # and Sender Score DNS may be deprecated anytime. Only earned/proven
    # signals (whitelists) and negative signals (reputation flags) affect score.

    points = 0
    max_points = 8
    details = []
    status = "pass"

    # ─── Whitelist presence (2-4 points) — earned positive reputation ───
    # Baseline of 2 for clean IPs not on any whitelist (most legitimate domains)
    if len(whitelisted) >= 2:
        points += 4
        details.append(f"Whitelisted on {len(whitelisted)} reputation services ({', '.join(whitelisted)})")
    elif len(whitelisted) == 1:
        points += 3
        details.append(f"Whitelisted on {whitelisted[0]}")
    else:
        points += 2
        details.append("Not found on reputation whitelists — most legitimate domains aren't; this improves with volume")

    # ─── Reputation flags (0-4 points) — negative reputation signals ───
    if not reputation_flags:
        points += 4
        details.append("No reputation flags detected")
    elif len(reputation_flags) == 1:
        points += 1
        status = "warn"
        details.append(f"Flagged on {reputation_flags[0]} — monitor your sending practices")
    else:
        points += 0
        status = "fail"
        details.append(f"Flagged on {len(reputation_flags)} reputation services — review sending practices immediately")

    # ─── ASN info (informational — 0 points) ───
    asn_name = asn_info.get("asn_name", "Unknown")
    asn_num = asn_info.get("asn", "")
    country = asn_info.get("country", "??")
    is_known_esp = asn_info.get("is_known_esp", False)

    if is_known_esp:
        details.append(f"Network: {asn_name}")
    elif asn_info:
        details.append(f"Network: {asn_name} (AS{asn_num}, {country})")
    else:
        details.append(f"Network: could not identify hosting provider")

    # ─── Sender Score (informational — 0 points) ───
    if sender_score is not None:
        if sender_score >= 80:
            details.append(f"Sender Score: {sender_score}/100 — good")
        elif sender_score >= 50:
            details.append(f"Sender Score: {sender_score}/100 — moderate, room for improvement")
        else:
            details.append(f"Sender Score: {sender_score}/100 — poor, may cause deliverability issues")

    # Build fix steps
    fix_steps = None
    if status == "fail":
        fix_steps = [
            "Your IP has been flagged by reputation monitoring services — this directly impacts inbox placement",
            "Check for high bounce rates (>2%) and spam complaints (>0.1%) in your email logs",
            "Ensure you only email opted-in recipients with valid addresses",
            "If using shared infrastructure, contact your ESP about the IP's reputation",
            "Set up feedback loops with Gmail Postmaster Tools and Microsoft SNDS to monitor complaints"
        ]
    elif status == "warn":
        fix_steps = [
            "Your IP has a minor reputation flag — address it before it escalates",
            "Review recent sending patterns for any spikes in bounces or complaints",
            "Warm up your IP gradually if you've recently changed email providers",
            "Set up feedback loops with major mailbox providers to catch complaints early"
        ]
    elif not whitelisted:
        fix_steps = [
            "Your IP isn't on any reputation whitelists yet — this builds over time with good sending",
            "Submit your IP to dnswl.org for whitelist consideration after 30+ days of clean sending",
            "Maintain low bounce rates (<2%) and spam complaints (<0.1%)",
            "Use consistent sending patterns — avoid large volume spikes"
        ]

    # Summary detail — lead with the most important signal
    if reputation_flags:
        detail = details[1] if len(details) > 1 else details[0]  # reputation flag detail
    elif whitelisted:
        detail = details[0]  # whitelist detail
    else:
        detail = f"IP {primary_ip} — no whitelist or reputation flags found"
    if len(ips) > 1:
        detail += f" ({len(ips)} IPs detected)"

    raw_data = {
        "primary_ip": primary_ip,
        "all_ips": sorted(ips)[:5],  # INBOX-26: deterministic ordering
        "asn": asn_info,
        "whitelisted_on": whitelisted,
        "reputation_flags": reputation_flags,
        "sender_score": sender_score,
        "details": details
    }

    return CheckResult(
        name="ip_reputation",
        category="reputation",
        status=status,
        title="IP Reputation",
        detail=detail,
        raw_data=raw_data,
        points=min(points, max_points),
        max_points=max_points,
        fix_steps=fix_steps
    )


# ─── GENERATE AI SUMMARY ───────────────────────────────────────────
