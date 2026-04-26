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

# Common DKIM selectors to check (INBOX-57: expanded from 17 to ~50).
# Senders use one of two patterns:
#   1. Stable, well-known selectors → enumerable, listed below
#   2. Random/rotating hashes (AWS SES, HubSpot, Salesforce MC) → NOT
#      enumerable. When we don't find DKIM via this list, we fall back
#      to a "may use a custom selector — verify via dkimvalidator.com"
#      message rather than a false-FAIL.
DKIM_SELECTORS = [
    # ─ Generic / fallback selectors (most domains)
    "default", "dkim", "mail", "email", "smtp", "cm",
    "k1", "k2", "k3", "s1", "s2", "key1", "key2",
    # ─ Microsoft 365 / Exchange Online
    "selector1", "selector2",
    # ─ Google Workspace
    "google",
    # ─ Amazon SES (also uses random hashes — these catch common cases)
    "amazonses",
    # ─ Mandrill / Mailchimp Transactional
    "mandrill", "mte1", "mte2", "mte3", "mte4", "mte5",
    # ─ Mailchimp
    "mailchimp", "mcdkim",
    # ─ SendGrid
    "smtpapi", "m1", "em1",
    # ─ Postmark
    "pm", "postmark",
    # ─ Resend (modern transactional)
    "resend",
    # ─ Mailgun
    "krs", "mxvault", "mta",
    # ─ Brevo (Sendinblue)
    "sib", "sib1", "mail2",
    # ─ Klaviyo (B2C marketing)
    "klaviyo", "klaviyo1", "klaviyo2",
    # ─ Zoho
    "zoho", "zohomail",
    # ─ ActiveCampaign
    "acdkim",
    # ─ Mailercloud (own infra — INBOX-57 audit lookup)
    "mlrcloud", "mlr", "mc",
    # ─ Other regional providers
    "mailo",
]


# ─── INBOX-69: Date-based rotating DKIM selectors ─────────────────
# Major senders (Google, Apple, Stripe, AWS, Cloudflare) rotate DKIM
# keys using YYYYMMDD-shaped selectors. Confirmed via direct DNS probes
# 2026-04-26: google.com publishes selectors `20221208`, `20210112`,
# and `20230601` (historical and current). Without these patterns we
# return FAIL 0/15 for the entire google.com / apple.com class of
# domains — false negatives that wreck product credibility.
KNOWN_ROTATING_SELECTORS = [
    # Google (historical confirmed selectors)
    "20230601", "20221208", "20210112", "20191024", "20161025",
    # Apple
    "s2048", "sig1",
]


def _generate_monthly_selectors(months_back: int = 24) -> list[str]:
    """Generate YYYYMM01 and YYYYMM15 selectors for last `months_back` months.

    Covers the most common date-based DKIM rotation patterns:
      • YYYYMM01 — first-of-month rotation (most common)
      • YYYYMM15 — mid-month rotation (some providers)

    Returns ~48 candidates for default 24 months.
    """
    today = datetime.now(timezone.utc).date()
    candidates = []
    year, month = today.year, today.month
    for _ in range(months_back):
        candidates.append(f"{year:04d}{month:02d}01")
        candidates.append(f"{year:04d}{month:02d}15")
        # Walk back one month
        month -= 1
        if month == 0:
            month = 12
            year -= 1
    return candidates


# Probe = static common selectors + known rotating + last 24 months of
# YYYYMMDD candidates. ~95 selectors total at module load. DNS probes
# parallelize so total wall-clock is bounded by the slowest query.
DKIM_PROBE_SELECTORS = (
    DKIM_SELECTORS
    + KNOWN_ROTATING_SELECTORS
    + _generate_monthly_selectors(months_back=24)
)

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
    """Check MX records for the domain.

    INBOX-58: in addition to the structural check (does MX exist? are
    there ≥2 for redundancy?), we now verify that each MX host actually
    resolves to an A or AAAA record. A domain whose MX hostnames don't
    resolve cannot accept mail — but the previous check returned 10/10
    PASS as long as the MX records existed in DNS. That was a real
    false-PASS risk surfaced by INBOX-44 audit.

    L1 only — DNS resolution. We do NOT attempt SMTP connections (port
    25 is blocked from Render anyway; INBOX-51's HetrixTools/dedicated-
    resolver path will cover full reachability).
    """
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

        # INBOX-58: per-MX A/AAAA resolution check. Run in parallel since
        # each is just a DNS query.
        def _mx_resolves(host: str) -> bool:
            for rtype in ("A", "AAAA"):
                if safe_dns_query(host, rtype, timeout=2):
                    return True
            return False

        if mx_records:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
                futures = {
                    executor.submit(_mx_resolves, mx["host"]): mx
                    for mx in mx_records
                }
                for fut in concurrent.futures.as_completed(futures, timeout=8):
                    mx = futures[fut]
                    try:
                        mx["resolves"] = fut.result()
                    except Exception:
                        mx["resolves"] = False
        unresolved = [mx for mx in mx_records if not mx.get("resolves", True)]
        all_resolved = all(mx.get("resolves") for mx in mx_records)

        # Scoring:
        # ≥2 MX, all resolve   → 10/10 PASS (unchanged happy path)
        # ≥2 MX, some resolve  →  7/10 WARN — partial reachability
        # ≥2 MX, none resolve  →  3/10 FAIL — domain can't accept mail
        # 1  MX, resolves      →  9/10 PASS with backup-suggestion
        # 1  MX, doesn't       →  3/10 FAIL — domain can't accept mail
        # 0  MX                →  0/10 FAIL (unchanged)
        if len(mx_records) >= 2:
            if all_resolved:
                detail = f"{len(mx_records)} MX records found with proper priority configuration"
                points, status, fix_steps = 10, "pass", None
            elif unresolved and len(unresolved) < len(mx_records):
                bad = ", ".join(mx["host"] for mx in unresolved)
                detail = (
                    f"{len(mx_records)} MX records found but {len(unresolved)} "
                    f"do not resolve: {bad}. Mail to those hosts will bounce."
                )
                points, status = 7, "warn"
                fix_steps = [
                    f"These MX hosts don't have an A/AAAA record: {bad}",
                    "Either fix their DNS so they resolve, or remove them from your MX records",
                    "Mail providers may try the unresolvable host first and delay delivery"
                ]
            else:
                detail = (
                    f"{len(mx_records)} MX records found but NONE resolve to an IP. "
                    "Mail to this domain will fail until the MX hosts are fixed."
                )
                points, status = 3, "fail"
                fix_steps = [
                    "All your MX hosts are missing A/AAAA records",
                    "Either fix the DNS for the MX hosts, or update your MX records to point at a working mail server",
                    "Run `dig MX " + domain + "` to see your current MX configuration"
                ]
        elif len(mx_records) == 1:
            if all_resolved:
                # INBOX-72 (2026-04-26): when single MX resolves to a known
                # load-balanced provider pool (Google, Microsoft, Proofpoint,
                # Mimecast), award full 10/10. The redundancy is at the IP
                # layer — `smtp.google.com` resolves to dozens of mail
                # servers behind one DNS name. Docking 1 point at the DNS
                # layer when redundancy actually exists is wrong-on-its-face.
                mx_host = mx_records[0]["host"].lower()
                load_balanced_pools = (
                    "google.com",         # smtp.google.com → Google pool
                    "googlemail.com",
                    "protection.outlook.com",  # Microsoft 365 pool
                    "pphosted.com",       # Proofpoint
                    "mimecast.com",
                )
                is_load_balanced = any(pool in mx_host for pool in load_balanced_pools)
                if is_load_balanced:
                    detail = (
                        f"1 MX record ({mx_records[0]['host']}) — provider pool with "
                        "IP-layer redundancy. Single DNS entry resolves to multiple "
                        "mail servers behind a load balancer."
                    )
                    points, status, fix_steps = 10, "pass", None
                else:
                    detail = "1 MX record found — consider adding a backup mail server for redundancy"
                    points, status, fix_steps = 9, "pass", None
            else:
                detail = (
                    f"1 MX record found ({mx_records[0]['host']}) but it does not resolve. "
                    "Mail to this domain will fail."
                )
                points, status = 3, "fail"
                fix_steps = [
                    f"Your MX host {mx_records[0]['host']} has no A/AAAA record",
                    "Fix the DNS for that host, or update your MX record to point at a working mail server"
                ]
        else:
            detail = "No MX records found"
            points, status = 0, "fail"
            fix_steps = [
                "Add at least 2 MX records in your DNS settings",
                "Set different priorities (e.g., 10 for primary, 20 for backup)",
                "Ensure both mail servers are reachable and accepting connections"
            ]

        return CheckResult(
            name="mx_records",
            category="infrastructure",
            status=status,
            title="MX Records",
            detail=detail,
            raw_data={
                "records": mx_records,
                "unresolved_count": len(unresolved),
                "all_resolved": all_resolved,
            },
            points=points,
            max_points=10,
            fix_steps=fix_steps,
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
        # INBOX-73 (2026-04-26): no longer dock a point for ~all.
        # Google, Microsoft, Apple, Stripe, GitHub all use ~all by
        # design — it handles forwarders and mailing-list edge cases
        # that strict -all would break. DMARC p=reject does the heavy
        # lifting for actual mail rejection. Industry tools (MXToolbox,
        # Dmarcian, Google Postmaster) treat ~all as PASS. Keep the
        # "consider -all" suggestion as a non-scoring fix-step for
        # educational value.
        issues.append("Uses ~all (soft fail) — widely accepted; -all (hard fail) offers stricter enforcement")
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
                    # INBOX-69: regex now uses `*` not `+` so `p=` with no
                    # content (operator-revoked selectors, common in Google's
                    # rotation breadcrumbs) is captured as an empty string
                    # and falls into the `key_bits == 0` revoked branch.
                    # Pre-INBOX-69 the regex required 1+ chars after `p=`,
                    # so revoked records silently stayed as "unknown" and
                    # leaked into the PASS branch.
                    p_match = re.search(r'p=([A-Za-z0-9+/=]*)', cleaned)
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

    # Probe all selectors in parallel (each is a single DNS query).
    # INBOX-57: bumped pool size to match the expanded selector list.
    # INBOX-69: probe DKIM_PROBE_SELECTORS (= static + known-rotating +
    # 48 date-based candidates) so we catch Google/Apple/Stripe rotating
    # selectors. Total ~95 selectors; max_workers caps at 32 so worst
    # case is ~3 batches of parallel DNS lookups, still fits in the 6s
    # as_completed budget on a healthy resolver.
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        future_map = {executor.submit(_probe_selector, s): s for s in DKIM_PROBE_SELECTORS}
        for future in concurrent.futures.as_completed(future_map, timeout=6):
            try:
                hit = future.result()
                if hit:
                    found_selectors.append(hit)
            except Exception:
                pass

    # INBOX-69: filter revoked selectors (key_length == "revoked (p=;)")
    # out of `found_selectors` for the PASS-branch decision. Operators
    # publish empty `p=` to retire a selector; an active rotating sender
    # signs new mail with a NEW selector, leaving these revoked records
    # behind as historical breadcrumbs. Counting them as "DKIM
    # configured" is wrong — google.com would PASS with revoked-only
    # selectors found and we'd miss the real story (active key not in
    # our list). Keep them in raw_data for transparency.
    revoked_selectors = [
        s for s in found_selectors
        if s.get("key_length") == "revoked (p=;)"
    ]
    active_selectors = [
        s for s in found_selectors
        if s.get("key_length") != "revoked (p=;)"
    ]

    if active_selectors:
        # Only the active set drives the PASS branches; revoked ones
        # were noise from key-rotation history.
        found_selectors = active_selectors

        # INBOX-77: plain-English rewrite of all DKIM messaging. The
        # technical bit-count + selector-list info is preserved in
        # raw_data for developers/support; the human-facing detail and
        # fix_steps now lead with what the situation MEANS, not the
        # protocol-level facts.
        selector_count = len(found_selectors)
        selector_names = ", ".join(f"`{s['selector']}`" for s in found_selectors)

        # Identify weak (1024-bit) vs strong (2048-bit) selectors.
        weak_selectors = [s for s in found_selectors
                           if "1024" in s.get("key_length", "")]
        strong_selectors = [s for s in found_selectors
                             if "2048" in s.get("key_length", "")]

        # Build the technical-detail string for raw_data (preserved from
        # INBOX-62 — per-selector key sizes) so support staff can still
        # see the exact bit counts. NOT shown in the user-facing detail.
        def _label(s):
            kl = s.get("key_length", "unknown")
            if kl == "CNAME redirect":
                return f"{s['selector']} (CNAME)"
            return f"{s['selector']} ({kl})"
        technical_detail = "; ".join(_label(s) for s in found_selectors)

        if weak_selectors and strong_selectors:
            # MIXED — most users have this. Name the specific weak key.
            weak_names = [s["selector"] for s in weak_selectors]
            weak_phrase = ", ".join(f"`{n}`" for n in weak_names)
            multiple_weak = len(weak_selectors) > 1
            key_word = "keys" if multiple_weak else "key"
            uses_word = "use" if multiple_weak else "uses"

            return CheckResult(
                name="dkim",
                category="authentication",
                status="pass",
                title="DKIM",
                detail=(
                    f"Your email signing setup is mostly modern, but "
                    f"{len(weak_selectors)} of your {selector_count} signing keys "
                    f"({weak_phrase}) {uses_word} older weaker encryption. "
                    "Newer email providers like Gmail and Yahoo prefer modern "
                    "encryption — older keys may be downgraded or treated as "
                    "suspicious."
                ),
                raw_data={
                    "selectors": found_selectors,
                    "weak_selectors": weak_names,
                    "strong_selectors": [s["selector"] for s in strong_selectors],
                    "technical_detail": technical_detail,
                },
                points=14,
                max_points=15,
                fix_steps=[
                    f"Find out which sending service uses {weak_phrase} — common "
                    "culprits are older Mailchimp, SendGrid, or self-hosted mail servers.",
                    f"If you still use that service: regenerate the DKIM {key_word} "
                    "in its settings (most modern services produce strong keys by "
                    f"default), then update the DNS record at "
                    f"`{weak_names[0]}._domainkey.<your-domain>` with the new key.",
                    f"If you no longer use that service: just delete the "
                    f"`{weak_names[0]}._domainkey.<your-domain>` DNS record entirely "
                    "— it's unused and weak.",
                    f"Don't touch your other {len(strong_selectors)} keys — "
                    "they're already strong.",
                ]
            )

        if weak_selectors:
            # ALL selectors weak — single key, weak across the board.
            return CheckResult(
                name="dkim",
                category="authentication",
                status="pass",
                title="DKIM",
                detail=(
                    f"Your emails are signed, but with older weaker encryption. "
                    "The modern standard is twice the strength. Newer email "
                    "providers like Gmail and Yahoo may treat older keys as "
                    "suspicious."
                ),
                raw_data={
                    "selectors": found_selectors,
                    "weak_selectors": [s["selector"] for s in weak_selectors],
                    "strong_selectors": [],
                    "technical_detail": technical_detail,
                },
                points=14,
                max_points=15,
                fix_steps=[
                    "Regenerate your DKIM key in your email provider's settings "
                    "(Google Workspace, Microsoft 365, Mailchimp, SendGrid, etc.) "
                    "— most produce the modern strong key by default now.",
                    "Replace the existing DNS record with the new stronger key.",
                    "Re-scan in 24 hours (DKIM updates take time to propagate).",
                ]
            )

        # ALL STRONG — best case
        if selector_count == 1:
            detail = (
                f"Your emails are signed with strong, modern encryption — "
                "receivers can verify they really came from you. Your signing "
                f"key is {selector_names} (using current-standard encryption)."
            )
        else:
            detail = (
                f"Your emails are signed with strong, modern encryption — "
                "receivers can verify they really came from you. You have "
                f"{selector_count} signing keys set up ({selector_names}), all "
                "using current-standard encryption."
            )
        return CheckResult(
            name="dkim",
            category="authentication",
            status="pass",
            title="DKIM",
            detail=detail,
            raw_data={
                "selectors": found_selectors,
                "technical_detail": technical_detail,
            },
            points=15,
            max_points=15
        )
    else:
        # INBOX-69: branch on whether we found revoked selectors (sender
        # rotates keys, real DKIM exists but active selector isn't in
        # our probe list) vs found nothing (probably no DKIM at all).
        # Different scoring: 5/15 INFO for the rotating case (don't
        # torpedo google.com), 0/15 FAIL for genuinely missing.
        if revoked_selectors:
            # INBOX-77: plain-English rewrite. Original technical detail
            # preserved in raw_data.technical_detail for support visibility.
            revoked_names = ", ".join(f"`{s['selector']}`" for s in revoked_selectors[:3])
            more = f" (+{len(revoked_selectors)-3} more)" if len(revoked_selectors) > 3 else ""
            return CheckResult(
                name="dkim",
                category="authentication",
                status="info",
                title="DKIM",
                detail=(
                    "We found old, retired signing keys for your domain "
                    f"({revoked_names}{more}) but couldn't find your active one. "
                    "This is the typical pattern for big senders that rotate keys "
                    "frequently (Google, Apple, Stripe, Cloudflare). Your DKIM "
                    "probably works fine — we just can't verify it from this scanner."
                ),
                raw_data={
                    "revoked_selectors": revoked_selectors,
                    "checked_count": len(DKIM_PROBE_SELECTORS),
                    "outcome": "revoked_only_likely_rotating_sender",
                    "technical_detail": (
                        f"Probed {len(DKIM_PROBE_SELECTORS)} selectors. Found "
                        f"{len(revoked_selectors)} with revoked keys (p=;) and zero "
                        "active. Active selector likely uses a non-standard pattern."
                    ),
                },
                points=5,
                max_points=15,
                fix_steps=[
                    "Verify externally first: send a test email to "
                    "https://www.dkimvalidator.com — if it shows DKIM passes, "
                    "you're good. Big senders' rotating keys typically pass in "
                    "real mail even when scanners can't probe them.",
                    "If verification passes, no action needed. We'll detect your "
                    "active selector once it appears in our probe list (we add "
                    "new patterns regularly).",
                    "If verification fails, turn on DKIM signing in your email "
                    "provider — see the no-DKIM case for provider-specific steps.",
                ]
            )

        # No DKIM at all — neither active nor revoked selectors found.
        # INBOX-77: plain-English rewrite.
        return CheckResult(
            name="dkim",
            category="authentication",
            status="fail",
            title="DKIM",
            detail=(
                "Your emails aren't signed. Without DKIM, receivers can't verify "
                "your emails really came from you — this hurts deliverability and "
                "lets others impersonate your domain."
            ),
            raw_data={
                "checked_selectors_sample": DKIM_PROBE_SELECTORS[:20],
                "checked_count": len(DKIM_PROBE_SELECTORS),
                "technical_detail": (
                    f"Probed {len(DKIM_PROBE_SELECTORS)} common DKIM selectors "
                    "(static + known-rotating + 24-month YYYYMMDD candidates). "
                    "No matching TXT or CNAME records found."
                ),
            },
            points=0,
            max_points=15,
            fix_steps=[
                "First check if it's just our limitation: send a test email to "
                "https://www.dkimvalidator.com. If it shows DKIM passes, your "
                "provider uses an unusual selector we don't probe yet — no "
                "action needed on your end.",
                "If the test also shows no DKIM, turn on signing in your email provider:",
                "  • Google Workspace → Admin Console → Apps → Gmail → Authenticate email",
                "  • Microsoft 365 → Exchange Admin → Protection → DKIM",
                "  • SendGrid / Mailgun / Postmark — each has a 'DKIM' section in its dashboard",
                "  • Mailchimp Transactional (Mandrill) → account settings → SMTP & API",
                "Add the generated TXT record to your DNS, then re-scan in 24 "
                "hours (DKIM updates take time to propagate).",
            ]
        )


def _parse_dmarc_tags(record: str) -> dict:
    """Parse a DMARC record into a tag dict.

    DMARC records are semicolon-separated `tag=value` pairs (RFC 7489 §6.4).
    Spaces around `=` and `;` are tolerated. Tag names are case-insensitive
    but their canonical form is lowercase. Returns a dict — missing tags
    are simply absent.
    """
    tags: dict[str, str] = {}
    # Some records use comma-separation by mistake (eg voicenotes.com); be
    # forgiving — split on both ; and , at the tag-pair level.
    parts = re.split(r"[;,]", record)
    for part in parts:
        part = part.strip()
        if "=" not in part:
            continue
        name, _, value = part.partition("=")
        tags[name.strip().lower()] = value.strip()
    return tags


def check_dmarc(domain: str) -> CheckResult:
    """Check DMARC policy + alignment + percentage + subdomain coverage.

    INBOX-56 — full DMARC nuance scoring. Pre-INBOX-56 we treated every
    `p=reject` as 15/15 PASS. But two domains with identical `p=reject`
    can have very different real-world protection:
      * `p=reject; pct=100; sp=reject` — fully locked down (15/15)
      * `p=reject; pct=20; sp=none` — root protected at 20%, every
        subdomain wide open (~9/15)

    Tags surfaced and scored:
      p     — root policy (none/quarantine/reject) — biggest factor
      sp    — subdomain policy. Missing = inherits p (RFC default — fine).
              Explicit `sp=none` with strong p= is a real gap.
      pct   — percentage of mail enforced. Missing = 100. Below 100 with
              p=reject means most mail is unprotected.
      aspf  / adkim — alignment mode (relaxed default vs strict). Strict
              catches more spoofing; surface as bonus credit.
      fo    — forensic reporting trigger (`fo=1` = any failure).
              Mature posture, surface in detail.
      rua   — aggregate report destination. Already scored.
      ruf   — forensic report destination. Surface only.
    """
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
        # INBOX-52 reuse: handle multi-string TXT records uniformly.
        cleaned = re.sub(r'"\s+"', '', record).strip('"')
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

    # ---------- Parse all tags ----------
    tags = _parse_dmarc_tags(dmarc_record)
    policy = tags.get("p", "none").lower()
    if policy not in ("none", "quarantine", "reject"):
        policy = "none"
    sp = tags.get("sp", "").lower() or None  # missing → inherits p (RFC)
    try:
        pct = int(tags.get("pct", "100"))
        if pct < 0 or pct > 100:
            pct = 100
    except ValueError:
        pct = 100
    aspf = tags.get("aspf", "r").lower()    # default = r (relaxed)
    adkim = tags.get("adkim", "r").lower()  # default = r (relaxed)
    fo = tags.get("fo", "")
    has_rua = "rua" in tags
    has_ruf = "ruf" in tags
    strict_alignment = aspf == "s" and adkim == "s"

    # ---------- Score the policy strength ----------
    # Base scoring on `p` first.
    if policy == "reject":
        base_points = 15
        status = "pass"
    elif policy == "quarantine":
        base_points = 14
        status = "pass"
    else:  # none
        base_points = 10
        status = "warn"

    points = base_points
    detail_parts = []
    fix_steps_collected = []

    # Policy line
    if policy == "reject":
        detail_parts.append("DMARC policy set to reject")
    elif policy == "quarantine":
        detail_parts.append("DMARC policy set to quarantine")
    else:
        detail_parts.append("DMARC exists with p=none (monitoring mode only)")
        fix_steps_collected.extend([
            "Your DMARC policy (p=none) only monitors — it doesn't protect against spoofing",
            "Step 1: Keep p=none for 2 weeks while reviewing DMARC reports",
            "Step 2: Change to p=quarantine to send failed emails to spam",
            "Step 3: After confirming no legitimate emails are affected, upgrade to p=reject",
            "This gradual approach prevents accidentally blocking your own emails"
        ])

    # ---------- pct enforcement ----------
    # Penalise sub-100 only when the policy is not `none` (a `none`+pct=20
    # is basically still none — already scored). Pct < 100 with p=reject
    # is the headline gap: most mail is unprotected.
    if pct < 100 and policy != "none":
        # Sliding penalty: -3pts at pct=50-99, -5pts at pct=1-49
        if pct >= 50:
            penalty = 3
        else:
            penalty = 5
        points -= penalty
        detail_parts.append(f"only {pct}% enforced — {100 - pct}% of mail is unprotected")
        fix_steps_collected.append(
            f"You're enforcing DMARC on only {pct}% of mail. Increase pct gradually "
            "to 100 once you've verified DMARC reports show no legitimate mail failing."
        )
    elif pct == 100 and policy != "none":
        detail_parts.append("at 100%")

    # ---------- Subdomain policy (sp) ----------
    # Missing sp= → inherits p= per RFC 7489 §6.3 — that's fine, even
    # good (less DNS sprawl). Explicit `sp=none` with strong p= is the
    # subdomain-takeover gap.
    if sp == "none" and policy != "none":
        points -= 2
        detail_parts.append("subdomains have no DMARC policy (sp=none)")
        fix_steps_collected.append(
            "Your subdomain policy is `sp=none` — attackers can spoof unused "
            "subdomains. Change to `sp=reject` (or `sp=quarantine`) to lock "
            "down subdomains too."
        )
    elif sp == "reject":
        detail_parts.append("subdomains protected")
    elif sp == "quarantine":
        detail_parts.append("subdomains quarantined")
    elif sp is None and policy in ("reject", "quarantine"):
        # Missing sp= — fine, inherits p=. Note in detail without penalty.
        detail_parts.append(f"subdomains inherit p={policy}")

    # ---------- Strict alignment bonus surface ----------
    # No bonus points (we're capped at 15 already), but surface in detail
    # because mature operators care.
    if strict_alignment and policy in ("reject", "quarantine"):
        detail_parts.append("with strict alignment (aspf=s adkim=s)")
    elif (aspf == "s") != (adkim == "s") and policy in ("reject", "quarantine"):
        # One strict, one relaxed — uncommon, surface.
        detail_parts.append(f"alignment aspf={aspf} adkim={adkim}")

    # ---------- fo= (forensic reporting trigger) ----------
    if fo and policy in ("reject", "quarantine"):
        # fo=1 = any underlying failure; fo=0 = both fail (default);
        # fo=d = DKIM only; fo=s = SPF only.
        if fo == "1":
            detail_parts.append("forensic reports on any failure (fo=1)")

    # ---------- rua presence (existing rule, kept) ----------
    if not has_rua:
        points = max(points - 2, 0)
        detail_parts.append("no rua tag — you're not receiving DMARC aggregate reports")
        fix_steps_collected.append(
            "Add a rua tag to receive DMARC aggregate reports. "
            "Example: rua=mailto:dmarc-reports@yourdomain.com"
        )

    # ---------- Floor + status promotion ----------
    points = max(points, 0)
    # If we've docked enough to drop a reject/quarantine into warn territory,
    # promote the status. >=12 stays pass, 8-11 warn, <8 fail.
    if policy in ("reject", "quarantine"):
        if points < 8:
            status = "fail"
        elif points < 12:
            status = "warn"
        # else status stays pass

    # Compose final detail
    detail = " — ".join(detail_parts) if detail_parts else "DMARC configured"

    # Cap status pass at the actual policy. p=none can never be pass.
    if policy == "none" and status == "pass":
        status = "warn"

    return CheckResult(
        name="dmarc",
        category="authentication",
        status=status,
        title="DMARC Policy",
        detail=detail,
        raw_data={
            "record": dmarc_record,
            "policy": policy,
            "sp": sp,
            "pct": pct,
            "aspf": aspf,
            "adkim": adkim,
            "fo": fo,
            "has_rua": has_rua,
            "has_ruf": has_ruf,
            "strict_alignment": strict_alignment,
        },
        points=points,
        max_points=15,
        fix_steps=fix_steps_collected or None
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
            # INBOX-71: 2s connect timeout (was 3s). Budget arithmetic:
            #   3 MX × 2s = 6s, fits in scan_service's 10s TLS budget
            #   with 4s headroom for DNS lookups and the unverifiable
            #   fallback path. Pre-INBOX-71 the 9s budget was racing
            #   the 10s timeout — DNS overhead pushed real scans past
            #   the budget, killing the check before its honest
            #   fallback could run. Now the fallback always runs.
            sock = socket.create_connection((mx_host, 25), timeout=2)
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
    # We CANNOT verify TLS from here.
    #
    # INBOX-71 (2026-04-26): aligned with the Hybrid scoring principle:
    # for environment-limited checks where verification is genuinely
    # impossible from our scan server, return max_points=0 info-only.
    # A 100% score should mean "everything we could verify, passed" —
    # not "everything passed plus we guessed on the unreachable parts."
    # This matches the existing pattern in domain_age (WHOIS blocked),
    # blacklists (refusal sentinel), and domain_blacklists (URIBL refusal).
    #
    # We still infer the provider for the user-facing message — knowing
    # mail goes to Google Workspace is useful context for the human —
    # but no longer use that to award arbitrary partial credit.
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
        detail = (
            f"Mail handled by {inferred_provider} ({inferred_mx}). "
            "TLS could not be verified directly from our scan server (port 25 blocked). "
            "Run an external test at https://www.checktls.com/TestReceiver "
            "or https://www.hardenize.com to confirm TLS configuration."
        )
        raw_data = {
            "mx_host": inferred_mx,
            "inferred_provider": inferred_provider,
            "verification": "unverified_port_25_blocked",
            "error": last_error,
        }
    else:
        detail = (
            "Could not verify TLS — port 25 not reachable from our scan server. "
            "Run an external test at https://www.checktls.com/TestReceiver "
            "or https://www.hardenize.com to confirm TLS configuration."
        )
        raw_data = {
            "mx_hosts_tried": mx_hosts[:5],
            "verification": "unverified_unknown_provider",
            "error": last_error,
        }

    return CheckResult(
        name="tls",
        category="infrastructure",
        status="info",
        title="TLS Encryption",
        detail=detail,
        raw_data=raw_data,
        points=0,
        max_points=0,  # Excluded from denominator — genuinely unverifiable
        fix_steps=[
            "TLS verification is blocked because our scan server can't reach port 25 outbound",
            "This is a limitation of our infrastructure, not your domain",
            "Verify TLS externally:",
            "  • https://www.checktls.com/TestReceiver — sends a test message and reports TLS",
            "  • https://www.hardenize.com — full TLS + MTA-STS + DANE audit",
            "  • Use Google's check-auth@verifier.port25.com (replies with TLS report)",
            "If those tools confirm TLS works, your domain is fine — we just can't see it"
        ],
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
    """Check MTA-STS policy (DNS record + /.well-known/mta-sts.txt).

    INBOX-70 (2026-04-26): scoring is now PART OF THE TOTAL (max_points=5),
    not info-only (max_points=0). Properly configured MTA-STS in enforce
    mode is one of the strongest deliverability signals modern receivers
    look for — Google's bulk-sender requirements explicitly recommend it.
    Pre-INBOX-70 we showed PASS but 0 max_points, leaving 5 points off
    the table for every well-configured sender (Google, Microsoft, etc.).
    """
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
                max_points=5,
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
                max_points=5,
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
                points=5,
                max_points=5
            )
        elif mode == "testing":
            return CheckResult(
                name="mta_sts",
                category="infrastructure",
                status="pass",
                title="MTA-STS (Strict Transport Security)",
                detail="MTA-STS configured in testing mode — switch to enforce mode when ready for full protection",
                raw_data={"dns_record": sts_record, "policy_mode": mode},
                points=3,
                max_points=5,
                fix_steps=[
                    "Testing mode means receivers report failures but still deliver — good for monitoring",
                    "Once you confirm no legitimate mail is failing, switch to mode: enforce",
                    "Enforce mode blocks downgrade attacks and earns full 5/5 score"
                ]
            )
        elif mode == "none":
            return CheckResult(
                name="mta_sts",
                category="infrastructure",
                status="info",
                title="MTA-STS (Strict Transport Security)",
                detail="MTA-STS configured with mode: none — policy effectively disabled",
                raw_data={"dns_record": sts_record, "policy_mode": mode},
                points=1,
                max_points=5,
                fix_steps=[
                    "Mode 'none' tells receivers to ignore the policy — same protection as not having one",
                    "Switch to mode: testing to start receiving failure reports",
                    "Then switch to mode: enforce for full TLS protection"
                ]
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
                max_points=5,
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
            max_points=5
        )


def check_tls_rpt(domain: str) -> CheckResult:
    """Check TLS-RPT (TLS Reporting) record.

    INBOX-70 (2026-04-26): scoring is now part of the total (max_points=3),
    not info-only. TLS-RPT pairs with MTA-STS to give the operator
    visibility into TLS enforcement failures — without it the policy is
    'flying blind'. Worth a small but real scoring credit.
    """
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

                    # Validate rua has a scheme (mailto:, https:, etc.) —
                    # malformed rua = report destination unreachable.
                    rua_valid = bool(rua) and (
                        "mailto:" in rua.lower() or "https:" in rua.lower()
                    )

                    if rua_valid:
                        return CheckResult(
                            name="tls_rpt",
                            category="infrastructure",
                            status="pass",
                            title="TLS-RPT (TLS Reporting)",
                            detail=f"TLS-RPT configured — reports sent to {rua[:60]}{'...' if len(rua) > 60 else ''}",
                            raw_data={"record": cleaned, "rua": rua},
                            points=3,
                            max_points=3
                        )
                    else:
                        return CheckResult(
                            name="tls_rpt",
                            category="infrastructure",
                            status="warn",
                            title="TLS-RPT (TLS Reporting)",
                            detail="TLS-RPT record found but rua tag missing or malformed — reports have nowhere to go",
                            raw_data={"record": cleaned, "rua": rua},
                            points=1,
                            max_points=3,
                            fix_steps=[
                                "Your TLS-RPT record is incomplete — receivers won't know where to send reports",
                                "Update the TXT record at _smtp._tls.yourdomain.com",
                                "Add a valid rua tag, eg: v=TLSRPTv1; rua=mailto:tls-reports@yourdomain.com",
                                "Or use HTTPS endpoint: rua=https://reports.example.com/tlsrpt"
                            ]
                        )

        return CheckResult(
            name="tls_rpt",
            category="infrastructure",
            status="info",
            title="TLS-RPT (TLS Reporting)",
            detail="No TLS-RPT record — optional feature for receiving TLS delivery failure reports",
            points=0,
            max_points=3,
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
            max_points=3
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


def _parse_scrollout_response(ip_str: str) -> str:
    """ScrolloutF1 returns 127.2.X.2 where X is the reputation score (0-100).
    Higher score = better reputation. Google's IPs return 60 (good).
    A 'listing' here is NOT a binary positive — it's a numerical score.
    INBOX-74: pre-fix we treated any response as 'listed' which falsely
    flagged every legitimate sender (Google, Microsoft, etc.)."""
    parts = ip_str.split(".")
    if len(parts) == 4 and parts[0] == "127" and parts[1] == "2":
        try:
            score = int(parts[2])
            if score >= 50:
                return "good_reputation"  # Score ≥ 50 = positive signal
            elif score >= 30:
                return "neutral"          # Mid-range — no strong signal
            else:
                return "listed"           # < 30 = real concerning reputation
        except ValueError:
            return "unknown"
    return "unknown"


def _parse_hostkarma_response(ip_str: str) -> str:
    """HostKarma codes (junkemailfilter.com):
       127.0.0.1 = whitelist (good)
       127.0.0.2 = blacklist (bad)
       127.0.0.3 = yellowlist (caution)
       127.0.0.4 = brownlist (worse)
       127.0.0.5 = no-op / refused
    INBOX-74: pre-fix we treated all of these as 'listed' which conflated
    whitelist and refused responses with actual blacklist hits."""
    if ip_str == "127.0.0.1":
        return "whitelisted"
    elif ip_str == "127.0.0.2":
        return "listed"
    elif ip_str in ("127.0.0.3", "127.0.0.4"):
        return "listed"      # Caution-level, still counts as flagged
    elif ip_str == "127.0.0.5":
        return "refused"     # Operator says "we don't have data" — ignore
    return "unknown"


# Per-zone response parsers. INBOX-74: each reputation DNSBL has its own
# code semantics; we can't use a single binary "listed" interpretation.
REPUTATION_RESPONSE_PARSERS = {
    "reputation-ip.rbl.scrolloutf1.com": _parse_scrollout_response,
    "hostkarma.junkemailfilter.com": _parse_hostkarma_response,
}


def _check_reputation_dnsbl(ip: str, zone: str) -> str:
    """Check a single reputation DNSBL — returns categorical status.

    Returns one of:
      - 'listed'           — real positive listing (bad reputation)
      - 'whitelisted'      — explicit whitelist hit
      - 'good_reputation'  — high reputation score (Scrollout-style)
      - 'neutral'          — mid-range score, no signal
      - 'refused'          — DNSBL operator returned a "no data" sentinel
      - 'unknown'          — response code didn't match any known pattern
      - 'not_found'        — no record at all (= clean, not in this DNSBL)

    INBOX-74 (2026-04-26): was returning bool, treated any successful
    resolve as 'listed'. ScrolloutF1 returns reputation scores not
    binary listings, so high-reputation IPs (Google = 60) were being
    falsely flagged as bad. Pre-fix, every clean Google/Microsoft scan
    showed 'Flagged on ScrolloutF1' and lost 4/8 points.
    """
    reversed_ip = ".".join(reversed(ip.split(".")))
    query = f"{reversed_ip}.{zone}"
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 3
        answers = resolver.resolve(query, "A")
        for rdata in answers:
            ip_str = rdata.to_text()
            parser = REPUTATION_RESPONSE_PARSERS.get(zone)
            if parser:
                return parser(ip_str)
            # Default for zones without a custom parser: any 127.0.0.X
            # response means "listed" (or "whitelisted" if zone is a
            # whitelist — that mapping happens in check_ip_reputation).
            return "listed"
        return "not_found"
    except Exception:
        return "not_found"


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

        # Collect reputation DNSBL results.
        # INBOX-74: _check_reputation_dnsbl now returns categorical status
        # ('listed', 'whitelisted', 'good_reputation', 'neutral', 'refused',
        # 'unknown', 'not_found') instead of bool. Map each category to
        # whitelist/flag bucket — refused/neutral/unknown/not_found all
        # produce no signal.
        for future in concurrent.futures.as_completed(rbl_futures, timeout=10):
            rbl = rbl_futures[future]
            zone_type = rbl.get("type", "blacklist")
            try:
                result = future.result()
                if result in ("whitelisted", "good_reputation"):
                    whitelisted.append(rbl["name"])
                elif result == "listed":
                    if zone_type == "whitelist":
                        # Listed in a whitelist zone = the IP is whitelisted
                        whitelisted.append(rbl["name"])
                    else:
                        reputation_flags.append(rbl["name"])
                # 'neutral', 'refused', 'unknown', 'not_found' → no signal
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
