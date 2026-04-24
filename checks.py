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
                cleaned = record.strip('"')
                if "v=DKIM1" in cleaned or "p=" in cleaned:
                    key_length = "unknown"
                    p_match = re.search(r'p=([A-Za-z0-9+/=]+)', cleaned)
                    if p_match:
                        key_b64 = p_match.group(1)
                        key_bits = len(key_b64) * 6
                        if key_bits > 2000:
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

    mx_records = safe_dns_query(domain, "MX")
    if mx_records:
        for mx in mx_records:
            mx_host = mx.split()[-1].rstrip(".")
            a_records = safe_dns_query(mx_host, "A")
            if a_records:
                for ip in a_records:
                    ip_sources.setdefault(ip, []).append(f"MX: {mx_host}")

    # Also check domain's A record
    a_records = safe_dns_query(domain, "A")
    if a_records:
        for ip in a_records:
            ip_sources.setdefault(ip, []).append("A record")

    if not ip_sources:
        return CheckResult(
            name="blacklists",
            category="reputation",
            status="pass",
            title="Blacklist Status",
            detail="Mail server uses a cloud provider — blacklist check not applicable",
            points=15,
            max_points=15,
            raw_data={"checked": 0, "listed": []}
        )

    # INBOX-26: sort deterministically so slices at :518, :538, and downstream
    # callers (hetrix, app) see the same IPs in the same order between runs.
    # Order here is insertion-order-from-DNS, which is NOT stable across
    # scans even with identical upstream state.
    ips = sorted(ip_sources.keys())

    # Check each IP against blacklists
    listed_on = []
    clean_on = 0
    checked = 0

    def check_single_bl(ip, bl):
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.{bl}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            resolver.resolve(query, "A")
            return {"blacklist": bl, "ip": ip, "source": ", ".join(ip_sources.get(ip, ["unknown"]))}
        except:
            return None

    # Use thread pool for parallel blacklist checks
    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
        futures = []
        for ip in ips[:2]:  # Check up to 2 IPs (primary MX + A record)
            for bl in BLACKLISTS:
                futures.append(executor.submit(check_single_bl, ip, bl))

        for future in concurrent.futures.as_completed(futures, timeout=8):
            checked += 1
            try:
                result = future.result()
                if result:
                    listed_on.append(result)
                else:
                    clean_on += 1
            except:
                pass

    total_lists = len(BLACKLISTS)
    listings = len(listed_on)

    # Build IP summary for display
    ip_summary = []
    for ip in ips[:3]:
        sources = ", ".join(ip_sources.get(ip, []))
        ip_summary.append({"ip": ip, "source": sources})

    if listings == 0:
        detail = f"Not listed on any of {total_lists} blacklists checked"
        if len(ips) == 1:
            detail += f" (checked IP: {ips[0]} via {ip_sources[ips[0]][0]})"
        else:
            detail += f" (checked {len(ips[:3])} IPs)"
        return CheckResult(
            name="blacklists",
            category="reputation",
            status="pass",
            title="Blacklist Status",
            detail=detail,
            raw_data={"checked": total_lists, "listed": [], "ips_checked": ip_summary},
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
            raw_data={"checked": total_lists, "listed": listed_on, "ips_checked": ip_summary, "listings_by_ip": listings_by_ip},
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
            raw_data={"checked": total_lists, "listed": listed_on, "ips_checked": ip_summary, "listings_by_ip": listings_by_ip},
            points=0,
            max_points=15,
            fix_steps=fix_steps
        )


def check_tls(domain: str) -> CheckResult:
    """Check if mail server supports TLS — tries all MX hosts"""
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
            sock = socket.create_connection((mx_host, 25), timeout=4)
            banner = sock.recv(1024).decode("utf-8", errors="ignore")

            # Send EHLO
            sock.sendall(b"EHLO inboxscore.test\r\n")
            ehlo_response = sock.recv(4096).decode("utf-8", errors="ignore")

            supports_starttls = "STARTTLS" in ehlo_response.upper()

            if supports_starttls:
                # Try STARTTLS
                sock.sendall(b"STARTTLS\r\n")
                starttls_response = sock.recv(1024).decode("utf-8", errors="ignore")

                if starttls_response.startswith("220"):
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    ssl_sock = context.wrap_socket(sock, server_hostname=mx_host)
                    tls_version = ssl_sock.version()
                    ssl_sock.close()

                    if "TLSv1.3" in str(tls_version):
                        return CheckResult(
                            name="tls",
                            category="infrastructure",
                            status="pass",
                            title="TLS Encryption",
                            detail=f"Mail server supports {tls_version} — excellent encryption",
                            raw_data={"mx_host": mx_host, "tls_version": str(tls_version)},
                            points=10,
                            max_points=10
                        )
                    else:
                        return CheckResult(
                            name="tls",
                            category="infrastructure",
                            status="pass",
                            title="TLS Encryption",
                            detail=f"Mail server supports TLS ({tls_version})",
                            raw_data={"mx_host": mx_host, "tls_version": str(tls_version)},
                            points=8,
                            max_points=10
                        )

            sock.close()

            if supports_starttls:
                return CheckResult(
                    name="tls",
                    category="infrastructure",
                    status="warn",
                    title="TLS Encryption",
                    detail=f"STARTTLS advertised on {mx_host} but could not complete handshake",
                    raw_data={"mx_host": mx_host},
                    points=5,
                    max_points=10,
                    fix_steps=[
                        f"Mail server {mx_host} advertises STARTTLS but the handshake failed",
                        "Verify your SSL certificate is valid and not expired",
                        "Ensure the certificate matches the mail server hostname"
                    ]
                )
            else:
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
                        "Most modern email providers (Google, Microsoft, etc.) support TLS by default"
                    ]
                )
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            last_error = str(e)
            continue  # Try next MX host
        except Exception as e:
            last_error = str(e)
            continue  # Try next MX host

    # If we get here, none of the MX hosts were reachable on port 25
    # For well-known providers, we can infer TLS support
    provider_tls = {
        "google.com": ("Google Workspace", "TLSv1.3"),
        "googlemail.com": ("Google Workspace", "TLSv1.3"),
        "outlook.com": ("Microsoft 365", "TLSv1.2+"),
        "protection.outlook.com": ("Microsoft 365", "TLSv1.2+"),
        "pphosted.com": ("Proofpoint", "TLSv1.2+"),
        "mimecast.com": ("Mimecast", "TLSv1.2+"),
    }

    for mx_host in mx_hosts:
        mx_lower = mx_host.lower()
        for provider_domain, (provider_name, tls_ver) in provider_tls.items():
            if provider_domain in mx_lower:
                return CheckResult(
                    name="tls",
                    category="infrastructure",
                    status="pass",
                    title="TLS Encryption",
                    detail=f"Mail handled by {provider_name} ({mx_host}) — {tls_ver} supported",
                    raw_data={"mx_host": mx_host, "tls_version": tls_ver, "inferred": True, "provider": provider_name},
                    points=10,
                    max_points=10
                )

    # Truly couldn't determine
    tried = ", ".join(mx_hosts[:3])
    return CheckResult(
        name="tls",
        category="infrastructure",
        status="info",
        title="TLS Encryption",
        detail=f"Could not verify TLS directly — port 25 not reachable from scan server (common for cloud providers)",
        raw_data={"mx_hosts_tried": mx_hosts[:5], "error": last_error},
        points=8,
        max_points=10
    )


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
