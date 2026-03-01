"""
InboxScore - Email Deliverability Diagnostic Tool
Backend API that performs real domain health checks
"""

import dns.resolver
import dns.reversename
import socket
import ssl
import json
import time
import re
import os
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import concurrent.futures

app = FastAPI(title="InboxScore API", version="1.0.0")

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── BLACKLISTS TO CHECK ───────────────────────────────────────────
BLACKLISTS = [
    "zen.spamhaus.org",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "dul.dnsbl.sorbs.net",
    "smtp.dnsbl.sorbs.net",
    "new.spam.dnsbl.sorbs.net",
    "cbl.abuseat.org",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "db.wpbl.info",
    "bl.mailspike.net",
    "dyna.spamrats.com",
    "noptr.spamrats.com",
    "spam.spamrats.com",
    "combined.abuse.ch",
    "drone.abuse.ch",
    "httpbl.abuse.ch",
    "spam.abuse.ch",
    "psbl.surriel.com",
    "ubl.unsubscore.com",
    "rbl.interserver.net",
    "bl.spameatingmonkey.net",
    "backscatter.spameatingmonkey.net",
    "netbl.spameatingmonkey.net",
    "ix.dnsbl.manitu.net",
    "tor.dan.me.uk",
    "torexit.dan.me.uk",
    "truncate.gbudb.net",
    "dnsbl.dronebl.org",
    "access.redhawk.org",
    "rbl.megarbl.net",
    "bl.blocklist.de",
    "all.s5h.net",
    "dnsbl.spfbl.net",
    "bogons.cymru.com",
    "bl.nordspam.com",
    "combined.mail.abusix.zone",
]

# Common DKIM selectors to check
DKIM_SELECTORS = [
    "google", "default", "selector1", "selector2",
    "dkim", "mail", "k1", "k2", "s1", "s2",
    "mandrill", "amazonses", "smtp", "cm",
    "mailchimp", "mailo", "mxvault",
]


# ─── MODELS ─────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    domain: str


class SubscribeRequest(BaseModel):
    email: str
    domain: str
    score: int


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
            detail = f"1 MX record found — consider adding a backup mail server"
            points = 7
            status = "warn"
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
        issues.append("Uses ~all (soft fail) — consider changing to -all (hard fail) for stricter enforcement")
        points = 12
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
    """Check DKIM by testing common selectors"""
    found_selectors = []

    for selector in DKIM_SELECTORS:
        dkim_domain = f"{selector}._domainkey.{domain}"
        result = safe_dns_query(dkim_domain, "TXT", timeout=3)
        if result:
            for record in result:
                cleaned = record.strip('"')
                if "v=DKIM1" in cleaned or "p=" in cleaned:
                    key_length = "unknown"
                    # Try to determine key length from p= tag
                    p_match = re.search(r'p=([A-Za-z0-9+/=]+)', cleaned)
                    if p_match:
                        key_b64 = p_match.group(1)
                        key_bits = len(key_b64) * 6  # rough estimate
                        if key_bits > 2000:
                            key_length = "2048-bit"
                        elif key_bits > 1000:
                            key_length = "1024-bit"
                        else:
                            key_length = f"~{key_bits}-bit"

                    found_selectors.append({
                        "selector": selector,
                        "key_length": key_length,
                        "record_preview": cleaned[:100]
                    })
                    break
        # Also check CNAME (some providers use CNAME for DKIM)
        if not found_selectors or found_selectors[-1]["selector"] != selector:
            cname_result = safe_dns_query(dkim_domain, "CNAME", timeout=3)
            if cname_result:
                found_selectors.append({
                    "selector": selector,
                    "key_length": "CNAME redirect",
                    "record_preview": f"CNAME -> {cname_result[0]}"
                })

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
                status="warn",
                title="DKIM",
                detail=detail + " — using 1024-bit key, upgrade to 2048-bit recommended",
                raw_data={"selectors": found_selectors},
                points=12,
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
            max_points=20,
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
            max_points=20,
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
        points = 20
        status = "pass"
        detail = f"DMARC policy set to reject — maximum protection enabled"
    elif policy == "quarantine":
        points = 16
        status = "pass"
        detail = f"DMARC policy set to quarantine — good protection"
    else:
        points = 8
        status = "warn"
        detail = f"DMARC exists but policy is p=none — not enforcing protection"

    if not has_rua:
        detail += ". No rua tag — you're not receiving DMARC reports"
        points = max(points - 3, 0)

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
        max_points=20,
        fix_steps=fix_steps
    )


def check_blacklists(domain: str) -> CheckResult:
    """Check domain against multiple blacklists"""
    # First, resolve domain to IP(s)
    ips = set()
    mx_records = safe_dns_query(domain, "MX")
    if mx_records:
        for mx in mx_records:
            mx_host = mx.split()[-1].rstrip(".")
            a_records = safe_dns_query(mx_host, "A")
            if a_records:
                ips.update(a_records)

    # Also check domain's A record
    a_records = safe_dns_query(domain, "A")
    if a_records:
        ips.update(a_records)

    if not ips:
        return CheckResult(
            name="blacklists",
            category="reputation",
            status="info",
            title="Blacklist Status",
            detail="Could not resolve domain IPs for blacklist checking",
            points=15,
            max_points=25,
            raw_data={"checked": 0, "listed": []}
        )

    # Check each IP against blacklists
    listed_on = []
    clean_on = 0
    checked = 0

    def check_single_bl(ip, bl):
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.{bl}"
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 3
            resolver.resolve(query, "A")
            return {"blacklist": bl, "ip": ip}
        except:
            return None

    # Use thread pool for parallel blacklist checks
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = []
        for ip in list(ips)[:3]:  # Check up to 3 IPs
            for bl in BLACKLISTS:
                futures.append(executor.submit(check_single_bl, ip, bl))

        for future in concurrent.futures.as_completed(futures, timeout=15):
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

    if listings == 0:
        return CheckResult(
            name="blacklists",
            category="reputation",
            status="pass",
            title="Blacklist Status",
            detail=f"Not listed on any of {total_lists} blacklists checked",
            raw_data={"checked": total_lists, "listed": [], "ips_checked": list(ips)[:3]},
            points=25,
            max_points=25
        )
    elif listings <= 2:
        # Build specific fix steps
        fix_steps = [
            f"Your IP is listed on {listings} blacklist{'s' if listings > 1 else ''}. Here's how to get delisted:"
        ]
        for item in listed_on:
            bl_name = item["blacklist"]
            if "spamhaus" in bl_name:
                fix_steps.append(f"{bl_name}: Visit spamhaus.org/lookup and submit a removal request")
            elif "barracuda" in bl_name:
                fix_steps.append(f"{bl_name}: Go to barracudacentral.org/rbl/removal-request")
            elif "spamcop" in bl_name:
                fix_steps.append(f"{bl_name}: Listings auto-expire in 24-48 hours once spam stops")
            elif "sorbs" in bl_name:
                fix_steps.append(f"{bl_name}: Visit sorbs.net and request delisting")
            else:
                fix_steps.append(f"{bl_name}: Search for '{bl_name} removal request' to find the delisting form")
        fix_steps.append("Before requesting removal, identify and fix the root cause (high bounces, spam complaints, compromised account)")

        return CheckResult(
            name="blacklists",
            category="reputation",
            status="warn" if listings == 1 else "fail",
            title="Blacklist Status",
            detail=f"Listed on {listings} blacklist{'s' if listings > 1 else ''} out of {total_lists} checked",
            raw_data={"checked": total_lists, "listed": listed_on, "ips_checked": list(ips)[:3]},
            points=max(25 - (listings * 8), 0),
            max_points=25,
            fix_steps=fix_steps
        )
    else:
        return CheckResult(
            name="blacklists",
            category="reputation",
            status="fail",
            title="Blacklist Status",
            detail=f"Listed on {listings} blacklists — this is severely impacting your deliverability",
            raw_data={"checked": total_lists, "listed": listed_on, "ips_checked": list(ips)[:3]},
            points=0,
            max_points=25,
            fix_steps=[
                f"Your IP appears on {listings} blacklists — this is critical",
                "Immediately check for compromised accounts or open relays on your mail server",
                "Review recent bounce-back messages for patterns",
                "Contact your email hosting provider — they may need to assign you a clean IP",
                "After fixing the root cause, submit removal requests to each blacklist individually",
                "Consider using a dedicated IP or a reputable email service provider"
            ]
        )


def check_tls(domain: str) -> CheckResult:
    """Check if mail server supports TLS"""
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

    mx_host = mx_records[0].split()[-1].rstrip(".")

    try:
        sock = socket.create_connection((mx_host, 25), timeout=5)
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
                detail="STARTTLS advertised but could not complete handshake",
                raw_data={"mx_host": mx_host},
                points=5,
                max_points=10,
                fix_steps=[
                    "Your mail server advertises STARTTLS but the handshake failed",
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
                detail="Mail server does not support STARTTLS — emails sent in plain text",
                raw_data={"mx_host": mx_host},
                points=0,
                max_points=10,
                fix_steps=[
                    "Your mail server doesn't support TLS encryption",
                    "Gmail and other providers flag unencrypted emails with a red padlock icon",
                    "Enable STARTTLS on your mail server or switch to a provider that supports it",
                    "Most modern email providers (Google, Microsoft, etc.) support TLS by default"
                ]
            )
    except socket.timeout:
        return CheckResult(
            name="tls",
            category="infrastructure",
            status="info",
            title="TLS Encryption",
            detail=f"Could not connect to mail server {mx_host} on port 25 (timeout)",
            raw_data={"mx_host": mx_host},
            points=5,
            max_points=10
        )
    except Exception as e:
        return CheckResult(
            name="tls",
            category="infrastructure",
            status="info",
            title="TLS Encryption",
            detail=f"Could not test TLS — connection to {mx_host} failed",
            raw_data={"mx_host": mx_host, "error": str(e)},
            points=5,
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


# ─── GENERATE AI SUMMARY ───────────────────────────────────────────

def generate_summary(domain: str, score: int, checks: list) -> dict:
    """Generate a human-readable summary based on check results"""
    failed = [c for c in checks if c.status == "fail"]
    warned = [c for c in checks if c.status == "warn"]
    passed = [c for c in checks if c.status == "pass"]

    if score >= 85:
        verdict = "Excellent"
        color = "good"
        summary = f"Your domain has strong email deliverability. "
        if warned:
            summary += f"There {'is' if len(warned) == 1 else 'are'} {len(warned)} minor issue{'s' if len(warned) > 1 else ''} to address, but overall your emails should reliably reach the inbox."
        else:
            summary += "All major checks passed. Your emails should reliably reach the inbox."
    elif score >= 65:
        verdict = "Good"
        color = "good"
        summary = f"Your email setup is solid but has room for improvement. "
        if failed:
            summary += f"Fix the {len(failed)} failed check{'s' if len(failed) > 1 else ''} to improve your score significantly."
        elif warned:
            summary += f"Address the {len(warned)} warning{'s' if len(warned) > 1 else ''} to strengthen your deliverability."
    elif score >= 40:
        verdict = "Needs Improvement"
        color = "moderate"
        issues = []
        for c in failed:
            if c.name == "blacklists":
                issues.append("blacklist listings")
            elif c.name == "dmarc":
                issues.append("missing DMARC protection")
            elif c.name == "spf":
                issues.append("SPF misconfiguration")
            elif c.name == "dkim":
                issues.append("missing DKIM")
        summary = f"Your domain has deliverability issues that are likely causing emails to land in spam. "
        if issues:
            summary += f"The main problems are: {', '.join(issues)}. Fix these to significantly improve inbox placement."
        else:
            summary += f"Address the {len(failed)} failed checks to improve your score."
    else:
        verdict = "Critical Issues"
        color = "danger"
        summary = f"Your domain has serious deliverability problems. Most of your emails are likely going to spam or being rejected entirely. Immediate action is needed on the failed checks below."

    return {
        "verdict": verdict,
        "color": color,
        "summary": summary,
        "stats": {
            "passed": len(passed),
            "warnings": len(warned),
            "failed": len(failed)
        }
    }


# ─── HELPERS ────────────────────────────────────────────────────────

def save_subscriber(email: str, domain: str, score: int):
    """Save subscriber to JSON file for future use"""
    subscribers_file = os.path.join(os.path.dirname(__file__), 'subscribers.json')

    try:
        if os.path.exists(subscribers_file):
            with open(subscribers_file, 'r') as f:
                subscribers = json.load(f)
        else:
            subscribers = []

        # Check if already exists
        existing = next((s for s in subscribers if s['email'] == email and s['domain'] == domain), None)
        if not existing:
            subscribers.append({
                'email': email,
                'domain': domain,
                'score': score,
                'subscribed_at': datetime.utcnow().isoformat()
            })

        with open(subscribers_file, 'w') as f:
            json.dump(subscribers, f, indent=2)

        return True
    except Exception as e:
        print(f"Error saving subscriber: {e}")
        return False


# ─── API ENDPOINTS ──────────────────────────────────────────────────

@app.post("/api/scan")
async def scan_domain(request: ScanRequest):
    """Run a complete deliverability scan on a domain"""
    domain = request.domain.strip().lower()

    # Basic domain validation
    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "")
    domain = domain.split("/")[0].strip()

    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Please enter a valid domain name")

    start_time = time.time()

    # Run all checks (some in parallel using thread pool)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        future_mx = executor.submit(check_mx_records, domain)
        future_spf = executor.submit(check_spf, domain)
        future_dkim = executor.submit(check_dkim, domain)
        future_dmarc = executor.submit(check_dmarc, domain)
        future_blacklists = executor.submit(check_blacklists, domain)
        future_tls = executor.submit(check_tls, domain)
        future_rdns = executor.submit(check_reverse_dns, domain)
        future_bimi = executor.submit(check_bimi, domain)

        checks = [
            future_mx.result(timeout=20),
            future_spf.result(timeout=20),
            future_dkim.result(timeout=20),
            future_dmarc.result(timeout=20),
            future_blacklists.result(timeout=25),
            future_tls.result(timeout=15),
            future_rdns.result(timeout=10),
            future_bimi.result(timeout=10),
        ]

    # Calculate total score
    total_points = sum(c.points for c in checks)
    max_points = sum(c.max_points for c in checks if c.max_points > 0)
    score = round((total_points / max_points * 100)) if max_points > 0 else 0

    # Generate summary
    summary = generate_summary(domain, score, checks)

    scan_time = round(time.time() - start_time, 1)

    return {
        "domain": domain,
        "score": score,
        "summary": summary,
        "checks": [c.dict() for c in checks],
        "scan_time": scan_time,
        "scanned_at": datetime.utcnow().isoformat()
    }


@app.post("/api/subscribe")
async def subscribe(request: SubscribeRequest):
    """Subscribe user to email reports"""
    # Validate email
    import re
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, request.email):
        raise HTTPException(status_code=400, detail="Invalid email address")

    # Validate domain
    if not request.domain or "." not in request.domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

    # Validate score
    if not isinstance(request.score, int) or request.score < 0 or request.score > 100:
        raise HTTPException(status_code=400, detail="Invalid score")

    # Save subscriber
    success = save_subscriber(request.email, request.domain, request.score)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to save subscription")

    return {
        "status": "success",
        "message": "Successfully subscribed to email reports",
        "email": request.email,
        "domain": request.domain
    }


@app.get("/api/health")
async def health_check():
    return {"status": "ok", "version": "1.0.0"}


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
    """Return robots.txt for SEO"""
    return """User-agent: *
Allow: /
Sitemap: https://inboxscore.ai/sitemap.xml
"""


@app.get("/sitemap.xml", response_class=Response)
async def sitemap_xml():
    """Return XML sitemap"""
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://inboxscore.ai/</loc>
    <lastmod>2026-03-01T00:00:00Z</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>
"""
    return Response(content=xml, media_type="application/xml")


# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
async def serve_frontend():
    return FileResponse("static/index.html")


@app.get("/scan/{domain}")
async def serve_scan_page(domain: str):
    """Serve homepage for shareable scan URLs"""
    return FileResponse("static/index.html")


if __name__ == "__main__":
    import uvicorn
    print("\n🚀 InboxScore is running!")
    print("   Open http://localhost:8000 in your browser\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
