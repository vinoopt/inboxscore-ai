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
import httpx
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import concurrent.futures
import whois

# Database
from db import (
    is_db_available, save_scan, save_subscriber as db_save_subscriber,
    check_rate_limit, get_user_scans, get_user_scan_stats,
    add_user_domain, get_user_domains, remove_user_domain,
    get_domain_scans, get_scan_detail, update_domain_score,
    get_user_profile, get_user_plan, PLAN_LIMITS, ANONYMOUS_LIMIT,
    get_full_user_profile, update_user_profile, update_user_preferences,
    export_user_data, delete_user_data,
    get_user_alerts, get_unread_alert_count, mark_alert_read,
    mark_all_alerts_read, delete_alert,
    update_domain_monitoring, get_monitored_domains, get_monitoring_logs,
    save_postmaster_connection, get_postmaster_connection,
    delete_postmaster_connection, get_postmaster_metrics as db_get_postmaster_metrics,
    save_snds_connection, get_snds_connection, delete_snds_connection,
    get_snds_metrics as db_get_snds_metrics, update_snds_sync_status,
    upsert_snds_metrics,
    add_user_ips, get_user_ips, remove_user_ip, set_ip_domains, get_ips_for_domain,
)

# Auth
from auth import (
    is_auth_available, sign_up, sign_in, reset_password,
    get_user_from_token, refresh_session
)

# PDF report generation
from pdf_report import generate_pdf_report

app = FastAPI(title="InboxScore API", version="1.14.0")

# CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── BACKGROUND MONITORING SCHEDULER ─────────────────────────────
from apscheduler.schedulers.background import BackgroundScheduler
from monitor import run_monitoring_cycle
from postmaster_scheduler import sync_all_postmaster_users
from snds_scheduler import sync_all_snds_users

scheduler = BackgroundScheduler()
# Run monitoring check every 15 minutes to find domains due for their scan
scheduler.add_job(run_monitoring_cycle, 'interval', minutes=15, id='monitoring_cycle',
                  max_instances=1, replace_existing=True)
# Sync Google Postmaster data daily at 6 AM UTC
scheduler.add_job(sync_all_postmaster_users, 'cron', hour=6, minute=0,
                  id='postmaster_sync', max_instances=1, replace_existing=True)
# Sync Microsoft SNDS data daily at 7 AM UTC
scheduler.add_job(sync_all_snds_users, 'cron', hour=7, minute=0,
                  id='snds_sync', max_instances=1, replace_existing=True)


@app.on_event("startup")
async def startup_event():
    """Start the background monitoring scheduler"""
    try:
        scheduler.start()
        print("[Scheduler] Monitoring scheduler started (every 15 min)")
    except Exception as e:
        print(f"[Scheduler] Failed to start: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """Gracefully stop the scheduler"""
    try:
        scheduler.shutdown(wait=False)
        print("[Scheduler] Monitoring scheduler stopped")
    except Exception as e:
        print(f"[Scheduler] Shutdown error: {e}")

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


# ─── MODELS ─────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    domain: str


class SubscribeRequest(BaseModel):
    email: str
    domain: str
    score: int


class SignupRequest(BaseModel):
    email: str
    password: str
    name: Optional[str] = None


class LoginRequest(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


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

    ips = list(ip_sources.keys())

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

        # Calculate age
        now = datetime.now(creation_date.tzinfo) if creation_date.tzinfo else datetime.utcnow()
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

    primary_ip = list(ips)[0]

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
        "all_ips": list(ips)[:5],
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
            elif c.name == "ip_reputation":
                issues.append("poor IP reputation")
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

def save_subscriber_local(email: str, domain: str, score: int):
    """Fallback: Save subscriber to JSON file when DB is unavailable"""
    subscribers_file = os.path.join(os.path.dirname(__file__), 'subscribers.json')

    try:
        if os.path.exists(subscribers_file):
            with open(subscribers_file, 'r') as f:
                subscribers = json.load(f)
        else:
            subscribers = []

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
        print(f"Error saving subscriber locally: {e}")
        return False


# ─── API ENDPOINTS ──────────────────────────────────────────────────

@app.post("/api/scan")
async def scan_domain(request: ScanRequest, req: Request):
    """Run a complete deliverability scan on a domain"""
    try:
        return await _run_scan(request, req)
    except HTTPException:
        raise
    except Exception as e:
        print(f"[SCAN ERROR] Unhandled exception scanning {request.domain}: {e}")
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

async def _run_scan(request: ScanRequest, req: Request):
    """Internal scan logic — wrapped by scan_domain for error handling"""
    domain = request.domain.strip().lower()

    # Basic domain validation
    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "")
    domain = domain.split("/")[0].strip()

    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Please enter a valid domain name")

    # Get client IP for rate limiting
    client_ip = req.headers.get("x-forwarded-for", req.client.host if req.client else "0.0.0.0")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    # Check if user is authenticated (needed for plan-based rate limiting)
    scan_user_id = None
    auth_header = req.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "")
        user_result = get_user_from_token(token)
        if user_result["success"]:
            scan_user_id = user_result["user"]["id"]

    # Rate limit check — plan-aware
    if is_db_available():
        rate_check = check_rate_limit(
            ip_address=client_ip,
            max_scans=ANONYMOUS_LIMIT,
            user_id=scan_user_id
        )
        if not rate_check["allowed"]:
            plan = rate_check.get("plan", "anonymous")
            if plan == "anonymous":
                message = "You've used your 3 free scans today. Create a free account for 5 scans/day, or upgrade to Pro for unlimited scans."
            elif plan == "free":
                message = "You've used your 5 free scans today. Upgrade to Pro for unlimited scans and advanced monitoring."
            else:
                message = "Daily scan limit reached."

            raise HTTPException(
                status_code=429,
                detail={
                    "message": message,
                    "scans_used": rate_check["scans_used"],
                    "max_scans": rate_check["max_scans"],
                    "plan": plan
                }
            )

    start_time = time.time()

    # Run all checks in parallel — each check is individually wrapped so
    # one timeout or crash never kills the entire scan
    def safe_result(future, name, title, category, timeout_sec):
        """Collect a check result; return a safe fallback if it crashes."""
        check_start = time.time()
        try:
            result = future.result(timeout=timeout_sec)
            elapsed = round(time.time() - check_start, 2)
            if elapsed > 3:
                print(f"[SCAN] Check '{name}' for {domain} took {elapsed}s (slow)")
            return result
        except Exception as e:
            elapsed = round(time.time() - check_start, 2)
            print(f"[SCAN] Check '{name}' failed for {domain} after {elapsed}s: {e}")
            return CheckResult(
                name=name, category=category, status="warn", title=title,
                detail=f"Could not complete this check (timeout or service error)",
                points=0, max_points=0,
            )

    with concurrent.futures.ThreadPoolExecutor(max_workers=13) as executor:
        future_mx = executor.submit(check_mx_records, domain)
        future_spf = executor.submit(check_spf, domain)
        future_dkim = executor.submit(check_dkim, domain)
        future_dmarc = executor.submit(check_dmarc, domain)
        future_blacklists = executor.submit(check_blacklists, domain)
        future_tls = executor.submit(check_tls, domain)
        future_rdns = executor.submit(check_reverse_dns, domain)
        future_bimi = executor.submit(check_bimi, domain)
        future_mta_sts = executor.submit(check_mta_sts, domain)
        future_tls_rpt = executor.submit(check_tls_rpt, domain)
        future_senders = executor.submit(check_sender_detection, domain)
        future_age = executor.submit(check_domain_age, domain)
        future_ip_rep = executor.submit(check_ip_reputation, domain)

        # Timeouts: DNS-only checks get 8s, network-heavy checks get 12s
        checks = [
            safe_result(future_mx, "mx_records", "MX Records", "infrastructure", 8),
            safe_result(future_spf, "spf", "SPF Record", "authentication", 8),
            safe_result(future_dkim, "dkim", "DKIM", "authentication", 8),
            safe_result(future_dmarc, "dmarc", "DMARC Policy", "authentication", 8),
            safe_result(future_blacklists, "blacklists", "Blacklist Check", "reputation", 12),
            safe_result(future_tls, "tls", "TLS Encryption", "infrastructure", 10),
            safe_result(future_rdns, "reverse_dns", "Reverse DNS", "infrastructure", 8),
            safe_result(future_bimi, "bimi", "BIMI Record", "authentication", 8),
            safe_result(future_mta_sts, "mta_sts", "MTA-STS Policy", "infrastructure", 8),
            safe_result(future_tls_rpt, "tls_rpt", "TLS Reporting", "infrastructure", 8),
            safe_result(future_senders, "sender_detection", "Email Provider", "infrastructure", 8),
            safe_result(future_age, "domain_age", "Domain Age", "reputation", 10),
            safe_result(future_ip_rep, "ip_reputation", "IP Reputation", "reputation", 10),
        ]

    # Calculate total score
    total_points = sum(c.points for c in checks)
    max_points = sum(c.max_points for c in checks if c.max_points > 0)
    score = min(100, round((total_points / max_points * 100))) if max_points > 0 else 0

    # Generate summary
    summary = generate_summary(domain, score, checks)

    scan_time = round(time.time() - start_time, 1)

    # Build response
    response_data = {
        "domain": domain,
        "score": score,
        "summary": summary,
        "checks": [c.dict() for c in checks],
        "scan_time": scan_time,
        "scanned_at": datetime.utcnow().isoformat()
    }

    # Store scan in database (async-safe, non-blocking to the response)
    if is_db_available():
        try:
            saved = save_scan(
                domain=domain,
                score=score,
                results=response_data,
                ip_address=client_ip,
                user_id=scan_user_id,
            )
            if saved:
                response_data["scan_id"] = saved["id"]
                # Update domain score if user has this domain saved
                if scan_user_id:
                    try:
                        update_domain_score(domain, score, saved["id"])
                    except Exception:
                        pass
        except Exception as e:
            print(f"Failed to save scan to DB: {e}")

    return response_data


@app.post("/api/subscribe")
async def subscribe(request: SubscribeRequest):
    """Subscribe user to email reports"""
    # Validate email
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, request.email):
        raise HTTPException(status_code=400, detail="Invalid email address")

    # Validate domain
    if not request.domain or "." not in request.domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

    # Validate score
    if not isinstance(request.score, int) or request.score < 0 or request.score > 100:
        raise HTTPException(status_code=400, detail="Invalid score")

    # Save subscriber — try Supabase first, fall back to local JSON
    if is_db_available():
        success = db_save_subscriber(request.email, request.domain, request.score)
    else:
        success = save_subscriber_local(request.email, request.domain, request.score)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to save subscription")

    return {
        "status": "success",
        "message": "Successfully subscribed to email reports",
        "email": request.email,
        "domain": request.domain
    }


# ─── AUTH ENDPOINTS ────────────────────────────────────────────────

@app.post("/api/auth/signup")
async def api_signup(request: SignupRequest):
    """Register a new user"""
    # Validate email
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, request.email):
        raise HTTPException(status_code=400, detail="Invalid email address")

    if len(request.password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    result = sign_up(request.email, request.password, request.name)

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=400, detail=result["error"])


@app.post("/api/auth/login")
async def api_login(request: LoginRequest):
    """Log in and get access token"""
    if not request.email or not request.password:
        raise HTTPException(status_code=400, detail="Email and password required")

    result = sign_in(request.email, request.password)

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=401, detail=result["error"])


@app.post("/api/auth/forgot-password")
async def api_forgot_password(request: ForgotPasswordRequest):
    """Send password reset email"""
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, request.email):
        raise HTTPException(status_code=400, detail="Invalid email address")

    result = reset_password(request.email)
    return result


@app.get("/api/auth/me")
async def api_get_current_user(req: Request):
    """Get current user from access token"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")

    token = auth_header.replace("Bearer ", "")
    result = get_user_from_token(token)

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=401, detail=result["error"])


@app.post("/api/auth/refresh")
async def api_refresh_token(request: RefreshTokenRequest):
    """Refresh an expired access token"""
    if not request.refresh_token:
        raise HTTPException(status_code=400, detail="Refresh token required")

    result = refresh_session(request.refresh_token)

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=401, detail=result["error"])


@app.get("/api/user/scans")
async def api_user_scans(req: Request, limit: int = 20):
    """Get scan history for authenticated user"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    scans = get_user_scans(user_id, limit=min(limit, 50))
    return {"scans": scans}


@app.get("/api/user/stats")
async def api_user_stats(req: Request):
    """Get scan stats for authenticated user"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    stats = get_user_scan_stats(user_id)
    return stats


@app.get("/api/user/plan")
async def api_user_plan(req: Request):
    """Get user plan info and scan usage"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    profile = get_user_profile(user_id)
    plan = profile.get("plan", "free") if profile else "free"
    limit = PLAN_LIMITS.get(plan, 5)

    # Get today's scan count
    scans_today = 0
    if is_db_available() and limit != -1:
        from db import get_supabase
        from datetime import date as date_type
        sb = get_supabase()
        if sb:
            try:
                today = date_type.today().isoformat()
                result = sb.table("rate_limits").select("scan_count").eq(
                    "ip_address", user_id
                ).eq("date", today).execute()
                if result.data:
                    scans_today = result.data[0]["scan_count"]
            except Exception:
                pass

    return {
        "plan": plan,
        "name": profile.get("name") if profile else None,
        "scans_today": scans_today,
        "scans_limit": limit,  # -1 = unlimited
        "features": {
            "unlimited_scans": limit == -1,
            "monitoring": plan in ("pro", "growth", "enterprise"),
            "api_access": plan in ("growth", "enterprise"),
            "white_label": plan == "enterprise",
        }
    }


# ─── SETTINGS API ENDPOINTS ──────────────────────────────────────

@app.get("/api/user/profile")
async def api_get_profile(req: Request):
    """Get full user profile including preferences"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    profile = get_full_user_profile(user_result["user"]["id"])
    if not profile:
        return {"name": "", "company": "", "plan": "free", "preferences": {}}
    return profile


@app.put("/api/user/profile")
async def api_update_profile(req: Request):
    """Update user profile (name, company)"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    body = await req.json()
    name = body.get("name", "").strip()
    company = body.get("company", "").strip()

    updated = update_user_profile(user_result["user"]["id"], name=name, company=company)
    if updated is None:
        raise HTTPException(status_code=500, detail="Failed to update profile")
    return {"success": True, "profile": updated}


@app.put("/api/user/password")
async def api_change_password(req: Request):
    """Change user password via Supabase Admin API"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    body = await req.json()
    new_password = body.get("new_password", "")
    if len(new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")

    # Use Supabase service role to update password
    from db import get_supabase
    sb = get_supabase()
    if not sb:
        raise HTTPException(status_code=500, detail="Database unavailable")

    try:
        sb.auth.admin.update_user_by_id(
            user_result["user"]["id"],
            {"password": new_password}
        )
        return {"success": True}
    except Exception as e:
        print(f"Password update error: {e}")
        raise HTTPException(status_code=500, detail="Failed to update password")


@app.put("/api/user/preferences")
async def api_update_preferences(req: Request):
    """Update user notification preferences"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    body = await req.json()
    prefs = {
        "scan_alerts": body.get("scan_alerts", True),
        "blacklist_alerts": body.get("blacklist_alerts", True),
        "weekly_digest": body.get("weekly_digest", False),
    }

    success = update_user_preferences(user_result["user"]["id"], prefs)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to save preferences")
    return {"success": True}


@app.get("/api/user/export")
async def api_export_data(req: Request):
    """Export all user data (GDPR data portability)"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    data = export_user_data(user_result["user"]["id"])
    if "error" in data:
        raise HTTPException(status_code=500, detail=data["error"])
    return data


@app.delete("/api/user/account")
async def api_delete_account(req: Request):
    """Delete user account and all associated data"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]

    # Delete user data from our tables
    success = delete_user_data(user_id)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete account data")

    # Delete auth user via Supabase admin
    from db import get_supabase
    sb = get_supabase()
    if sb:
        try:
            sb.auth.admin.delete_user(user_id)
        except Exception as e:
            print(f"Auth user deletion error: {e}")
            # Data is already deleted, so continue

    return {"success": True, "message": "Account deleted"}


# ─── ALERTS API ENDPOINTS ─────────────────────────────────────────

@app.get("/api/user/alerts")
async def api_get_alerts(req: Request, severity: str = None, unread: bool = False, limit: int = 50):
    """Get alerts for authenticated user"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    alerts = get_user_alerts(user_id, limit=min(limit, 100), severity=severity, unread_only=unread)
    return {"alerts": alerts}


@app.get("/api/user/alerts/count")
async def api_alert_count(req: Request):
    """Get unread alert count for sidebar badge"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    count = get_unread_alert_count(user_id)
    return {"unread_count": count}


@app.put("/api/alerts/{alert_id}/read")
async def api_mark_alert_read(req: Request, alert_id: str):
    """Mark a single alert as read"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    success = mark_alert_read(user_id, alert_id)
    if success:
        return {"ok": True}
    raise HTTPException(status_code=500, detail="Failed to mark alert as read")


@app.put("/api/user/alerts/read-all")
async def api_mark_all_read(req: Request):
    """Mark all alerts as read"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    success = mark_all_alerts_read(user_id)
    if success:
        return {"ok": True}
    raise HTTPException(status_code=500, detail="Failed to mark alerts as read")


@app.delete("/api/alerts/{alert_id}")
async def api_delete_alert(req: Request, alert_id: str):
    """Delete an alert"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    success = delete_alert(user_id, alert_id)
    if success:
        return {"ok": True}
    raise HTTPException(status_code=500, detail="Failed to delete alert")


# ─── DOMAIN API ENDPOINTS ─────────────────────────────────────────

@app.get("/api/user/domains")
async def api_get_domains(req: Request):
    """Get all domains for authenticated user"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    domains = get_user_domains(user_id)
    return {"domains": domains}


class AddDomainRequest(BaseModel):
    domain: str


@app.post("/api/user/domains")
async def api_add_domain(req: Request, body: AddDomainRequest):
    """Add a domain to user's list"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]

    # Clean domain
    domain = body.domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = re.sub(r'^www\.', '', domain)
    domain = domain.split('/')[0]

    if not domain or '.' not in domain:
        raise HTTPException(status_code=400, detail="Invalid domain")

    result = add_user_domain(user_id, domain)
    if result:
        return {"domain": result}
    else:
        raise HTTPException(status_code=500, detail="Failed to add domain")


@app.delete("/api/user/domains/{domain_id}")
async def api_remove_domain(req: Request, domain_id: str):
    """Remove a domain from user's list"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    success = remove_user_domain(user_id, domain_id)
    if success:
        return {"ok": True}
    else:
        raise HTTPException(status_code=500, detail="Failed to remove domain")


# ─── SENDING IP ENDPOINTS ─────────────────────────────────────────


@app.get("/api/user/ips")
async def api_get_ips(req: Request):
    """Get all sending IPs for authenticated user (with domain mappings)"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    ips = get_user_ips(user_id)
    return {"ips": ips}


class AddIpsRequest(BaseModel):
    ips: list


@app.post("/api/user/ips")
async def api_add_ips(req: Request, body: AddIpsRequest):
    """Add one or more sending IPs"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]

    # Validate and clean IPs
    import ipaddress
    clean_ips = []
    invalid = []
    for ip_str in body.ips:
        ip_str = str(ip_str).strip()
        if not ip_str:
            continue
        try:
            ipaddress.ip_address(ip_str)
            clean_ips.append(ip_str)
        except ValueError:
            invalid.append(ip_str)

    if not clean_ips and invalid:
        raise HTTPException(status_code=400, detail=f"Invalid IP addresses: {', '.join(invalid)}")

    added = add_user_ips(user_id, clean_ips)
    return {"added": added, "invalid": invalid}


@app.get("/api/user/ips/by-domain/{domain}")
async def api_get_ips_by_domain(req: Request, domain: str):
    """Get sending IPs mapped to a specific domain"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    ips = get_ips_for_domain(user_id, domain.strip().lower())
    return {"ips": ips, "domain": domain}


class SetIpDomainsRequest(BaseModel):
    domains: list


@app.put("/api/user/ips/{ip}/domains")
async def api_set_ip_domains(req: Request, ip: str, body: SetIpDomainsRequest):
    """Set domain mappings for a sending IP"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    domains = [d.strip().lower() for d in body.domains if d.strip()]
    success = set_ip_domains(user_id, ip, domains)
    if success:
        return {"ok": True, "domains": domains}
    else:
        raise HTTPException(status_code=500, detail="Failed to update IP domains")


@app.delete("/api/user/ips/{ip}")
async def api_remove_ip(req: Request, ip: str):
    """Remove a sending IP and its domain mappings"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    success = remove_user_ip(user_id, ip)
    if success:
        return {"ok": True}
    else:
        raise HTTPException(status_code=500, detail="Failed to remove IP")


# ─── MONITORING API ENDPOINTS ─────────────────────────────────────


class UpdateMonitoringRequest(BaseModel):
    is_monitored: bool
    monitor_interval: Optional[int] = 24
    alert_threshold: Optional[int] = 70


@app.put("/api/user/domains/{domain_id}/monitoring")
async def api_update_monitoring(req: Request, domain_id: str, body: UpdateMonitoringRequest):
    """Enable or disable monitoring for a domain"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]

    # Validate interval (must be 6, 12, or 24 hours)
    if body.monitor_interval not in (6, 12, 24):
        raise HTTPException(status_code=400, detail="Monitor interval must be 6, 12, or 24 hours")

    # Validate threshold (10-100)
    if body.alert_threshold < 10 or body.alert_threshold > 100:
        raise HTTPException(status_code=400, detail="Alert threshold must be between 10 and 100")

    result = update_domain_monitoring(
        user_id=user_id,
        domain_id=domain_id,
        is_monitored=body.is_monitored,
        monitor_interval=body.monitor_interval,
        alert_threshold=body.alert_threshold,
    )

    if result:
        action = "enabled" if body.is_monitored else "disabled"
        return {"ok": True, "message": f"Monitoring {action}", "domain": result}
    else:
        raise HTTPException(status_code=500, detail="Failed to update monitoring")


@app.get("/api/user/domains/{domain_id}/monitoring-logs")
async def api_monitoring_logs(req: Request, domain_id: str, limit: int = 20):
    """Get monitoring scan logs for a domain"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    logs = get_monitoring_logs(domain_id, limit=min(limit, 100))
    return {"logs": logs}


@app.get("/api/monitoring/status")
async def api_monitoring_status(req: Request):
    """Get monitoring status overview for authenticated user"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    all_monitored = get_monitored_domains()

    # Filter to only this user's domains
    user_monitored = [d for d in all_monitored if d["user_id"] == user_id]

    return {
        "monitored_count": len(user_monitored),
        "domains": user_monitored,
        "scheduler_running": scheduler.running,
    }


@app.get("/api/domains/{domain}/scans")
async def api_domain_scans(req: Request, domain: str, limit: int = 50):
    """Get scan history for a specific domain"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    scans = get_domain_scans(domain, limit=min(limit, 100))
    return {"scans": scans}


@app.get("/api/scans/{scan_id}")
async def api_scan_detail(req: Request, scan_id: str):
    """Get full scan details"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    scan = get_scan_detail(scan_id)
    if scan:
        return {"scan": scan}
    else:
        raise HTTPException(status_code=404, detail="Scan not found")


# ─── PDF REPORT ENDPOINTS ──────────────────────────────────────────

@app.get("/api/scans/{scan_id}/pdf")
async def api_scan_pdf(req: Request, scan_id: str):
    """Download PDF report for a saved scan (authenticated users)"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    scan = get_scan_detail(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # The scan detail stores full results JSON
    scan_data = scan.get("results", scan)
    try:
        pdf_bytes = generate_pdf_report(scan_data)
    except Exception as e:
        print(f"[PDF] Generation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate PDF report")

    domain = scan_data.get("domain", "scan")
    filename = f"inboxscore-{domain}-report.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        }
    )


@app.post("/api/report/pdf")
async def api_report_pdf(req: Request):
    """Generate PDF report from scan data (no auth required — for live scans).
    Accepts the same JSON body as the scan response."""
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    # Validate minimum required fields
    if not body.get("domain") or "checks" not in body:
        raise HTTPException(status_code=400, detail="Missing domain or checks data")

    try:
        pdf_bytes = generate_pdf_report(body)
    except Exception as e:
        print(f"[PDF] Generation error: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate PDF report")

    domain = body.get("domain", "scan")
    filename = f"inboxscore-{domain}-report.pdf"

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(pdf_bytes)),
        }
    )


# ─── CSV EXPORT ENDPOINT ───────────────────────────────────────────

@app.get("/api/user/scans/csv")
async def api_export_scans_csv(req: Request):
    """Export user's scan history as CSV file (authenticated)"""
    import csv
    import io as _io

    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]

    # Fetch all scans (up to 500)
    scans = get_user_scans(user_id, limit=500)

    if not scans:
        raise HTTPException(status_code=404, detail="No scans found")

    # Build CSV
    output = _io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow([
        "Domain", "Score", "Verdict", "Scanned At",
        "SPF", "DKIM", "DMARC", "MX Records", "Blacklists",
        "TLS", "Reverse DNS", "BIMI", "MTA-STS", "TLS-RPT",
        "Domain Age", "IP Reputation", "Sender Detection",
        "Scan Time (s)"
    ])

    check_names_order = [
        "spf", "dkim", "dmarc", "mx_records", "blacklists",
        "tls", "reverse_dns", "bimi", "mta_sts", "tls_rpt",
        "domain_age", "ip_reputation", "sender_detection"
    ]

    for scan in scans:
        results = scan.get("results", {})
        if isinstance(results, str):
            try:
                results = json.loads(results)
            except Exception:
                results = {}

        score = results.get("score", scan.get("score", ""))
        domain = results.get("domain", scan.get("domain", ""))
        scan_time = results.get("scan_time", "")
        scanned_at = scan.get("created_at", results.get("scanned_at", ""))

        # Determine verdict from score
        try:
            s = int(score)
            if s >= 85:
                verdict = "Excellent"
            elif s >= 65:
                verdict = "Good"
            elif s >= 40:
                verdict = "Needs Work"
            else:
                verdict = "Critical"
        except (ValueError, TypeError):
            verdict = ""

        # Extract check statuses
        checks_list = results.get("checks", [])
        check_map = {}
        for c in checks_list:
            cname = c.get("name", "")
            cstatus = c.get("status", "")
            cpoints = c.get("points", "")
            cmax = c.get("max_points", "")
            if cmax:
                check_map[cname] = f"{cstatus} ({cpoints}/{cmax})"
            else:
                check_map[cname] = cstatus

        # Build row
        row = [domain, score, verdict, scanned_at]
        for cn in check_names_order:
            row.append(check_map.get(cn, ""))
        row.append(scan_time)

        writer.writerow(row)

    csv_content = output.getvalue()
    output.close()

    filename = f"inboxscore-scan-history-{datetime.utcnow().strftime('%Y%m%d')}.csv"

    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        }
    )


@app.get("/api/health")
async def health_check():
    return {
        "status": "ok",
        "version": "1.14.0",
        "database": "connected" if is_db_available() else "not configured",
        "auth": "enabled" if is_auth_available() else "not configured",
        "monitoring": "running" if scheduler.running else "stopped"
    }


# ─── HETRIXTOOLS BLACKLIST CHECK ENDPOINTS ───────────────────────

@app.get("/api/blacklist/check/{domain}")
async def api_blacklist_check(domain: str, req: Request):
    """
    Run a full blacklist check for a domain via HetrixTools API (1000+ lists).
    Resolves MX/A record IPs and checks both domain + IPs.
    Requires authentication. Uses 1 credit per check (cached 30 min by HetrixTools).
    """
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    from hetrix import full_blacklist_check, HETRIX_API_KEY
    if not HETRIX_API_KEY:
        raise HTTPException(status_code=503, detail="Blacklist monitoring not configured")

    user_id = user_result["user"]["id"]

    # 1) Use centralized user_ips mapped to this domain (if any)
    ips = set()
    ip_sources = {}  # ip -> source label
    user_domain_ips = get_ips_for_domain(user_id, domain)
    if user_domain_ips:
        for ip in user_domain_ips:
            ips.add(ip)
            ip_sources[ip] = "Sending IPs"

    # 2) Also resolve from DNS as additional sources
    mx_records = safe_dns_query(domain, "MX")
    if mx_records:
        for mx in mx_records:
            mx_host = mx.split()[-1].rstrip(".")
            a_records = safe_dns_query(mx_host, "A")
            if a_records:
                for ip in a_records:
                    ips.add(ip)
                    if ip not in ip_sources:
                        ip_sources[ip] = f"MX: {mx_host}"

    a_records = safe_dns_query(domain, "A")
    if a_records:
        for ip in a_records:
            ips.add(ip)
            if ip not in ip_sources:
                ip_sources[ip] = "A record"

    result = await full_blacklist_check(domain, list(ips)[:5])

    # Attach IP source labels for display
    for ip_result in result.get("ip_results", []):
        ip = ip_result.get("ip", "")
        ip_result["source"] = ip_sources.get(ip, "unknown")

    return result


# ─── GOOGLE POSTMASTER TOOLS ENDPOINTS ───────────────────────────

def _require_pro_plan(user_id: str):
    """Check if user has Pro+ plan for Postmaster features"""
    plan = get_user_plan(user_id)
    if plan not in ("pro", "growth", "enterprise"):
        raise HTTPException(
            status_code=403,
            detail="Google Postmaster Tools requires a Pro plan or higher. Upgrade to unlock advanced deliverability insights."
        )
    return plan


@app.get("/api/postmaster/authorize")
async def api_postmaster_authorize(req: Request):
    """Start Google Postmaster OAuth flow — redirects to Google consent"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    _require_pro_plan(user_id)

    from postmaster import get_authorization_url, GOOGLE_CLIENT_ID
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=500, detail="Google Postmaster not configured")

    # Use user_id as state parameter for callback verification
    auth_url = get_authorization_url(state=user_id)
    return {"authorization_url": auth_url}


@app.get("/api/postmaster/callback")
async def api_postmaster_callback(req: Request):
    """
    OAuth callback from Google. Exchanges code for tokens, saves connection.
    Redirects user back to settings page.
    """
    code = req.query_params.get("code")
    state = req.query_params.get("state")  # This is the user_id
    error = req.query_params.get("error")

    if error:
        # User denied consent or other error
        return FileResponse("static/settings.html")

    if not code or not state:
        raise HTTPException(status_code=400, detail="Missing code or state parameter")

    try:
        from postmaster import exchange_code_for_tokens, get_google_user_email

        tokens = await exchange_code_for_tokens(code)
        google_email = await get_google_user_email(tokens["access_token"])

        save_postmaster_connection(
            user_id=state,
            access_token=tokens["access_token"],
            refresh_token=tokens["refresh_token"],
            token_expiry=tokens["token_expiry"],
            google_email=google_email or "unknown",
        )

        # Trigger initial sync for this user in the background
        import asyncio
        from postmaster import fetch_metrics_for_user
        connection = get_postmaster_connection(state)
        if connection:
            asyncio.create_task(fetch_metrics_for_user(state, connection, days=14))

        # Redirect back to settings with success indicator
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/settings?postmaster=connected", status_code=302)

    except Exception as e:
        print(f"[Postmaster] OAuth callback error: {e}")
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url="/settings?postmaster=error", status_code=302)


@app.get("/api/postmaster/status")
async def api_postmaster_status(req: Request):
    """Get Postmaster connection status for the current user"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    plan = get_user_plan(user_id)
    is_pro = plan in ("pro", "growth", "enterprise")

    connection = get_postmaster_connection(user_id)

    if connection:
        return {
            "connected": True,
            "google_email": connection.get("google_email", ""),
            "connected_at": connection.get("connected_at", ""),
            "is_pro": is_pro,
        }
    else:
        return {
            "connected": False,
            "google_email": None,
            "connected_at": None,
            "is_pro": is_pro,
        }


@app.post("/api/postmaster/disconnect")
async def api_postmaster_disconnect(req: Request):
    """Disconnect Google Postmaster (remove stored tokens)"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    success = delete_postmaster_connection(user_id)

    if success:
        return {"success": True, "message": "Google Postmaster disconnected"}
    else:
        raise HTTPException(status_code=500, detail="Failed to disconnect")


@app.get("/api/postmaster/metrics/{domain}")
async def api_postmaster_metrics(domain: str, req: Request, days: int = 30):
    """Get Postmaster metrics for a specific domain"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    _require_pro_plan(user_id)

    # Check if connected
    connection = get_postmaster_connection(user_id)
    if not connection:
        return {"connected": False, "metrics": [], "message": "Connect Google Postmaster in Settings to see metrics"}

    metrics = db_get_postmaster_metrics(user_id, domain, days=min(days, 90))
    return {
        "connected": True,
        "domain": domain,
        "metrics": metrics,
        "google_email": connection.get("google_email", ""),
    }


@app.post("/api/postmaster/sync")
async def api_postmaster_sync(req: Request):
    """Manually trigger a Postmaster data sync for the current user"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    _require_pro_plan(user_id)

    connection = get_postmaster_connection(user_id)
    if not connection:
        raise HTTPException(status_code=400, detail="Google Postmaster not connected")

    from postmaster import fetch_metrics_for_user
    result = await fetch_metrics_for_user(user_id, connection, days=14)

    return {
        "success": True,
        "domains_synced": result["domains_synced"],
        "metrics_saved": result["metrics_saved"],
        "errors": result["errors"] if result["errors"] else None,
    }


# ─── MICROSOFT SNDS ENDPOINTS ────────────────────────────────────

@app.post("/api/snds/connect")
async def api_snds_connect(req: Request):
    """Connect Microsoft SNDS — validate key and save connection"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    _require_pro_plan(user_id)

    body = await req.json()
    snds_key = body.get("snds_key", "").strip()
    if not snds_key:
        raise HTTPException(status_code=400, detail="SNDS key is required")

    # Validate the key by fetching data
    from snds import validate_snds_key, fetch_snds_data
    validation = await validate_snds_key(snds_key)

    if not validation["valid"]:
        raise HTTPException(
            status_code=400,
            detail=validation["error"] or "Invalid SNDS key"
        )

    # Save connection
    save_snds_connection(user_id, snds_key)

    # Trigger initial sync
    try:
        result = await fetch_snds_data(snds_key)
        if result["success"] and result["data"]:
            ip_set = set()
            for row in result["data"]:
                ip_set.add(row["ip_address"])
                upsert_snds_metrics(
                    user_id=user_id,
                    ip_address=row["ip_address"],
                    metric_date=row["metric_date"],
                    metrics=row,
                )
            update_snds_sync_status(user_id, ip_count=len(ip_set))
    except Exception as e:
        print(f"[SNDS] Initial sync error: {e}")

    return {
        "success": True,
        "message": "Microsoft SNDS connected successfully",
        "ip_count": validation["ip_count"],
    }


@app.get("/api/snds/status")
async def api_snds_status(req: Request):
    """Get SNDS connection status for the current user"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    plan = get_user_plan(user_id)
    is_pro = plan in ("pro", "growth", "enterprise")

    connection = get_snds_connection(user_id)

    if connection:
        import json
        tracked_ips_raw = connection.get("tracked_ips")
        tracked_ips = None
        if tracked_ips_raw:
            tracked_ips = json.loads(tracked_ips_raw) if isinstance(tracked_ips_raw, str) else tracked_ips_raw
        return {
            "connected": True,
            "connected_at": connection.get("connected_at", ""),
            "last_sync_at": connection.get("last_sync_at"),
            "ip_count": connection.get("ip_count", 0),
            "tracked_ips": tracked_ips,
            "is_pro": is_pro,
        }
    else:
        return {
            "connected": False,
            "connected_at": None,
            "last_sync_at": None,
            "ip_count": 0,
            "tracked_ips": None,
            "is_pro": is_pro,
        }


@app.post("/api/snds/disconnect")
async def api_snds_disconnect(req: Request):
    """Disconnect Microsoft SNDS (remove key + metrics)"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    success = delete_snds_connection(user_id)

    if success:
        return {"success": True, "message": "Microsoft SNDS disconnected"}
    else:
        raise HTTPException(status_code=500, detail="Failed to disconnect")


@app.post("/api/snds/sync")
async def api_snds_sync(req: Request):
    """Manually trigger an SNDS data sync for the current user"""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    _require_pro_plan(user_id)

    connection = get_snds_connection(user_id)
    if not connection:
        raise HTTPException(status_code=400, detail="Microsoft SNDS not connected")

    from snds import fetch_snds_data
    result = await fetch_snds_data(connection["snds_key"])

    if not result["success"]:
        return {
            "success": False,
            "error": result["error"],
            "ips_synced": 0,
            "metrics_saved": 0,
        }

    ip_set = set()
    metrics_saved = 0
    for row in result["data"]:
        ip_set.add(row["ip_address"])
        upsert_snds_metrics(
            user_id=user_id,
            ip_address=row["ip_address"],
            metric_date=row["metric_date"],
            metrics=row,
        )
        metrics_saved += 1

    update_snds_sync_status(user_id, ip_count=len(ip_set))

    return {
        "success": True,
        "ips_synced": len(ip_set),
        "metrics_saved": metrics_saved,
    }


@app.get("/api/snds/metrics")
async def api_snds_metrics(req: Request, days: int = 30, domain: str = ""):
    """Get SNDS IP metrics, optionally filtered by domain-mapped IPs from user_ips."""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    _require_pro_plan(user_id)

    connection = get_snds_connection(user_id)
    if not connection:
        return {
            "connected": False,
            "metrics": [],
            "message": "Connect Microsoft SNDS in Settings or Sending IPs to see metrics",
        }

    metrics = db_get_snds_metrics(user_id, days=min(days, 90))

    # Filter by centralized user_ips (domain-mapped if domain param given)
    if domain:
        allowed_ips = set(get_ips_for_domain(user_id, domain))
    else:
        user_ip_rows = get_user_ips(user_id)
        allowed_ips = {row["ip_address"] for row in user_ip_rows} if user_ip_rows else set()

    # Only filter if user has IPs configured; if none configured, show all SNDS data
    if allowed_ips:
        metrics = [m for m in metrics if m.get("ip_address") in allowed_ips]

    return {
        "connected": True,
        "metrics": metrics,
        "ip_count": connection.get("ip_count", 0),
        "last_sync_at": connection.get("last_sync_at"),
    }


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


@app.get("/pricing")
async def serve_pricing():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/#pricing", status_code=302)


@app.get("/signup")
async def serve_signup():
    return FileResponse("static/signup.html")


@app.get("/login")
async def serve_login():
    return FileResponse("static/login.html")


@app.get("/forgot-password")
async def serve_forgot_password():
    return FileResponse("static/forgot-password.html")


@app.get("/dashboard")
async def serve_dashboard():
    return FileResponse("static/dashboard.html")


@app.get("/sending-ips")
async def serve_sending_ips():
    return FileResponse("static/sending-ips.html")


@app.get("/domains")
async def serve_domains():
    return FileResponse("static/domains.html")


@app.get("/domains/{domain}")
async def serve_domain_detail(domain: str):
    return FileResponse("static/domains.html")


@app.get("/alerts")
async def serve_alerts():
    return FileResponse("static/alerts.html")


@app.get("/settings")
async def serve_settings():
    return FileResponse("static/settings.html")


@app.get("/email-health")
async def serve_email_health():
    return FileResponse("static/email-health.html")


if __name__ == "__main__":
    import uvicorn
    print("\n🚀 InboxScore is running!")
    print("   Open http://localhost:8000 in your browser\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
