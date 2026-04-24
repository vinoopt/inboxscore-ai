"""
InboxScore - HetrixTools Blacklist Check Integration
Uses HetrixTools API v2 to check IPs and domains against 1000+ blacklists.
Docs: https://docs.hetrixtools.com/blacklist-check-api/
"""

import os
import httpx
from typing import Optional

HETRIX_API_KEY = os.environ.get("HETRIX_API_KEY", "")
HETRIX_BASE_URL = "https://api.hetrixtools.com/v2"


def _safe_url(url: str) -> str:
    """Mask API key in URL for safe logging."""
    if HETRIX_API_KEY and HETRIX_API_KEY in url:
        return url.replace(HETRIX_API_KEY, "***KEY***")
    return url

# Severity classification for known blacklists
HIGH_SEVERITY_RBLS = {
    "zen.spamhaus.org", "sbl.spamhaus.org", "xbl.spamhaus.org",
    "b.barracudacentral.org", "bl.spamcop.net",
    "cbl.abuseat.org", "dnsbl.sorbs.net",
}

MEDIUM_SEVERITY_RBLS = {
    "pbl.spamhaus.org",  # Policy block — dynamic IP ranges
    "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
    "psbl.surriel.com", "dnsbl.dronebl.org",
    "bl.mailspike.net", "bl.score.senderscore.com",
}
# Everything else is low severity


def _classify_severity(rbl_name: str) -> str:
    """Classify a blacklist listing by severity."""
    rbl_lower = rbl_name.lower() if rbl_name else ""
    if rbl_lower in HIGH_SEVERITY_RBLS:
        return "high"
    if rbl_lower in MEDIUM_SEVERITY_RBLS:
        return "medium"
    return "low"


async def check_ip_blacklist(ip: str, api_key: Optional[str] = None) -> dict:
    """
    Check an IPv4 address against 1000+ blacklists via HetrixTools.

    Returns:
        {
            "status": "success" | "error" | "in_progress",
            "ip": str,
            "blacklisted_count": int,
            "blacklisted_on": [{"rbl": str, "delist": str, "severity": str}, ...],
            "credits_left": int,
            "report_link": str,
            "error": str | None
        }
    """
    key = api_key or HETRIX_API_KEY
    if not key:
        return {"status": "error", "ip": ip, "error": "HETRIX_API_KEY not configured"}

    url = f"{HETRIX_BASE_URL}/{key}/blacklist-check/ipv4/{ip}/"

    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.get(url)
            data = resp.json()

        if data.get("status") == "SUCCESS":
            listings = []
            for item in data.get("blacklisted_on", []):
                if item.get("rbl"):  # Skip null entries
                    listings.append({
                        "rbl": item["rbl"],
                        "delist": item.get("delist", ""),
                        "severity": _classify_severity(item["rbl"]),
                    })
            return {
                "status": "success",
                "ip": ip,
                "blacklisted_count": data.get("blacklisted_count", 0),
                "blacklisted_on": listings,
                "credits_left": data.get("blacklist_check_credits_left", 0),
                "report_link": data.get("links", {}).get("report_link", ""),
                "error": None,
            }
        elif data.get("status") == "ERROR":
            msg = data.get("error_message", "Unknown error")
            # "blacklist check in progress" means we need to poll again
            if "in progress" in msg.lower():
                return {"status": "in_progress", "ip": ip, "error": msg}
            return {"status": "error", "ip": ip, "error": msg}
        else:
            return {"status": "error", "ip": ip, "error": "Unexpected response"}

    except httpx.TimeoutException:
        return {"status": "in_progress", "ip": ip, "error": "Check timed out — still processing"}
    except Exception as e:
        # Sanitize — str(e) may contain the full URL with API key
        err_msg = str(e)
        if HETRIX_API_KEY and HETRIX_API_KEY in err_msg:
            err_msg = err_msg.replace(HETRIX_API_KEY, "***")
        return {"status": "error", "ip": ip, "error": err_msg}


async def check_domain_blacklist(domain: str, api_key: Optional[str] = None) -> dict:
    """
    Check a domain/hostname against 1000+ blacklists via HetrixTools.

    Returns same shape as check_ip_blacklist but with "domain" instead of "ip".
    """
    key = api_key or HETRIX_API_KEY
    if not key:
        return {"status": "error", "domain": domain, "error": "HETRIX_API_KEY not configured"}

    url = f"{HETRIX_BASE_URL}/{key}/blacklist-check/domain/{domain}/"

    try:
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.get(url)
            data = resp.json()

        if data.get("status") == "SUCCESS":
            listings = []
            for item in data.get("blacklisted_on", []):
                if item.get("rbl"):
                    listings.append({
                        "rbl": item["rbl"],
                        "delist": item.get("delist", ""),
                        "severity": _classify_severity(item["rbl"]),
                    })
            return {
                "status": "success",
                "domain": domain,
                "blacklisted_count": data.get("blacklisted_count", 0),
                "blacklisted_on": listings,
                "credits_left": data.get("blacklist_check_credits_left", 0),
                "report_link": data.get("links", {}).get("report_link", ""),
                "error": None,
            }
        elif data.get("status") == "ERROR":
            msg = data.get("error_message", "Unknown error")
            if "in progress" in msg.lower():
                return {"status": "in_progress", "domain": domain, "error": msg}
            return {"status": "error", "domain": domain, "error": msg}
        else:
            return {"status": "error", "domain": domain, "error": "Unexpected response"}

    except httpx.TimeoutException:
        return {"status": "in_progress", "domain": domain, "error": "Check timed out — still processing"}
    except Exception as e:
        err_msg = str(e)
        if HETRIX_API_KEY and HETRIX_API_KEY in err_msg:
            err_msg = err_msg.replace(HETRIX_API_KEY, "***")
        return {"status": "error", "domain": domain, "error": err_msg}


async def full_blacklist_check(domain: str, ips: list[str] = None, api_key: Optional[str] = None) -> dict:
    """
    Run a complete blacklist check: domain + all sending IPs.

    Args:
        domain: The domain to check
        ips: List of sending IP addresses (resolved from MX/A records).
             If None, only the domain check is performed.

    Returns:
        {
            "domain": str,
            "domain_result": { ... },
            "ip_results": [ { ... }, ... ],
            "total_listings": int,
            "high_severity_count": int,
            "overall_status": "clean" | "warning" | "critical",
            "credits_left": int,
            "checked_at": str (ISO timestamp)
        }
    """
    import asyncio
    from datetime import datetime, timezone

    key = api_key or HETRIX_API_KEY

    # Run domain check
    domain_result = await check_domain_blacklist(domain, key)

    # Run IP checks in parallel
    ip_results = []
    if ips:
        # INBOX-26: sort defensively even though callers now sort upstream —
        # cheap, and a future caller that forgets won't reintroduce drift.
        tasks = [check_ip_blacklist(ip, key) for ip in sorted(ips)[:5]]
        ip_results = await asyncio.gather(*tasks)
        ip_results = list(ip_results)

    # Aggregate
    total_listings = domain_result.get("blacklisted_count", 0)
    high_count = 0
    for r in [domain_result] + ip_results:
        for listing in r.get("blacklisted_on", []):
            if listing.get("severity") == "high":
                high_count += 1
        if r != domain_result:
            total_listings += r.get("blacklisted_count", 0)

    # Determine overall status
    if total_listings == 0:
        overall = "clean"
    elif high_count > 0 or total_listings >= 3:
        overall = "critical"
    else:
        overall = "warning"

    # Get credits from most recent successful response
    credits_left = 0
    for r in [domain_result] + ip_results:
        if r.get("credits_left"):
            credits_left = r["credits_left"]
            break

    return {
        "domain": domain,
        "domain_result": domain_result,
        "ip_results": ip_results,
        "total_listings": total_listings,
        "high_severity_count": high_count,
        "overall_status": overall,
        "credits_left": credits_left,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
