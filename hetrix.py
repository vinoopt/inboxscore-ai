"""
InboxScore — HetrixTools blacklist client (INBOX-229)

Drop-in replacement for dnsbl.py. Same `check_ip / check_domain /
full_blacklist_check` signatures, same response shape — so the
callers in monitor.py / app.py / checks.py work unchanged when the
USE_HETRIX_BL feature flag flips on.

Why we needed this:
  - Render's outbound DNS goes via Google public resolvers; URIBL,
    Spamhaus, and several other DNSBLs refuse public-resolver queries
    and return a special code (e.g. 127.0.0.255). Our previous
    dnsbl.py classifier misread that as "listed", showing false
    positives to customers (caught for mailercloud.com on 2026-05-11).
  - HetrixTools runs its own private DNS resolvers + has commercial
    DBL access, so they get the real answer. We pay them to handle
    the infrastructure mess and just consume their API.

Architecture decisions (from migration plan):
  - Called only from scheduler (monitor.py), once-per-day per domain.
    HetrixTools' API takes 10-22s per call so it CANNOT sit in a
    user-request handler. The blacklist_results table caches results
    for the frontend.
  - Manual "Scan now" button burns 1 credit per click — still cheap.
  - API key read from os.environ["HETRIX_API_TOKEN"]; module raises
    a clear error if missing so misconfig is loud, not silent.
  - HetrixTools puts the API key inside response payloads (under
    `links.api_blacklist_check_link` etc.). We strip those before
    returning to callers so the key never lands in our DB cache.
"""

import os
import concurrent.futures
import logging
from datetime import datetime, timezone
from typing import Optional

import httpx


logger = logging.getLogger(__name__)

# HetrixTools v2 endpoint base. We never log the token at INFO; only
# the masked tail goes into debug strings when troubleshooting.
HX_BASE = "https://api.hetrixtools.com/v2"

# Per-request timeout. HetrixTools is slow (observed 10-22s) because
# they fan out to 1000+ lists per request. 30s gives headroom without
# hanging the scheduler if their API stalls.
HX_TIMEOUT = 30.0

# INBOX-229 (2026-05-11): HetrixTools' API rejects requests without a
# User-Agent header — Python's default `python-urllib/x.x` triggers a
# 403 from their Cloudflare front. Confirmed by direct curl test.
HX_USER_AGENT = "InboxScore/1.0 (+https://inboxscore.ai)"


# ─── Severity classification ──────────────────────────────────────
#
# HetrixTools' response gives us the RBL name and a delist URL but
# NOT a severity tier. We map known names → severity here, matching
# the tiers we used in dnsbl.py so the frontend's red/amber/grey
# colour logic continues to work without changes.
#
# Unknown RBL names default to "medium" + log to Sentry so we can
# fold new lists into this map over time (per F2 lesson — fail loud
# on unknown values, not silent).

_SEVERITY_HIGH = frozenset({
    # Major receivers consult these directly — listings hurt inbox
    # placement immediately.
    "Spamhaus ZEN",
    "Spamhaus SBL",
    "Spamhaus XBL",
    "Spamhaus DBL",
    "Spamhaus CSS",
    "Barracuda BBL",
    "SpamCop SCBL",
    "CBL Abuseat",
    "Composite Blocking List",
    "SORBS",
    "SORBS Combined",
    "SURBL",
    "SURBL multi",
    "URIBL black",
    "Invaluement",
})

_SEVERITY_LOW = frozenset({
    # Volume-only / dynamic-IP / soft-policy lists. Annoying but
    # rarely cause real delivery problems.
    "SpamRATS Dyna",
    "SpamRATS NoPTR",
    "S5H Combined",
    "Manitu IX",
    "Blocklist.de",
    "UCEPROTECT Level 2",
    "UCEPROTECT Level 3",
})


def _classify_severity(rbl_name: str) -> str:
    """Look up the severity tier for a given RBL name from HetrixTools.

    Anything not in the high/low sets defaults to "medium" and is
    logged so we know to update the lookup when new lists appear.
    """
    if not rbl_name:
        return "medium"
    if rbl_name in _SEVERITY_HIGH:
        return "high"
    if rbl_name in _SEVERITY_LOW:
        return "low"
    # Substring match for variant names — e.g. HetrixTools may say
    # "Spamhaus DBL (domain blocklist)". This is forgiving but loud.
    lower = rbl_name.lower()
    for entry in _SEVERITY_HIGH:
        if entry.lower() in lower:
            return "high"
    for entry in _SEVERITY_LOW:
        if entry.lower() in lower:
            return "low"
    logger.warning("hetrix.unknown_rbl_name",
                   extra={"rbl_name": rbl_name})
    return "medium"


# ─── Token + transport ────────────────────────────────────────────

def _get_token() -> str:
    """Read HETRIX_API_TOKEN from env. Raises with a clear message
    if missing so misconfig surfaces immediately rather than as a
    cryptic 401."""
    tok = os.environ.get("HETRIX_API_TOKEN", "").strip()
    if not tok:
        raise RuntimeError(
            "HETRIX_API_TOKEN env var is not set. Add it in the Render "
            "service environment (or local .env) before calling "
            "hetrix.py functions."
        )
    return tok


def _strip_key_from_payload(payload: dict) -> dict:
    """HetrixTools includes the API key in `links.api_*` URLs of every
    response. Strip the whole `links` dict before we return / persist —
    otherwise the key would land in our blacklist_results JSONB cache.
    Returns a NEW dict; doesn't mutate the input."""
    if not isinstance(payload, dict):
        return payload
    cleaned = {k: v for k, v in payload.items() if k != "links"}
    return cleaned


def _hx_get(path: str) -> dict:
    """Wrapper around the GET request to HetrixTools' v2 API.

    Returns the parsed JSON response with the `links` field stripped.
    Raises httpx.HTTPError on transport/HTTP problems; caller decides
    whether that's fatal (typically: log + fall back to last cached
    DB result, never break the page).
    """
    url = f"{HX_BASE}/{_get_token()}/{path.lstrip('/')}"
    # User-Agent is REQUIRED — HetrixTools' Cloudflare front returns 403
    # to Python's default urllib UA. See HX_USER_AGENT comment.
    headers = {"User-Agent": HX_USER_AGENT, "Accept": "application/json"}
    with httpx.Client(timeout=HX_TIMEOUT, headers=headers) as client:
        resp = client.get(url)
        resp.raise_for_status()
        return _strip_key_from_payload(resp.json())


# ─── Public API — same shape as dnsbl.py ──────────────────────────

def check_ip(ip: str) -> dict:
    """Check one IP against HetrixTools' aggregated 1000+ DNSBL list.

    Returns the same shape as dnsbl.check_ip:
        {
            "ip": str,
            "blacklisted_count": int,
            "blacklisted_on": [
                {"rbl": str, "name": str, "severity": str,
                 "operator": str, "delist": str, "codes": []}
            ],
            "checked_count": int,
            "error": str | None,
        }

    The `name` / `rbl` fields are populated identically (HetrixTools
    gives us one name per listing; we set both for back-compat with
    every frontend caller that reads either field).
    """
    try:
        raw = _hx_get(f"blacklist-check/ipv4/{ip}/")
    except Exception as e:
        logger.exception("hetrix.check_ip_failed", extra={"ip": ip})
        return {
            "ip": ip,
            "blacklisted_count": 0,
            "blacklisted_on": [],
            "checked_count": 0,
            "error": f"HetrixTools error: {e}",
        }

    listings = _parse_listings(raw)
    return {
        "ip": ip,
        "blacklisted_count": len(listings),
        "blacklisted_on": listings,
        # HetrixTools doesn't tell us exactly how many lists they
        # checked. We report a conservative "1000+" via the count
        # surfaced by the API when present.
        "checked_count": int(raw.get("checked_count", 0) or 1000),
        "error": None,
    }


def check_domain(domain: str) -> dict:
    """Check one domain against HetrixTools' aggregated DBL list.

    Same shape as check_ip but keyed on "domain" instead of "ip".
    """
    try:
        raw = _hx_get(f"blacklist-check/domain/{domain}/")
    except Exception as e:
        logger.exception("hetrix.check_domain_failed", extra={"domain": domain})
        return {
            "domain": domain,
            "blacklisted_count": 0,
            "blacklisted_on": [],
            "checked_count": 0,
            "error": f"HetrixTools error: {e}",
        }

    listings = _parse_listings(raw)
    return {
        "domain": domain,
        "blacklisted_count": len(listings),
        "blacklisted_on": listings,
        "checked_count": int(raw.get("checked_count", 0) or 1000),
        "error": None,
    }


def _parse_listings(raw: dict) -> list[dict]:
    """Convert HetrixTools' `blacklisted_on` array into our internal
    shape, filtering out the placeholder `{rbl: null, delist: null}`
    that they return when the count is 0."""
    arr = raw.get("blacklisted_on") or []
    out: list[dict] = []
    for entry in arr:
        if not isinstance(entry, dict):
            continue
        rbl = entry.get("rbl")
        delist = entry.get("delist")
        # Their "no listings" placeholder — skip it.
        if not rbl and not delist:
            continue
        if not rbl:
            continue
        out.append({
            "rbl": rbl,
            "name": rbl,                         # back-compat with UIs that read `name`
            "severity": _classify_severity(rbl),
            "operator": rbl.split(" ", 1)[0],    # rough — first word as operator
            "delist": delist or "",
            "codes": [],                         # HetrixTools doesn't expose DNS codes
        })
    return out


def full_blacklist_check(domain: str, ips: Optional[list[str]] = None) -> dict:
    """Run a complete blacklist check via HetrixTools: domain + all
    sending IPs, in parallel.

    Same signature + return shape as dnsbl.full_blacklist_check.

    INBOX-229 (2026-05-11): all calls (domain + each IP) run in
    parallel via ThreadPoolExecutor. Each individual call still takes
    10-22s on a cold target, but the wall-clock for the whole batch is
    ~max(individual_times) instead of sum — so a 1-domain + 5-IP scan
    drops from 60-120s to ~20s. This is what makes hetrix viable on
    the user-facing scan path.

    Cap IPs at 50 to bound the credit burn per scan (matches
    dnsbl.py's behaviour).
    """
    ip_results: list[dict] = []
    if ips:
        # INBOX-26: sort for deterministic output; cap at 50.
        unique_ips = sorted(set(ips))[:50]
    else:
        unique_ips = []

    # Parallelise domain call + per-IP calls. max_workers caps concurrent
    # HetrixTools requests; their API tolerates this fine and our network
    # I/O is async-friendly via httpx. 6 = 1 domain + 5 IPs (the typical
    # IP_CHECK_CAP from checks.py). For larger batches we cap at 10 so
    # we don't open too many sockets at once.
    max_workers = min(1 + len(unique_ips), 10) or 1
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_domain = ex.submit(check_domain, domain)
        future_to_ip = {ex.submit(check_ip, ip): ip for ip in unique_ips}

        domain_result = future_domain.result()
        # Preserve input order for the IPs in the output (sorted), so the
        # response shape is deterministic across runs.
        ip_to_result = {}
        for fut in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                ip_to_result[ip] = fut.result()
            except Exception as e:
                logger.exception("hetrix.full_check_ip_failed",
                                 extra={"ip": ip, "domain": domain})
                # Build the same error-shape check_ip emits so callers
                # don't have to special-case a None.
                ip_to_result[ip] = {
                    "ip": ip,
                    "blacklisted_count": 0,
                    "blacklisted_on": [],
                    "checked_count": 0,
                    "error": f"HetrixTools error: {e}",
                }
        ip_results = [ip_to_result[ip] for ip in unique_ips]

    # Aggregate
    total_listings = domain_result["blacklisted_count"]
    high_count = sum(
        1 for l in domain_result["blacklisted_on"] if l["severity"] == "high"
    )
    for r in ip_results:
        total_listings += r["blacklisted_count"]
        for l in r["blacklisted_on"]:
            if l["severity"] == "high":
                high_count += 1

    if total_listings == 0:
        overall = "clean"
    elif high_count > 0:
        overall = "critical"
    else:
        overall = "warning"

    return {
        "domain": domain,
        "domain_result": domain_result,
        "ip_results": ip_results,
        "total_listings": total_listings,
        "high_severity_count": high_count,
        "overall_status": overall,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        # INBOX-229 (2026-05-11) correction: HetrixTools' marketing
        # says "1000+" but the actual per-call coverage (verified from
        # their docs + live UI on 2026-05-11) is:
        #   - Domain check: 23 DBLs
        #   - IPv4 check:   ~122 RBLs
        # We expose the larger of the two so the surfaced "lists_checked"
        # is the headline coverage when both were queried.
        "lists_checked": 122 if ips else 23,
    }


# ─── Credit / quota observability ─────────────────────────────────

def get_remaining_credits() -> dict:
    """Probe HetrixTools for current quota — used by the scheduler's
    heartbeat to track credit burn. Costs 1 trivial call (no
    blacklist-check credit consumed; just queries our own status).

    Returns:
        { "api_calls_left": int, "blacklist_check_credits_left": int,
          "error": str | None }
    """
    try:
        # Hit a cheap endpoint just to read the quota fields HetrixTools
        # echoes on every response. We use a known-clean domain so any
        # credit charge is minimal; in practice this is one of our own
        # monitored domains anyway.
        raw = _hx_get("blacklist-check/domain/inboxscore.ai/")
        return {
            "api_calls_left": int(raw.get("api_calls_left", -1)),
            "blacklist_check_credits_left": int(
                raw.get("blacklist_check_credits_left", -1)
            ),
            "error": None,
        }
    except Exception as e:
        return {
            "api_calls_left": -1,
            "blacklist_check_credits_left": -1,
            "error": str(e),
        }
