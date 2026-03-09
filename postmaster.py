"""
InboxScore - Google Postmaster Tools Integration (API v2)
OAuth 2.0 flow and API client for fetching domain deliverability data.
Migrated from deprecated v1 to v2 API (September 2025).
"""

import os
import json
import httpx
from datetime import datetime, timedelta
from urllib.parse import urlencode

# ─── GOOGLE OAUTH CONFIG ────────────────────────────────────

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_POSTMASTER_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_POSTMASTER_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.environ.get(
    "GOOGLE_POSTMASTER_REDIRECT_URI",
    "https://inboxscore.ai/api/postmaster/callback"
)

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
POSTMASTER_API_BASE = "https://gmailpostmastertools.googleapis.com/v2"

# v2 scopes: .domain for listing domains, .traffic.readonly for stats
SCOPES = "https://www.googleapis.com/auth/postmaster.domain https://www.googleapis.com/auth/postmaster.traffic.readonly openid email"


# ─── OAUTH HELPERS ───────────────────────────────────────────

def get_authorization_url(state: str) -> str:
    """Generate Google OAuth consent URL"""
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": SCOPES,
        "access_type": "offline",     # get refresh_token
        "prompt": "consent",           # always show consent to get refresh_token
        "state": state,
    }
    return f"{GOOGLE_AUTH_URL}?{urlencode(params)}"


async def exchange_code_for_tokens(code: str) -> dict:
    """Exchange authorization code for access + refresh tokens"""
    async with httpx.AsyncClient() as client:
        response = await client.post(GOOGLE_TOKEN_URL, data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": GOOGLE_REDIRECT_URI,
        })

        if response.status_code != 200:
            error_data = response.json()
            raise Exception(f"Token exchange failed: {error_data.get('error_description', response.text)}")

        data = response.json()
        expires_in = data.get("expires_in", 3600)
        token_expiry = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()

        return {
            "access_token": data["access_token"],
            "refresh_token": data.get("refresh_token", ""),
            "token_expiry": token_expiry,
        }


async def refresh_access_token(refresh_token: str) -> dict:
    """Refresh an expired access token"""
    async with httpx.AsyncClient() as client:
        response = await client.post(GOOGLE_TOKEN_URL, data={
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
        })

        if response.status_code != 200:
            error_data = response.json()
            raise Exception(f"Token refresh failed: {error_data.get('error_description', response.text)}")

        data = response.json()
        expires_in = data.get("expires_in", 3600)
        token_expiry = (datetime.utcnow() + timedelta(seconds=expires_in)).isoformat()

        return {
            "access_token": data["access_token"],
            "token_expiry": token_expiry,
        }


async def get_google_user_email(access_token: str) -> str:
    """Get the Google account email from the access token"""
    async with httpx.AsyncClient() as client:
        response = await client.get(GOOGLE_USERINFO_URL, headers={
            "Authorization": f"Bearer {access_token}"
        })
        if response.status_code == 200:
            return response.json().get("email", "")
        return ""


# ─── POSTMASTER API v2 CLIENT ─────────────────────────────────

async def get_postmaster_domains(access_token: str) -> list:
    """
    List all domains verified in Google Postmaster Tools (v2).
    Returns list of domain resource names, e.g. ['domains/example.com']
    Raises exceptions with details on failure for better error reporting.
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{POSTMASTER_API_BASE}/domains",
            headers={"Authorization": f"Bearer {access_token}"},
            params={"pageSize": 200},
            timeout=30.0,
        )

        print(f"[Postmaster v2] domains.list status={response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"[Postmaster v2] domains.list response keys: {list(data.keys())}")
            domains = data.get("domains", [])
            print(f"[Postmaster v2] Found {len(domains)} domain(s)")
            if domains:
                print(f"[Postmaster v2] First domain: {domains[0]}")
            return [d.get("name", "") for d in domains if d.get("name")]
        elif response.status_code == 401:
            raise Exception("TOKEN_EXPIRED")
        elif response.status_code == 403:
            error_text = response.text[:500]
            print(f"[Postmaster v2] 403 Forbidden listing domains: {error_text}")
            raise Exception(f"SCOPE_MISSING: Permission denied listing domains. "
                            f"Please disconnect and reconnect Google Postmaster to grant domain access. "
                            f"API response: {error_text}")
        else:
            error_text = response.text[:500]
            print(f"[Postmaster v2] List domains error {response.status_code}: {error_text}")
            raise Exception(f"API error {response.status_code}: {error_text}")


def _make_date_obj(date_str: str) -> dict:
    """Convert 'YYYY-MM-DD' string to Google Date object {year, month, day}"""
    parts = date_str.split("-")
    return {"year": int(parts[0]), "month": int(parts[1]), "day": int(parts[2])}


async def query_domain_stats(access_token: str, domain_resource: str,
                              start_date: str, end_date: str) -> list:
    """
    Query domain stats via the v2 API for a date range.
    domain_resource: 'domains/example.com'
    start_date / end_date: 'YYYY-MM-DD' format

    Returns list of daily metric dicts (parsed) or empty list.
    Uses DAILY granularity so we get per-day breakdowns.
    """
    url = f"{POSTMASTER_API_BASE}/{domain_resource}/domainStats:query"

    # Define the metrics we want to fetch
    # NOTE: filter values MUST be lowercase per Google v2 API spec
    metric_definitions = [
        {"name": "spam_rate", "baseMetric": {"standardMetric": "SPAM_RATE"}},
        {"name": "auth_spf", "baseMetric": {"standardMetric": "AUTH_SUCCESS_RATE"},
         "filter": 'auth_type = "spf"'},
        {"name": "auth_dkim", "baseMetric": {"standardMetric": "AUTH_SUCCESS_RATE"},
         "filter": 'auth_type = "dkim"'},
        {"name": "auth_dmarc", "baseMetric": {"standardMetric": "AUTH_SUCCESS_RATE"},
         "filter": 'auth_type = "dmarc"'},
        {"name": "tls_rate", "baseMetric": {"standardMetric": "TLS_ENCRYPTION_RATE"},
         "filter": 'traffic_direction = "outbound"'},
        {"name": "delivery_error_rate", "baseMetric": {"standardMetric": "DELIVERY_ERROR_RATE"}},
        {"name": "delivery_error_count", "baseMetric": {"standardMetric": "DELIVERY_ERROR_COUNT"}},
    ]

    request_body = {
        "metricDefinitions": metric_definitions,
        "timeQuery": {
            "dateRanges": [{
                "start": _make_date_obj(start_date),
                "end": _make_date_obj(end_date),
            }]
        },
        "aggregationGranularity": "DAILY",
        "pageSize": 200,
    }

    all_stats = []
    page_token = None

    async with httpx.AsyncClient() as client:
        while True:
            body = request_body.copy()
            if page_token:
                body["pageToken"] = page_token

            response = await client.post(
                url,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                },
                json=body,
                timeout=30.0,
            )

            print(f"[Postmaster v2] domainStats:query for {domain_resource} status={response.status_code}")
            if response.status_code == 200:
                data = response.json()
                print(f"[Postmaster v2] Response keys: {list(data.keys())}")
                stats = data.get("domainStats", [])
                print(f"[Postmaster v2] Got {len(stats)} stat entries for {domain_resource}")
                if not stats:
                    print(f"[Postmaster v2] Full 200 response (no stats): {json.dumps(data)[:1000]}")
                all_stats.extend(stats)

                page_token = data.get("nextPageToken")
                if not page_token:
                    break
            elif response.status_code == 401:
                raise Exception("TOKEN_EXPIRED")
            elif response.status_code == 404:
                # No data for this domain/range
                print(f"[Postmaster v2] 404 for {domain_resource}: {response.text[:500]}")
                return []
            else:
                print(f"[Postmaster v2] domainStats query error {response.status_code} for {domain_resource}: {response.text[:500]}")
                return []

    return parse_v2_domain_stats(all_stats)


def parse_v2_domain_stats(raw_stats: list) -> list:
    """
    Parse v2 domainStats response into per-day metric dicts.
    Groups the flat metric list by date.

    Returns list of dicts like:
    [
      {
        "date": "2025-03-01",
        "spam_rate": 0.01,
        "auth_success_spf": 0.98,
        "auth_success_dkim": 0.95,
        "auth_success_dmarc": 0.93,
        "encrypted_traffic_tls": 0.99,
        "delivery_error_rate": 0.02,
        "delivery_error_count": 5,
        "domain_reputation": None,   # removed in v2
        "ip_reputation": [],         # removed in v2
        "delivery_errors": {},
        "raw_data": {...}
      }, ...
    ]
    """
    # Group metrics by date
    by_date = {}

    for stat in raw_stats:
        metric_name = stat.get("metric", "")
        date_obj = stat.get("date")
        value_obj = stat.get("value", {})

        # Extract the actual value from the StatisticValue union
        value = _extract_stat_value(value_obj)

        # Build date string
        date_str = None
        if date_obj:
            y = date_obj.get("year", 0)
            m = date_obj.get("month", 0)
            d = date_obj.get("day", 0)
            if y and m and d:
                date_str = f"{y:04d}-{m:02d}-{d:02d}"

        if not date_str:
            continue

        if date_str not in by_date:
            by_date[date_str] = {
                "date": date_str,
                "spam_rate": None,
                "auth_success_spf": None,
                "auth_success_dkim": None,
                "auth_success_dmarc": None,
                "encrypted_traffic_tls": None,
                "delivery_error_rate": None,
                "delivery_error_count": None,
                "domain_reputation": None,    # removed in v2
                "ip_reputation": [],          # removed in v2
                "delivery_errors": {},
                "raw_data": {},
            }

        entry = by_date[date_str]

        if metric_name == "spam_rate" and value is not None:
            entry["spam_rate"] = float(value)
        elif metric_name == "auth_spf" and value is not None:
            entry["auth_success_spf"] = float(value)
        elif metric_name == "auth_dkim" and value is not None:
            entry["auth_success_dkim"] = float(value)
        elif metric_name == "auth_dmarc" and value is not None:
            entry["auth_success_dmarc"] = float(value)
        elif metric_name == "tls_rate" and value is not None:
            entry["encrypted_traffic_tls"] = float(value)
        elif metric_name == "delivery_error_rate" and value is not None:
            entry["delivery_error_rate"] = float(value)
            entry["delivery_errors"]["TOTAL"] = float(value)
        elif metric_name == "delivery_error_count" and value is not None:
            entry["delivery_error_count"] = int(value)

        # Store raw data
        entry["raw_data"][metric_name] = stat

    # Sort by date and return
    return sorted(by_date.values(), key=lambda x: x["date"])


def _extract_stat_value(value_obj: dict):
    """Extract the actual value from a v2 StatisticValue union field"""
    if not value_obj:
        return None
    # Check all possible value types
    for key in ("doubleValue", "floatValue", "intValue", "stringValue"):
        if key in value_obj:
            return value_obj[key]
    return None


async def get_compliance_status(access_token: str, domain: str) -> dict:
    """
    Get SPF/DKIM/DMARC compliance status for a domain (v2 only).
    Returns compliance data dict or None.
    """
    url = f"{POSTMASTER_API_BASE}/domains/{domain}/complianceStatus"

    async with httpx.AsyncClient() as client:
        response = await client.get(
            url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0,
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 401:
            raise Exception("TOKEN_EXPIRED")
        else:
            print(f"[Postmaster v2] Compliance status error {response.status_code}: {response.text}")
            return None


# ─── BACKWARD COMPAT WRAPPER ────────────────────────────────
# These wrappers maintain the same interface used by app.py and
# the scheduler, so we don't need to change those files.

async def get_domain_traffic_stats(access_token: str, domain_resource: str, date_str: str) -> dict:
    """
    Backward-compatible wrapper: fetch metrics for a single day.
    Uses v2 query_domain_stats internally but returns a single-day dict
    matching the old parse_traffic_stats format.
    """
    daily_stats = await query_domain_stats(
        access_token, domain_resource, date_str, date_str
    )

    if daily_stats and len(daily_stats) > 0:
        return daily_stats[0]
    return None


# ─── TOKEN MANAGEMENT ────────────────────────────────────────

async def ensure_valid_token(user_id: str, connection: dict) -> str:
    """
    Check if access token is still valid; refresh if expired.
    Returns a valid access token or raises an exception.
    """
    from db import update_postmaster_tokens

    token_expiry = connection.get("token_expiry", "")
    if token_expiry:
        try:
            expiry_dt = datetime.fromisoformat(token_expiry.replace("Z", "+00:00")).replace(tzinfo=None)
            # Refresh if token expires within 5 minutes
            if datetime.utcnow() >= expiry_dt - timedelta(minutes=5):
                refreshed = await refresh_access_token(connection["refresh_token"])
                update_postmaster_tokens(
                    user_id,
                    refreshed["access_token"],
                    refreshed["token_expiry"]
                )
                return refreshed["access_token"]
        except Exception as e:
            print(f"[Postmaster] Token refresh error for user {user_id}: {e}")
            # Try refreshing anyway
            try:
                refreshed = await refresh_access_token(connection["refresh_token"])
                update_postmaster_tokens(
                    user_id,
                    refreshed["access_token"],
                    refreshed["token_expiry"]
                )
                return refreshed["access_token"]
            except Exception as e2:
                raise Exception(f"Failed to refresh token: {e2}")

    return connection["access_token"]


# ─── BULK FETCH FOR SCHEDULER ───────────────────────────────

async def fetch_metrics_for_user(user_id: str, connection: dict, days: int = 7) -> dict:
    """
    Fetch Postmaster metrics for all domains of a user for the last N days.
    Uses v2 date-range query for efficiency (single call per domain instead
    of one call per day).
    Returns { "domains_synced": int, "metrics_saved": int, "errors": list, "debug": dict }
    """
    from db import upsert_postmaster_metrics

    result = {"domains_synced": 0, "metrics_saved": 0, "errors": [], "debug": {}}

    try:
        access_token = await ensure_valid_token(user_id, connection)
        result["debug"]["token_status"] = "valid"
    except Exception as e:
        result["errors"].append(f"Token error: {e}")
        result["debug"]["token_status"] = f"error: {e}"
        return result

    try:
        domain_resources = await get_postmaster_domains(access_token)
        result["debug"]["domains_found"] = domain_resources
    except Exception as e:
        error_msg = str(e)
        if "TOKEN_EXPIRED" in error_msg:
            result["errors"].append("Token expired and could not be refreshed")
        elif "SCOPE_MISSING" in error_msg:
            result["errors"].append(
                "Permission denied: Please disconnect and reconnect Google Postmaster "
                "in Settings to grant the required domain access scope."
            )
        else:
            result["errors"].append(f"Failed to list domains: {error_msg}")
        return result

    if not domain_resources:
        result["errors"].append(
            "No domains found. Make sure you have domains verified in "
            "Google Postmaster Tools (postmaster.google.com) with the same "
            "Google account you connected."
        )
        return result

    # v2 advantage: fetch entire date range in one API call per domain
    end_date = (datetime.utcnow() - timedelta(days=1)).strftime("%Y-%m-%d")
    start_date = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%d")
    result["debug"]["date_range"] = {"start": start_date, "end": end_date}

    domain_debug = []
    for domain_resource in domain_resources:
        domain_name = domain_resource.replace("domains/", "")
        d_info = {"domain": domain_name, "resource": domain_resource}

        try:
            daily_metrics = await query_domain_stats(
                access_token, domain_resource, start_date, end_date
            )
            d_info["metrics_count"] = len(daily_metrics) if daily_metrics else 0
            d_info["status"] = "ok" if daily_metrics else "no_data"

            if daily_metrics:
                d_info["first_date"] = daily_metrics[0].get("date", "")
                d_info["last_date"] = daily_metrics[-1].get("date", "")
                for day_data in daily_metrics:
                    metric_date = day_data.get("date", "")
                    if metric_date:
                        upsert_postmaster_metrics(user_id, domain_name, metric_date, day_data)
                        result["metrics_saved"] += 1
                result["domains_synced"] += 1

        except Exception as e:
            d_info["status"] = f"error: {e}"
            if "TOKEN_EXPIRED" in str(e):
                # Try refreshing once
                try:
                    access_token = await ensure_valid_token(user_id, connection)
                    daily_metrics = await query_domain_stats(
                        access_token, domain_resource, start_date, end_date
                    )
                    if daily_metrics:
                        for day_data in daily_metrics:
                            metric_date = day_data.get("date", "")
                            if metric_date:
                                upsert_postmaster_metrics(user_id, domain_name, metric_date, day_data)
                                result["metrics_saved"] += 1
                        result["domains_synced"] += 1
                        d_info["status"] = "ok_after_refresh"
                except Exception:
                    result["errors"].append(f"Token expired for {domain_name}")
            else:
                result["errors"].append(f"Error fetching {domain_name}: {e}")

        domain_debug.append(d_info)

    result["debug"]["per_domain"] = domain_debug
    return result
