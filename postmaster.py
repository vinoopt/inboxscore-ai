"""
InboxScore - Google Postmaster Tools Integration
OAuth 2.0 flow and API client for fetching domain reputation data.
"""

import os
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
POSTMASTER_API_BASE = "https://gmailpostmastertools.googleapis.com/v1"

SCOPES = "https://www.googleapis.com/auth/postmaster.readonly openid email"


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


# ─── POSTMASTER API CLIENT ──────────────────────────────────

async def get_postmaster_domains(access_token: str) -> list:
    """
    List all domains verified in Google Postmaster Tools.
    Returns list of domain resource names, e.g. ['domains/example.com']
    """
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{POSTMASTER_API_BASE}/domains",
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0,
        )

        if response.status_code == 200:
            data = response.json()
            domains = data.get("domains", [])
            return [d.get("name", "") for d in domains]
        elif response.status_code == 401:
            raise Exception("TOKEN_EXPIRED")
        else:
            print(f"[Postmaster] List domains error {response.status_code}: {response.text}")
            return []


async def get_domain_traffic_stats(access_token: str, domain_resource: str, date_str: str) -> dict:
    """
    Fetch traffic stats for a domain on a specific date.
    domain_resource: 'domains/example.com'
    date_str: 'YYYY-MM-DD' format

    Returns parsed metrics dict or None if no data.
    """
    # Google Postmaster API uses trafficStats/YYYYMMDD format
    formatted_date = date_str.replace("-", "")
    url = f"{POSTMASTER_API_BASE}/{domain_resource}/trafficStats/{formatted_date}"

    async with httpx.AsyncClient() as client:
        response = await client.get(
            url,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=30.0,
        )

        if response.status_code == 200:
            data = response.json()
            return parse_traffic_stats(data)
        elif response.status_code == 404:
            # No data for this date — normal for low-volume domains
            return None
        elif response.status_code == 401:
            raise Exception("TOKEN_EXPIRED")
        else:
            print(f"[Postmaster] Traffic stats error {response.status_code} for {domain_resource} on {date_str}")
            return None


def parse_traffic_stats(data: dict) -> dict:
    """Parse Google Postmaster traffic stats response into our metric format"""

    # Domain reputation: REPUTATION_UNSPECIFIED, HIGH, MEDIUM, LOW, BAD
    reputation = data.get("domainReputation", "UNKNOWN")
    if reputation == "REPUTATION_UNSPECIFIED":
        reputation = "UNKNOWN"

    # Spam rate
    spam_rate = None
    user_reported_spam = data.get("userReportedSpamRatio")
    if user_reported_spam is not None:
        spam_rate = float(user_reported_spam)

    # IP reputations
    ip_reputations = []
    for ip_rep in data.get("ipReputations", []):
        ip_reputations.append({
            "reputation": ip_rep.get("reputation", "UNKNOWN"),
            "ip_count": ip_rep.get("ipCount", 0),
            "sample_ips": ip_rep.get("sampleIps", []),
        })

    # Authentication rates
    auth_spf = None
    auth_dkim = None
    auth_dmarc = None
    for auth in data.get("spfSuccessRatio", [None]):
        auth_spf = float(auth) if auth is not None else None
        break
    # SPF, DKIM, DMARC success ratios are direct float fields
    if "spfSuccessRatio" in data and data["spfSuccessRatio"] is not None:
        auth_spf = float(data["spfSuccessRatio"])
    if "dkimSuccessRatio" in data and data["dkimSuccessRatio"] is not None:
        auth_dkim = float(data["dkimSuccessRatio"])
    if "dmarcSuccessRatio" in data and data["dmarcSuccessRatio"] is not None:
        auth_dmarc = float(data["dmarcSuccessRatio"])

    # Delivery errors
    delivery_errors = {}
    for err in data.get("deliveryErrors", []):
        err_type = err.get("errorType", "UNKNOWN")
        err_ratio = err.get("errorRatio", 0)
        delivery_errors[err_type] = float(err_ratio)

    # Encrypted traffic (TLS)
    tls_rate = None
    if "encryptedPercentage" in data and data["encryptedPercentage"] is not None:
        tls_rate = float(data["encryptedPercentage"])
    # Also check inboundEncryptionRatio
    if tls_rate is None and "inboundEncryptionRatio" in data:
        tls_rate = float(data["inboundEncryptionRatio"])

    return {
        "domain_reputation": reputation,
        "spam_rate": spam_rate,
        "ip_reputation": ip_reputations,
        "auth_success_spf": auth_spf,
        "auth_success_dkim": auth_dkim,
        "auth_success_dmarc": auth_dmarc,
        "delivery_errors": delivery_errors,
        "encrypted_traffic_tls": tls_rate,
        "raw_data": data,
    }


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


async def fetch_metrics_for_user(user_id: str, connection: dict, days: int = 7) -> dict:
    """
    Fetch Postmaster metrics for all domains of a user for the last N days.
    Returns { "domains_synced": int, "metrics_saved": int, "errors": list }
    """
    from db import upsert_postmaster_metrics

    result = {"domains_synced": 0, "metrics_saved": 0, "errors": []}

    try:
        access_token = await ensure_valid_token(user_id, connection)
    except Exception as e:
        result["errors"].append(f"Token error: {e}")
        return result

    try:
        domain_resources = await get_postmaster_domains(access_token)
    except Exception as e:
        if "TOKEN_EXPIRED" in str(e):
            result["errors"].append("Token expired and could not be refreshed")
        else:
            result["errors"].append(f"Failed to list domains: {e}")
        return result

    if not domain_resources:
        return result

    # Fetch metrics for each domain for the last N days
    for domain_resource in domain_resources:
        domain_name = domain_resource.replace("domains/", "")
        has_data = False

        for day_offset in range(days):
            target_date = (datetime.utcnow() - timedelta(days=day_offset + 1)).strftime("%Y-%m-%d")

            try:
                metrics = await get_domain_traffic_stats(access_token, domain_resource, target_date)
                if metrics:
                    upsert_postmaster_metrics(user_id, domain_name, target_date, metrics)
                    result["metrics_saved"] += 1
                    has_data = True
            except Exception as e:
                if "TOKEN_EXPIRED" in str(e):
                    # Try refreshing once more
                    try:
                        access_token = await ensure_valid_token(user_id, connection)
                        metrics = await get_domain_traffic_stats(access_token, domain_resource, target_date)
                        if metrics:
                            upsert_postmaster_metrics(user_id, domain_name, target_date, metrics)
                            result["metrics_saved"] += 1
                            has_data = True
                    except Exception:
                        result["errors"].append(f"Token expired for {domain_name}")
                        break
                else:
                    result["errors"].append(f"Error fetching {domain_name}/{target_date}: {e}")

        if has_data:
            result["domains_synced"] += 1

    return result
