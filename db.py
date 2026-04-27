"""
InboxScore - Supabase Database Helper
Handles all database operations via Supabase
"""

import os
import json
from datetime import datetime, date, timezone
from supabase import create_client, Client

# ─── SUPABASE CLIENT ──────────────────────────────────────────────

_supabase: Client | None = None
_db_init_failed = False


def get_supabase() -> Client:
    """Get or create Supabase client (singleton)"""
    global _supabase, _db_init_failed

    # If init already failed, don't retry (avoid repeated crashes)
    if _db_init_failed:
        return None

    if _supabase is None:
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_SERVICE_KEY")  # Service role for server-side ops

        if not url or not key:
            print("⚠️  SUPABASE_URL or SUPABASE_SERVICE_KEY not set — database disabled")
            _db_init_failed = True
            return None

        try:
            _supabase = create_client(url, key)
        except Exception as e:
            print(f"⚠️  Supabase connection failed: {e} — database disabled")
            _db_init_failed = True
            return None

    return _supabase


def is_db_available() -> bool:
    """Check if database connection is configured"""
    return get_supabase() is not None


# ─── SCAN OPERATIONS ──────────────────────────────────────────────

def save_scan(domain: str, score: int, results: dict, ip_address: str = None,
              user_id: str = None, domain_id: str = None, scan_type: str = "manual"):
    """Save a scan result to the database"""
    sb = get_supabase()
    if not sb:
        return None

    try:
        data = {
            "domain": domain,
            "score": score,
            "results": results,
            "scan_type": scan_type,
        }

        if user_id:
            data["user_id"] = user_id
        if domain_id:
            data["domain_id"] = domain_id
        if ip_address:
            data["ip_address"] = ip_address

        result = sb.table("scans").insert(data).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error saving scan: {e}")
        return None


def get_user_scans(user_id: str, limit: int = 20) -> list:
    """Get recent scans for a user"""
    sb = get_supabase()
    if not sb:
        return []

    try:
        result = sb.table("scans").select("*").eq(
            "user_id", user_id
        ).order("created_at", desc=True).limit(limit).execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error fetching user scans: {e}")
        return []


def get_user_scan_stats(user_id: str) -> dict:
    """Get scan statistics for a user"""
    sb = get_supabase()
    if not sb:
        return {"total_scans": 0, "unique_domains": 0, "avg_score": 0}

    try:
        result = sb.table("scans").select("domain, score").eq(
            "user_id", user_id
        ).execute()
        scans = result.data if result.data else []

        if not scans:
            return {"total_scans": 0, "unique_domains": 0, "avg_score": 0}

        domains = set(s["domain"] for s in scans)
        avg_score = round(sum(s["score"] for s in scans) / len(scans))

        return {
            "total_scans": len(scans),
            "unique_domains": len(domains),
            "avg_score": avg_score
        }
    except Exception as e:
        print(f"Error fetching scan stats: {e}")
        return {"total_scans": 0, "unique_domains": 0, "avg_score": 0}


# ─── DOMAIN OPERATIONS ───────────────────────────────────────────

def add_user_domain(user_id: str, domain: str) -> dict:
    """Add a domain to user's monitored list"""
    sb = get_supabase()
    if not sb:
        return None

    try:
        # Check if domain already exists for this user
        existing = sb.table("domains").select("*").eq(
            "user_id", user_id
        ).eq("domain", domain).execute()

        if existing.data:
            return existing.data[0]  # Already exists, return it

        # Get latest scan score for this domain (if any)
        latest_scan = sb.table("scans").select("id, score").eq(
            "domain", domain
        ).order("created_at", desc=True).limit(1).execute()

        data = {
            "user_id": user_id,
            "domain": domain,
            "is_monitored": False,
            "alert_threshold": 70,
        }

        if latest_scan.data:
            data["latest_score"] = latest_scan.data[0]["score"]
            data["latest_scan_id"] = latest_scan.data[0]["id"]

        result = sb.table("domains").insert(data).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error adding domain: {e}")
        return None


def get_user_domains(user_id: str) -> list:
    """Get all domains for a user"""
    sb = get_supabase()
    if not sb:
        return []

    try:
        result = sb.table("domains").select("*").eq(
            "user_id", user_id
        ).order("created_at", desc=True).execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error fetching domains: {e}")
        return []


def remove_user_domain(user_id: str, domain_id: str) -> bool:
    """Remove a domain from user's list"""
    sb = get_supabase()
    if not sb:
        return False

    try:
        sb.table("domains").delete().eq(
            "id", domain_id
        ).eq("user_id", user_id).execute()
        return True
    except Exception as e:
        print(f"Error removing domain: {e}")
        return False


def get_domain_scans(user_id: str, domain: str, limit: int = 50) -> list:
    """Get scan history for a specific domain, scoped to the calling user.

    INBOX-27 (2026-04-23): `user_id` is required and enforced via
    `.eq("user_id", user_id)`. Previously the `user_id` kwarg existed but
    was never applied to the query — any authenticated user could read any
    other user's scan history for a shared domain name (IDOR).
    """
    sb = get_supabase()
    if not sb:
        return []

    if not user_id:
        # Defensive: caller must always scope by user. Empty list is
        # preferable to leaking data if a handler ever forgets.
        return []

    try:
        query = sb.table("scans").select("id, domain, score, created_at, scan_type").eq(
            "user_id", user_id
        ).eq(
            "domain", domain
        ).order("created_at", desc=True).limit(limit)

        result = query.execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error fetching domain scans: {e}")
        return []


def get_scan_detail(scan_id: str, user_id: str = None) -> dict:
    """Get full scan details by ID, optionally filtered by user ownership (IDOR protection)."""
    sb = get_supabase()
    if not sb:
        return None

    try:
        query = sb.table("scans").select("*").eq("id", scan_id)
        if user_id:
            query = query.eq("user_id", user_id)
        result = query.execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error fetching scan detail: {e}")
        return None


def update_domain_score(user_id: str, domain: str, score: int, scan_id: str):
    """Update the latest score on a domain record after a new scan.

    INBOX-27 (2026-04-23): `user_id` is now required and enforced via
    `.eq("user_id", user_id)`. Previously the UPDATE filtered only by
    `domain` string, so User A's scan for `example.com` would overwrite
    every other user's `latest_score` row sharing that domain name — a
    cross-tenant write IDOR.
    """
    sb = get_supabase()
    if not sb:
        return

    if not user_id:
        # Defensive: never run an unscoped UPDATE.
        return

    try:
        sb.table("domains").update({
            "latest_score": score,
            "latest_scan_id": scan_id,
        }).eq("user_id", user_id).eq("domain", domain).execute()
    except Exception as e:
        print(f"Error updating domain score: {e}")


# ─── SUBSCRIBER OPERATIONS ────────────────────────────────────────

def save_subscriber(email: str, domain: str = None, score: int = None, source: str = "scan_results"):
    """Save email subscriber to database"""
    sb = get_supabase()
    if not sb:
        return False

    try:
        data = {
            "email": email,
            "source": source,
        }
        if domain:
            data["domain"] = domain
        if score is not None:
            data["score"] = score

        # Upsert — if email already exists, update domain/score
        result = sb.table("email_subscribers").upsert(
            data,
            on_conflict="email"
        ).execute()
        return True
    except Exception as e:
        print(f"Error saving subscriber: {e}")
        return False


# ─── USER PLAN ────────────────────────────────────────────────────

# Plan limits: scans per day
PLAN_LIMITS = {
    "free": 5,
    "pro": -1,        # unlimited
    "growth": -1,      # unlimited
    "enterprise": -1,  # unlimited
}

ANONYMOUS_LIMIT = 3


def get_user_profile(user_id: str) -> dict:
    """Get user profile including plan info"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        result = sb.table("profiles").select("id,name,company,plan").eq(
            "id", user_id
        ).execute()
        if result.data:
            return result.data[0]
        return None
    except Exception as e:
        print(f"Error getting user profile: {e}")
        return None


def get_user_plan(user_id: str) -> str:
    """Get user's current plan. Returns 'free' if not found."""
    profile = get_user_profile(user_id)
    if profile:
        return profile.get("plan", "free")
    return "free"


def get_full_user_profile(user_id: str) -> dict:
    """Get user profile including preferences"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        result = sb.table("profiles").select("id,name,company,plan,preferences").eq(
            "id", user_id
        ).execute()
        if result.data:
            return result.data[0]
        return None
    except Exception as e:
        print(f"Error getting full user profile: {e}")
        return None


def update_user_profile(user_id: str, name: str = None, company: str = None) -> dict:
    """Update user profile fields"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        data = {}
        if name is not None:
            data["name"] = name
        if company is not None:
            data["company"] = company

        if not data:
            return get_user_profile(user_id)

        result = sb.table("profiles").update(data).eq("id", user_id).execute()
        if result.data:
            return result.data[0]
        return None
    except Exception as e:
        print(f"Error updating profile: {e}")
        return None


def update_user_preferences(user_id: str, preferences: dict) -> bool:
    """Update user notification preferences (stored as JSONB)"""
    sb = get_supabase()
    if not sb:
        return False
    try:
        sb.table("profiles").update(
            {"preferences": preferences}
        ).eq("id", user_id).execute()
        return True
    except Exception as e:
        print(f"Error updating preferences: {e}")
        return False


def export_user_data(user_id: str) -> dict:
    """Export all user data for GDPR/data portability"""
    sb = get_supabase()
    if not sb:
        return {"error": "Database unavailable"}
    try:
        profile = sb.table("profiles").select("*").eq("id", user_id).execute()
        scans = sb.table("scans").select("domain,score,created_at,scan_type").eq(
            "user_id", user_id
        ).order("created_at", desc=True).execute()
        domains = sb.table("domains").select("domain,latest_score,created_at,is_monitored").eq(
            "user_id", user_id
        ).execute()

        return {
            "profile": profile.data[0] if profile.data else {},
            "scans": scans.data or [],
            "domains": domains.data or [],
            "exported_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        print(f"Error exporting user data: {e}")
        return {"error": str(e)}


def delete_user_data(user_id: str) -> bool:
    """Delete all user data (scans, domains, rate limits, profile).

    INBOX-30: the rate_limits filter was `WHERE ip_address = <user_id UUID>`,
    which Postgres silently refused (UUID can't be cast to INET), leaving
    the user's rate-limit rows behind forever. Fixed by filtering on the
    new rate_limits.user_id column added in migration 009.
    """
    sb = get_supabase()
    if not sb:
        return False
    try:
        # Delete in order: scans, domains, rate limits, profile
        sb.table("scans").delete().eq("user_id", user_id).execute()
        sb.table("domains").delete().eq("user_id", user_id).execute()
        sb.table("rate_limits").delete().eq("user_id", user_id).execute()
        sb.table("profiles").delete().eq("id", user_id).execute()
        return True
    except Exception as e:
        print(f"Error deleting user data: {e}")
        return False


# ─── ALERT OPERATIONS ────────────────────────────────────────────

def create_alert(user_id: str, alert_type: str, severity: str, title: str,
                 message: str = None, domain_id: str = None, domain: str = None) -> dict:
    """Create a new alert for a user"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        data = {
            "user_id": user_id,
            "type": alert_type,
            "severity": severity,
            "title": title,
        }
        if message:
            data["message"] = message
        if domain_id:
            data["domain_id"] = domain_id
        if domain:
            data["domain"] = domain

        result = sb.table("alerts").insert(data).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error creating alert: {e}")
        return None


def get_user_alerts(user_id: str, limit: int = 50, severity: str = None,
                    unread_only: bool = False) -> list:
    """Get alerts for a user with optional filters"""
    sb = get_supabase()
    if not sb:
        return []
    try:
        query = sb.table("alerts").select("*").eq("user_id", user_id)

        if severity:
            query = query.eq("severity", severity)
        if unread_only:
            query = query.eq("is_read", False)

        query = query.order("created_at", desc=True).limit(limit)
        result = query.execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error fetching alerts: {e}")
        return []


def get_unread_alert_count(user_id: str) -> int:
    """Get count of unread alerts for sidebar badge"""
    sb = get_supabase()
    if not sb:
        return 0
    try:
        result = sb.table("alerts").select("id", count="exact").eq(
            "user_id", user_id
        ).eq("is_read", False).execute()
        return result.count if result.count else 0
    except Exception as e:
        print(f"Error counting unread alerts: {e}")
        return 0


def mark_alert_read(user_id: str, alert_id: str) -> bool:
    """Mark a single alert as read"""
    sb = get_supabase()
    if not sb:
        return False
    try:
        sb.table("alerts").update({"is_read": True}).eq(
            "id", alert_id
        ).eq("user_id", user_id).execute()
        return True
    except Exception as e:
        print(f"Error marking alert read: {e}")
        return False


def mark_all_alerts_read(user_id: str) -> bool:
    """Mark all alerts as read for a user"""
    sb = get_supabase()
    if not sb:
        return False
    try:
        sb.table("alerts").update({"is_read": True}).eq(
            "user_id", user_id
        ).eq("is_read", False).execute()
        return True
    except Exception as e:
        print(f"Error marking all alerts read: {e}")
        return False


def delete_alert(user_id: str, alert_id: str) -> bool:
    """Delete an alert"""
    sb = get_supabase()
    if not sb:
        return False
    try:
        sb.table("alerts").delete().eq(
            "id", alert_id
        ).eq("user_id", user_id).execute()
        return True
    except Exception as e:
        print(f"Error deleting alert: {e}")
        return False


# ─── MONITORING OPERATIONS ────────────────────────────────────────

def get_monitored_domains() -> list:
    """Get all domains with monitoring enabled (for background scheduler)"""
    sb = get_supabase()
    if not sb:
        return []
    try:
        result = sb.table("domains").select(
            "id, user_id, domain, latest_score, monitor_interval, last_monitored_at, previous_score, alert_threshold, is_monitored"
        ).eq("is_monitored", True).execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error fetching monitored domains: {e}")
        return []


def get_domains_due_for_scan() -> list:
    """Get monitored domains that are due for their next scan based on interval"""
    sb = get_supabase()
    if not sb:
        return []
    try:
        # Get all monitored domains
        domains = get_monitored_domains()
        if not domains:
            return []

        # INBOX-29: compare tz-AWARE values end-to-end. Supabase returns
        # last_monitored_at as an ISO string with "+00:00" or "Z"; Python
        # datetime with tzinfo=UTC subtracts cleanly. The old code
        # stripped tz from last_dt and compared it to a naive
        # datetime.now(timezone.utc) — the exact pattern that masked INBOX-1.
        now = datetime.now(timezone.utc)
        due = []
        for d in domains:
            interval_hours = d.get("monitor_interval") or 24
            last_monitored = d.get("last_monitored_at")

            if not last_monitored:
                # Never scanned via monitor — due immediately
                due.append(d)
                continue

            # Parse the timestamp into a tz-AWARE datetime.
            if isinstance(last_monitored, str):
                # Normalise the "Z" suffix that Supabase/Postgres emits.
                iso = last_monitored.replace("Z", "+00:00")
                last_dt = datetime.fromisoformat(iso)
            else:
                last_dt = last_monitored
            # Defensive: if we somehow got a naive datetime (e.g. a test
            # fixture or a legacy row), assume UTC rather than crashing
            # on the subtraction.
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)

            hours_since = (now - last_dt).total_seconds() / 3600
            if hours_since >= interval_hours:
                due.append(d)

        return due
    except Exception as e:
        print(f"Error getting domains due for scan: {e}")
        return []


def update_domain_monitoring(user_id: str, domain_id: str, is_monitored: bool,
                             monitor_interval: int = 24, alert_threshold: int = 70) -> dict:
    """Enable or disable monitoring for a domain"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        data = {
            "is_monitored": is_monitored,
            "monitor_interval": monitor_interval,
            "alert_threshold": alert_threshold,
        }
        result = sb.table("domains").update(data).eq(
            "id", domain_id
        ).eq("user_id", user_id).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error updating domain monitoring: {e}")
        return None


def update_domain_after_monitor_scan(domain_id: str, new_score: int, scan_id: str):
    """Update domain record after a monitoring scan completes"""
    sb = get_supabase()
    if not sb:
        return
    try:
        # First get current score to save as previous
        current = sb.table("domains").select("latest_score").eq("id", domain_id).execute()
        previous_score = current.data[0]["latest_score"] if current.data and current.data[0].get("latest_score") else None

        update_data = {
            "latest_score": new_score,
            "latest_scan_id": scan_id,
            "last_monitored_at": datetime.now(timezone.utc).isoformat(),
            "previous_score": previous_score,
        }
        sb.table("domains").update(update_data).eq("id", domain_id).execute()
    except Exception as e:
        print(f"Error updating domain after monitor scan: {e}")


def save_monitoring_log(domain_id: str, user_id: str, domain: str,
                        old_score: int, new_score: int, scan_id: str,
                        changes_detected: list = None, alerts_created: int = 0) -> dict:
    """Log a monitoring scan run"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        data = {
            "domain_id": domain_id,
            "user_id": user_id,
            "domain": domain,
            "old_score": old_score,
            "new_score": new_score,
            "score_change": (new_score - old_score) if old_score is not None and new_score is not None else 0,
            "changes_detected": json.dumps(changes_detected or []),
            "alerts_created": alerts_created,
            "scan_id": scan_id,
        }
        result = sb.table("monitoring_logs").insert(data).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error saving monitoring log: {e}")
        return None


def get_monitoring_logs(user_id: str, domain_id: str, limit: int = 20) -> list:
    """Get monitoring logs for a domain, scoped to the calling user.

    INBOX-27 (2026-04-23): `user_id` is required and enforced via
    `.eq("user_id", user_id)`. Previously the handler accepted any
    `domain_id` from the URL and returned matching logs with no ownership
    check — a classic IDOR allowing cross-tenant log disclosure.

    The `monitoring_logs` table stores `user_id` on every row, so
    filtering by BOTH columns makes a guessed `domain_id` from another
    tenant return an empty list rather than leaking data.
    """
    sb = get_supabase()
    if not sb:
        return []

    if not user_id:
        # Defensive: never leak logs without an explicit user scope.
        return []

    try:
        result = sb.table("monitoring_logs").select("*").eq(
            "user_id", user_id
        ).eq(
            "domain_id", domain_id
        ).order("created_at", desc=True).limit(limit).execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error fetching monitoring logs: {e}")
        return []


# ─── RATE LIMITING ────────────────────────────────────────────────

def check_rate_limit(ip_address: str, max_scans: int = 3, user_id: str = None) -> dict:
    """
    Check and increment rate limit.
    For logged-in users: tracks by user_id with plan-based limits.
    For anonymous users: tracks by IP address with default limit (3/day).
    Returns: {"allowed": bool, "scans_used": int, "max_scans": int, "plan": str}
    """
    sb = get_supabase()
    if not sb:
        return {"allowed": True, "scans_used": 0, "max_scans": max_scans, "plan": "free"}

    today = date.today().isoformat()

    # Determine plan and limits
    plan = "anonymous"
    if user_id:
        plan = get_user_plan(user_id)
        limit = PLAN_LIMITS.get(plan, 5)
        if limit == -1:
            # Unlimited — no need to check/track
            return {"allowed": True, "scans_used": 0, "max_scans": -1, "plan": plan}
        max_scans = limit

    try:
        # INBOX-30: authenticated users key on the user_id column (added
        # in migration 009); anonymous users key on ip_address. The old
        # code stored the user_id UUID in the ip_address INET column for
        # logged-in users — Postgres rejected the INSERT/UPDATE, the
        # bare except swallowed the error, and rate limiting was
        # silently disabled for every authenticated user.
        if user_id:
            key_column = "user_id"
            key_value = user_id
            insert_row = {"user_id": user_id, "scan_count": 1, "date": today}
        else:
            key_column = "ip_address"
            key_value = ip_address
            insert_row = {"ip_address": ip_address, "scan_count": 1, "date": today}

        result = sb.table("rate_limits").select("*").eq(
            key_column, key_value
        ).eq("date", today).execute()

        if result.data:
            current_count = result.data[0]["scan_count"]
            if current_count >= max_scans:
                return {
                    "allowed": False,
                    "scans_used": current_count,
                    "max_scans": max_scans,
                    "plan": plan
                }

            # Increment count — conditional update to reduce race window
            sb.table("rate_limits").update(
                {"scan_count": current_count + 1}
            ).eq(key_column, key_value).eq("date", today).lt(
                "scan_count", max_scans
            ).execute()

            return {
                "allowed": True,
                "scans_used": current_count + 1,
                "max_scans": max_scans,
                "plan": plan
            }
        else:
            # First scan today — insert new record
            sb.table("rate_limits").insert(insert_row).execute()

            return {
                "allowed": True,
                "scans_used": 1,
                "max_scans": max_scans,
                "plan": plan
            }
    except Exception as e:
        print(f"Rate limit check error: {e}")
        return {"allowed": True, "scans_used": 0, "max_scans": max_scans, "plan": plan}


# ─── POSTMASTER OPERATIONS ───────────────────────────────────

def save_postmaster_connection(user_id: str, access_token: str, refresh_token: str,
                                token_expiry: str, google_email: str) -> dict:
    """Save or update Google Postmaster OAuth connection for a user"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        data = {
            "user_id": user_id,
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_expiry": token_expiry,
            "google_email": google_email,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        result = sb.table("postmaster_connections").upsert(
            data, on_conflict="user_id"
        ).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error saving postmaster connection: {e}")
        return None


def get_postmaster_connection(user_id: str) -> dict:
    """Get Postmaster OAuth connection for a user"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        result = sb.table("postmaster_connections").select("*").eq(
            "user_id", user_id
        ).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error getting postmaster connection: {e}")
        return None


def update_postmaster_tokens(user_id: str, access_token: str, token_expiry: str) -> bool:
    """Update access token after refresh"""
    sb = get_supabase()
    if not sb:
        return False
    try:
        sb.table("postmaster_connections").update({
            "access_token": access_token,
            "token_expiry": token_expiry,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("user_id", user_id).execute()
        return True
    except Exception as e:
        print(f"Error updating postmaster tokens: {e}")
        return False


def delete_postmaster_connection(user_id: str) -> bool:
    """Remove Postmaster OAuth connection (disconnect)"""
    sb = get_supabase()
    if not sb:
        return False
    try:
        sb.table("postmaster_connections").delete().eq(
            "user_id", user_id
        ).execute()
        return True
    except Exception as e:
        print(f"Error deleting postmaster connection: {e}")
        return False


def upsert_postmaster_metrics(user_id: str, domain: str, metric_date: str, metrics: dict) -> dict:
    """Insert or update daily Postmaster metrics for a domain"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        # Build delivery_errors JSON — include v2 rate/count alongside categories
        delivery_err = dict(metrics.get("delivery_errors", {}))
        if metrics.get("delivery_error_rate") is not None:
            delivery_err["_rate"] = metrics["delivery_error_rate"]
        if metrics.get("delivery_error_count") is not None:
            delivery_err["_count"] = metrics["delivery_error_count"]

        data = {
            "user_id": user_id,
            "domain": domain,
            "date": metric_date,
            "domain_reputation": metrics.get("domain_reputation"),
            "spam_rate": metrics.get("spam_rate"),
            "ip_reputation": json.dumps(metrics.get("ip_reputation", [])),
            "auth_success_spf": metrics.get("auth_success_spf"),
            "auth_success_dkim": metrics.get("auth_success_dkim"),
            "auth_success_dmarc": metrics.get("auth_success_dmarc"),
            "delivery_errors": json.dumps(delivery_err),
            "encrypted_traffic_tls": metrics.get("encrypted_traffic_tls"),
            "raw_data": json.dumps(metrics.get("raw_data", {})),
        }
        result = sb.table("postmaster_metrics").upsert(
            data, on_conflict="user_id,domain,date"
        ).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error upserting postmaster metrics: {e}")
        return None


def get_postmaster_metrics(user_id: str, domain: str, days: int = 30) -> list:
    """Get Postmaster metrics for a domain (last N days)"""
    sb = get_supabase()
    if not sb:
        return []
    try:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        result = sb.table("postmaster_metrics").select("*").eq(
            "user_id", user_id
        ).eq("domain", domain).gte("date", cutoff).order("date", desc=False).execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error getting postmaster metrics: {e}")
        return []


def get_postmaster_domains_for_user(user_id: str) -> list:
    """Get distinct domains that have Postmaster metrics for a user"""
    sb = get_supabase()
    if not sb:
        return []
    try:
        result = sb.table("postmaster_metrics").select("domain").eq(
            "user_id", user_id
        ).execute()
        if result.data:
            # INBOX-26: sorted() so callers that slice/index the result get
            # reproducible behaviour between processes.
            return sorted({row["domain"] for row in result.data})
        return []
    except Exception as e:
        print(f"Error getting postmaster domains: {e}")
        return []


def get_last_postmaster_sync_at(user_id: str) -> str | None:
    """INBOX-102: return the ISO timestamp of the user's most recent
    successful Postmaster sync. Used by /api/postmaster/status to render
    "Last synced X ago" on the Email Health page.

    Source of truth is postmaster_sync_log.sync_completed_at where
    status = 'success' (the scheduler writes one row per run via
    log_postmaster_sync). Falls back to MAX(created_at) on
    postmaster_metrics if the log table is empty (older accounts that
    were synced before sync_log existed). Returns None if neither path
    finds a record."""
    sb = get_supabase()
    if not sb:
        return None
    try:
        # Primary: most recent successful sync run.
        result = sb.table("postmaster_sync_log").select(
            "sync_completed_at"
        ).eq("user_id", user_id).eq("status", "success").order(
            "sync_completed_at", desc=True
        ).limit(1).execute()
        if result.data and result.data[0].get("sync_completed_at"):
            return result.data[0]["sync_completed_at"]

        # Fallback: most recent metric row created_at. NB this changes
        # only when a NEW (user, domain, date) tuple is inserted — i.e.
        # roughly once per day, when the scheduler picks up yesterday's
        # data. Same-day re-syncs upsert existing rows and don't bump
        # created_at, but that's an acceptable approximation when the
        # sync_log isn't available.
        result = sb.table("postmaster_metrics").select("created_at").eq(
            "user_id", user_id
        ).order("created_at", desc=True).limit(1).execute()
        if result.data:
            return result.data[0].get("created_at")
        return None
    except Exception as e:
        print(f"Error getting last postmaster sync time: {e}")
        return None


def get_all_postmaster_connections() -> list:
    """Get all active Postmaster connections (for scheduler sync)"""
    sb = get_supabase()
    if not sb:
        return []
    try:
        result = sb.table("postmaster_connections").select("*").execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error getting all postmaster connections: {e}")
        return []


def log_postmaster_sync(user_id: str, status: str, domains_synced: int = 0,
                         error_message: str = None, sync_started_at: str = None) -> dict:
    """Log a Postmaster sync run"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        data = {
            "user_id": user_id,
            "status": status,
            "domains_synced": domains_synced,
            "sync_completed_at": datetime.now(timezone.utc).isoformat(),
        }
        if sync_started_at:
            data["sync_started_at"] = sync_started_at
        if error_message:
            data["error_message"] = error_message

        result = sb.table("postmaster_sync_log").insert(data).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error logging postmaster sync: {e}")
        return None


# ─── MICROSOFT SNDS OPERATIONS ──────────────────────────────────

def save_snds_connection(user_id: str, snds_key: str) -> dict:
    """Save or update Microsoft SNDS connection for a user"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        data = {
            "user_id": user_id,
            "snds_key": snds_key,
            "connected_at": datetime.now(timezone.utc).isoformat(),
        }
        result = sb.table("snds_connections").upsert(
            data, on_conflict="user_id"
        ).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error saving SNDS connection: {e}")
        return None


def get_snds_connection(user_id: str) -> dict:
    """Get SNDS connection for a user"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        result = sb.table("snds_connections").select("*").eq(
            "user_id", user_id
        ).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error getting SNDS connection: {e}")
        return None


def delete_snds_connection(user_id: str) -> bool:
    """Remove SNDS connection and all associated metrics"""
    sb = get_supabase()
    if not sb:
        return False
    try:
        # Delete metrics first, then connection
        sb.table("snds_metrics").delete().eq("user_id", user_id).execute()
        sb.table("snds_connections").delete().eq("user_id", user_id).execute()
        return True
    except Exception as e:
        print(f"Error deleting SNDS connection: {e}")
        return False


def get_all_snds_connections() -> list:
    """Get all active SNDS connections (for scheduler sync)"""
    sb = get_supabase()
    if not sb:
        return []
    try:
        result = sb.table("snds_connections").select("*").execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error getting all SNDS connections: {e}")
        return []


def update_snds_sync_status(user_id: str, ip_count: int) -> bool:
    """Update last_sync_at and ip_count after a successful sync"""
    sb = get_supabase()
    if not sb:
        return False
    try:
        sb.table("snds_connections").update({
            "last_sync_at": datetime.now(timezone.utc).isoformat(),
            "ip_count": ip_count,
        }).eq("user_id", user_id).execute()
        return True
    except Exception as e:
        print(f"Error updating SNDS sync status: {e}")
        return False


def upsert_snds_metrics(user_id: str, ip_address: str, metric_date: str, metrics: dict) -> dict:
    """Insert or update daily SNDS metrics for an IP"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        data = {
            "user_id": user_id,
            "ip_address": ip_address,
            "metric_date": metric_date,
            "ip_status": metrics.get("ip_status"),
            "complaint_rate": metrics.get("complaint_rate"),
            "trap_hits": metrics.get("trap_hits", 0),
            "message_count": metrics.get("message_count", 0),
            "filter_results": json.dumps(metrics.get("filter_results", {})),
            "sample_helos": json.dumps(metrics.get("sample_helos", [])),
            "raw_data": metrics.get("raw_data", ""),
        }
        result = sb.table("snds_metrics").upsert(
            data, on_conflict="user_id,ip_address,metric_date"
        ).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error upserting SNDS metrics: {e}")
        return None


def get_snds_metrics(user_id: str, days: int = 30) -> list:
    """Get all SNDS IP metrics for a user (last N days)"""
    sb = get_supabase()
    if not sb:
        return []
    try:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        result = sb.table("snds_metrics").select("*").eq(
            "user_id", user_id
        ).gte("metric_date", cutoff).order("metric_date", desc=False).execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error getting SNDS metrics: {e}")
        return []


def get_snds_metrics_for_ip(user_id: str, ip_address: str, days: int = 30) -> list:
    """Get SNDS metrics for a specific IP (last N days)"""
    sb = get_supabase()
    if not sb:
        return []
    try:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        result = sb.table("snds_metrics").select("*").eq(
            "user_id", user_id
        ).eq("ip_address", ip_address).gte(
            "metric_date", cutoff
        ).order("metric_date", desc=False).execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error getting SNDS metrics for IP: {e}")
        return []


# ─── SENDING IP OPERATIONS ──────────────────────────────────────

def add_user_ips(user_id: str, ip_addresses: list) -> list:
    """Add one or more IPs to user's sending IP list. Skips duplicates."""
    sb = get_supabase()
    if not sb:
        return []

    added = []
    for ip in ip_addresses:
        ip = ip.strip()
        if not ip:
            continue
        try:
            result = sb.table("user_ips").upsert(
                {"user_id": user_id, "ip_address": ip},
                on_conflict="user_id,ip_address"
            ).execute()
            if result.data:
                added.append(result.data[0])
        except Exception as e:
            print(f"Error adding IP {ip}: {e}")
    return added


def get_user_ips(user_id: str) -> list:
    """Get all IPs for a user with their domain mappings."""
    sb = get_supabase()
    if not sb:
        return []

    try:
        # Get all IPs
        ips_result = sb.table("user_ips").select("*").eq(
            "user_id", user_id
        ).order("added_at", desc=True).execute()

        if not ips_result.data:
            return []

        # Get all domain mappings for this user
        domains_result = sb.table("user_ip_domains").select("*").eq(
            "user_id", user_id
        ).execute()

        # Build domain map: ip_address -> [domain1, domain2, ...]
        domain_map = {}
        if domains_result.data:
            for row in domains_result.data:
                ip = row["ip_address"]
                if ip not in domain_map:
                    domain_map[ip] = []
                domain_map[ip].append(row["domain"])

        # Merge
        for ip_row in ips_result.data:
            ip_row["domains"] = domain_map.get(ip_row["ip_address"], [])

        return ips_result.data
    except Exception as e:
        print(f"Error fetching user IPs: {e}")
        return []


def remove_user_ip(user_id: str, ip_address: str) -> bool:
    """Remove an IP and its domain mappings."""
    sb = get_supabase()
    if not sb:
        return False

    try:
        # Delete domain mappings first
        sb.table("user_ip_domains").delete().eq(
            "user_id", user_id
        ).eq("ip_address", ip_address).execute()

        # Delete the IP
        sb.table("user_ips").delete().eq(
            "user_id", user_id
        ).eq("ip_address", ip_address).execute()
        return True
    except Exception as e:
        print(f"Error removing IP {ip_address}: {e}")
        return False


def set_ip_domains(user_id: str, ip_address: str, domains: list) -> bool:
    """Replace domain mappings for an IP. Pass empty list to clear."""
    sb = get_supabase()
    if not sb:
        return False

    try:
        # Delete existing mappings
        sb.table("user_ip_domains").delete().eq(
            "user_id", user_id
        ).eq("ip_address", ip_address).execute()

        # Insert new mappings
        for domain in domains:
            domain = domain.strip()
            if not domain:
                continue
            sb.table("user_ip_domains").upsert(
                {"user_id": user_id, "ip_address": ip_address, "domain": domain},
                on_conflict="user_id,ip_address,domain"
            ).execute()
        return True
    except Exception as e:
        print(f"Error setting IP domains: {e}")
        return False


def get_ips_for_domain(user_id: str, domain: str) -> list:
    """Get IPs mapped to a specific domain (for email-health dropdown)."""
    sb = get_supabase()
    if not sb:
        return []

    try:
        result = sb.table("user_ip_domains").select("ip_address").eq(
            "user_id", user_id
        ).eq("domain", domain).execute()

        if not result.data:
            return []
        return [row["ip_address"] for row in result.data]
    except Exception as e:
        print(f"Error fetching IPs for domain {domain}: {e}")
        return []


# ─── BLACKLIST RESULTS PERSISTENCE ─────────────────────────────

def save_blacklist_results(user_id: str, domain: str, results: dict) -> bool:
    """Save blacklist check results for a domain (upsert — one row per user+domain)."""
    sb = get_supabase()
    if not sb:
        return False
    try:
        import json
        sb.table("blacklist_results").upsert(
            {
                "user_id": user_id,
                "domain": domain,
                "results": json.dumps(results),
                "checked_at": results.get("checked_at", None) or "now()",
            },
            on_conflict="user_id,domain"
        ).execute()
        return True
    except Exception as e:
        print(f"Error saving blacklist results for {domain}: {e}")
        return False


def get_blacklist_results(user_id: str, domain: str) -> dict | None:
    """Get last saved blacklist check results for a domain. Returns None if no saved results."""
    sb = get_supabase()
    if not sb:
        return None
    try:
        result = sb.table("blacklist_results").select("results, checked_at").eq(
            "user_id", user_id
        ).eq("domain", domain).single().execute()
        if result.data:
            import json
            data = result.data["results"]
            # results is stored as JSONB so it may already be a dict
            if isinstance(data, str):
                data = json.loads(data)
            return data
        return None
    except Exception as e:
        # .single() throws if no rows — that's normal (no prior check)
        return None
