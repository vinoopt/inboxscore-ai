"""
InboxScore - Supabase Database Helper
Handles all database operations via Supabase
"""

import os
from datetime import datetime, date
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


def get_domain_scans(domain: str, user_id: str = None, limit: int = 50) -> list:
    """Get scan history for a specific domain"""
    sb = get_supabase()
    if not sb:
        return []

    try:
        query = sb.table("scans").select("id, domain, score, created_at, scan_type").eq(
            "domain", domain
        ).order("created_at", desc=True).limit(limit)

        result = query.execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error fetching domain scans: {e}")
        return []


def get_scan_detail(scan_id: str) -> dict:
    """Get full scan details by ID"""
    sb = get_supabase()
    if not sb:
        return None

    try:
        result = sb.table("scans").select("*").eq("id", scan_id).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error fetching scan detail: {e}")
        return None


def update_domain_score(domain: str, score: int, scan_id: str):
    """Update the latest score on a domain record after a new scan"""
    sb = get_supabase()
    if not sb:
        return

    try:
        sb.table("domains").update({
            "latest_score": score,
            "latest_scan_id": scan_id,
        }).eq("domain", domain).execute()
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
            "exported_at": datetime.utcnow().isoformat(),
        }
    except Exception as e:
        print(f"Error exporting user data: {e}")
        return {"error": str(e)}


def delete_user_data(user_id: str) -> bool:
    """Delete all user data (scans, domains, rate limits, profile)"""
    sb = get_supabase()
    if not sb:
        return False
    try:
        # Delete in order: scans, domains, rate limits, profile
        sb.table("scans").delete().eq("user_id", user_id).execute()
        sb.table("domains").delete().eq("user_id", user_id).execute()
        sb.table("rate_limits").delete().eq("ip_address", user_id).execute()
        sb.table("profiles").delete().eq("id", user_id).execute()
        return True
    except Exception as e:
        print(f"Error deleting user data: {e}")
        return False


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
        # Use user_id as key for logged-in users, IP for anonymous
        lookup_key = user_id if user_id else ip_address

        result = sb.table("rate_limits").select("*").eq(
            "ip_address", lookup_key
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

            # Increment count
            sb.table("rate_limits").update(
                {"scan_count": current_count + 1}
            ).eq("ip_address", lookup_key).eq("date", today).execute()

            return {
                "allowed": True,
                "scans_used": current_count + 1,
                "max_scans": max_scans,
                "plan": plan
            }
        else:
            # First scan today — insert new record
            sb.table("rate_limits").insert({
                "ip_address": lookup_key,
                "scan_count": 1,
                "date": today,
            }).execute()

            return {
                "allowed": True,
                "scans_used": 1,
                "max_scans": max_scans,
                "plan": plan
            }
    except Exception as e:
        print(f"Rate limit check error: {e}")
        return {"allowed": True, "scans_used": 0, "max_scans": max_scans, "plan": plan}
