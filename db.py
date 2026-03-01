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


# ─── RATE LIMITING ────────────────────────────────────────────────

def check_rate_limit(ip_address: str, max_scans: int = 3) -> dict:
    """
    Check and increment rate limit for an IP address.
    Returns: {"allowed": bool, "scans_used": int, "max_scans": int}
    """
    sb = get_supabase()
    if not sb:
        # If DB unavailable, allow the scan (graceful degradation)
        return {"allowed": True, "scans_used": 0, "max_scans": max_scans}

    today = date.today().isoformat()

    try:
        # Check current count
        result = sb.table("rate_limits").select("*").eq(
            "ip_address", ip_address
        ).eq("date", today).execute()

        if result.data:
            current_count = result.data[0]["scan_count"]
            if current_count >= max_scans:
                return {
                    "allowed": False,
                    "scans_used": current_count,
                    "max_scans": max_scans
                }

            # Increment count
            sb.table("rate_limits").update(
                {"scan_count": current_count + 1}
            ).eq("ip_address", ip_address).eq("date", today).execute()

            return {
                "allowed": True,
                "scans_used": current_count + 1,
                "max_scans": max_scans
            }
        else:
            # First scan today — insert new record
            sb.table("rate_limits").insert({
                "ip_address": ip_address,
                "scan_count": 1,
                "date": today,
            }).execute()

            return {
                "allowed": True,
                "scans_used": 1,
                "max_scans": max_scans
            }
    except Exception as e:
        print(f"Rate limit check error: {e}")
        # On error, allow the scan (graceful degradation)
        return {"allowed": True, "scans_used": 0, "max_scans": max_scans}
