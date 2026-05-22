"""
InboxScore - Supabase Database Helper
Handles all database operations via Supabase
"""

import os
import json
import logging
from datetime import datetime, date, timezone, timedelta
from supabase import create_client, Client

# Webhook-helper logger. Used by mark_webhook_received,
# mark_webhook_completed, was_webhook_processed_ok,
# upsert_subscription_from_stripe so their failures surface in
# structured logs alongside the matching events from app.py
# (logger inboxscore.webhook).
_webhook_log = logging.getLogger("inboxscore.webhook.db")
_billing_log = logging.getLogger("inboxscore.billing.db")

# INBOX-269 (2026-05-20): structured logger for the alerts table operations.
# Previously each function caught Exception with `print(f"Error ...: {e}")`
# which writes to stdout — invisible to Sentry's LoggingIntegration. The
# entire alerts feature was silently broken in prod for months because
# create_alert() raised on missing `title` + `domain` columns and the
# print() handler swallowed it. Migration 019 adds the columns;
# logger.exception() here ensures the next schema/code drift surfaces
# in Sentry instead of dying in stdout.
_alerts_log = logging.getLogger("inboxscore.alerts.db")

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


def get_user_scans(user_id: str, limit: int = 20,
                   since_days: int = None) -> list:
    """Get recent scans for a user.

    INBOX-160 (2026-04-30): added optional ``since_days`` param.

    - Default behaviour (``since_days=None``): top-``limit`` scans across
      ALL the user's domains, newest first. Backward-compatible.
    - With ``since_days``: ALL scans with ``created_at >= now - N days``,
      newest first, for ALL domains. The Dashboard uses this so the
      7-day Score Trend chart never misses days for active multi-domain
      users — the previous global LIMIT=20 only covered ~2 days for users
      with 5+ daily-scanned domains (today's INBOX-160 symptom).

    Both paths are still bounded — ``since_days`` queries cap at 5,000
    rows defensively to protect the API from runaway responses if a user
    has thousands of monitored domains and someone calls with
    ``since_days=365``.
    """
    sb = get_supabase()
    if not sb:
        return []

    try:
        query = sb.table("scans").select("*").eq("user_id", user_id)

        if since_days is not None and since_days > 0:
            # Time-window query — ALL scans in the window, no count limit
            # except the 5,000-row safety cap.
            cutoff = (datetime.now(timezone.utc) - timedelta(days=since_days)).isoformat()
            query = query.gte("created_at", cutoff).order(
                "created_at", desc=True
            ).limit(5000)
        else:
            # Legacy: top-N across all domains.
            query = query.order("created_at", desc=True).limit(limit)

        result = query.execute()
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
    """Add a domain to user's monitored list.

    INBOX-169 (F10, 2026-04-30): enforces ``PLAN_DOMAIN_LIMITS``. Adding
    a domain that would push the user past their plan cap raises
    ``PlanDomainLimitExceeded`` so the API layer can return 403 with a
    friendly upgrade message. Existing domains are NOT removed when the
    limit is lowered — only new additions are blocked.
    """
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

        # INBOX-169: gate by plan-domain limit BEFORE inserting.
        # Pulled here (not in the API layer) so every code path that
        # adds a domain — current API + any future bulk import — is
        # bounded equally.
        plan = get_user_plan(user_id) or "free"
        allowed = PLAN_DOMAIN_LIMITS.get(plan, PLAN_DOMAIN_LIMITS["free"])
        if allowed != -1:
            # Count existing monitored + unmonitored — both consume a slot.
            current_count = get_user_domains_count(user_id)
            if current_count >= allowed:
                raise PlanDomainLimitExceeded(
                    plan=plan, current=current_count, allowed=allowed,
                )

        # Get latest scan score for this domain (if any)
        latest_scan = sb.table("scans").select("id, score").eq(
            "domain", domain
        ).order("created_at", desc=True).limit(1).execute()

        # INBOX-126: Auto-monitoring is on by default. Users add domains
        # because they want to monitor them — there's no realistic story
        # for "track this domain but don't scan it." The plan-based
        # domain-count cap (INBOX-169 / PLAN_DOMAIN_LIMITS, enforced
        # above) naturally bounds load.
        data = {
            "user_id": user_id,
            "domain": domain,
            "is_monitored": True,
            "alert_threshold": 70,
        }

        if latest_scan.data:
            data["latest_score"] = latest_scan.data[0]["score"]
            data["latest_scan_id"] = latest_scan.data[0]["id"]

        result = sb.table("domains").insert(data).execute()
        return result.data[0] if result.data else None
    except PlanDomainLimitExceeded:
        # Re-raise so the API layer can return a 403 with the right
        # message. Don't swallow this in the broad except below.
        raise
    except Exception as e:
        print(f"Error adding domain: {e}")
        return None


def get_user_domains(user_id: str,
                     page: int = None, page_size: int = None) -> list:
    """Get domains for a user, ordered by created_at DESC.

    INBOX-163 (F4, 2026-04-30): added optional ``page`` + ``page_size``
    for pagination. When BOTH are set, returns
    ``[(page-1)*size : page*size]``. When neither is set, returns ALL
    domains — preserves the legacy "give me everything" behaviour every
    existing caller (dashboard, domains page, sending-ips, email-health)
    relies on. Backward-compatible.

    At enterprise scale (~1000+ domains) the un-paginated path becomes
    costly. Frontend can opt into pagination by passing ``?page=`` once
    we add a "Load more" UI on the domains page (separate ticket).
    """
    sb = get_supabase()
    if not sb:
        return []

    try:
        query = sb.table("domains").select("*").eq(
            "user_id", user_id
        ).order("created_at", desc=True)

        if page is not None and page_size is not None and page >= 1 and page_size > 0:
            start = (page - 1) * page_size
            end = start + page_size - 1
            query = query.range(start, end)
        # else: no LIMIT — legacy behaviour.

        result = query.execute()
        return result.data if result.data else []
    except Exception as e:
        print(f"Error fetching domains: {e}")
        return []


def get_user_domains_count(user_id: str) -> int:
    """INBOX-163: total domain count for a user. Used by paginated
    callers to render "Showing N of M" + know when to stop pagination."""
    sb = get_supabase()
    if not sb:
        return 0
    try:
        result = sb.table("domains").select(
            "id", count="exact"
        ).eq("user_id", user_id).execute()
        return result.count if result.count is not None else 0
    except Exception as e:
        print(f"Error counting domains: {e}")
        return 0


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
#
# Plan strings + limits straddle two eras after INBOX-208 (2026-05-13):
#
#   New (post-Stripe billing): trial | pro | stub
#     - Source of truth: subscriptions table (INBOX-203)
#     - trial = 14-day Pro trial, full features, no card collected
#     - pro   = active paid subscription (or past_due during retries)
#     - stub  = expired trial / cancelled / unpaid — lights-on,
#               severely limited (1 scan/week, dashboard read-only)
#
#   Legacy (pre-Stripe): free | pro | growth | enterprise
#     - Source of truth: profiles.plan column
#     - Kept for backward-compat until grandfather migration runs
#       (separate ticket, see PAYMENT-PLAN.md §4 migration note)
#     - get_user_plan returns legacy values for users without a
#       subscriptions row
#
# Once INBOX-209 (auto-trial on signup) + grandfather migration ship,
# every account will have a subscriptions row and the legacy keys can
# be retired. Until then both keysets coexist.

# Plan limits: scans per day (-1 = unlimited). Note: stub is NOT in
# this dict — it uses a weekly limit, not a daily one. See
# STUB_WEEKLY_SCAN_LIMIT below and the special-case in check_rate_limit.
# Putting stub here with value 1 was misleading (audit H3 2026-05-15):
# the value was never consulted because check_rate_limit branches on
# `plan == "stub"` before doing the dict lookup.
PLAN_LIMITS = {
    # New model (Stripe billing)
    "trial": -1,       # full Pro access during trial
    "pro":   -1,
    # Legacy (pre-Stripe, grandfathered)
    "free":      5,
    "growth":   -1,
    "enterprise": -1,
}

# Stub Free: 1 scan per 7 days. Implemented via direct scans-table
# lookup (not the rate_limits day-keyed table) in check_rate_limit.
# Bumping this is a product decision — see PAYMENT-PLAN.md §5.
STUB_WEEKLY_SCAN_LIMIT = 1
STUB_WEEKLY_WINDOW_DAYS = 7

# Max number of MONITORED domains per plan. Distinct from PLAN_LIMITS
# (which gates scans/day). Without this, a free user could add thousands
# of domains and exhaust scheduler throughput + GSB API quota.
PLAN_DOMAIN_LIMITS = {
    # New model (matches PAYMENT-PLAN.md §4)
    "trial": 10,
    "pro":   10,
    "stub":   0,       # cannot ADD new domains; existing rows visible/frozen
    # Legacy (pre-Stripe)
    "free":      10,
    "growth":    500,
    "enterprise": -1,  # unlimited
}

# INBOX-201: bumped 3→10. The marketing scan-flow is the single biggest
# top-of-funnel asset; capping anonymous prospects at 3 scans/day was
# brutal — even a curious buyer who tested 2 domains then refreshed the
# page hit the wall. Each scan is ~10–25s of server CPU only (no money
# cost), so we can be generous. Logged-in users still tracked by
# user_id with their plan's limit (5 free / unlimited Pro).
ANONYMOUS_LIMIT = 10


class PlanDomainLimitExceeded(Exception):
    """Raised by add_user_domain when adding would exceed the plan cap."""

    def __init__(self, plan: str, current: int, allowed: int):
        self.plan = plan
        self.current = current
        self.allowed = allowed
        super().__init__(
            f"Plan '{plan}' allows {allowed} monitored domains; you have {current}."
        )


# ─── SUBSCRIPTIONS (Stripe billing, INBOX-205/206/207) ────────────
#
# Single source of truth for plan + Stripe IDs per user. Mirrors what
# Stripe knows about the customer's subscription state. The legacy
# profiles.plan column becomes a denormalised cache (kept in sync by
# the webhook handler). Security-relevant gating decisions resolve
# through this table — see effective_plan() rule in PAYMENT-PLAN.md §4.
#
# Table created by migration 015_subscriptions.sql. If migration not
# applied yet, these helpers return None and callers handle gracefully.

def get_user_subscription(user_id: str) -> dict:
    """
    Fetch the user's subscription row from the subscriptions table.

    Returns None if:
      - User has no subscription row yet (pre-INBOX-209 signup, or
        Stripe customer never created)
      - Migration 015 hasn't been applied (table doesn't exist)
      - DB error

    The caller should treat None as "user is in implicit stub state
    with no Stripe relationship yet" and gracefully handle.
    """
    sb = get_supabase()
    if not sb:
        return None
    try:
        result = sb.table("subscriptions").select(
            "id,user_id,stripe_customer_id,stripe_subscription_id,"
            "stripe_price_id,plan,status,current_period_start,"
            "current_period_end,trial_end,cancel_at_period_end,"
            "canceled_at,created_at,updated_at"
        ).eq("user_id", user_id).limit(1).execute()
        if result.data:
            return result.data[0]
        return None
    except Exception as e:
        # Migration not yet applied OR transient DB error — both
        # result in None. Log but don't crash.
        _billing_log.exception(
            "get_user_subscription error",
            extra={"user_id": user_id, "error_type": type(e).__name__},
        )
        return None


def set_user_stripe_customer(user_id: str, stripe_customer_id: str) -> bool:
    """
    Persist the user's stripe_customer_id to the subscriptions table.

    Called the FIRST time a user touches a billing flow (checkout or
    portal) before INBOX-209 has run on their signup. Idempotent —
    re-running with the same customer ID is a no-op.

    Creates a row in 'stub' state if none exists (so the user has a
    valid subscription record even before they convert to paid).
    The webhook handler will upgrade the row to 'trialing' or
    'active' once Stripe events arrive.

    Returns True on success, False if migration not applied or DB error.
    """
    sb = get_supabase()
    if not sb:
        return False
    try:
        # Try update first (most common: row exists from signup trial)
        result = sb.table("subscriptions").update({
            "stripe_customer_id": stripe_customer_id,
        }).eq("user_id", user_id).execute()
        if result.data:
            return True
        # No row to update — insert a stub row with just the customer
        # ID populated. plan='stub' and status='stub' are the safe
        # defaults; the webhook handler will refine when Stripe fires
        # subscription events.
        sb.table("subscriptions").insert({
            "user_id": user_id,
            "stripe_customer_id": stripe_customer_id,
            "plan": "stub",
            "status": "stub",
        }).execute()
        return True
    except Exception as e:
        _billing_log.exception(
            "set_user_stripe_customer error",
            extra={
                "user_id": user_id,
                "stripe_customer_id": stripe_customer_id,
                "error_type": type(e).__name__,
            },
        )
        return False


def get_user_id_by_stripe_customer(stripe_customer_id: str) -> str:
    """
    Resolve stripe_customer_id → user_id via the subscriptions table.

    Used by the webhook handler (INBOX-207) to map a Stripe event
    (which only knows stripe_customer_id) back to our internal user.

    Returns None if no subscription row matches OR migration 015 not
    applied. Webhook handler interprets None as "event for a customer
    we don't know about" and silently ignores — safer than 500-ing
    and letting Stripe retry forever.
    """
    sb = get_supabase()
    if not sb:
        return None
    try:
        result = sb.table("subscriptions").select("user_id").eq(
            "stripe_customer_id", stripe_customer_id
        ).limit(1).execute()
        if result.data:
            return result.data[0]["user_id"]
        return None
    except Exception as e:
        _billing_log.exception(
            "get_user_id_by_stripe_customer error",
            extra={
                "stripe_customer_id": stripe_customer_id,
                "error_type": type(e).__name__,
            },
        )
        return None


# ─── STRIPE WEBHOOK IDEMPOTENCY (INBOX-207) ───────────────────────
#
# Table created by migration 016_stripe_webhook_events.sql. Pattern:
#   1. INSERT into stripe_webhook_events ON CONFLICT DO NOTHING
#   2. If insert succeeded → process event
#   3. If conflict → already processed, return 200 immediately
#
# Stripe replays events on failure for up to 3 days. Without
# idempotency, every retry re-processes the event and double-fires
# side effects (welcome emails, Mixpanel events, etc.).

def was_webhook_processed(stripe_event_id: str) -> bool:
    """
    Has this Stripe event ID already been processed?

    True iff a row with that event_id exists in stripe_webhook_events.
    Returns False on DB unavailability — better to risk a duplicate
    process than to drop the event entirely.
    """
    sb = get_supabase()
    if not sb:
        return False
    try:
        result = sb.table("stripe_webhook_events").select(
            "stripe_event_id"
        ).eq("stripe_event_id", stripe_event_id).limit(1).execute()
        return bool(result.data)
    except Exception as e:
        _webhook_log.exception(
            "was_webhook_processed error",
            extra={"stripe_event_id": stripe_event_id, "error_type": type(e).__name__},
        )
        return False


def mark_webhook_received(
    stripe_event_id: str, event_type: str, payload: dict
) -> bool:
    """
    Record a webhook event as RECEIVED but not yet successfully processed.

    Two-phase idempotency pattern (fixed 2026-05-15, audit C2):
      Phase 1 — mark_webhook_received: insert with processed_at=NULL.
                If PK conflict, caller checks was_webhook_processed_ok
                to decide whether to retry the handler.
      Phase 2 — mark_webhook_completed: stamp processed_at=NOW() once
                the handler returns successfully.

    The previous single-phase design recorded the event before the
    handler ran. If the handler then threw, Stripe would retry → we'd
    short-circuit at "already processed" → state never repaired. With
    two-phase, a row with processed_at=NULL signals "we saw this event
    but never finished it" — retries are allowed to re-run the handler.

    Inserts a row into stripe_webhook_events with processed_at=NULL.
    The PK on stripe_event_id enforces idempotency at the DB layer.

    Returns True on successful insert (this is the first time we've
    seen this event ID). Returns False on duplicate or any other
    failure — caller MUST then call was_webhook_processed_ok to
    distinguish "already-done, skip" from "stuck-pending, allow retry".
    """
    sb = get_supabase()
    if not sb:
        return False
    try:
        sb.table("stripe_webhook_events").insert({
            "stripe_event_id": stripe_event_id,
            "event_type": event_type,
            "payload": payload,
            "processed_at": None,  # set by mark_webhook_completed
        }).execute()
        return True
    except Exception as e:
        # Most likely: duplicate (PK violation). Could also be a
        # transient DB issue. Caller distinguishes via was_webhook_processed_ok.
        # Logged at debug because the PK-violation path is the EXPECTED
        # idempotent case and would otherwise spam logs on every retry.
        _webhook_log.debug(
            "mark_webhook_received insert failed (duplicate or transient)",
            extra={
                "stripe_event_id": stripe_event_id,
                "event_type": event_type,
                "error_type": type(e).__name__,
                "error": str(e)[:200],
            },
        )
        return False


# Backwards-compat alias. New code should call mark_webhook_received +
# mark_webhook_completed explicitly.
mark_webhook_processed = mark_webhook_received


def was_webhook_processed_ok(stripe_event_id: str) -> bool:
    """
    Has this Stripe event been processed to *completion* (processed_at IS NOT NULL)?

    Used after a duplicate-insert on mark_webhook_received to decide:
      - True  → handler ran successfully before → safe idempotent skip
      - False → row exists but processed_at is NULL → previous handler
                threw or crashed → safe to retry the handler

    Returns False on DB unavailability (fail-open = let the handler run).
    """
    sb = get_supabase()
    if not sb:
        return False
    try:
        result = sb.table("stripe_webhook_events").select(
            "processed_at"
        ).eq("stripe_event_id", stripe_event_id).limit(1).execute()
        if not result.data:
            return False
        return result.data[0].get("processed_at") is not None
    except Exception as e:
        _webhook_log.exception(
            "was_webhook_processed_ok error",
            extra={"stripe_event_id": stripe_event_id, "error_type": type(e).__name__},
        )
        return False


def mark_webhook_completed(stripe_event_id: str) -> bool:
    """
    Stamp processed_at=NOW() to signal the handler finished successfully.

    Called by /api/webhooks/stripe AFTER the handler returns without
    raising. If the handler raises, this is NOT called — the row stays
    in processed_at=NULL state and Stripe's retry can re-attempt.
    """
    sb = get_supabase()
    if not sb:
        return False
    try:
        from datetime import datetime, timezone
        sb.table("stripe_webhook_events").update({
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }).eq("stripe_event_id", stripe_event_id).execute()
        return True
    except Exception as e:
        _webhook_log.exception(
            "mark_webhook_completed error",
            extra={
                "stripe_event_id": stripe_event_id,
                "error_type": type(e).__name__,
            },
        )
        return False


# ─── SUBSCRIPTION UPSERT FROM STRIPE EVENT (INBOX-207) ───────────

# Stripe subscription.status → our plan strings. Trial keeps plan='trial'
# even though feature-gating treats trial like pro — that distinction
# lets us run "did this user ever pay?" analytics. past_due users keep
# 'pro' access during Stripe's Smart Retries window; only after the
# subscription transitions out of past_due do they drop to stub.
_STRIPE_STATUS_TO_PLAN = {
    "trialing": "trial",
    "active": "pro",
    "past_due": "pro",
    "canceled": "stub",
    "unpaid": "stub",
    "incomplete": "stub",
    "incomplete_expired": "stub",
    "paused": "stub",  # we don't support pause in product, but map for safety
}


def _stripe_ts_to_iso(ts):
    """Convert a Unix timestamp from Stripe → ISO 8601 UTC string."""
    if not ts:
        return None
    from datetime import datetime, timezone
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()


def upsert_subscription_from_stripe(
    user_id: str,
    stripe_sub: dict,
    force_stub: bool = False,
    stripe_event_id: str = None,
) -> bool:
    """
    Write a Stripe subscription object into the local subscriptions
    table. Used by the webhook handler on subscription.created/.updated
    /.deleted events and on checkout.session.completed.

    Idempotent — calling with the same payload twice produces the
    same row state. Safe under Stripe webhook replays.

    force_stub=True is used for the deleted event specifically: even
    though Stripe might still report status='canceled' (which maps to
    plan='stub' anyway), this is the explicit cleanup signal that the
    subscription is fully gone.

    stripe_event_id (optional, audit fix M1 2026-05-15): the Stripe
    event ID that triggered this upsert. Recorded in
    subscriptions.last_webhook_event_id so ops can answer
    "which webhook last touched this row?". Was a dead column before.

    Side effect: also updates profiles.plan as a cache (read by the
    fast-path /api/user/plan endpoint).

    Returns True on success, False on DB error or missing migration.
    """
    sb = get_supabase()
    if not sb:
        return False

    stripe_status = stripe_sub.get("status", "incomplete")
    plan = "stub" if force_stub else _STRIPE_STATUS_TO_PLAN.get(stripe_status, "stub")
    local_status = "stub" if force_stub else stripe_status

    # Extract price_id from the first item (we sell single-item subs
    # — InboxScore Pro at $49/mo or $470/yr, never multi-item).
    price_id = None
    items = stripe_sub.get("items", {}).get("data", [])
    if items:
        price_id = items[0].get("price", {}).get("id")

    row = {
        "user_id": user_id,
        "stripe_customer_id": stripe_sub.get("customer"),
        "stripe_subscription_id": stripe_sub.get("id"),
        "stripe_price_id": price_id,
        "plan": plan,
        "status": local_status,
        "current_period_start": _stripe_ts_to_iso(stripe_sub.get("current_period_start")),
        "current_period_end":   _stripe_ts_to_iso(stripe_sub.get("current_period_end")),
        "trial_end":            _stripe_ts_to_iso(stripe_sub.get("trial_end")),
        "cancel_at_period_end": stripe_sub.get("cancel_at_period_end", False),
        "canceled_at":          _stripe_ts_to_iso(stripe_sub.get("canceled_at")),
        "last_webhook_event_id": stripe_event_id,
    }
    # Strip Nones — Supabase upsert preserves existing values when a
    # column is missing from the payload, which is what we want.
    row = {k: v for k, v in row.items() if v is not None}

    try:
        sb.table("subscriptions").upsert(
            row, on_conflict="user_id"
        ).execute()
        # Keep profiles.plan in sync as a denormalised cache. The
        # /api/user/plan endpoint reads this for speed; security
        # gating still resolves through subscriptions.plan.
        sb.table("profiles").update({"plan": plan}).eq("id", user_id).execute()
        return True
    except Exception as e:
        _billing_log.exception(
            "upsert_subscription_from_stripe error",
            extra={
                "user_id": user_id,
                "stripe_event_id": stripe_event_id,
                "stripe_status": stripe_status,
                "error_type": type(e).__name__,
            },
        )
        return False


def log_orphaned_subscription(
    orphaned_sub_id: str,
    stripe_customer_id: str,
    keeper_sub_id: str = None,
    user_id: str = None,
    reason: str = "reconciler_duplicate",
    triggered_by_event_id: str = None,
) -> bool:
    """
    INBOX-267 Layer 5: record a Stripe subscription that got orphaned.

    Called by the webhook reconciler whenever it cancels a duplicate
    live subscription on Stripe. Lets ops verify the cancellation
    actually took effect on the Stripe side and provides an audit
    trail.

    Safe to call even if migration 018 hasn't been applied — failures
    are logged but don't break the reconciler. Stripe-side cleanup
    has already happened by the time we get here; this is just
    bookkeeping.

    Returns True on success, False on DB error or missing migration.
    """
    sb = get_supabase()
    if not sb:
        return False
    try:
        sb.table("subscriptions_orphan_audit").insert({
            "orphaned_sub_id": orphaned_sub_id,
            "stripe_customer_id": stripe_customer_id,
            "keeper_sub_id": keeper_sub_id,
            "user_id": user_id,
            "reason": reason,
            "triggered_by_event_id": triggered_by_event_id,
        }).execute()
        return True
    except Exception as e:
        _billing_log.warning(
            "log_orphaned_subscription error (migration 018 applied?)",
            extra={
                "orphaned_sub_id": orphaned_sub_id,
                "error_type": type(e).__name__,
            },
        )
        return False


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
    """
    Get user's current plan. INBOX-208 (2026-05-13): subscriptions
    table is the source of truth; falls back to legacy profiles.plan
    for grandfathered users without a subscriptions row.

    Resolution order:
      1. Subscriptions row exists AND status in (active, trialing,
         past_due) AND plan in (trial, pro) → return that plan
         (the active billing state)
      2. Subscriptions row exists but in any other state → 'stub'
         (canceled / expired / incomplete / paused etc.)
      3. No subscriptions row → fall back to legacy profiles.plan
         (returns 'free' / 'pro' / 'growth' / 'enterprise' for
         pre-Stripe users; defaults to 'free' if profile missing)

    Returns one of: trial, pro, stub, free, growth, enterprise.

    Callers gating on plan should accept both legacy and new keys.
    PLAN_LIMITS + PLAN_DOMAIN_LIMITS define rates for both keysets.
    """
    # New model: subscriptions table = source of truth
    sub = get_user_subscription(user_id)
    if sub:
        status = sub.get("status")
        plan = sub.get("plan")
        if status in ("active", "trialing", "past_due") and plan in ("trial", "pro"):
            return plan
        # Subscription exists but is in stub state (canceled, expired, etc.)
        return "stub"

    # Legacy path: no subscriptions row yet → use profiles.plan
    # (this is the path pre-INBOX-209 signups follow; goes away once
    # grandfather migration completes)
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


# INBOX-143 (v1.16.2): added GET helper so /alerts → Rules + Channels
# tabs can hydrate their toggles from saved values. Was previously
# write-only; the old Settings → Notifications panel rendered toggles
# from defaults only and re-saved everything every time.
def get_user_preferences(user_id: str) -> dict:
    """Read the user's stored alert preferences. Returns {} if unset."""
    sb = get_supabase()
    if not sb:
        return {}
    try:
        result = sb.table("profiles").select("preferences").eq(
            "id", user_id
        ).execute()
        if result.data and isinstance(result.data[0].get("preferences"), dict):
            return result.data[0]["preferences"]
        return {}
    except Exception as e:
        print(f"Error reading preferences: {e}")
        return {}


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

def get_recent_scan_scores(domain_id: str, days: int = 7) -> list:
    """INBOX-270 (2026-05-20): return list of recent score ints for a domain.

    Used by monitor.compare_scan_results() trend guard to catch
    cumulative score declines that don't cross a band threshold.
    For example, score walking 89 → 84 → 80 → 76 stays in the "Good"
    band (75-89) the whole way down — no band crossing fires — but
    that's a 13-point decline customers want to know about.

    Returns scores ordered newest-first. May be empty if domain has
    no scan history within the window, or if Supabase is unavailable.
    """
    sb = get_supabase()
    if not sb:
        return []
    if not domain_id:
        return []
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        result = sb.table("scans").select("score, created_at").eq(
            "domain_id", domain_id
        ).gte("created_at", cutoff).order("created_at", desc=True).limit(200).execute()
        return [
            r["score"]
            for r in (result.data or [])
            if r.get("score") is not None
        ]
    except Exception:
        _alerts_log.exception("alerts.recent_scores_failed", extra={
            "domain_id": domain_id,
            "days": days,
        })
        return []


def create_alert(user_id: str, alert_type: str, severity: str, title: str,
                 message: str = None, domain_id: str = None, domain: str = None,
                 raw_data: dict = None) -> dict:
    """Create a new alert for a user.

    INBOX-144 (2026-05-21): added `raw_data` JSONB payload. Carries
    structured event data (blacklists_listed, score_delta, etc.) that
    notifier.py uses to render dynamic email content per alert type.
    Backward-compatible — callers that don't pass raw_data skip the
    field; the column has a '{}' default in migration 020.
    """
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
        if raw_data:
            data["raw_data"] = raw_data

        result = sb.table("alerts").insert(data).execute()
        return result.data[0] if result.data else None
    except Exception:
        # INBOX-269: replaced `print(f"Error creating alert: {e}")` which
        # masked the title/domain column-missing bug for months.
        _alerts_log.exception("alerts.create_failed", extra={
            "user_id_prefix": user_id[:8] if user_id else None,
            "domain": domain,
            "alert_type": alert_type,
            "severity": severity,
        })
        return None


def get_user_alerts(user_id: str, limit: int = 50, severity: str = None,
                    unread_only: bool = False,
                    page: int = None, page_size: int = None) -> list:
    """Get alerts for a user with optional filters.

    INBOX-162 (F3, 2026-04-30): added optional ``page`` + ``page_size``
    for pagination. When BOTH are set, returns the slice
    ``[(page-1)*size : page*size]`` of the user's alerts ordered newest-
    first. When neither is set, falls back to the legacy ``limit=N``
    behaviour (top-N global) — fully backward-compatible.

    Callers that want the full count alongside the page should call
    ``get_user_alerts_count`` separately. We do NOT bake count into
    every list call (Supabase's ``count='exact'`` is a separate query
    server-side).
    """
    sb = get_supabase()
    if not sb:
        return []
    try:
        query = sb.table("alerts").select("*").eq("user_id", user_id)

        if severity:
            query = query.eq("severity", severity)
        if unread_only:
            query = query.eq("is_read", False)

        query = query.order("created_at", desc=True)

        if page is not None and page_size is not None and page >= 1 and page_size > 0:
            # Paginated mode: zero-indexed inclusive Supabase ranges.
            start = (page - 1) * page_size
            end = start + page_size - 1
            query = query.range(start, end)
        else:
            # Legacy mode — preserve original behaviour exactly.
            query = query.limit(limit)

        result = query.execute()
        return result.data if result.data else []
    except Exception:
        # INBOX-269: structured logging so silent failures surface in Sentry.
        _alerts_log.exception("alerts.fetch_failed", extra={
            "user_id_prefix": user_id[:8] if user_id else None,
            "severity_filter": severity,
            "unread_only": unread_only,
            "page": page,
        })
        return []


def get_user_alerts_count(user_id: str, severity: str = None,
                          unread_only: bool = False) -> int:
    """INBOX-162: total alert count matching the same filters as
    ``get_user_alerts``. Used to populate the ``pagination.total``
    field so the UI can render "Showing N of M" without fetching
    everything client-side."""
    sb = get_supabase()
    if not sb:
        return 0
    try:
        query = sb.table("alerts").select("id", count="exact").eq("user_id", user_id)
        if severity:
            query = query.eq("severity", severity)
        if unread_only:
            query = query.eq("is_read", False)
        result = query.execute()
        return result.count if result.count is not None else 0
    except Exception:
        # INBOX-269: structured logging so silent failures surface in Sentry.
        _alerts_log.exception("alerts.count_failed", extra={
            "user_id_prefix": user_id[:8] if user_id else None,
            "severity_filter": severity,
            "unread_only": unread_only,
        })
        return 0


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
    except Exception:
        # INBOX-269: structured logging so silent failures surface in Sentry.
        _alerts_log.exception("alerts.unread_count_failed", extra={
            "user_id_prefix": user_id[:8] if user_id else None,
        })
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
    except Exception:
        # INBOX-269: structured logging so silent failures surface in Sentry.
        _alerts_log.exception("alerts.mark_read_failed", extra={
            "user_id_prefix": user_id[:8] if user_id else None,
            "alert_id": alert_id,
        })
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
    except Exception:
        # INBOX-269: structured logging so silent failures surface in Sentry.
        _alerts_log.exception("alerts.mark_all_read_failed", extra={
            "user_id_prefix": user_id[:8] if user_id else None,
        })
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
    except Exception:
        # INBOX-269: structured logging so silent failures surface in Sentry.
        _alerts_log.exception("alerts.delete_failed", extra={
            "user_id_prefix": user_id[:8] if user_id else None,
            "alert_id": alert_id,
        })
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


# INBOX-113: scheduled scans run at fixed UTC slots so every timezone gets
# fresh data before business hours. Previously each domain scanned on a
# rolling 24h cadence anchored to its first scan, which meant the chart
# bar for "today" was empty until the rolling-anchor time passed. With
# fixed slots, the trend chart fills predictably no matter when the user
# created the domain or signed up.
#
#   03:00 UTC  →  08:30 IST  /  04:00 BST  /  20:00 PT (prior day)
#   09:00 UTC  →  14:30 IST  /  10:00 BST  /  02:00 PT
#   15:00 UTC  →  20:30 IST  /  16:00 BST  /  08:00 PT
#   21:00 UTC  →  02:30 IST  /  22:00 BST  /  14:00 PT
#
# Every TZ gets a fresh scan within ~6h of any business hour anywhere.
# Future Pro feature: per-user TZ + custom preferred scan time (INBOX-135).
SCHEDULED_SCAN_SLOTS_UTC = (3, 9, 15, 21)


def _most_recent_open_slot(now_utc: datetime) -> datetime:
    """Return the most recent fixed UTC slot that has 'opened' relative to
    `now_utc`. If we're before the first slot today, fall back to the
    last slot of the previous UTC day. The returned value is tz-AWARE
    (UTC) so callers can compare directly against last_monitored_at.
    """
    today_midnight = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    # Walk slots from latest to earliest — the first one that's already
    # passed today is "the most recent open slot".
    for hour in reversed(SCHEDULED_SCAN_SLOTS_UTC):
        slot_time = today_midnight.replace(hour=hour)
        if now_utc >= slot_time:
            return slot_time
    # Before today's first slot — fall back to yesterday's last slot.
    yesterday_midnight = today_midnight - timedelta(days=1)
    return yesterday_midnight.replace(hour=SCHEDULED_SCAN_SLOTS_UTC[-1])


def get_domains_due_for_scan() -> list:
    """Get monitored domains that are due for their next scheduled scan.

    INBOX-113: A domain is "due" when the most recent fixed UTC scan slot
    has opened AND the domain hasn't been scanned since that slot opened.
    This replaces the old rolling-24h logic which let scan times drift
    based on when the user first added the domain.
    """
    sb = get_supabase()
    if not sb:
        return []
    try:
        domains = get_monitored_domains()
        if not domains:
            return []

        now = datetime.now(timezone.utc)
        last_open_slot = _most_recent_open_slot(now)

        due = []
        for d in domains:
            last_monitored = d.get("last_monitored_at")

            # Never scanned by the monitor — due immediately.
            if not last_monitored:
                due.append(d)
                continue

            # INBOX-29: compare tz-AWARE values end-to-end. Supabase returns
            # last_monitored_at as an ISO string with "+00:00" or "Z";
            # Python datetime with tzinfo=UTC subtracts cleanly.
            if isinstance(last_monitored, str):
                iso = last_monitored.replace("Z", "+00:00")
                last_dt = datetime.fromisoformat(iso)
            else:
                last_dt = last_monitored
            # Defensive: legacy or test rows may be naive — assume UTC.
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)

            # Due if we haven't scanned since the most recent slot opened.
            if last_dt < last_open_slot:
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

        # Stub plan uses a WEEKLY window (1 scan per 7 days), not the
        # day-keyed rate_limits table. Branch BEFORE the dict lookup —
        # plan='stub' is intentionally absent from PLAN_LIMITS (audit
        # H3, 2026-05-15). See STUB_WEEKLY_SCAN_LIMIT for the cap.
        if plan == "stub":
            try:
                from datetime import datetime, timedelta, timezone
                window_start = (
                    datetime.now(timezone.utc)
                    - timedelta(days=STUB_WEEKLY_WINDOW_DAYS)
                ).isoformat()
                last_scan = sb.table("scans").select("created_at").eq(
                    "user_id", user_id
                ).gte("created_at", window_start).order(
                    "created_at", desc=True
                ).limit(1).execute()
                if last_scan.data:
                    # Found a scan in the last 7 days → block
                    return {
                        "allowed": False,
                        "scans_used": STUB_WEEKLY_SCAN_LIMIT,
                        "max_scans": STUB_WEEKLY_SCAN_LIMIT,
                        "plan": "stub",
                    }
                # No scan in last 7 days → allow this one (counted by
                # the scans-table insert downstream, not rate_limits)
                return {
                    "allowed": True,
                    "scans_used": 0,
                    "max_scans": STUB_WEEKLY_SCAN_LIMIT,
                    "plan": "stub",
                }
            except Exception as e:
                # On error, fail open to avoid blocking legitimate users
                # because of a transient DB issue. Logged so we notice.
                print(f"[rate_limit] stub 7-day check failed for {user_id}: {e}")
                return {
                    "allowed": True,
                    "scans_used": 0,
                    "max_scans": STUB_WEEKLY_SCAN_LIMIT,
                    "plan": "stub",
                }

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


def _is_zero_traffic_postmaster_day(metrics: dict) -> bool:
    """INBOX-211: detect zero-traffic days from a parsed Postmaster v2 row.

    Google's v2 API returns ``floatValue: 0`` for auth/TLS/spam rates on
    days where the domain had no Gmail traffic — mathematically meaningless
    values that the UI was rendering as red "0.00%" failure pills (see
    redrail.redbus.com Apr 25–26 2026).

    Detection signature: if BOTH the DMARC auth-rate and the inbound TLS
    rate are exactly 0 (or null), there was no measurable traffic. Healthy
    senders never report 0% on both at once on real volume — DMARC and TLS
    are negotiated per-message and run >95% under normal sending. Spam
    rate alone is unreliable (a real 0% spam rate is healthy), so we anchor
    on auth+TLS as the load-bearing signal.

    Google's own Postmaster UI hides these days from charts entirely; we
    store ``null`` instead of ``0`` so charts/tables/aggregations all
    correctly render "No data" rather than a misleading 0%.
    """
    auth_dmarc = metrics.get("auth_success_dmarc")
    tls = metrics.get("encrypted_traffic_tls")
    auth_zero = auth_dmarc in (0, 0.0, None)
    tls_zero = tls in (0, 0.0, None)
    return auth_zero and tls_zero


def upsert_postmaster_metrics(user_id: str, domain: str, metric_date: str, metrics: dict) -> dict:
    """Insert or update daily Postmaster metrics for a domain"""
    sb = get_supabase()
    if not sb:
        return None
    try:
        # INBOX-211: zero-traffic-day handling. On days where Gmail received
        # no mail from the domain, Google's v2 API returns 0 for every rate
        # field — meaningless values that the UI rendered as red "0.00%"
        # failure pills. We null them all out at ingest so the UI's
        # ``!= null`` guards correctly route to "No data" everywhere
        # (charts skip the point, tables show "No data" muted, averages
        # exclude the day from the denominator).
        zero_traffic = _is_zero_traffic_postmaster_day(metrics)
        if zero_traffic:
            spam_rate = None
            auth_spf = None
            auth_dkim = None
            auth_dmarc = None
            tls_inbound = None
            tls_outbound = None
            delivery_error_rate = None
            delivery_error_count = None
            delivery_errors_categories = {}
        else:
            spam_rate = metrics.get("spam_rate")
            auth_spf = metrics.get("auth_success_spf")
            auth_dkim = metrics.get("auth_success_dkim")
            auth_dmarc = metrics.get("auth_success_dmarc")
            tls_inbound = metrics.get("encrypted_traffic_tls")
            tls_outbound = metrics.get("encrypted_traffic_tls_outbound")
            delivery_error_rate = metrics.get("delivery_error_rate")
            delivery_error_count = metrics.get("delivery_error_count")
            delivery_errors_categories = dict(metrics.get("delivery_errors", {}))

        # Build delivery_errors JSON — include v2 rate/count alongside categories
        delivery_err = dict(delivery_errors_categories)
        if delivery_error_rate is not None:
            delivery_err["_rate"] = delivery_error_rate
        if delivery_error_count is not None:
            delivery_err["_count"] = delivery_error_count
        if zero_traffic:
            # Tag the JSON so downstream queries / debugging can identify
            # backfilled zero-traffic rows even after the rate fields are
            # null (we lose the signature once we null auth+tls).
            delivery_err["_zero_traffic"] = True

        # INBOX-112: stash outbound TLS into raw_data JSON since the
        # postmaster_metrics table doesn't have a dedicated column for it
        # (and adding one needs migration 010, separate ticket). The UI
        # reads it from raw_data._tls_outbound.
        raw = dict(metrics.get("raw_data", {}))
        if tls_outbound is not None:
            raw["_tls_outbound"] = tls_outbound

        data = {
            "user_id": user_id,
            "domain": domain,
            "date": metric_date,
            "domain_reputation": metrics.get("domain_reputation"),
            "spam_rate": spam_rate,
            "ip_reputation": json.dumps(metrics.get("ip_reputation", [])),
            "auth_success_spf": auth_spf,
            "auth_success_dkim": auth_dkim,
            "auth_success_dmarc": auth_dmarc,
            "delivery_errors": json.dumps(delivery_err),
            "encrypted_traffic_tls": tls_inbound,
            "raw_data": json.dumps(raw),
        }
        result = sb.table("postmaster_metrics").upsert(
            data, on_conflict="user_id,domain,date"
        ).execute()
        return result.data[0] if result.data else None
    except Exception as e:
        print(f"Error upserting postmaster metrics: {e}")
        return None


def _normalize_postmaster_row(row: dict) -> dict:
    """INBOX-211 (read-path defense): null out rate fields on zero-traffic
    rows that pre-date the ingest fix.

    The ingest fix in upsert_postmaster_metrics catches new rows, but the
    DB still has weeks of older rows stored with 0s on quiet days. Rather
    than make the backfill SQL a hard dependency for the UI fix, we
    normalize at read-time: any row matching the zero-traffic signature
    (auth_dmarc==0 AND tls==0 — impossible on real traffic) gets its rate
    fields blanked to null on the way out.

    INBOX-211 followup-2: also clean raw_data._tls_outbound on zero-
    traffic days — that field lives in a JSON blob (no dedicated column)
    so the frontend's getOutbound() reads it directly. Without this,
    outbound TLS averages drag down because 0-value rows count toward
    the denominator (Vinoop caught this on redrail.redbus.com — outbound
    avg showed 40.9% when most days had no Gmail-to-domain traffic).

    Behavioural notes:
      • Idempotent — already-null rows pass through unchanged.
      • Mutates a copy (not the supabase response object).
      • delivery_errors JSON is untouched — readers already skip
        underscore-prefixed metadata keys.
    """
    if not row:
        return row
    auth_dmarc = row.get("auth_success_dmarc")
    tls = row.get("encrypted_traffic_tls")
    if not (auth_dmarc in (0, 0.0) and tls in (0, 0.0)):
        return row

    out = dict(row)
    out["spam_rate"] = None
    out["auth_success_spf"] = None
    out["auth_success_dkim"] = None
    out["auth_success_dmarc"] = None
    out["encrypted_traffic_tls"] = None

    # raw_data is stored as a JSON string in Supabase. Parse, null the
    # _tls_outbound key (without dropping unrelated keys), re-serialize.
    raw_val = row.get("raw_data")
    if raw_val:
        try:
            raw = json.loads(raw_val) if isinstance(raw_val, str) else dict(raw_val)
            if "_tls_outbound" in raw:
                raw["_tls_outbound"] = None
            out["raw_data"] = json.dumps(raw)
        except (json.JSONDecodeError, TypeError):
            # Malformed raw_data — leave it alone rather than corrupt it.
            pass
    return out


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
        rows = result.data if result.data else []
        # INBOX-211: read-path normalize so the UI never sees pre-fix
        # zero-traffic rows that still carry 0s in the DB.
        return [_normalize_postmaster_row(r) for r in rows]
    except Exception as e:
        print(f"Error getting postmaster metrics: {e}")
        return []


def get_postmaster_metrics_all_domains(user_id: str, days: int = 7) -> dict:
    """INBOX-161 (F2): one-shot fetch of postmaster metrics across ALL the
    user's domains. Returns a ``{ "<domain>": <latest_metric_row> }`` map.

    The Dashboard previously fan-out one ``/api/postmaster/metrics/<domain>``
    request per domain on every page load (40+ parallel requests at 20
    domains). This helper does it in a single SQL query and groups in
    Python — independent of domain count.

    Caller is expected to use this for the per-domain "latest snapshot"
    view (Dashboard cards). For the long-history Email Health chart
    keep using ``get_postmaster_metrics`` per domain — it serves a
    different access pattern (~30 days × 1 domain per page view).

    Date order: returns the latest row per domain (highest ``date``).
    """
    sb = get_supabase()
    if not sb:
        return {}
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
        result = sb.table("postmaster_metrics").select("*").eq(
            "user_id", user_id
        ).gte("date", cutoff).order("date", desc=True).execute()

        rows = result.data or []
        # Group by domain, keep first row per domain (already sorted desc).
        # INBOX-211: read-path normalize each row so dashboard cards never
        # see a pre-fix zero-traffic row with 0s.
        latest_by_domain: dict[str, dict] = {}
        for r in rows:
            d = r.get("domain")
            if not d:
                continue
            if d not in latest_by_domain:
                latest_by_domain[d] = _normalize_postmaster_row(r)
        return latest_by_domain
    except Exception as e:
        print(f"Error getting postmaster metrics bulk: {e}")
        return {}


# ─── INBOX-226: Postmaster compliance cache ─────────────────────────
#
# The Dashboard's /api/postmaster/compliance-bulk used to fan-out to
# Google's compliance API in real time, once per domain. Per the audit
# Vinoop requested in INBOX-225, we moved compliance verdicts into the
# daily scheduler so the dashboard reads from DB instead. These helpers
# back the new flow.

def upsert_postmaster_compliance(
    user_id: str, domain: str,
    auth_verdict: str | None,
    spam_verdict: str | None,
    encryption_verdict: str | None,
    raw_data: dict | None,
) -> bool:
    """Write the latest compliance verdicts for one (user, domain).

    Called by postmaster_scheduler.py after fetch_compliance_for_user
    pulls verdicts from Google. Idempotent — upsert on (user_id, domain).
    """
    sb = get_supabase()
    if not sb:
        return False
    has_any = any(v in ("COMPLIANT", "NEEDS_WORK")
                  for v in (auth_verdict, spam_verdict, encryption_verdict))
    try:
        sb.table("postmaster_compliance").upsert({
            "user_id": user_id,
            "domain": domain,
            "auth_verdict": auth_verdict,
            "spam_verdict": spam_verdict,
            "encryption_verdict": encryption_verdict,
            "has_any_verdict": has_any,
            "raw_data": json.dumps(raw_data) if raw_data else None,
            "synced_at": datetime.now(timezone.utc).isoformat(),
        }, on_conflict="user_id,domain").execute()
        return True
    except Exception as e:
        print(f"Error upserting postmaster compliance for {domain}: {e}")
        return False


def get_postmaster_compliance_bulk(user_id: str) -> dict:
    """Return all cached compliance verdicts for a user.

    Returns ``{ "<domain>": {auth, spam, encryption, has_any_verdict, synced_at} }``.
    Empty dict if no rows. Powers /api/postmaster/compliance-bulk's
    fast path (replaces the live Google fan-out).
    """
    sb = get_supabase()
    if not sb:
        return {}
    try:
        result = sb.table("postmaster_compliance").select(
            "domain,auth_verdict,spam_verdict,encryption_verdict,has_any_verdict,synced_at"
        ).eq("user_id", user_id).execute()
        rows = result.data or []
        out: dict[str, dict] = {}
        for r in rows:
            d = r.get("domain")
            if not d:
                continue
            out[d] = {
                "auth": r.get("auth_verdict"),
                "spam": r.get("spam_verdict"),
                "encryption": r.get("encryption_verdict"),
                "has_any_verdict": bool(r.get("has_any_verdict")),
                "synced_at": r.get("synced_at"),
            }
        return out
    except Exception as e:
        print(f"Error getting postmaster compliance bulk: {e}")
        return {}


def get_postmaster_compliance_single(user_id: str, domain: str) -> dict | None:
    """Return cached compliance for one domain — full raw_data payload.

    Used by /api/postmaster/compliance/<domain> on the Postmaster details
    page so the 8-row Compliance Status table renders from cache. Returns
    None if no row exists (caller can decide to fall back to live Google
    fetch on a miss).
    """
    sb = get_supabase()
    if not sb:
        return None
    try:
        result = sb.table("postmaster_compliance").select("raw_data,synced_at").eq(
            "user_id", user_id
        ).eq("domain", domain).limit(1).execute()
        rows = result.data or []
        if not rows:
            return None
        row = rows[0]
        raw = row.get("raw_data")
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                raw = None
        return {"compliance": raw, "synced_at": row.get("synced_at")}
    except Exception as e:
        print(f"Error getting postmaster compliance for {domain}: {e}")
        return None


def get_user_ip_domain_mappings(user_id: str) -> dict:
    """INBOX-161 (F2): fetch ALL (ip, domain) mappings for the user.

    Returns ``{ "<domain>": ["1.2.3.4", "5.6.7.8", ...] }``. Used by the
    SNDS bulk dashboard endpoint to pre-compute per-domain IP lists in
    one query instead of N. Empty dict if no mappings exist.
    """
    sb = get_supabase()
    if not sb:
        return {}
    try:
        result = sb.table("user_ip_domains").select("ip_address, domain").eq(
            "user_id", user_id
        ).execute()
        out: dict[str, list] = {}
        for row in (result.data or []):
            d = row.get("domain")
            ip = row.get("ip_address")
            if not d or not ip:
                continue
            out.setdefault(d, []).append(ip)
        return out
    except Exception as e:
        print(f"Error getting user_ip_domain mappings: {e}")
        return {}


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
        # INBOX-128: pass dicts directly to supabase-py — it serializes
        # them once on the wire. Calling json.dumps() here causes a
        # double-encode: Postgres stores the JSON-encoded *string* as a
        # jsonb string value, and the frontend gets a string instead of
        # an object. Bug surfaced when Volume & Delivery's Sent column
        # showed "—" because filter_results.rcpt_commands was unreadable.
        data = {
            "user_id": user_id,
            "ip_address": ip_address,
            "metric_date": metric_date,
            "ip_status": metrics.get("ip_status"),
            "complaint_rate": metrics.get("complaint_rate"),
            "trap_hits": metrics.get("trap_hits", 0),
            "message_count": metrics.get("message_count", 0),
            "filter_results": metrics.get("filter_results", {}),
            "sample_helos": metrics.get("sample_helos", []),
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
    except Exception:
        # .single() throws if no rows — that's normal (no prior check)
        return None


# ─── GSB CACHE (INBOX-171 / F12) ─────────────────────────────────

# How long a GSB lookup is considered fresh. Google updates the GSB
# threat list daily, so a 24h TTL is loss-free in normal operation.
GSB_CACHE_TTL_SECONDS = 24 * 60 * 60


def get_cached_gsb(domain: str) -> dict | None:
    """INBOX-171: return ``{"threats": [...], "checked_at": "..."}`` if
    the cached GSB lookup for ``domain`` is fresh (≤ TTL). Returns None
    on cache miss, expired entry, or DB unavailability — caller should
    fall through to a live GSB API call.

    NB ``threats`` is the raw ``matches`` array from the GSB v4
    response. An empty list = "GSB checked, no threats reported".
    """
    sb = get_supabase()
    if not sb:
        return None
    try:
        result = sb.table("gsb_cache").select("threats, checked_at").eq(
            "domain", domain
        ).single().execute()
        if not result.data:
            return None

        checked_at_raw = result.data.get("checked_at")
        if not checked_at_raw:
            return None

        # Postgres returns ISO8601 with timezone; parse defensively.
        if isinstance(checked_at_raw, str):
            iso = checked_at_raw.replace("Z", "+00:00")
            checked_at = datetime.fromisoformat(iso)
        else:
            checked_at = checked_at_raw
        if checked_at.tzinfo is None:
            checked_at = checked_at.replace(tzinfo=timezone.utc)

        age = (datetime.now(timezone.utc) - checked_at).total_seconds()
        if age > GSB_CACHE_TTL_SECONDS:
            return None  # expired

        threats = result.data.get("threats")
        # JSONB columns may come back as already-parsed Python lists,
        # or as JSON-encoded strings depending on supabase-py version.
        if isinstance(threats, str):
            try:
                threats = json.loads(threats)
            except Exception:
                threats = []
        return {"threats": threats or [], "checked_at": checked_at_raw}
    except Exception:
        # .single() raises when no rows match — normal cold-cache path.
        return None


def set_cached_gsb(domain: str, threats: list) -> bool:
    """INBOX-171: upsert the latest GSB lookup for ``domain``.

    ``threats`` is the GSB v4 ``matches`` array. Empty list = no
    threats. We store both shapes so the cached path can reconstruct
    the same CheckResult the live path would have produced.
    """
    sb = get_supabase()
    if not sb:
        return False
    try:
        sb.table("gsb_cache").upsert({
            "domain": domain,
            "threats": threats or [],
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }, on_conflict="domain").execute()
        return True
    except Exception as e:
        print(f"Error caching GSB result for {domain}: {e}")
        return False
