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
from datetime import datetime, timezone
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
    get_user_preferences,
    export_user_data, delete_user_data,
    get_user_alerts, get_unread_alert_count, mark_alert_read,
    mark_all_alerts_read, delete_alert,
    update_domain_monitoring, get_monitored_domains, get_monitoring_logs,
    save_postmaster_connection, get_postmaster_connection,
    delete_postmaster_connection, get_postmaster_metrics as db_get_postmaster_metrics,
    get_last_postmaster_sync_at,
    save_snds_connection, get_snds_connection, delete_snds_connection,
    get_snds_metrics as db_get_snds_metrics, update_snds_sync_status,
    upsert_snds_metrics,
    add_user_ips, get_user_ips, remove_user_ip, set_ip_domains, get_ips_for_domain,
    save_blacklist_results, get_blacklist_results,
)

# Auth
from auth import (
    is_auth_available, sign_up, sign_in, reset_password,
    get_user_from_token, refresh_session
)

# PDF report generation
from pdf_report import generate_pdf_report

# ─── STRUCTURED LOGGING ──────────────────────────────────────────
# Initialised before Sentry so Sentry's own init log lines come out as JSON too.
# After this call, every logger.info / logger.error is emitted as one-line JSON
# on stdout with ts, level, logger, msg, and the current request_id.
from logging_config import setup_logging
setup_logging(os.environ.get("LOG_LEVEL", "INFO"))

# ─── SENTRY ERROR REPORTING ──────────────────────────────────────
# Initialised before FastAPI() per Sentry FastAPI integration docs.
# If SENTRY_DSN is not set, this is a no-op — app behaviour unchanged.
SENTRY_DSN = os.environ.get("SENTRY_DSN", "").strip()
if SENTRY_DSN:
    import sentry_sdk

    # Release: "inboxscore@1.15.0" or "inboxscore@1.15.0+abc1234" if a git SHA is
    # available. Render auto-injects RENDER_GIT_COMMIT on every deploy; we also
    # honour an explicit APP_GIT_SHA override.
    _version = os.environ.get("APP_VERSION", "1.16.6")
    _git_sha = (os.environ.get("APP_GIT_SHA")
                or os.environ.get("RENDER_GIT_COMMIT", "")
                or "").strip()
    _release = f"inboxscore@{_version}+{_git_sha[:7]}" if _git_sha else f"inboxscore@{_version}"

    def _before_send(event, hint):
        """Drop noise events before they consume Sentry quota."""
        url = (event.get("request") or {}).get("url", "") or ""
        if "/health" in url or "/robots.txt" in url or "/favicon" in url:
            return None
        exc_info = hint.get("exc_info") if hint else None
        if exc_info and exc_info[0] is not None:
            name = exc_info[0].__name__
            # CancelledError / SystemExit fire on normal shutdowns, not real bugs.
            if name in ("CancelledError", "KeyboardInterrupt", "SystemExit"):
                return None
        return event

    def _before_send_transaction(event, hint):
        """Drop noise performance-transactions."""
        tx = event.get("transaction", "") or ""
        if tx in ("/health", "/robots.txt", "/sitemap.xml") or "/favicon" in tx:
            return None
        return event

    sentry_sdk.init(
        dsn=SENTRY_DSN,
        environment=os.environ.get("SENTRY_ENV", "production"),
        release=_release,
        server_name="inboxscore-render",    # friendly name in Sentry UI
        max_breadcrumbs=50,
        traces_sample_rate=0.1,             # 10% of requests sampled for perf tracing
        profiles_sample_rate=0.0,           # profiling disabled to minimise overhead
        send_default_pii=False,             # don't send user IPs, headers, cookies — GDPR hygiene
        ignore_errors=[KeyboardInterrupt],
        before_send=_before_send,
        before_send_transaction=_before_send_transaction,
    )
    # Global tags — applied to every event for filtering in Sentry UI
    sentry_sdk.set_tag("app", "inboxscore")
    sentry_sdk.set_tag("component", "api")
    print(f"[Sentry] Initialised release={_release} environment={os.environ.get('SENTRY_ENV','production')}")
else:
    print("[Sentry] SENTRY_DSN not set — error reporting disabled")

app = FastAPI(title="InboxScore API", version="1.16.6")

# CORS — restrict to known origins (set ALLOWED_ORIGINS env var in production)
ALLOWED_ORIGINS = [o.strip() for o in os.environ.get(
    "ALLOWED_ORIGINS", "https://inboxscore.ai,https://www.inboxscore.ai"
).split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Request-ID middleware. Added AFTER CORS → Starlette puts it OUTER in the
# chain, so every request is tagged with a request_id before CORS runs and
# an access-log line is emitted on the way out (even for 4xx/5xx).
from middleware import RequestContextMiddleware
app.add_middleware(RequestContextMiddleware, sentry_enabled=bool(SENTRY_DSN))

# ─── BACKGROUND MONITORING SCHEDULER ─────────────────────────────
from apscheduler.schedulers.background import BackgroundScheduler
from monitor import run_monitoring_cycle
from postmaster_scheduler import sync_all_postmaster_users
from snds_scheduler import sync_all_snds_users
from heartbeat import watchdog_tick

scheduler = BackgroundScheduler()
# Run monitoring check every 15 minutes to find domains due for their scan
scheduler.add_job(run_monitoring_cycle, 'interval', minutes=15, id='monitoring_cycle',
                  max_instances=1, replace_existing=True)
# Sync Google Postmaster data daily at 15:00 UTC.
# INBOX-133: Google Postmaster reports per UTC day, but the day's data is
# only fully published several hours after midnight UTC. Running at 06:00
# UTC was too early — the most recent day was almost always missing,
# making our "Latest" view show data ~2 days behind Google's UI. 15:00
# UTC gives Google a full half-day to finalise the previous UTC day's
# aggregates (14h after midnight UTC), and is also after their typical
# reprocessing window. Tier-3 evidence: latest day appears in our UI
# within 2 hours of the cron run.
scheduler.add_job(sync_all_postmaster_users, 'cron', hour=15, minute=0,
                  id='postmaster_sync', max_instances=1, replace_existing=True)
# Sync Microsoft SNDS data daily at 11:00 UTC.
# INBOX-133: Microsoft SNDS publishes the previous UTC day's CSV between
# ~03:00–10:00 UTC. 11:00 UTC is conservative enough that the latest day
# is reliably present without being so late that overnight clients miss
# the data on European business hours.
scheduler.add_job(sync_all_snds_users, 'cron', hour=11, minute=0,
                  id='snds_sync', max_instances=1, replace_existing=True)
# INBOX-16: Watchdog checks scheduler heartbeats every 5 min; fires Sentry on stale cycles.
scheduler.add_job(watchdog_tick, 'interval', minutes=5, id='watchdog',
                  max_instances=1, replace_existing=True)


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


# ─── HEALTH CHECK ──────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Health check for Render / load balancers / monitoring.

    INBOX-149 (v1.16.3): version was hard-coded as a string literal,
    so /health kept reporting an old version even after a successful
    deploy. Reading from app.version makes the response track what
    FastAPI actually instantiated with — bumped automatically every
    time we change the version arg above.
    """
    checks = {"status": "ok", "version": app.version, "db": False, "auth": False}

    if is_db_available():
        checks["db"] = True
    if is_auth_available():
        checks["auth"] = True

    status_code = 200 if checks["db"] else 503
    return JSONResponse(content=checks, status_code=status_code)


@app.get("/api/monitoring/heartbeat-status")
async def heartbeat_status_endpoint():
    """
    INBOX-16: Public read of scheduler heartbeats.
    Returns overall status + per-cycle details so external uptime checks
    and the UI can both consume this. Always HTTP 200 — staleness is
    communicated in the payload, not the status code, so this never
    trips an accidental load-balancer page.
    """
    from heartbeat import heartbeat_status
    try:
        return JSONResponse(content=heartbeat_status(), status_code=200)
    except Exception as e:
        return JSONResponse(
            content={"overall_status": "error", "error": str(e)[:200]},
            status_code=500,
        )


# ─── CHECK FUNCTIONS + MODEL (moved to checks.py in INBOX-20) ───
# All domain-health check functions plus their model and helpers live in
# `checks.py` now. `app.py` is the HTTP surface + scan orchestrator; it
# composes these checks but no longer defines them.
from checks import (
    BLACKLISTS,
    DKIM_SELECTORS,
    CheckResult,
    safe_dns_query,
    check_mx_records,
    check_spf,
    check_dkim,
    check_dmarc,
    check_blacklists,
    check_tls,
    check_reverse_dns,
    check_bimi,
    check_mta_sts,
    check_tls_rpt,
    check_sender_detection,
    check_domain_age,
    check_ip_reputation,
)



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







# ─── generate_summary moved to scan_service.py in INBOX-21 ───


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
                'subscribed_at': datetime.now(timezone.utc).isoformat()
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
    # Tag the transaction with scan context so Sentry errors are filterable
    # in the UI ("show me all failures on bankofamerica.com this week").
    if SENTRY_DSN:
        sentry_sdk.set_tag("endpoint", "scan")
        sentry_sdk.set_tag("scan_domain", (request.domain or "").lower()[:120])
    try:
        return await _run_scan(request, req)
    except HTTPException:
        raise
    except Exception as e:
        print(f"[SCAN ERROR] Unhandled exception scanning {request.domain}: {e}")
        import traceback; traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

def _is_safe_domain(domain: str) -> bool:
    """SSRF protection: verify domain resolves to public (non-internal) IPs."""
    import ipaddress as _ipa
    try:
        answers = dns.resolver.resolve(domain, "A")
        for rdata in answers:
            ip = _ipa.ip_address(str(rdata))
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        return True
    except Exception:
        # If DNS fails, let individual checks handle it
        return True


async def _run_scan(request: ScanRequest, req: Request):
    """Internal scan logic — wrapped by scan_domain for error handling"""
    domain = request.domain.strip().lower()

    # Basic domain validation
    domain = domain.replace("http://", "").replace("https://", "").replace("www.", "")
    domain = domain.split("/")[0].strip()

    if not domain or "." not in domain:
        raise HTTPException(status_code=400, detail="Please enter a valid domain name")

    # SSRF protection — block internal/private/reserved domains
    if not _is_safe_domain(domain):
        raise HTTPException(status_code=400, detail="This domain cannot be scanned (resolves to a private/reserved IP)")

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

    # Sentry: attach user identity (Supabase UUID only — no email/IP leak since
    # send_default_pii=False). Enables "users affected" metric + user filters.
    if SENTRY_DSN:
        sentry_sdk.set_user({"id": scan_user_id} if scan_user_id else None)
        sentry_sdk.set_tag("user_authenticated", "true" if scan_user_id else "false")

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

    # Delegate the actual scan composition to scan_service (INBOX-21).
    # app.py owns HTTP concerns (SSRF, auth, rate-limit, Sentry, persistence);
    # scan_service owns check orchestration, timeouts, score, and summary.
    from scan_service import run_full_scan
    response_data = run_full_scan(domain, source="api")
    score = response_data["score"]

    # Store scan in database (async-safe, non-blocking to the response)
    if is_db_available():
        try:
            # INBOX-22 (2026-04-21): scan_type="manual" made explicit (matches the
            # DB default; defensive against future default changes).
            saved = save_scan(
                domain=domain,
                score=score,
                results=response_data,
                ip_address=client_ip,
                user_id=scan_user_id,
                scan_type="manual",
            )
            if saved:
                response_data["scan_id"] = saved["id"]
                # Update domain score if user has this domain saved.
                # INBOX-27: scoped by scan_user_id so we can never
                # overwrite another user's latest_score for the same
                # domain name.
                if scan_user_id:
                    try:
                        update_domain_score(scan_user_id, domain, score, saved["id"])
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


# ─── AUTH RATE LIMITING ─────────────────────────────────────────────
from collections import defaultdict
import time as _time

_login_attempts = defaultdict(list)  # ip -> [timestamp, ...]
_LOGIN_RATE_LIMIT = 5   # max attempts
_LOGIN_RATE_WINDOW = 300  # per 5 minutes (seconds)


def _check_login_rate(ip: str) -> bool:
    """Returns True if the IP is allowed to attempt login."""
    now = _time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < _LOGIN_RATE_WINDOW]
    if len(_login_attempts[ip]) >= _LOGIN_RATE_LIMIT:
        return False
    _login_attempts[ip].append(now)
    return True


# ─── PASSWORD POLICY ───────────────────────────────────────────────

def _validate_password(password: str) -> str | None:
    """Returns error message if password is invalid, None if OK."""
    if len(password) < 8:
        return "Password must be at least 8 characters"
    if not re.search(r'[A-Z]', password):
        return "Password must contain at least one uppercase letter"
    if not re.search(r'[0-9]', password):
        return "Password must contain at least one number"
    return None


# ─── AUTH ENDPOINTS ────────────────────────────────────────────────

@app.post("/api/auth/signup")
async def api_signup(request: SignupRequest):
    """Register a new user"""
    # Validate email
    email_regex = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
    if not re.match(email_regex, request.email):
        raise HTTPException(status_code=400, detail="Invalid email address")

    pw_error = _validate_password(request.password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

    result = sign_up(request.email, request.password, request.name)

    if result["success"]:
        return result
    else:
        raise HTTPException(status_code=400, detail=result["error"])


@app.post("/api/auth/login")
async def api_login(request: LoginRequest, req: Request):
    """Log in and get access token"""
    # Rate limit by IP
    client_ip = req.headers.get("x-forwarded-for", req.client.host if req.client else "0.0.0.0")
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    if not _check_login_rate(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many login attempts. Please wait 5 minutes and try again."
        )

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
                # INBOX-30: filter on user_id (rate_limits.user_id column
                # added in migration 009). Previously filtered on
                # ip_address = <user_id UUID>, which Postgres silently
                # refused; scans_today always returned 0 for authenticated
                # users and the profile UI always showed "0 scans used today."
                result = sb.table("rate_limits").select("scan_count").eq(
                    "user_id", user_id
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
    """Update user profile (name, company).

    INBOX-149 (v1.16.3): only update fields the client actually sent.
    Previously we used `body.get("name", "").strip()` which returned an
    empty string when the client only meant to update one field — that
    silently blanked the OTHER column. Now `body.get("name")` returns
    None when missing, and the db helper's `if name is not None` guard
    skips it correctly.
    """
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    body = await req.json()
    raw_name = body.get("name")
    raw_company = body.get("company")
    name = raw_name.strip() if isinstance(raw_name, str) else None
    company = raw_company.strip() if isinstance(raw_company, str) else None

    user_id = user_result["user"]["id"]
    updated = update_user_profile(user_id, name=name, company=company)
    if updated is None:
        # Defensive: if no row was matched (edge case where the auth
        # trigger missed creating the profile row), upsert it now so
        # the user isn't permanently locked out of saving their profile.
        # See INBOX-149 for the bug Vinoop hit on 2026-04-29.
        from db import get_supabase
        sb = get_supabase()
        if sb is not None:
            try:
                seed = {"id": user_id}
                if name is not None:    seed["name"] = name
                if company is not None: seed["company"] = company
                upsert_result = sb.table("profiles").upsert(seed).execute()
                if upsert_result.data:
                    updated = upsert_result.data[0]
            except Exception as e:
                import logging
                logging.getLogger(__name__).exception(
                    "Profile upsert fallback failed",
                    extra={"user_id": user_id, "error": str(e)},
                )
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
    pw_error = _validate_password(new_password)
    if pw_error:
        raise HTTPException(status_code=400, detail=pw_error)

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


# INBOX-143 (v1.16.2): the alert-rule + delivery-channel UI now lives
# on /alerts (Rules + Channels tabs). The old Settings → Notifications
# panel was write-only, but the new UI hydrates its toggles from saved
# state, so we need a GET pair for the PUT.
#
# Defaults match how the UI renders an unconfigured user's first visit:
# every alert rule is ON; weekly_digest is OFF (opt-in to extra email).
PREFERENCE_DEFAULTS = {
    "spam_threshold": True,    # Rules: spam rate exceeds 0.1% / 0.3%
    "auth_drops": True,        # Rules: SPF/DKIM/DMARC pass-rate drops
    "blacklist_alerts": True,  # Rules: any IP/domain listed
    "scan_alerts": True,       # Channels: email
    "weekly_digest": False,    # Channels: Monday 9am summary (opt-in)
}


@app.get("/api/user/preferences")
async def api_get_preferences(req: Request):
    """Get user notification preferences (with defaults for unset keys)."""
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")

    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    saved = get_user_preferences(user_result["user"]["id"]) or {}
    # Merge defaults so the response always has the full key set the
    # UI expects, even for users who haven't hit Save once.
    prefs = {**PREFERENCE_DEFAULTS, **{k: v for k, v in saved.items() if k in PREFERENCE_DEFAULTS}}
    return {"preferences": prefs}


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
    # INBOX-143: accept the full key set the /alerts UI emits. Unknown
    # keys are ignored so a stale client can't corrupt the JSONB blob.
    prefs = {
        key: bool(body.get(key, default))
        for key, default in PREFERENCE_DEFAULTS.items()
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

    # INBOX-27: scope monitoring-log reads to the authenticated user.
    # Previously any logged-in user could read another tenant's logs by
    # guessing a domain_id UUID (IDOR).
    user_id = user_result["user"]["id"]
    logs = get_monitoring_logs(user_id, domain_id, limit=min(limit, 100))
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

    # INBOX-27: scope scan-history reads to the authenticated user.
    # Previously any user querying a shared domain name (e.g.
    # mailercloud.com) saw scans from every other tenant (IDOR).
    user_id = user_result["user"]["id"]
    scans = get_domain_scans(user_id, domain, limit=min(limit, 100))
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

    user_id = user_result["user"]["id"]
    scan = get_scan_detail(scan_id, user_id=user_id)
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

    user_id = user_result["user"]["id"]
    scan = get_scan_detail(scan_id, user_id=user_id)
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

    filename = f"inboxscore-scan-history-{datetime.now(timezone.utc).strftime('%Y%m%d')}.csv"

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


# ─── BLACKLIST CHECK ENDPOINTS (INBOX-142: native DNSBL) ─────────

@app.get("/api/blacklist/check/{domain}")
async def api_blacklist_check(domain: str, req: Request):
    """
    Run a full blacklist check for a domain across our 25-list catalog.

    INBOX-142: Replaced HetrixTools with direct DNSBL queries via
    dnsbl.py. Sub-second response, no third-party API, no per-call
    cost.

    IP source rule: ONLY user-mapped IPs (from /sending-ips Map Domains).
    NOT SPF expansion (which can balloon to 10k+ IPs from Google/AWS
    includes that the user can't act on anyway). Empty mapping →
    domain-only check + empty ip_results.
    """
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    from dnsbl import full_blacklist_check

    user_id = user_result["user"]["id"]

    # IPs = strictly user-mapped IPs for this domain. No DNS fallback.
    user_domain_ips = get_ips_for_domain(user_id, domain) or []
    ips = sorted(set(user_domain_ips))

    # Run the check (synchronous DNS but fast — sub-second).
    result = full_blacklist_check(domain, ips)

    # Attach a "source" tag per IP for UI consistency with the prior
    # response shape. All entries are user-mapped now.
    for ip_result in result.get("ip_results", []):
        ip_result["source"] = "Sending IPs"

    # Persist so /api/blacklist/results/{domain} can return cached data.
    save_blacklist_results(user_id, domain, result)

    return result


@app.get("/api/blacklist/results/{domain}")
async def api_blacklist_saved_results(domain: str, req: Request):
    """
    Get the last saved blacklist check results for a domain.
    Returns 404 if no prior check exists.
    """
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")

    user_id = user_result["user"]["id"]
    saved = get_blacklist_results(user_id, domain)
    if not saved:
        raise HTTPException(status_code=404, detail="No saved blacklist results for this domain")
    return saved


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
        return FileResponse("static/settings.html", headers={"Cache-Control": "no-cache, must-revalidate"})

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
        # INBOX-102: include last_sync_at so the Email Health page can
        # render "Last synced X ago" next to the Sync button.
        last_sync_at = get_last_postmaster_sync_at(user_id)
        return {
            "connected": True,
            "google_email": connection.get("google_email", ""),
            "connected_at": connection.get("connected_at", ""),
            "last_sync_at": last_sync_at,
            "is_pro": is_pro,
        }
    else:
        return {
            "connected": False,
            "google_email": None,
            "connected_at": None,
            "last_sync_at": None,
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


@app.get("/api/postmaster/compliance/{domain}")
async def api_postmaster_compliance(domain: str, req: Request):
    """Get Google Postmaster compliance status for a domain (v2 API)"""
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
        return {"connected": False, "compliance": None}

    try:
        from postmaster import ensure_valid_token, get_compliance_status
        access_token = await ensure_valid_token(user_id, connection)
        compliance = await get_compliance_status(access_token, domain)
        return {"connected": True, "domain": domain, "compliance": compliance}
    except Exception as e:
        print(f"[Postmaster] Compliance status error for {domain}: {e}")
        return {"connected": True, "domain": domain, "compliance": None, "error": str(e)}


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
    from snds import validate_snds_key, fetch_snds_data, backfill_snds_history
    validation = await validate_snds_key(snds_key)

    if not validation["valid"]:
        raise HTTPException(
            status_code=400,
            detail=validation["error"] or "Invalid SNDS key"
        )

    # Save connection
    save_snds_connection(user_id, snds_key)

    # INBOX-127: pull today's data + the last 30 days of history.
    # Without the backfill, /microsoft would show one day of data
    # until 30 daily syncs pass naturally. Backfill takes ~15-20s
    # but gives the user a populated dashboard immediately.
    ip_set = set()
    rows_saved = 0
    try:
        # Today's data first (fast)
        today_result = await fetch_snds_data(snds_key)
        if today_result["success"] and today_result["data"]:
            for row in today_result["data"]:
                ip_set.add(row["ip_address"])
                upsert_snds_metrics(
                    user_id=user_id,
                    ip_address=row["ip_address"],
                    metric_date=row["metric_date"],
                    metrics=row,
                )
                rows_saved += 1

        # 30-day backfill (paced ~0.5s per day so ~15s total)
        backfill = await backfill_snds_history(snds_key, days=30)
        for row in backfill.get("rows", []):
            ip_set.add(row["ip_address"])
            upsert_snds_metrics(
                user_id=user_id,
                ip_address=row["ip_address"],
                metric_date=row["metric_date"],
                metrics=row,
            )
            rows_saved += 1

        update_snds_sync_status(user_id, ip_count=len(ip_set))
        print(
            f"[SNDS] Initial sync + backfill: {rows_saved} rows, {len(ip_set)} IPs, "
            f"{backfill.get('days_with_data', 0)}/{backfill.get('days_fetched', 0)} days had data"
        )
    except Exception as e:
        print(f"[SNDS] Initial sync error: {e}")

    return {
        "success": True,
        "message": "Microsoft SNDS connected successfully",
        "ip_count": validation["ip_count"],
        "rows_saved": rows_saved,
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
        # If domain specified but has no mapped IPs, return empty (not all IPs)
        if not allowed_ips:
            return {
                "connected": True,
                "metrics": [],
                "ip_count": connection.get("ip_count", 0),
                "last_sync_at": connection.get("last_sync_at"),
                "no_ips_mapped": True,
            }
        metrics = [m for m in metrics if m.get("ip_address") in allowed_ips]
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


@app.get("/api/snds/dashboard-summary")
async def api_snds_dashboard_summary(req: Request, domain: str = ""):
    """
    Per-domain SNDS state for the Dashboard Microsoft card.
    Returns one of 4 states (INBOX-125):
      - disconnected     : user has no SNDS connection at all
      - no_ips_mapped    : SNDS connected but no IPs in user_ip_domains for this domain
      - no_recent_data   : IPs mapped but no Microsoft data in last 24h
      - ok               : happy path — return summary metrics
    """
    auth_header = req.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing authorization")
    token = auth_header.replace("Bearer ", "")
    user_result = get_user_from_token(token)
    if not user_result["success"]:
        raise HTTPException(status_code=401, detail="Invalid token")
    user_id = user_result["user"]["id"]

    if not domain:
        raise HTTPException(status_code=400, detail="domain query param required")

    connection = get_snds_connection(user_id)
    if not connection:
        return {"state": "disconnected", "summary": None, "mapped_ip_count": 0}

    mapped_ips = get_ips_for_domain(user_id, domain)
    if not mapped_ips:
        return {
            "state": "no_ips_mapped",
            "summary": None,
            "mapped_ip_count": 0,
            "last_sync_at": connection.get("last_sync_at"),
        }

    # Pull last 7 days for the mapped IPs and find the most recent row.
    metrics = db_get_snds_metrics(user_id, days=7)
    allowed = set(mapped_ips)
    metrics = [m for m in metrics if m.get("ip_address") in allowed]

    if not metrics:
        return {
            "state": "no_recent_data",
            "summary": None,
            "mapped_ip_count": len(mapped_ips),
            "last_sync_at": connection.get("last_sync_at"),
        }

    # Latest row per IP — use the most recent metric_date
    latest_by_ip: dict[str, dict] = {}
    for m in metrics:
        ip = m.get("ip_address")
        if not ip:
            continue
        prev = latest_by_ip.get(ip)
        if prev is None or (m.get("metric_date") or "") > (prev.get("metric_date") or ""):
            latest_by_ip[ip] = m

    rows = list(latest_by_ip.values())
    # Aggregate: status (worst), avg complaint rate, total trap hits
    status_rank = {"GREEN": 0, "YELLOW": 1, "RED": 2}
    status_label = "GREEN"
    for r in rows:
        s = (r.get("filter_result") or "GREEN").upper()
        if status_rank.get(s, 0) > status_rank.get(status_label, 0):
            status_label = s

    # complaint_rate stored as e.g. "< 0.1%" or "0.20%" — parse defensively
    def _to_float(v):
        if v is None:
            return None
        s = str(v).strip().replace("<", "").replace("%", "").strip()
        try:
            return float(s)
        except Exception:
            return None

    rates = [r for r in (_to_float(m.get("complaint_rate")) for m in rows) if r is not None]
    avg_complaint = (sum(rates) / len(rates)) if rates else None
    if avg_complaint is None:
        complaint_str = "—"
    elif avg_complaint < 0.1:
        complaint_str = "< 0.1%"
    else:
        complaint_str = f"{avg_complaint:.2f}%"

    total_traps = sum(int(r.get("trap_hits") or 0) for r in rows)

    # Colour mapping (matches DESIGN-SYSTEM.md empty-state rule)
    status_color = {"GREEN": "good", "YELLOW": "warn", "RED": "bad"}.get(status_label, "good")
    if avg_complaint is None:
        complaint_color = "none"
    elif avg_complaint < 0.3:
        complaint_color = "good"
    elif avg_complaint < 1.0:
        complaint_color = "warn"
    else:
        complaint_color = "bad"
    if total_traps == 0:
        trap_color = "none"
    elif total_traps < 5:
        trap_color = "warn"
    else:
        trap_color = "bad"

    return {
        "state": "ok",
        "summary": {
            "has_data": True,
            "status_label": status_label,
            "status_color": status_color,
            "complaint_rate": complaint_str,
            "complaint_color": complaint_color,
            "trap_hits": str(total_traps),
            "trap_color": trap_color,
        },
        "mapped_ip_count": len(mapped_ips),
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


# INBOX-37: every HTML page response must carry a no-cache directive so a
# browser doesn't serve a stale copy of the file after we deploy a new build.
# Without this header the browser applies freshness heuristics and may hold
# onto a several-hour-old dashboard.html, which is how Vinoop hit the
# INBOX-34 "fix looks broken in the browser" bug even though the new bytes
# were already live on Render.
#
# "no-cache" is the Goldilocks choice: browsers still store the file, but
# they revalidate with a conditional request (If-Modified-Since / ETag) on
# every use. If the file hasn't changed, the server returns 304 and the
# cached bytes are reused. If it has, the browser gets the fresh copy.
#
# Mounted /static/* assets (CSS/JS/images) keep their default caching —
# they're small, infrequently changed, and aren't susceptible to the
# "page-after-deploy" class of confusion this ticket addresses.
_NO_CACHE = {"Cache-Control": "no-cache, must-revalidate"}


def _html(filename: str) -> FileResponse:
    """Return an HTML FileResponse with the no-cache header applied."""
    return FileResponse(f"static/{filename}", headers=_NO_CACHE)


@app.get("/")
async def serve_frontend():
    return _html("index.html")


@app.get("/scan/{domain}")
async def serve_scan_page(domain: str):
    """Serve homepage for shareable scan URLs"""
    return _html("index.html")


@app.get("/pricing")
async def serve_pricing():
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/#pricing", status_code=302)


@app.get("/signup")
async def serve_signup():
    return _html("signup.html")


@app.get("/login")
async def serve_login():
    return _html("login.html")


@app.get("/forgot-password")
async def serve_forgot_password():
    return _html("forgot-password.html")


@app.get("/dashboard")
async def serve_dashboard():
    return _html("dashboard.html")


@app.get("/sending-ips")
async def serve_sending_ips():
    return _html("sending-ips.html")


@app.get("/domains")
async def serve_domains():
    return _html("domains.html")


@app.get("/domains/{domain}")
async def serve_domain_detail(domain: str):
    return _html("domains.html")


@app.get("/alerts")
async def serve_alerts():
    return _html("alerts.html")


@app.get("/settings")
async def serve_settings():
    return _html("settings.html")


# INBOX-110: Email Health flattened into 4 top-level provider pages.
# /email-health is gone (404). Each provider gets its own URL but they
# all serve the same email-health.html for now (Phase 2 / INBOX-111
# splits them into dedicated files). The page reads window.location.pathname
# on load and switches to the matching section.
@app.get("/postmaster")
async def serve_postmaster():
    return _html("email-health.html")


@app.get("/microsoft")
async def serve_microsoft():
    return _html("email-health.html")


@app.get("/blacklist")
async def serve_blacklist():
    return _html("email-health.html")


# INBOX-132: /reputation route removed — the IP Reputation page was a
# duplicate consolidated view of SNDS + blacklist data already shown
# on /microsoft and /blacklist. No redirect; bookmarks return 404 and
# users navigate via the sidebar.


if __name__ == "__main__":
    import uvicorn
    print("\n🚀 InboxScore is running!")
    print("   Open http://localhost:8000 in your browser\n")
    uvicorn.run(app, host="0.0.0.0", port=8000)
