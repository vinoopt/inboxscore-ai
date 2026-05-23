"""
InboxScore — email alert notifier (INBOX-144, 2026-05-21)

Sends per-event critical alert emails via MailerCloud's Transactional
API. Hooked into monitor.py, alerts_postmaster.py, and alerts_snds.py —
called right after create_alert() succeeds.

Design rules:
  • Critical-severity alerts only for v1. Warning + info stay in the
    in-app feed only. Email templates for those can come later.
  • Respect user_preferences.email_mode — 'off' means skip silently.
  • Idempotent via notification_log table — same (user_id, alert_id,
    channel) cannot fire twice. UNIQUE constraint catches duplicates.
  • Never crash the caller. Every failure path is caught + logged via
    logger.exception so the underlying scan / sync cycle is unaffected.
  • Dynamic content per alert type — blocklist names get specific
    delisting URLs, score alerts lead with the actual number, etc.

Required env vars (set in Render):
  MAILERCLOUD_API_KEY    — API key from MailerCloud admin
  ALERT_SENDER_EMAIL     — From address (must be verified in MailerCloud)
  ALERT_SENDER_NAME      — Display name (e.g. "InboxScore")

Optional env var:
  ALERT_LOGO_URL         — Public URL of the 88x88 PNG logo
                           (defaults to https://inboxscore.ai/static/email-logo.png)
  APP_BASE_URL           — App base URL for CTAs (defaults to https://inboxscore.ai)
  MAILERCLOUD_API_URL    — API endpoint
                           (defaults to https://email-api.mailercloud.com/email)

API spec reference:
  https://help.mailercloud.com/en/articles/155-mailercloud-email-api-help-guide
"""

import html
import json
import logging
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional

from db import (
    get_supabase,
    get_user_preferences,
    get_user_plan,
)
from blocklists import get_blocklist_info, render_delisting_url


_log = logging.getLogger("inboxscore.notifier")


# ─── Configuration ──────────────────────────────────────────────────

MAILERCLOUD_API_URL = os.environ.get(
    "MAILERCLOUD_API_URL", "https://email-api.mailercloud.com/email"
)
MAILERCLOUD_API_KEY = os.environ.get("MAILERCLOUD_API_KEY", "").strip()
ALERT_SENDER_EMAIL = os.environ.get("ALERT_SENDER_EMAIL", "help@inboxscore.ai").strip()
ALERT_SENDER_NAME = os.environ.get("ALERT_SENDER_NAME", "InboxScore").strip()
ALERT_LOGO_URL = os.environ.get(
    "ALERT_LOGO_URL", "https://inboxscore.ai/static/email-logo.png"
)
APP_BASE_URL = os.environ.get("APP_BASE_URL", "https://inboxscore.ai").rstrip("/")

# Plans that get email notifications. Stub Free has monitoring paused
# (INBOX-258) so no alerts fire for them anyway; this is a belt-and-
# suspenders guard.
EMAILABLE_PLANS = {"trial", "pro", "legacy_pro"}

# Email modes that allow sending. 'all_rt' currently behaves the same
# as 'critical_rt' until we build warning/info templates.
EMAIL_MODES_THAT_SEND = {"all_rt", "critical_rt"}

# MailerCloud success status code (from API docs)
MC_STATUS_SUCCESS = 1000


# ─── Public entry point ─────────────────────────────────────────────


def send_alert_email(user_id: str, alert: dict) -> dict:
    """Send a critical-alert email for ``alert`` to ``user_id``.

    Returns a dict {status, ...} describing what happened. Never raises
    — every error path logs via _log.exception and returns a structured
    status the caller can ignore safely.

    Status values:
      'sent'    — email submitted to MailerCloud, message-id stored
      'skipped' — preference check failed (email_mode off, severity not
                  critical, user plan not emailable, no email on file)
      'failed'  — MailerCloud or DB error; recorded in notification_log
      'duplicate' — notification_log already has a row for this
                   (user_id, alert_id, channel) — idempotency hit
    """
    if not alert or not alert.get("id"):
        _log.warning("notifier.bad_input", extra={"user_id_prefix": (user_id or "")[:8]})
        return {"status": "skipped", "reason": "invalid_alert"}

    alert_id = alert["id"]

    try:
        # Pre-flight eligibility checks
        eligibility = _check_eligibility(user_id, alert)
        if eligibility["status"] != "ok":
            _log_skip(user_id, alert_id, alert.get("domain"), eligibility["reason"])
            return {"status": "skipped", "reason": eligibility["reason"]}

        user_email = eligibility["email"]
        user_name = eligibility["name"]

        # Idempotency check — insert pre-flight row, UNIQUE catches dups
        insert_result = _insert_pending_log(user_id, alert_id, alert.get("domain"))
        if insert_result["status"] == "duplicate":
            return {"status": "duplicate"}
        if insert_result["status"] == "failed":
            return {"status": "failed", "reason": "log_insert_failed"}
        log_id = insert_result["log_id"]

        # Build the email (subject, preview, html, text)
        rendered = _render_email(alert, user_name)

        # Build MailerCloud payload
        payload = _build_payload(
            to_email=user_email,
            to_name=user_name,
            subject=rendered["subject"],
            html_body=rendered["html"],
            text_body=rendered["text"],
            message_id=f"alert-{alert_id}",
        )

        # Send
        api_result = _call_mailercloud(payload)

        # Update log with outcome
        if api_result["status"] == "sent":
            _update_log_sent(log_id, api_result.get("message_id"))
            _log.info("notifier.sent", extra={
                "user_id_prefix": user_id[:8],
                "alert_id": alert_id,
                "alert_type": alert.get("type"),
                "domain": alert.get("domain"),
            })
            return {"status": "sent", "message_id": api_result.get("message_id")}
        else:
            _update_log_failed(
                log_id,
                error_code=api_result.get("error_code"),
                error_message=api_result.get("error_message"),
            )
            _log.warning("notifier.send_failed", extra={
                "user_id_prefix": user_id[:8],
                "alert_id": alert_id,
                "error_code": api_result.get("error_code"),
                "error_message": api_result.get("error_message"),
            })
            return {"status": "failed", "reason": api_result.get("error_message")}

    except Exception:
        _log.exception("notifier.unexpected_error", extra={
            "user_id_prefix": user_id[:8] if user_id else None,
            "alert_id": alert_id,
        })
        return {"status": "failed", "reason": "unexpected_error"}


# ─── Eligibility ────────────────────────────────────────────────────


def _check_eligibility(user_id: str, alert: dict) -> dict:
    """Pre-flight checks before sending. Returns
    {"status": "ok", "email": ..., "name": ...} or
    {"status": "skip", "reason": "..."}.

    Skip reasons:
      'not_critical'        — alert severity is warning/info (v1 scope)
      'no_user'             — couldn't look up the user
      'no_email'            — user has no email on file
      'plan_not_emailable'  — user is on stub/free plan
      'email_mode_off'      — user disabled email
    """
    if alert.get("severity") != "critical":
        return {"status": "skip", "reason": "not_critical"}

    # User lookup
    user = _lookup_user(user_id)
    if not user:
        return {"status": "skip", "reason": "no_user"}
    user_email = user.get("email")
    if not user_email:
        return {"status": "skip", "reason": "no_email"}

    # Plan check
    plan = get_user_plan(user_id)
    if plan not in EMAILABLE_PLANS:
        return {"status": "skip", "reason": "plan_not_emailable"}

    # Email-mode preference
    prefs = get_user_preferences(user_id) or {}
    mode = prefs.get("email_mode", "critical_rt")
    if mode not in EMAIL_MODES_THAT_SEND:
        return {"status": "skip", "reason": "email_mode_off"}

    return {
        "status": "ok",
        "email": user_email,
        "name": user.get("name") or user.get("first_name") or user_email.split("@")[0],
    }


def _lookup_user(user_id: str) -> Optional[dict]:
    """Read the user's email (from auth.users) + name (from profiles).
    Returns None on failure.

    INBOX-144 fix: original implementation selected `id, email, name,
    first_name` from public.profiles which broke for TWO reasons:
      (a) `email` lives in auth.users, NOT public.profiles
      (b) `first_name` doesn't exist on profiles either
    The whole SELECT failed at the Supabase layer → empty result →
    _lookup_user returned None → eligibility check returned 'no_user'
    → no email ever sent.

    Fix: use the Supabase auth admin API (sb.auth.admin.get_user_by_id)
    for email — works because the server initialises with the
    SUPABASE_SERVICE_KEY which has admin scope. Then a separate SELECT
    on profiles for the display name.
    """
    sb = get_supabase()
    if not sb:
        return None
    try:
        # ── Email from auth.users via admin API ─────────────────────
        auth_resp = sb.auth.admin.get_user_by_id(user_id)
        email = None
        if auth_resp is not None:
            # supabase-py returns either an object with .user.email or a
            # dict-like {'user': {'email': ...}} depending on version
            user_obj = getattr(auth_resp, "user", None)
            if user_obj is None and isinstance(auth_resp, dict):
                user_obj = auth_resp.get("user")
            if user_obj is not None:
                email = getattr(user_obj, "email", None)
                if email is None and isinstance(user_obj, dict):
                    email = user_obj.get("email")
        if not email:
            return None

        # ── Name from profiles (best-effort) ────────────────────────
        name = None
        try:
            prof_result = sb.table("profiles").select("id, name").eq(
                "id", user_id
            ).limit(1).execute()
            rows = prof_result.data or []
            if rows:
                name = rows[0].get("name")
        except Exception:
            # If profiles lookup fails we still proceed with email-only —
            # name is just used for the greeting and has a fallback.
            pass

        return {
            "id": user_id,
            "email": email,
            "name": name,
            # first_name derived from name (split on first space) so
            # _check_eligibility's fallback chain still works.
            "first_name": (name or "").split(" ")[0] if name else None,
        }
    except Exception:
        _log.exception("notifier.lookup_user_failed", extra={
            "user_id_prefix": user_id[:8] if user_id else None,
        })
        return None


# ─── Notification log ───────────────────────────────────────────────


def _insert_pending_log(
    user_id: str, alert_id: str, domain: Optional[str],
) -> dict:
    """Insert a 'sending' row. Returns:
      {"status": "ok", "log_id": ...}      — new row inserted
      {"status": "duplicate"}              — UNIQUE constraint hit
      {"status": "failed"}                 — other DB error
    """
    sb = get_supabase()
    if not sb:
        return {"status": "failed"}
    try:
        result = sb.table("notification_log").insert({
            "user_id": user_id,
            "alert_id": alert_id,
            "domain": domain,
            "channel": "email",
            "status": "sending",
        }).execute()
        rows = result.data or []
        if not rows:
            return {"status": "failed"}
        return {"status": "ok", "log_id": rows[0]["id"]}
    except Exception as e:
        msg = str(e).lower()
        # Supabase / PostgREST surfaces unique-constraint violations
        # with 'duplicate key' or '23505' in the message
        if "duplicate" in msg or "23505" in msg or "unique" in msg:
            return {"status": "duplicate"}
        _log.exception("notifier.log_insert_failed", extra={
            "user_id_prefix": user_id[:8] if user_id else None,
            "alert_id": alert_id,
        })
        return {"status": "failed"}


def _log_skip(
    user_id: str, alert_id: str, domain: Optional[str], reason: str,
) -> None:
    """Record a 'skipped' row so audit trail is complete. Best-effort —
    failures here are non-fatal."""
    sb = get_supabase()
    if not sb:
        return
    try:
        sb.table("notification_log").insert({
            "user_id": user_id,
            "alert_id": alert_id,
            "domain": domain,
            "channel": "email",
            "status": "skipped",
            "skip_reason": reason,
        }).execute()
    except Exception:
        # Skipped log itself is best-effort. Duplicates here are fine.
        pass


def _update_log_sent(log_id: str, message_id: Optional[str]) -> None:
    sb = get_supabase()
    if not sb:
        return
    try:
        sb.table("notification_log").update({
            "status": "sent",
            "message_id": message_id,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", log_id).execute()
    except Exception:
        _log.exception("notifier.log_update_sent_failed", extra={"log_id": log_id})


def _update_log_failed(
    log_id: str, error_code: Optional[str], error_message: Optional[str],
) -> None:
    sb = get_supabase()
    if not sb:
        return
    try:
        sb.table("notification_log").update({
            "status": "failed",
            "error_code": error_code,
            "error_message": (error_message or "")[:1000],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }).eq("id", log_id).execute()
    except Exception:
        _log.exception("notifier.log_update_failed_failed", extra={"log_id": log_id})


# ─── Email template ─────────────────────────────────────────────────
# Severity colour map and shared shell. Each alert type has its own
# subject + body content; the shell wraps it consistently.

_SEV_COLOURS = {
    "critical": {"text": "#b91c1c", "bg": "#fef2f2", "dot": "#dc2626"},
    "warning":  {"text": "#b45309", "bg": "#fffbeb", "dot": "#d97706"},
    "info":     {"text": "#047857", "bg": "#ecfdf5", "dot": "#059669"},
}


def _esc(s) -> str:
    """HTML-escape a string, accepting None."""
    if s is None:
        return ""
    return html.escape(str(s), quote=True)


def _render_email(alert: dict, user_name: str) -> dict:
    """Returns {subject, preview, html, text} for an alert."""
    raw = alert.get("raw_data") or {}
    type_ = alert.get("type", "")
    if type_ == "blacklist_added":
        return _render_blacklist(alert, raw, user_name)
    if type_ == "score_drop":
        return _render_score_drop(alert, raw, user_name)
    if type_ == "dmarc_change":
        return _render_dmarc_change(alert, raw, user_name)
    if type_ in ("spf_change", "dkim_change", "dns_change"):
        return _render_auth_change(alert, raw, user_name)
    if type_ == "cert_expiry":
        return _render_cert_expiry(alert, raw, user_name)
    if type_ == "reputation_change":
        return _render_reputation_change(alert, raw, user_name)
    # Generic fallback for any unhandled type — uses the alert's own
    # title + message verbatim.
    return _render_generic(alert, raw, user_name)


def _render_shell(
    *, subject: str, preview: str, sev_label: str, severity: str,
    title: str, subtitle_html: str, body_html: str, steps_html: str,
    cta_label: str, cta_url: str, detected_at: str, domain: str,
) -> dict:
    """Wrap content blocks in the shared email shell.
    Returns {subject, preview, html, text}. Caller is expected to
    construct the plain-text version separately and pass it in via the
    higher-level render functions."""
    palette = _SEV_COLOURS.get(severity, _SEV_COLOURS["critical"])
    html_body = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="x-apple-disable-message-reformatting">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>{_esc(subject)}</title>
<style>
  @media only screen and (max-width: 620px) {{
    .container {{ width: 100% !important; }}
    .card {{ padding: 24px 20px !important; }}
    .cta-btn {{ display: block !important; width: 100% !important; text-align: center !important; box-sizing: border-box; }}
  }}
</style>
</head>
<body style="margin:0;padding:0;background-color:#fafafa;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;color:#09090b;">
<!-- Preview text -->
<div style="display:none;max-height:0;overflow:hidden;font-size:1px;line-height:1px;color:#fafafa;opacity:0;">{_esc(preview)}</div>
<table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="background-color:#fafafa;padding:32px 0;">
  <tr><td align="center">
    <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="600" class="container" style="max-width:600px;background-color:#ffffff;">
      <!-- Header / brand -->
      <tr><td class="card" style="padding:40px 32px 0;">
        <table role="presentation" cellspacing="0" cellpadding="0" border="0">
          <tr>
            <td style="vertical-align:middle;padding-right:9px;">
              <img src="{_esc(ALERT_LOGO_URL)}" alt="InboxScore" width="22" height="22" style="display:block;border-radius:5px;border:0;">
            </td>
            <td style="vertical-align:middle;font-size:15px;font-weight:700;color:#09090b;letter-spacing:-0.01em;line-height:1;">
              InboxScore
            </td>
          </tr>
        </table>
      </td></tr>
      <!-- Spacer -->
      <tr><td style="height:56px;line-height:56px;font-size:1px;">&nbsp;</td></tr>
      <!-- Severity badge -->
      <tr><td class="card" style="padding:0 32px;">
        <table role="presentation" cellspacing="0" cellpadding="0" border="0"><tr>
          <td style="background-color:{palette['bg']};border-radius:999px;padding:5px 12px;">
            <table role="presentation" cellspacing="0" cellpadding="0" border="0"><tr>
              <td style="width:6px;height:6px;background-color:{palette['dot']};border-radius:50%;line-height:1px;font-size:1px;">&nbsp;</td>
              <td style="width:6px;font-size:1px;line-height:1px;">&nbsp;</td>
              <td style="color:{palette['text']};font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.08em;line-height:1;">{_esc(sev_label)}</td>
            </tr></table>
          </td>
        </tr></table>
      </td></tr>
      <!-- Title -->
      <tr><td class="card" style="padding:18px 32px 6px;">
        <h1 style="margin:0;font-size:26px;font-weight:700;color:#09090b;line-height:1.25;letter-spacing:-0.02em;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">{_esc(title)}</h1>
      </td></tr>
      <!-- Subtitle -->
      <tr><td class="card" style="padding:0 32px 28px;">
        <p style="margin:0;font-size:14px;color:#71717a;line-height:1.5;">{subtitle_html}</p>
      </td></tr>
      <!-- Body -->
      <tr><td class="card" style="padding:0 32px;">
        {body_html}
      </td></tr>
      {steps_html}
      <!-- CTA -->
      <tr><td class="card" style="padding:32px 32px 0;">
        <table role="presentation" cellspacing="0" cellpadding="0" border="0"><tr>
          <td style="background-color:#09090b;border-radius:8px;">
            <a href="{_esc(cta_url)}" class="cta-btn" style="display:inline-block;padding:11px 18px;color:#fafafa;font-size:14px;font-weight:500;text-decoration:none;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">{_esc(cta_label)} &rarr;</a>
          </td>
        </tr></table>
      </td></tr>
      <!-- Detected timestamp -->
      <tr><td class="card" style="padding:32px 32px 0;">
        <table role="presentation" cellspacing="0" cellpadding="0" border="0" width="100%" style="border-top:1px solid #f4f4f5;">
          <tr><td style="padding:20px 0 0;font-size:12px;color:#a1a1aa;">Detected {_esc(detected_at)}</td></tr>
        </table>
      </td></tr>
      <!-- Footer -->
      <tr><td class="card" style="padding:24px 32px 32px;background-color:#fafafa;border-top:1px solid #f4f4f5;margin-top:32px;">
        <p style="margin:0 0 8px;font-size:12px;color:#71717a;line-height:1.6;">
          <strong style="color:#18181b;font-weight:600;">InboxScore</strong> &middot; Sent on behalf of Luvia Digital LTD
        </p>
        <p style="margin:0 0 8px;font-size:12px;color:#a1a1aa;line-height:1.6;">
          Luvia Digital LTD &middot; London, United Kingdom
        </p>
        <p style="margin:0;font-size:12px;color:#71717a;line-height:1.6;">
          You're getting this because you're monitoring <strong style="color:#52525b;">{_esc(domain)}</strong> on InboxScore.
          <a href="{_esc(APP_BASE_URL)}/alerts" style="color:#52525b;text-decoration:underline;">Email settings</a>
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>"""
    return {
        "subject": subject,
        "preview": preview,
        "html": html_body,
        # text rendered by callers via _render_text_*
        "text": "",
    }


def _build_text(
    *, sev_label: str, title: str, subtitle: str, paragraphs: list,
    steps: Optional[list], cta_label: str, cta_url: str,
    detected_at: str, domain: str,
) -> str:
    """Plain text version. Modeled after the HTML structure."""
    out = []
    out.append(f"[{sev_label.upper()}]")
    out.append("")
    out.append(title)
    out.append(subtitle)
    out.append("")
    for p in paragraphs:
        out.append(p)
        out.append("")
    if steps:
        out.append("What to do:")
        for i, step in enumerate(steps, 1):
            out.append(f"  {i}. {step}")
        out.append("")
    out.append(f"{cta_label}: {cta_url}")
    out.append("")
    out.append(f"Detected {detected_at}")
    out.append("")
    out.append("---")
    out.append("InboxScore — Sent on behalf of Luvia Digital LTD")
    out.append("Luvia Digital LTD, London, United Kingdom")
    out.append(f"You're getting this because you're monitoring {domain} on InboxScore.")
    out.append(f"Email settings: {APP_BASE_URL}/alerts")
    return "\n".join(out)


# ─── Type-specific renderers ────────────────────────────────────────


def _format_detected_at(alert: dict) -> str:
    """ISO timestamp → human-readable UTC string."""
    ts = alert.get("created_at")
    if not ts:
        return datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC")
    try:
        # Supabase returns ISO 8601 with Z or offset
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%d %b %Y %H:%M UTC")
    except Exception:
        return ts


def _alert_url(alert_id: str) -> str:
    return f"{APP_BASE_URL}/alerts#alert-{alert_id}"


def _render_blacklist(alert: dict, raw: dict, user_name: str) -> dict:
    domain = alert.get("domain") or ""
    blacklists = raw.get("blacklists_listed") or []
    count = len(blacklists)
    ip = raw.get("ip")
    detected_at = _format_detected_at(alert)
    cta_url = _alert_url(alert["id"])

    if count == 0:
        # Fallback if raw_data doesn't carry the list
        subject = f"Critical: {domain} was added to a blocklist"
        preview = alert.get("message", "")[:90]
        title = f"{domain} was added to a blocklist"
        body_paragraphs = [alert.get("message", "")]
        steps_text = []
    elif count == 1:
        name = blacklists[0]
        info = get_blocklist_info(name)
        delist_url = render_delisting_url(name, domain, ip)
        subject = f"Critical: {domain} listed on {name}"
        preview = f"{domain} appeared on {name}. Gmail, Outlook, and Yahoo are blocking your mail."
        title = f"{domain} was listed on {name}"
        body_paragraphs = [
            f"{info['description']} Mail from <strong>{_esc(domain)}</strong> is now being blocked or filtered to spam at most major providers.",
        ]
        steps_text = [
            f"Open the alert in InboxScore to see the specific listing reason.",
        ]
        if delist_url:
            steps_text.append(f"Submit a delisting request at {delist_url}.")
        else:
            steps_text.append(f"Contact {name} via their published removal process.")
        steps_text.append("We'll re-scan every 6 hours and notify you the moment you're delisted.")
    else:
        names_inline = ", ".join(blacklists[:3])
        if count > 3:
            names_inline += f", and {count - 3} more"
        subject = f"Critical: {domain} listed on {count} blocklists"
        preview = f"{names_inline} all flagged {domain} in the same scan cycle."
        title = f"{domain} was listed on {count} blocklists"
        body_paragraphs = [
            f"<strong>{_esc(domain)}</strong> appeared on multiple blocklists in the same scan cycle &mdash; <strong>{_esc(names_inline)}</strong>. Multiple simultaneous listings usually point to a real reputation event, not a false positive: a compromised sender, spike in complaints, or content that triggered automated pattern-matching.",
            "Mail to most major providers (Gmail, Outlook, Yahoo, plus enterprise filters) will be blocked or filtered to spam until you're delisted from all of these.",
        ]
        steps_text = [
            "Open the alert in InboxScore to see each listing's specific reason &mdash; these are usually correlated.",
        ]
        for name in blacklists:
            url = render_delisting_url(name, domain, ip)
            if url:
                steps_text.append(f"Submit a delisting request for {name}: {url}")
        steps_text.append("Investigate the root cause before resubmitting &mdash; fix the underlying issue or you'll relist within days.")

    return _format_output(
        subject=subject, preview=preview, sev_label="Critical", severity="critical",
        title=title,
        subtitle=f"Detected on {domain}",
        body_paragraphs=body_paragraphs,
        steps=steps_text,
        cta_label="View alert in InboxScore",
        cta_url=cta_url,
        detected_at=detected_at,
        domain=domain,
    )


def _render_score_drop(alert: dict, raw: dict, user_name: str) -> dict:
    domain = alert.get("domain") or ""
    old_score = raw.get("old_score")
    new_score = raw.get("new_score")
    if new_score is None:
        # Last-resort fallback if raw_data missing
        return _render_generic(alert, raw, user_name)
    delta = (old_score - new_score) if (old_score is not None) else None
    detected_at = _format_detected_at(alert)
    cta_url = _alert_url(alert["id"])
    failing_checks = raw.get("failing_checks") or []

    subject = f"Critical: {domain} score dropped to {new_score}"
    title = f"{domain} score dropped to {new_score}"

    if old_score is not None:
        subtitle = f"From {old_score} &rarr; {new_score} &middot; {domain}"
        preview = f"Down from {old_score}. " + (
            f"Scores below 40 mean your domain is at serious risk."
            if new_score < 40
            else "Scores below 60 mean active deliverability problems."
        )
    else:
        subtitle = f"Detected on {domain}"
        preview = f"Score is now {new_score}. " + (
            "Below 40 means your domain is at serious risk."
            if new_score < 40
            else "Below 60 means active deliverability problems."
        )

    if new_score < 40:
        body_paragraphs = []
        if delta is not None:
            body_paragraphs.append(
                f"Your domain health score dropped <strong>{delta} points</strong> in the last scan cycle, falling from {old_score} to {new_score}. Scores below 40 mean your domain is at serious risk &mdash; most mail will be filtered or rejected."
            )
        else:
            body_paragraphs.append(
                f"Your domain health score is now <strong>{new_score}</strong>. Scores below 40 mean your domain is at serious risk &mdash; most mail will be filtered or rejected."
            )
        body_paragraphs.append(
            "This is a deep regression. Multiple deliverability signals are failing simultaneously."
        )
        steps_text = [
            "Pause active sending campaigns until you understand the root cause.",
            "Open the alert to see every check that's currently failing.",
            "Plan a recovery &mdash; small, consistent sends to engaged contacts over 2-4 weeks.",
        ]
    else:
        body_paragraphs = []
        if delta is not None:
            body_paragraphs.append(
                f"Your domain health score dropped <strong>{delta} points</strong> in the last scan cycle, falling from {old_score} to {new_score}. Scores below 60 mean active deliverability problems that need attention now."
            )
        else:
            body_paragraphs.append(
                f"Your domain health score is now <strong>{new_score}</strong>. Scores below 60 mean active deliverability problems that need attention now."
            )
        if failing_checks:
            check_labels = ", ".join(failing_checks)
            body_paragraphs.append(
                f"The drop was driven by <strong>{len(failing_checks)} failing checks</strong>: {_esc(check_labels)}."
            )
        steps_text = [
            "Open the alert to see exactly which checks regressed.",
            "Fix the highest-impact issue first &mdash; usually authentication.",
            "Review recent campaigns for any change that correlates with the drop.",
        ]

    return _format_output(
        subject=subject, preview=preview, sev_label="Critical", severity="critical",
        title=title, subtitle=subtitle,
        body_paragraphs=body_paragraphs,
        steps=steps_text,
        cta_label="View the failing checks",
        cta_url=cta_url,
        detected_at=detected_at, domain=domain,
    )


def _render_dmarc_change(alert: dict, raw: dict, user_name: str) -> dict:
    domain = alert.get("domain") or ""
    old_policy = raw.get("old_policy")
    new_policy = raw.get("new_policy")
    detected_at = _format_detected_at(alert)
    cta_url = _alert_url(alert["id"])

    if old_policy and new_policy and old_policy != new_policy:
        # Policy weakened
        subject = f"Critical: DMARC policy weakened on {domain}"
        preview = f"DMARC went from p={old_policy} to p={new_policy}. Your spoofing protection just dropped."
        title = f"DMARC policy was weakened"
        subtitle = f"<strong>{old_policy}</strong> &rarr; <strong>{new_policy}</strong> &middot; {domain}"
        body_paragraphs = [
            f"Someone changed your DMARC policy from <strong>p={_esc(old_policy)}</strong> to <strong>p={_esc(new_policy)}</strong> on <strong>{_esc(domain)}</strong>. This is a significant downgrade &mdash; spoofed messages claiming to be from your domain will now land in spam instead of being rejected outright.",
            "If you did not authorise this change, treat it as a security incident.",
        ]
        steps_text = [
            "Confirm whether someone on your team made this change intentionally.",
            "If not authorised, revert your DMARC record and audit who has DNS access.",
            "If the change was intentional, no further action needed.",
        ]
    else:
        # DMARC check went from pass to fail
        subject = f"Critical: DMARC now failing on {domain}"
        preview = f"DMARC validation broke. Spoofed messages will now reach inboxes."
        title = f"DMARC is now failing"
        subtitle = f"Was passing yesterday &middot; {domain}"
        body_paragraphs = [
            f"DMARC validation on <strong>{_esc(domain)}</strong> failed in our latest scan. DMARC depends on SPF or DKIM alignment &mdash; one or both has broken."
        ]
        steps_text = [
            "Open the alert for the exact DMARC record we saw.",
            "Check whether a recent DNS change broke SPF or DKIM alignment.",
            "Most DMARC failures resolve once the underlying SPF/DKIM issue is fixed.",
        ]

    return _format_output(
        subject=subject, preview=preview, sev_label="Critical", severity="critical",
        title=title, subtitle=subtitle,
        body_paragraphs=body_paragraphs, steps=steps_text,
        cta_label="See the DMARC change",
        cta_url=cta_url, detected_at=detected_at, domain=domain,
    )


def _render_auth_change(alert: dict, raw: dict, user_name: str) -> dict:
    domain = alert.get("domain") or ""
    type_ = alert.get("type", "auth")
    auth_label = {
        "spf_change": "SPF",
        "dkim_change": "DKIM",
        "dns_change": "Authentication",
    }.get(type_, "Authentication")
    detected_at = _format_detected_at(alert)
    cta_url = _alert_url(alert["id"])

    subject = f"Critical: {auth_label} now failing on {domain}"
    preview = f"Your {auth_label} record is failing validation. Mail will be rejected at Gmail and Outlook."
    title = f"{auth_label} authentication is now failing"
    subtitle = f"Was passing yesterday &middot; {domain}"
    body_paragraphs = [
        f"The {auth_label} record on <strong>{_esc(domain)}</strong> failed validation in our latest scan. {auth_label} is one of the three core authentication standards &mdash; when it fails, Gmail and Outlook may treat your mail as spoofed."
    ]
    if auth_label == "SPF":
        body_paragraphs.append(
            "Most SPF failures come from exceeding the 10-DNS-lookup limit or a syntax error in the record itself."
        )
    steps_text = [
        f"Open the alert for the exact {auth_label} record we saw and what failed.",
        "Check whether a recent DNS change broke it.",
        "Fix and re-scan to confirm.",
    ]

    return _format_output(
        subject=subject, preview=preview, sev_label="Critical", severity="critical",
        title=title, subtitle=subtitle,
        body_paragraphs=body_paragraphs, steps=steps_text,
        cta_label=f"See the {auth_label} record",
        cta_url=cta_url, detected_at=detected_at, domain=domain,
    )


def _render_cert_expiry(alert: dict, raw: dict, user_name: str) -> dict:
    domain = alert.get("domain") or ""
    detected_at = _format_detected_at(alert)
    cta_url = _alert_url(alert["id"])

    subject = f"Critical: TLS cert issue on {domain}"
    preview = f"Your TLS certificate is failing validation."
    title = f"TLS certificate is failing"
    subtitle = f"Detected on {domain}"
    body_paragraphs = [
        f"The TLS certificate on <strong>{_esc(domain)}</strong> failed validation in our latest scan. This affects encrypted-transport delivery and may cause mail to be rejected by strict receivers."
    ]
    steps_text = [
        "Open the alert for the specific TLS error we saw.",
        "Renew or reissue the certificate via your hosting / DNS provider.",
        "Re-scan to confirm the fix.",
    ]
    return _format_output(
        subject=subject, preview=preview, sev_label="Critical", severity="critical",
        title=title, subtitle=subtitle,
        body_paragraphs=body_paragraphs, steps=steps_text,
        cta_label="View certificate details", cta_url=cta_url,
        detected_at=detected_at, domain=domain,
    )


def _render_reputation_change(alert: dict, raw: dict, user_name: str) -> dict:
    """Covers Postmaster (spam rate, IP/domain reputation, auth pass rate)
    + SNDS (status colour transitions, trap hits). Branches on raw_data
    contents."""
    domain = alert.get("domain") or ""
    detected_at = _format_detected_at(alert)
    cta_url = _alert_url(alert["id"])
    title_text = alert.get("title") or "Reputation change"
    message_text = alert.get("message") or ""

    # Best-effort subject — strip leading provider names from title
    subject = f"Critical: {title_text} &middot; {domain}" if domain else f"Critical: {title_text}"
    preview = message_text[:90]
    subtitle = f"Detected on {domain}" if domain else ""

    body_paragraphs = [message_text]
    steps_text = [
        "Open the alert in InboxScore to see the full data behind this transition.",
        "If the metric continues degrading, pause active campaigns and investigate the root cause.",
    ]
    return _format_output(
        subject=subject, preview=preview, sev_label="Critical", severity="critical",
        title=title_text, subtitle=subtitle,
        body_paragraphs=body_paragraphs, steps=steps_text,
        cta_label="Open reputation data", cta_url=cta_url,
        detected_at=detected_at, domain=domain,
    )


def _render_generic(alert: dict, raw: dict, user_name: str) -> dict:
    """Fallback for any critical alert type we don't have a specific
    renderer for. Uses the alert's own title + message verbatim."""
    domain = alert.get("domain") or ""
    detected_at = _format_detected_at(alert)
    cta_url = _alert_url(alert["id"])
    title = alert.get("title") or "Critical alert"
    message = alert.get("message") or ""
    subject = f"Critical: {title}" + (f" &middot; {domain}" if domain else "")
    preview = message[:90]
    subtitle = f"Detected on {domain}" if domain else "Detected"
    return _format_output(
        subject=subject, preview=preview, sev_label="Critical", severity="critical",
        title=title, subtitle=subtitle,
        body_paragraphs=[message] if message else [],
        steps=["Open the alert in InboxScore for the full context and recommended next steps."],
        cta_label="View alert in InboxScore", cta_url=cta_url,
        detected_at=detected_at, domain=domain,
    )


def _format_output(
    *, subject: str, preview: str, sev_label: str, severity: str,
    title: str, subtitle: str, body_paragraphs: list,
    steps: list, cta_label: str, cta_url: str,
    detected_at: str, domain: str,
) -> dict:
    """Wrap content into shell + build matching plain text."""
    # Strip HTML escapes from subject/preview (these are header values)
    # Subject is plain text per RFC; we accept HTML entities but they
    # render literally in inbox lists — better to use plain text.
    plain_subject = subject.replace("&mdash;", "—").replace("&middot;", "·").replace("&rarr;", "→")
    plain_preview = preview.replace("&mdash;", "—").replace("&middot;", "·").replace("&rarr;", "→")

    body_html_parts = []
    for p in body_paragraphs:
        body_html_parts.append(
            f'<p style="margin:0 0 18px;font-size:15px;color:#27272a;line-height:1.65;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Helvetica,Arial,sans-serif;">{p}</p>'
        )
    body_html = "".join(body_html_parts) or '<p style="margin:0;"></p>'

    steps_html = ""
    if steps:
        rows = []
        for i, step in enumerate(steps, 1):
            rows.append(f"""
            <tr><td style="padding:0 0 12px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">
              <table role="presentation" cellspacing="0" cellpadding="0" border="0"><tr>
                <td style="width:20px;height:20px;background-color:#f4f4f5;color:#52525b;border-radius:50%;font-size:11px;font-weight:600;text-align:center;line-height:20px;font-family:inherit;">{i}</td>
                <td style="width:8px;font-size:1px;line-height:1px;">&nbsp;</td>
                <td style="font-size:14px;color:#27272a;line-height:1.55;font-family:inherit;">{step}</td>
              </tr></table>
            </td></tr>""")
        steps_html = f"""
        <tr><td class="card" style="padding:28px 32px 0;">
          <div style="font-size:12px;font-weight:600;color:#52525b;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:14px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">What to do</div>
          <table role="presentation" cellspacing="0" cellpadding="0" border="0">{''.join(rows)}</table>
        </td></tr>"""

    rendered = _render_shell(
        subject=plain_subject, preview=plain_preview,
        sev_label=sev_label, severity=severity,
        title=title, subtitle_html=subtitle,
        body_html=body_html, steps_html=steps_html,
        cta_label=cta_label, cta_url=cta_url,
        detected_at=detected_at, domain=domain,
    )

    # Plain text — strip HTML, decode entities
    plain_paragraphs = [_html_to_text(p) for p in body_paragraphs]
    plain_steps = [_html_to_text(s) for s in steps] if steps else None
    rendered["text"] = _build_text(
        sev_label=sev_label, title=title, subtitle=_html_to_text(subtitle),
        paragraphs=plain_paragraphs, steps=plain_steps,
        cta_label=cta_label, cta_url=cta_url,
        detected_at=detected_at, domain=domain,
    )
    rendered["subject"] = plain_subject
    rendered["preview"] = plain_preview
    return rendered


def _html_to_text(s: str) -> str:
    """Crude HTML-to-text for the plain version."""
    if not s:
        return ""
    # Replace common entities
    s = s.replace("&mdash;", "—").replace("&middot;", "·").replace("&rarr;", "→")
    s = s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"")
    # Strip simple tags
    import re
    s = re.sub(r"<[^>]+>", "", s)
    return s.strip()


# ─── MailerCloud API call ───────────────────────────────────────────


def _build_payload(
    *, to_email: str, to_name: str, subject: str,
    html_body: str, text_body: str, message_id: str,
) -> dict:
    """Build the MailerCloud Transactional API request body."""
    return {
        "email": {
            "from": ALERT_SENDER_EMAIL,
            "fromName": ALERT_SENDER_NAME,
            "replyTo": [ALERT_SENDER_EMAIL],
            "subject": subject,
            "text": text_body,
            "html": html_body,
            "recipients": {
                "to": [{"name": to_name, "email": to_email}],
            },
        },
        "metadata": {
            "campaignType": "TRANSACTIONAL",
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+0000"),
            "messageId": message_id,
        },
        "version": "1.0",
    }


def _call_mailercloud(payload: dict) -> dict:
    """POST to MailerCloud's transactional endpoint.
    Returns:
      {"status": "sent", "message_id": ...}
      {"status": "failed", "error_code": ..., "error_message": ...}
    """
    if not MAILERCLOUD_API_KEY:
        return {
            "status": "failed",
            "error_code": "no_api_key",
            "error_message": "MAILERCLOUD_API_KEY not configured",
        }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        MAILERCLOUD_API_URL,
        data=data,
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("Authorization", MAILERCLOUD_API_KEY)
    req.add_header("User-Agent", "InboxScore/1.0 (notifier.py)")

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
            try:
                data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                data = {}
            status_code = data.get("statusCode")
            if data.get("status") == "SUCCESS" or status_code == MC_STATUS_SUCCESS:
                return {
                    "status": "sent",
                    "message_id": payload.get("metadata", {}).get("messageId"),
                }
            return {
                "status": "failed",
                "error_code": str(status_code) if status_code is not None else "unknown",
                "error_message": data.get("message") or "MailerCloud returned non-success status",
            }
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("utf-8")
        except Exception:
            err_body = ""
        return {
            "status": "failed",
            "error_code": str(e.code),
            "error_message": (err_body or str(e))[:500],
        }
    except Exception as e:
        return {
            "status": "failed",
            "error_code": "network_error",
            "error_message": str(e)[:500],
        }
