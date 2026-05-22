"""
InboxScore — Postmaster alert comparison (INBOX-270, 2026-05-20)

Compares yesterday's postmaster_metrics row to today's for each (user, domain)
pair after the daily Postmaster sync writes new data. Creates alerts when
threshold crossings happen.

Triggers covered (Tier 1 mandatory from INBOX-270 scope):
  • Gmail spam rate crosses 0.1% (warning)
  • Gmail spam rate crosses 0.3% (critical — Gmail's enforcement threshold)
  • Gmail domain reputation tier transition (HIGH → MEDIUM/LOW/BAD)
  • Gmail IP reputation tier transition (per-IP, same ladder)
  • Gmail SPF auth pass rate < 99% (warning) / < 95% (critical)
  • Gmail DKIM auth pass rate < 99% (warning) / < 95% (critical)
  • Gmail DMARC auth pass rate < 99% (warning) / < 95% (critical)

Design rule — alerts fire on TRANSITIONS, not on persistent state. A spam
rate sitting at 0.18% for three days should fire ONE alert on day 1, not
three alerts. The comparison logic only triggers when yesterday's value
was below the threshold AND today's value is above (or vice versa for
positive recovery alerts).

Called from postmaster_scheduler.py after fetch_metrics_for_user completes
for each user — see hook there. Failures inside this module never crash
the sync cycle (all exceptions caught + logged to Sentry via
_alerts_log.exception).
"""

import logging
from typing import Iterable, Optional

from db import create_alert, get_postmaster_metrics


_log = logging.getLogger("inboxscore.alerts.postmaster")


# ─── Thresholds + tier ordering ─────────────────────────────────────

# Spam rate thresholds (Postmaster reports as 0.0-1.0).
SPAM_RATE_WARNING = 0.001   # 0.1%
SPAM_RATE_CRITICAL = 0.003  # 0.3% — Gmail's enforcement threshold

# Auth pass rate thresholds (Postmaster reports as 0.0-1.0).
AUTH_WARNING = 0.99   # below this = warning
AUTH_CRITICAL = 0.95  # below this = critical

# Reputation tier ordering — best to worst. Used for tier-transition
# detection. Postmaster returns uppercase strings; we normalise.
REPUTATION_TIERS = ["HIGH", "MEDIUM", "LOW", "BAD"]
_REP_RANK = {tier: idx for idx, tier in enumerate(REPUTATION_TIERS)}


def _tier_rank(tier: Optional[str]) -> Optional[int]:
    if not tier or not isinstance(tier, str):
        return None
    return _REP_RANK.get(tier.upper())


def _pct(x: float) -> str:
    """Format a 0-1 float as a 1-decimal percentage."""
    if x is None:
        return "?"
    return f"{x * 100:.2f}%"


# ─── Per-metric comparison helpers ──────────────────────────────────


def _check_spam_rate(yesterday: dict, today: dict, domain: str) -> list:
    """Spam rate threshold crossings."""
    y = yesterday.get("spam_rate") if yesterday else None
    t = today.get("spam_rate") if today else None
    if t is None:
        return []  # no traffic today — no alert

    changes = []

    # Crossed into critical (0.3%)
    if t >= SPAM_RATE_CRITICAL and (y is None or y < SPAM_RATE_CRITICAL):
        changes.append({
            "type": "reputation_change",
            "severity": "critical",
            "title": f"Gmail spam rate exceeded 0.3% ({_pct(t)})",
            "message": (
                f"{domain}'s Gmail spam rate is now {_pct(t)}, above Gmail's "
                f"enforcement threshold of 0.3%. Mail is likely being blocked "
                f"or routed to spam at scale. Pause campaigns and investigate "
                f"send-list hygiene immediately."
            ),
        })
    # Crossed into warning (0.1%) but not critical
    elif t >= SPAM_RATE_WARNING and (y is None or y < SPAM_RATE_WARNING):
        changes.append({
            "type": "reputation_change",
            "severity": "warning",
            "title": f"Gmail spam rate above 0.1% ({_pct(t)})",
            "message": (
                f"{domain}'s Gmail spam rate is now {_pct(t)}, above the "
                f"warning threshold of 0.1%. At 0.3% Gmail starts blocking. "
                f"Review recent campaigns for content/list issues."
            ),
        })
    # Crossed BACK below the warning threshold — positive
    elif (t < SPAM_RATE_WARNING and y is not None
          and y >= SPAM_RATE_WARNING):
        changes.append({
            "type": "reputation_change",
            "severity": "info",
            "title": f"Gmail spam rate recovered to {_pct(t)}",
            "message": (
                f"{domain}'s Gmail spam rate is now below 0.1% "
                f"(from {_pct(y)} yesterday). Whatever you changed is working."
            ),
        })

    return changes


def _check_domain_reputation(yesterday: dict, today: dict, domain: str) -> list:
    """Domain reputation tier transitions."""
    y_tier = yesterday.get("domain_reputation") if yesterday else None
    t_tier = today.get("domain_reputation") if today else None
    y_rank = _tier_rank(y_tier)
    t_rank = _tier_rank(t_tier)
    if y_rank is None or t_rank is None or y_rank == t_rank:
        return []

    if t_rank > y_rank:
        # Dropped to a worse tier
        severity = "critical" if t_tier.upper() == "BAD" else "warning"
        return [{
            "type": "reputation_change",
            "severity": severity,
            "title": f"Gmail domain reputation dropped: {y_tier} → {t_tier}",
            "message": (
                f"{domain}'s domain reputation at Gmail dropped from "
                f"{y_tier} to {t_tier}. This directly affects inbox "
                f"placement for everything you send from this domain."
            ),
        }]
    # Recovered to a better tier
    return [{
        "type": "reputation_change",
        "severity": "info",
        "title": f"Gmail domain reputation improved: {y_tier} → {t_tier}",
        "message": (
            f"{domain}'s domain reputation at Gmail improved from "
            f"{y_tier} to {t_tier}. Sustained good sending is paying off."
        ),
    }]


def _check_ip_reputation(yesterday: dict, today: dict, domain: str) -> list:
    """Per-IP reputation tier transitions.

    ip_reputation is stored as a JSONB list of {ip, reputation, ...}.
    upsert_postmaster_metrics dumps it as a JSON string, so it may be
    str or list depending on how it was read back.
    """
    import json

    def _parse(blob):
        if not blob:
            return []
        if isinstance(blob, str):
            try:
                return json.loads(blob)
            except Exception:
                return []
        if isinstance(blob, list):
            return blob
        return []

    y_list = _parse(yesterday.get("ip_reputation") if yesterday else None)
    t_list = _parse(today.get("ip_reputation") if today else None)
    if not t_list:
        return []

    y_by_ip = {
        item.get("ip"): item.get("reputation")
        for item in y_list if isinstance(item, dict) and item.get("ip")
    }

    changes = []
    for item in t_list:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        t_tier = item.get("reputation")
        if not ip or not t_tier:
            continue
        y_tier = y_by_ip.get(ip)
        y_rank = _tier_rank(y_tier)
        t_rank = _tier_rank(t_tier)
        if y_rank is None or t_rank is None or y_rank == t_rank:
            continue
        if t_rank > y_rank:
            severity = "critical" if t_tier.upper() == "BAD" else "warning"
            changes.append({
                "type": "reputation_change",
                "severity": severity,
                "title": f"Gmail IP reputation dropped on {ip}: {y_tier} → {t_tier}",
                "message": (
                    f"Sending IP {ip} (for {domain}) dropped from {y_tier} "
                    f"to {t_tier} reputation at Gmail. Inbox placement from "
                    f"this IP will suffer."
                ),
            })
        else:
            changes.append({
                "type": "reputation_change",
                "severity": "info",
                "title": f"Gmail IP reputation improved on {ip}: {y_tier} → {t_tier}",
                "message": (
                    f"Sending IP {ip} (for {domain}) recovered from {y_tier} "
                    f"to {t_tier} reputation at Gmail."
                ),
            })
    return changes


def _check_auth_pass_rate(
    yesterday: dict, today: dict, domain: str,
    column: str, label: str,
) -> list:
    """Generic auth pass-rate threshold logic for SPF / DKIM / DMARC.

    Fires when crossing 99% (warning) or 95% (critical) threshold.
    """
    y = yesterday.get(column) if yesterday else None
    t = today.get(column) if today else None
    if t is None:
        return []

    # Determine yesterday + today buckets
    def _bucket(rate):
        if rate is None:
            return None
        if rate < AUTH_CRITICAL:
            return "critical"
        if rate < AUTH_WARNING:
            return "warning"
        return "ok"

    y_bucket = _bucket(y)
    t_bucket = _bucket(t)
    if y_bucket == t_bucket:
        return []

    if t_bucket == "critical":
        return [{
            "type": "reputation_change",
            "severity": "critical",
            "title": f"Gmail {label} pass rate below 95% ({_pct(t)})",
            "message": (
                f"{domain}'s {label} authentication pass rate at Gmail "
                f"dropped to {_pct(t)} (was {_pct(y)} yesterday). Below "
                f"95% strongly suggests a misconfigured sender or a third-"
                f"party tool sending without proper authentication."
            ),
        }]
    if t_bucket == "warning":
        return [{
            "type": "reputation_change",
            "severity": "warning",
            "title": f"Gmail {label} pass rate below 99% ({_pct(t)})",
            "message": (
                f"{domain}'s {label} authentication pass rate at Gmail "
                f"dropped to {_pct(t)} (was {_pct(y)} yesterday). Investigate "
                f"which sender or campaign is failing authentication."
            ),
        }]
    # t_bucket == "ok" — recovered
    return [{
        "type": "reputation_change",
        "severity": "info",
        "title": f"Gmail {label} pass rate recovered to {_pct(t)}",
        "message": (
            f"{domain}'s {label} pass rate at Gmail is now {_pct(t)} "
            f"(was {_pct(y)} yesterday)."
        ),
    }]


# ─── Public entry point ─────────────────────────────────────────────


def compare_and_alert_postmaster(
    user_id: str,
    domains: Iterable[str],
) -> int:
    """For each domain, compare yesterday's vs today's postmaster_metrics
    and create alerts for any threshold crossings.

    Returns the total number of alerts created across all domains. Never
    raises — every failure is caught and logged via _log.exception so the
    enclosing sync cycle is unaffected.

    Called from postmaster_scheduler.sync_all_postmaster_users after
    fetch_metrics_for_user has written today's metrics for each user.
    """
    total_created = 0
    for domain in domains:
        try:
            # Fetch last 2 days of metrics (yesterday + today)
            rows = get_postmaster_metrics(user_id, domain, days=2)
            if len(rows) < 2:
                # Need at least 2 rows to detect a transition
                continue

            # get_postmaster_metrics returns ascending by date; the last
            # row is today.
            today_row = rows[-1]
            yesterday_row = rows[-2]

            # Sanity: today must be strictly more recent than yesterday
            if today_row.get("date") == yesterday_row.get("date"):
                continue

            changes = []
            changes.extend(_check_spam_rate(yesterday_row, today_row, domain))
            changes.extend(_check_domain_reputation(yesterday_row, today_row, domain))
            changes.extend(_check_ip_reputation(yesterday_row, today_row, domain))
            changes.extend(_check_auth_pass_rate(
                yesterday_row, today_row, domain,
                column="auth_success_spf", label="SPF"))
            changes.extend(_check_auth_pass_rate(
                yesterday_row, today_row, domain,
                column="auth_success_dkim", label="DKIM"))
            changes.extend(_check_auth_pass_rate(
                yesterday_row, today_row, domain,
                column="auth_success_dmarc", label="DMARC"))

            for change in changes:
                alert = create_alert(
                    user_id=user_id,
                    alert_type=change["type"],
                    severity=change["severity"],
                    title=change["title"],
                    message=change["message"],
                    domain=domain,
                    # INBOX-144: structured payload for notifier.py.
                    # alerts_postmaster doesn't currently populate this,
                    # so the email falls back to the generic renderer
                    # using title/message verbatim — acceptable for v1.
                    raw_data=change.get("raw_data"),
                )
                if alert:
                    total_created += 1
                    # INBOX-144: fire critical-alert email via notifier.
                    try:
                        from notifier import send_alert_email
                        send_alert_email(user_id, alert)
                    except Exception:
                        _log.exception("alerts.postmaster.notifier_hook_failed", extra={
                            "user_id_prefix": user_id[:8] if user_id else None,
                            "alert_id": alert.get("id"),
                            "domain": domain,
                        })

        except Exception:
            _log.exception("alerts.postmaster.compare_failed", extra={
                "user_id_prefix": user_id[:8] if user_id else None,
                "domain": domain,
            })

    return total_created
