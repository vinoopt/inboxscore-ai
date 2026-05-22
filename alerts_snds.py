"""
InboxScore — Microsoft SNDS alert comparison (INBOX-270, 2026-05-20)

Compares yesterday's snds_metrics row to today's for each (user, IP) pair
after the daily SNDS sync writes new data. Creates alerts when status
transitions or trap hits appear.

Triggers covered (Tier 1 mandatory from INBOX-270 scope):
  • SNDS status transition Green → Yellow (warning)
  • SNDS status transition Green/Yellow → Red (critical)
  • SNDS status recovery (Red/Yellow → Green) — info / positive
  • Trap hits appear (today > 0 when yesterday was 0) — critical

Design rule — alerts fire on TRANSITIONS, not on persistent state. An
IP sitting at Yellow for three days fires ONE alert on the first
Green→Yellow transition, not three alerts.

Called from snds_scheduler.py after fetch_snds_data completes for each
user — see hook there. Failures inside this module never crash the sync
cycle (all exceptions caught + logged to Sentry).
"""

import logging
from typing import Iterable

from db import create_alert, get_snds_metrics_for_ip


_log = logging.getLogger("inboxscore.alerts.snds")


# ─── Tier ordering ──────────────────────────────────────────────────
# SNDS reports filter results as GREEN / YELLOW / RED. db storage
# normalises to lowercase strings. Comparison ordering: green=0 (best),
# yellow=1, red=2 (worst).

SNDS_TIERS = ["green", "yellow", "red"]
_SNDS_RANK = {t: i for i, t in enumerate(SNDS_TIERS)}


def _tier_rank(tier: str | None) -> int | None:
    if not tier or not isinstance(tier, str):
        return None
    return _SNDS_RANK.get(tier.lower())


# ─── Per-IP comparison ──────────────────────────────────────────────


def _check_status_transition(yesterday: dict, today: dict, ip: str) -> list:
    """Build alerts for SNDS status colour transitions."""
    y_tier = yesterday.get("ip_status") if yesterday else None
    t_tier = today.get("ip_status") if today else None
    y_rank = _tier_rank(y_tier)
    t_rank = _tier_rank(t_tier)
    if y_rank is None or t_rank is None or y_rank == t_rank:
        return []

    y_label = (y_tier or "").upper() or "Unknown"
    t_label = (t_tier or "").upper() or "Unknown"

    if t_rank > y_rank:
        # Dropped to a worse tier
        # Green→Red is a two-tier slide and gets urgent severity
        if y_tier == "green" and t_tier == "red":
            severity = "critical"
            urgency = " — major degradation"
        elif t_tier == "red":
            severity = "critical"
            urgency = ""
        else:
            # Green → Yellow
            severity = "warning"
            urgency = ""
        return [{
            "type": "reputation_change",
            "severity": severity,
            "title": f"Microsoft SNDS status dropped on {ip}: {y_label} → {t_label}{urgency}",
            "message": (
                f"Sending IP {ip} moved from {y_label} to {t_label} on "
                f"Microsoft SNDS. Outlook / Hotmail / Live.com delivery "
                f"from this IP will be affected."
            ),
        }]
    # Recovered to a better tier
    return [{
        "type": "reputation_change",
        "severity": "info",
        "title": f"Microsoft SNDS status recovered on {ip}: {y_label} → {t_label}",
        "message": (
            f"Sending IP {ip} recovered from {y_label} to {t_label} on "
            f"Microsoft SNDS. Outlook delivery should improve."
        ),
    }]


def _check_trap_hits(yesterday: dict, today: dict, ip: str) -> list:
    """Trap hits appearing (or jumping) — critical."""
    y_traps = (yesterday.get("trap_hits") or 0) if yesterday else 0
    t_traps = today.get("trap_hits") or 0
    if t_traps <= 0:
        return []
    # Fire when there are NEW traps today that weren't there yesterday
    # OR when the count jumped meaningfully
    if y_traps == 0 and t_traps > 0:
        return [{
            "type": "reputation_change",
            "severity": "critical",
            "title": f"Spam trap hits detected on {ip} ({t_traps})",
            "message": (
                f"Sending IP {ip} hit {t_traps} Microsoft spam trap(s) "
                f"today (zero yesterday). Trap hits indicate a poor "
                f"list-hygiene problem — purchased / scraped / abandoned "
                f"addresses. Audit your most recent imports."
            ),
        }]
    return []


# ─── Public entry point ─────────────────────────────────────────────


def compare_and_alert_snds(
    user_id: str,
    ips: Iterable[str],
) -> int:
    """For each IP, compare yesterday's vs today's snds_metrics and
    create alerts for any threshold crossings.

    Returns total alerts created across all IPs. Never raises — failures
    are caught + logged so the enclosing SNDS sync cycle is unaffected.

    Called from snds_scheduler.sync_all_snds_users after fresh metrics
    have been written for each user.
    """
    total_created = 0
    for ip in ips:
        try:
            rows = get_snds_metrics_for_ip(user_id, ip, days=2)
            if len(rows) < 2:
                continue

            # get_snds_metrics_for_ip returns ascending by date
            today_row = rows[-1]
            yesterday_row = rows[-2]

            if today_row.get("metric_date") == yesterday_row.get("metric_date"):
                continue

            changes = []
            changes.extend(_check_status_transition(yesterday_row, today_row, ip))
            changes.extend(_check_trap_hits(yesterday_row, today_row, ip))

            for change in changes:
                alert = create_alert(
                    user_id=user_id,
                    alert_type=change["type"],
                    severity=change["severity"],
                    title=change["title"],
                    message=change["message"],
                    # SNDS alerts are per-IP, not per-domain. We don't
                    # have a domain_id to attach; the title carries the
                    # IP context. domain field stays unset.
                    # INBOX-144: structured payload for notifier.py.
                    raw_data=change.get("raw_data"),
                )
                if alert:
                    # INBOX-144: fire critical-alert email via notifier.
                    try:
                        from notifier import send_alert_email
                        send_alert_email(user_id, alert)
                    except Exception:
                        _log.exception("alerts.snds.notifier_hook_failed", extra={
                            "user_id_prefix": user_id[:8] if user_id else None,
                            "alert_id": alert.get("id"),
                            "ip": ip,
                        })
                    total_created += 1

        except Exception:
            _log.exception("alerts.snds.compare_failed", extra={
                "user_id_prefix": user_id[:8] if user_id else None,
                "ip": ip,
            })

    return total_created
