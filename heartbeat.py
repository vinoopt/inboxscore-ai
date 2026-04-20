"""
Scheduler heartbeat recording + watchdog for InboxScore.

Purpose (INBOX-16 / INBOX-1 post-mortem):
  The monitor loop silently failed every 15 min for 42 days before anyone
  noticed. This module records a row at the start and end of every scheduler
  cycle so we can detect "scheduler stopped running" from fresh data in a
  table rather than log archaeology.

Design:
  - record_start(cycle_type) -> heartbeat UUID (INSERT, returns id)
  - record_end(hb_id, ...)  (UPDATE with completion data)
  - heartbeat_status()      returns the public status payload for the endpoint
  - watchdog_tick()         runs every 5 min via APScheduler; if any cycle is
                            stale (older than its threshold), emits a Sentry
                            error-level message. Sentry's existing alert rule
                            then emails the on-call.

Fail-loud but never fatal:
  ALL helpers swallow exceptions after logging — a broken heartbeat table
  must not crash the scheduler cycle that depends on it. If Supabase is
  unreachable, record_start returns None and record_end is a no-op.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("inboxscore.heartbeat")

# How long we tolerate silence from each cycle before considering it stale.
# - monitor runs every 15 min: one missed cycle = 30 min window
# - postmaster/snds run daily:  one missed day + 1h slack = 25 hours
STALENESS_MINUTES = {
    "monitor": 30,
    "postmaster_sync": 25 * 60,
    "snds_sync": 25 * 60,
}


def record_start(cycle_type: str) -> Optional[str]:
    """Insert a heartbeat row marking cycle start. Returns the new row's UUID.

    Returns None if DB is unavailable or the insert fails (intentionally — a
    broken heartbeat path must never stop the cycle itself).
    """
    from db import get_supabase
    sb = get_supabase()
    if not sb:
        logger.warning("heartbeat.start_skipped_no_db", extra={"cycle_type": cycle_type})
        return None
    try:
        result = sb.table("monitoring_heartbeats").insert({
            "cycle_type": cycle_type,
        }).execute()
        if result.data:
            hb_id = result.data[0].get("id")
            logger.info("heartbeat.start", extra={
                "cycle_type": cycle_type,
                "heartbeat_id": hb_id,
            })
            return hb_id
    except Exception as e:
        logger.error("heartbeat.start_failed", extra={
            "cycle_type": cycle_type,
            "error": str(e)[:200],
        })
    return None


def record_end(heartbeat_id: Optional[str],
               domains_processed: int = 0,
               errors_count: int = 0,
               notes: Optional[str] = None) -> None:
    """Patch the heartbeat row with completion data. No-op if hb_id is None."""
    if not heartbeat_id:
        return
    from db import get_supabase
    sb = get_supabase()
    if not sb:
        return
    try:
        payload = {
            "cycle_completed_at": datetime.now(timezone.utc).isoformat(),
            "domains_processed": int(domains_processed or 0),
            "errors_count": int(errors_count or 0),
        }
        if notes:
            payload["notes"] = str(notes)[:500]
        sb.table("monitoring_heartbeats").update(payload).eq("id", heartbeat_id).execute()
        logger.info("heartbeat.end", extra={
            "heartbeat_id": heartbeat_id,
            "domains_processed": payload["domains_processed"],
            "errors_count": payload["errors_count"],
        })
    except Exception as e:
        logger.error("heartbeat.end_failed", extra={
            "heartbeat_id": heartbeat_id,
            "error": str(e)[:200],
        })


def _latest_heartbeat(cycle_type: str) -> Optional[dict]:
    """Return the latest heartbeat row for a cycle_type, or None."""
    from db import get_supabase
    sb = get_supabase()
    if not sb:
        return None
    try:
        result = (sb.table("monitoring_heartbeats")
                  .select("*")
                  .eq("cycle_type", cycle_type)
                  .order("cycle_started_at", desc=True)
                  .limit(1)
                  .execute())
        return result.data[0] if result.data else None
    except Exception as e:
        logger.error("heartbeat.fetch_failed", extra={
            "cycle_type": cycle_type,
            "error": str(e)[:200],
        })
        return None


def _age_minutes(iso_ts: Optional[str]) -> Optional[float]:
    """Given an ISO-8601 timestamp string, return minutes since then."""
    if not iso_ts:
        return None
    try:
        # Tolerate trailing Z or explicit offset
        normalised = iso_ts.replace("Z", "+00:00") if iso_ts.endswith("Z") else iso_ts
        ts = datetime.fromisoformat(normalised)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        delta = datetime.now(timezone.utc) - ts
        return delta.total_seconds() / 60.0
    except Exception:
        return None


def heartbeat_status() -> dict:
    """Build the payload for /api/monitoring/heartbeat-status.

    Returns a dict shaped like:
        {
            "overall_status": "ok" | "stale" | "unknown",
            "checked_at": "<ISO-8601>",
            "cycles": {
                "monitor": {
                    "status": "ok"|"stale"|"unknown",
                    "last_started_at": "<ISO-8601>"|None,
                    "last_completed_at": "<ISO-8601>"|None,
                    "age_minutes": 12.34|None,
                    "threshold_minutes": 30,
                    "domains_processed": 5|None,
                    "errors_count": 0|None
                },
                ...
            }
        }
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    cycles: dict = {}
    overall = "ok"

    for cycle_type, threshold in STALENESS_MINUTES.items():
        latest = _latest_heartbeat(cycle_type)
        if not latest:
            cycles[cycle_type] = {
                "status": "unknown",
                "last_started_at": None,
                "last_completed_at": None,
                "age_minutes": None,
                "threshold_minutes": threshold,
                "domains_processed": None,
                "errors_count": None,
            }
            if overall == "ok":
                overall = "unknown"
            continue

        started_at = latest.get("cycle_started_at")
        age = _age_minutes(started_at)
        is_stale = age is None or age > threshold
        status = "stale" if is_stale else "ok"
        cycles[cycle_type] = {
            "status": status,
            "last_started_at": started_at,
            "last_completed_at": latest.get("cycle_completed_at"),
            "age_minutes": round(age, 2) if age is not None else None,
            "threshold_minutes": threshold,
            "domains_processed": latest.get("domains_processed"),
            "errors_count": latest.get("errors_count"),
        }
        if status == "stale":
            overall = "stale"

    return {
        "overall_status": overall,
        "checked_at": now_iso,
        "cycles": cycles,
    }


def watchdog_tick() -> None:
    """Runs every 5 min via APScheduler.

    Fires a Sentry error-level message if any scheduler cycle is stale.
    Sentry dedupes so repeat-stale won't spam (one alert per issue-fingerprint).
    """
    try:
        report = heartbeat_status()
    except Exception as e:
        logger.error("watchdog.tick_failed", extra={"error": str(e)[:200]})
        return

    overall = report.get("overall_status")
    stale_cycles = [name for name, data in report.get("cycles", {}).items()
                    if data.get("status") == "stale"]

    if overall == "stale" and stale_cycles:
        msg = f"Scheduler watchdog: stale cycle(s) — {', '.join(stale_cycles)}"
        logger.error("watchdog.stale", extra={
            "stale_cycles": stale_cycles,
            "report": report,
        })
        try:
            import sentry_sdk
            sentry_sdk.set_tag("component", "watchdog")
            for name in stale_cycles:
                sentry_sdk.set_tag(f"stale_{name}", "true")
            sentry_sdk.set_context("heartbeat_report", report)
            sentry_sdk.capture_message(msg, level="error")
        except ImportError:
            # Sentry SDK not installed (dev mode) — local log is the only signal
            pass
        except Exception as e:
            logger.error("watchdog.sentry_send_failed", extra={"error": str(e)[:200]})
    else:
        logger.info("watchdog.ok", extra={"overall_status": overall})
