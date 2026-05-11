"""
InboxScore — Blacklist provider chokepoint

INBOX-229 phase 3 (2026-05-11): consolidated on HetrixTools for ALL
blacklist queries product-wide. dnsbl.py is retained as a file (no
callers) until we're confident in the migration; the public/full-
depth scan split lives as a follow-up Plane task.

This module is the single import point for callers that need a
blacklist-check function. It also owns the 23-hour freshness gate
that protects HetrixTools credits on the scheduled monitor path.

Why we keep the helper layer instead of importing hetrix everywhere:
  - One place to bolt on the freshness gate (used only by monitor.py).
  - One place to add per-user routing later (e.g., free-tier reads
    from cache, paid-tier gets live calls).
  - One place to add an anonymous-cache layer (Plane task: anonymous
    scans cached by domain only).
"""

import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


def use_hetrix_for_user(user_id: str | None) -> bool:
    """Provider selector.

    INBOX-229 phase 3: always returns True now — every caller in the
    product uses HetrixTools. We keep the function (and the user_id
    parameter) so the future routing layer has a clean injection
    point. When we add anonymous-cache or per-tier behaviour, only
    this function changes.
    """
    _ = user_id  # reserved for future per-user routing
    return True


def get_full_blacklist_check_fn(user_id: str | None = None):
    """Return the `full_blacklist_check(domain, ips)` function. Today
    this is always hetrix; the helper exists so callers don't have
    to change when we add routing later."""
    _ = user_id
    from hetrix import full_blacklist_check
    return full_blacklist_check


# ─── Freshness gate ─────────────────────────────────────────────────
#
# HetrixTools costs 1 credit per call. The scheduled monitor cycle
# runs 4×/day per domain — that would burn 4 credits/day/domain. To
# fit our 5000/month budget, we cap blacklist refresh at once per 23
# hours when called from the scheduler.
#
# The freshness gate is OPT-IN — only monitor.py applies it. User-
# facing scan paths (app.py /api/scan, /api/blacklist/check) always
# run live so the user sees fresh data when they click "Scan now".

_FRESHNESS_WINDOW = timedelta(hours=23)


def should_skip_blacklist_refresh(user_id: str, domain: str,
                                  last_checked_at: str | None) -> bool:
    """Return True if the cached blacklist_results row for this
    (user, domain) is still fresh and the scheduler should skip the
    API call.

    Args:
        user_id: the user we're scanning for
        domain: the domain being checked
        last_checked_at: ISO timestamp of the last blacklist_results
                         row for this (user, domain), or None if no
                         row exists yet (then we MUST run — first-time
                         check).
    """
    if not last_checked_at:
        # Never checked → must run.
        return False

    try:
        if isinstance(last_checked_at, str):
            iso = last_checked_at.replace("Z", "+00:00")
            last_dt = datetime.fromisoformat(iso)
            if last_dt.tzinfo is None:
                last_dt = last_dt.replace(tzinfo=timezone.utc)
        else:
            last_dt = last_checked_at
    except (ValueError, TypeError) as e:
        # Unparseable timestamp → log + run (be safe, don't skip).
        logger.warning("blacklist_provider.unparseable_timestamp",
                       extra={"last_checked_at": last_checked_at,
                              "error": str(e)})
        return False

    age = datetime.now(timezone.utc) - last_dt
    return age < _FRESHNESS_WINDOW
