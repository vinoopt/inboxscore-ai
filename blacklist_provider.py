"""
InboxScore — Blacklist provider selector (INBOX-229 phase 2)

Single chokepoint that decides whether to use direct DNS (dnsbl.py)
or the HetrixTools API (hetrix.py) for a given user. Lets us
canary-deploy HetrixTools to specific users before flipping the
global flag.

Env vars consumed:
  USE_HETRIX_BL          — "true" / "1" to flip the global default
                           to HetrixTools. Default: dnsbl.
  HETRIX_CANARY_USER_IDS — comma-separated user UUIDs that get
                           HetrixTools regardless of global flag.
                           Used to test on Vinoop's account first
                           without affecting anyone else.

Both flags are read at call time (not module-load) so they can be
flipped via Render env-var changes without a redeploy of the code.
"""

import os
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)


def _env_truthy(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes", "on")


def _canary_user_ids() -> set[str]:
    raw = os.environ.get("HETRIX_CANARY_USER_IDS", "")
    return {u.strip() for u in raw.split(",") if u.strip()}


def use_hetrix_for_user(user_id: str | None) -> bool:
    """Decide whether to call HetrixTools or dnsbl for a given user.

    Resolution order (first true wins):
      1. user_id is in the canary list → HetrixTools
      2. USE_HETRIX_BL=true globally   → HetrixTools
      3. otherwise                      → dnsbl
    """
    if user_id and user_id in _canary_user_ids():
        return True
    return _env_truthy("USE_HETRIX_BL")


def get_full_blacklist_check_fn(user_id: str | None = None):
    """Return the right `full_blacklist_check(domain, ips)` function
    for the given user. Caller imports/calls the returned function
    exactly as they did before — same signature, same return shape.
    """
    if use_hetrix_for_user(user_id):
        from hetrix import full_blacklist_check
        return full_blacklist_check
    from dnsbl import full_blacklist_check
    return full_blacklist_check


# ─── Freshness gate ─────────────────────────────────────────────────
#
# HetrixTools costs 1 credit per call. The scheduled monitor cycle
# runs 4×/day per domain — that would burn 4 credits/day/domain. To
# fit our 5000/month budget (~5 users × 5 domains × 1×/day ≈ 25/day
# = 750/month), we cap blacklist refresh at once per 23 hours when
# HetrixTools is the active provider.
#
# dnsbl path is unconstrained (it's free + sub-second) so this gate
# only applies when use_hetrix_for_user() == True. The check is
# "did we last write a result for this (user, domain) within the
# past 23h?" If yes → skip. Otherwise → run.

_FRESHNESS_WINDOW = timedelta(hours=23)


def should_skip_blacklist_refresh(user_id: str, domain: str,
                                  last_checked_at: str | None) -> bool:
    """Return True if the cached blacklist_results row for this
    (user, domain) is still fresh and we should skip the API call.

    Always returns False for the dnsbl path so the existing 4×/day
    cadence keeps working. Only HetrixTools is rate-limited here.

    Args:
        user_id: the user we're scanning for
        domain: the domain being checked
        last_checked_at: ISO timestamp of the last blacklist_results
                         row for this (user, domain), or None if no
                         row exists yet (then we MUST run — first-time
                         check).
    """
    if not use_hetrix_for_user(user_id):
        # dnsbl: no rate limit. Always refresh on every monitor tick.
        return False

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
