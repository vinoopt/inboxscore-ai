"""
InboxScore - Postmaster Sync Scheduler
Daily background job that fetches Google Postmaster metrics for all connected users.
"""

import asyncio
from datetime import datetime

from db import (
    is_db_available, get_all_postmaster_connections,
    log_postmaster_sync
)
from postmaster import fetch_metrics_for_user


def sync_all_postmaster_users():
    """
    Sync Postmaster data for all connected users.
    Called by APScheduler daily at 6 AM UTC.
    Runs the async fetch in a new event loop since APScheduler uses sync threads.
    """
    # INBOX-16: heartbeat so the watchdog can detect silent scheduler failures
    from heartbeat import record_start, record_end
    hb_id = record_start("postmaster_sync")
    users_processed = 0
    users_failed = 0

    try:
        if not is_db_available():
            print("[Postmaster Sync] Database not available, skipping")
            record_end(hb_id, domains_processed=0, errors_count=0, notes="db unavailable")
            return

        connections = get_all_postmaster_connections()
        if not connections:
            print("[Postmaster Sync] No connected users, skipping")
            record_end(hb_id, domains_processed=0, errors_count=0, notes="no connected users")
            return

        print(f"[Postmaster Sync] Starting sync for {len(connections)} user(s)")

        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            for conn in connections:
                user_id = conn["user_id"]
                sync_started = datetime.utcnow().isoformat()

                try:
                    result = loop.run_until_complete(
                        fetch_metrics_for_user(user_id, conn, days=7)
                    )

                    status = "success" if not result["errors"] else "partial"
                    error_msg = "; ".join(result["errors"]) if result["errors"] else None

                    log_postmaster_sync(
                        user_id=user_id,
                        status=status,
                        domains_synced=result["domains_synced"],
                        error_message=error_msg,
                        sync_started_at=sync_started,
                    )

                    users_processed += 1
                    if status == "partial":
                        users_failed += 1

                    print(f"[Postmaster Sync] User {user_id[:8]}...: "
                          f"{result['domains_synced']} domains, "
                          f"{result['metrics_saved']} metrics, "
                          f"status={status}")

                except Exception as e:
                    users_failed += 1
                    print(f"[Postmaster Sync] Error for user {user_id[:8]}...: {e}")
                    log_postmaster_sync(
                        user_id=user_id,
                        status="failed",
                        error_message=str(e),
                        sync_started_at=sync_started,
                    )
        finally:
            loop.close()

        print("[Postmaster Sync] Sync complete")
        record_end(hb_id, domains_processed=users_processed, errors_count=users_failed)

    except Exception as e:
        print(f"[Postmaster Sync] CRITICAL — scheduler job crashed: {e}")
        import traceback
        traceback.print_exc()
        record_end(hb_id, domains_processed=users_processed, errors_count=users_failed + 1,
                   notes=f"cycle crashed: {str(e)[:200]}")
