"""
InboxScore - SNDS Sync Scheduler
Daily background job that fetches Microsoft SNDS data for all connected users.
"""

import asyncio
from datetime import datetime

from db import (
    is_db_available, get_all_snds_connections,
    upsert_snds_metrics, update_snds_sync_status
)
from snds import fetch_snds_data


def sync_all_snds_users():
    """
    Sync SNDS data for all connected users.
    Called by APScheduler daily at 7 AM UTC.
    Runs the async fetch in a new event loop since APScheduler uses sync threads.
    """
    try:
        if not is_db_available():
            print("[SNDS Sync] Database not available, skipping")
            return

        connections = get_all_snds_connections()
        if not connections:
            print("[SNDS Sync] No connected users, skipping")
            return

        print(f"[SNDS Sync] Starting sync for {len(connections)} user(s)")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            for conn in connections:
                user_id = conn["user_id"]
                snds_key = conn["snds_key"]

                try:
                    result = loop.run_until_complete(fetch_snds_data(snds_key))

                    if not result["success"]:
                        print(f"[SNDS Sync] User {user_id[:8]}...: fetch failed — {result['error']}")
                        continue

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

                    # Update connection sync status
                    update_snds_sync_status(user_id, ip_count=len(ip_set))

                    print(f"[SNDS Sync] User {user_id[:8]}...: "
                          f"{len(ip_set)} IPs, {metrics_saved} metrics saved")

                except Exception as e:
                    print(f"[SNDS Sync] Error for user {user_id[:8]}...: {e}")

        finally:
            loop.close()

        print("[SNDS Sync] Sync complete")

    except Exception as e:
        print(f"[SNDS Sync] CRITICAL — scheduler job crashed: {e}")
        import traceback
        traceback.print_exc()
