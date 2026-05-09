"""INBOX-211 — preview / verify zero-traffic backfill on postmaster_metrics.

Run BEFORE applying migrations/013_postmaster_zero_traffic_backfill.sql to
see how many rows will be affected, and AFTER to confirm the cleanup
landed. Read-only — never writes.

Usage:
    cd code/inboxscore && python scripts/inbox211_zero_traffic_report.py

Requires SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY in the environment
(same as the running app uses).
"""

import os
import sys

# Allow `import db` from the repo root.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import get_supabase  # noqa: E402


def main() -> None:
    sb = get_supabase()
    if not sb:
        print("[INBOX-211] Supabase client unavailable — check env vars")
        sys.exit(1)

    # 1. How many rows match the zero-traffic signature today?
    res = sb.table("postmaster_metrics").select(
        "user_id,domain,date", count="exact"
    ).eq("auth_success_dmarc", 0).eq("encrypted_traffic_tls", 0).execute()
    pending_count = res.count if hasattr(res, "count") else len(res.data or [])
    print(f"[INBOX-211] rows still matching zero-traffic signature: {pending_count}")

    # Sample 5 so Vinoop can eyeball them.
    sample = (res.data or [])[:5]
    if sample:
        print("[INBOX-211] sample (first 5):")
        for r in sample:
            print(f"    domain={r.get('domain'):<40} date={r.get('date')}")

    # 2. How many rows have already been backfilled (the JSON tag)?
    #    Use the `like` filter on the JSON-as-text representation. Supabase
    #    doesn't expose JSON-path operators via the PostgREST surface, so
    #    we rely on the textual presence of the tag.
    res2 = sb.table("postmaster_metrics").select(
        "user_id,domain,date", count="exact"
    ).like("delivery_errors", "%_zero_traffic%").execute()
    done_count = res2.count if hasattr(res2, "count") else len(res2.data or [])
    print(f"[INBOX-211] rows already tagged _zero_traffic: {done_count}")

    # 3. Total rows in the table (context — for sanity-check ratios).
    res3 = sb.table("postmaster_metrics").select("date", count="exact").execute()
    total = res3.count if hasattr(res3, "count") else len(res3.data or [])
    print(f"[INBOX-211] total postmaster_metrics rows: {total}")

    if pending_count == 0:
        print("[INBOX-211] ✅ no pending rows — backfill complete (or never needed)")
    else:
        print(f"[INBOX-211] ⚠ {pending_count} rows still need the backfill SQL run")


if __name__ == "__main__":
    main()
