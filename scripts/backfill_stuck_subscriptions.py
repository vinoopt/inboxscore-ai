#!/usr/bin/env python3
"""
Backfill stuck subscriptions — heal rows where local status diverged
from Stripe's truth.

Background (audit fix, 2026-05-15):
  The checkout.session.completed handler used to just log instead of
  upserting. As a result, when users paid via Checkout, their local
  subscriptions row stayed at plan='stub' / status='stub' forever
  even though Stripe had them at status='active'. This script finds
  those rows and re-runs the upsert from Stripe's current state.

Usage (from repo root or code/inboxscore/):
    python scripts/backfill_stuck_subscriptions.py [--dry-run]

Env required (same as production):
    STRIPE_SECRET_KEY        — Luvia UK live or test key
    SUPABASE_URL
    SUPABASE_SERVICE_ROLE_KEY

Behaviour:
  1. Fetch every subscriptions row that has a stripe_subscription_id.
  2. For each, fetch the live Subscription from Stripe.
  3. If Stripe's status differs from ours → call
     upsert_subscription_from_stripe to heal.
  4. Print a one-line summary per healed row.

Safe to re-run — upsert is idempotent.
"""
from __future__ import annotations

import os
import sys
import argparse


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing to the DB",
    )
    parser.add_argument(
        "--user-id",
        help="Restrict the backfill to a single user_id (debug)",
    )
    args = parser.parse_args()

    # Late imports so --help works without the env being set up.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import billing
    from db import (
        get_supabase, get_user_subscription, upsert_subscription_from_stripe,
    )

    sb = get_supabase()
    if not sb:
        print("ERROR: Supabase not available. Check SUPABASE_URL + SERVICE_ROLE_KEY.")
        return 2

    # Fetch every subscriptions row that has a stripe_subscription_id.
    query = sb.table("subscriptions").select(
        "user_id,stripe_subscription_id,plan,status,stripe_customer_id"
    ).not_.is_("stripe_subscription_id", "null")
    if args.user_id:
        query = query.eq("user_id", args.user_id)
    rows = query.execute().data or []

    print(f"Scanning {len(rows)} subscription rows with a Stripe sub ID...")

    healed = 0
    matched = 0
    errored = 0
    deleted_on_stripe = 0

    for row in rows:
        user_id = row["user_id"]
        sub_id = row["stripe_subscription_id"]
        local_plan = row.get("plan")
        local_status = row.get("status")

        try:
            stripe_sub = billing.retrieve_subscription(sub_id)
        except Exception as e:
            # Distinguish "subscription deleted on Stripe" (404) from
            # other failures. A 404 means the sub is fully gone on
            # Stripe's side — local row should be forced to stub state.
            msg = str(e)
            is_not_found = (
                "No such subscription" in msg
                or "404" in msg
                or "resource_missing" in msg
            )
            if is_not_found:
                print(
                    f"  [GONE]  {user_id} {sub_id}: deleted on Stripe — "
                    f"forcing local row to stub"
                )
                if not args.dry_run:
                    # Build a synthetic Stripe-shape payload so the upsert
                    # produces the right row state. force_stub=True ensures
                    # plan/status are 'stub' regardless of the synthetic
                    # status value.
                    synth = {
                        "id": sub_id,
                        "customer": row.get("stripe_customer_id"),
                        "status": "canceled",
                    }
                    if upsert_subscription_from_stripe(
                        user_id, synth, force_stub=True,
                        stripe_event_id=f"backfill-2026-05-15-gone",
                    ):
                        deleted_on_stripe += 1
                    else:
                        errored += 1
                else:
                    deleted_on_stripe += 1
                continue
            print(f"  [ERROR] {user_id} {sub_id}: retrieve failed — {type(e).__name__}: {e}")
            errored += 1
            continue

        stripe_status = stripe_sub.get("status")

        # Decide if we need to heal. We compare against the mapping that
        # upsert_subscription_from_stripe uses.
        from db import _STRIPE_STATUS_TO_PLAN
        expected_plan = _STRIPE_STATUS_TO_PLAN.get(stripe_status, "stub")

        needs_heal = (local_status != stripe_status) or (local_plan != expected_plan)
        if not needs_heal:
            matched += 1
            continue

        print(
            f"  [HEAL] {user_id} {sub_id}: "
            f"local={local_plan}/{local_status} → stripe={expected_plan}/{stripe_status}"
        )
        if args.dry_run:
            healed += 1
            continue

        ok = upsert_subscription_from_stripe(
            user_id, stripe_sub, stripe_event_id=f"backfill-2026-05-15"
        )
        if ok:
            healed += 1
        else:
            errored += 1

    print()
    print(
        f"Done. matched={matched}  healed={healed}  "
        f"deleted_on_stripe={deleted_on_stripe}  errored={errored}"
    )
    if args.dry_run:
        print("(dry-run — no DB writes)")
    return 0 if errored == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
