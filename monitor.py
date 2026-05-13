"""
InboxScore - Domain Monitoring Scheduler
Background job that re-scans monitored domains and creates alerts on changes.

INBOX-21 (2026-04-20): The previous local `run_domain_scan` was deleted.
Scan composition now lives in `scan_service.run_full_scan` so the monitor
and the HTTP handler share a single orchestrator (fixes INBOX-3 — monitor
was missing `check_ip_reputation` — and kills the divergent-behaviour
class of bugs at the source).
"""

import logging
import time
from datetime import datetime

from db import (
    is_db_available, get_domains_due_for_scan, save_scan,
    update_domain_after_monitor_scan, save_monitoring_log,
    create_alert, get_scan_detail,
    # INBOX-205: scheduled scans now refresh the blacklist_results table
    # so /blacklist Monitor page stays current. Previously only manual
    # scans (/api/blacklist/check) populated this table — meaning the
    # cron silently improved scan history but the standalone Blacklist
    # Monitor page kept showing whatever timestamp the user last clicked.
    get_ips_for_domain, save_blacklist_results,
    # INBOX-229 phase 2: freshness check reads the cached row's
    # checked_at timestamp before deciding to spend a HetrixTools
    # credit. dnsbl path bypasses the gate (always refreshes).
    get_blacklist_results,
)
from blacklist_provider import (
    get_full_blacklist_check_fn,
    should_skip_blacklist_refresh,
)
from scan_service import run_full_scan

# INBOX-28: use stdlib logging so Sentry's LoggingIntegration captures
# unhandled-in-background errors. `logger.exception(...)` emits at ERROR
# level with the traceback attached, which Sentry ships as an event.
logger = logging.getLogger(__name__)


def compare_scan_results(old_scan: dict, new_result: dict, domain_data: dict) -> list:
    """
    Compare old scan with new scan and detect meaningful changes.
    Returns a list of change dicts with type, severity, and description.
    """
    changes = []
    old_score = domain_data.get("latest_score")
    new_score = new_result["score"]
    alert_threshold = domain_data.get("alert_threshold") or 70

    # ── Score drop detection ──
    if old_score is not None and new_score < old_score:
        drop = old_score - new_score
        if drop >= 15:
            changes.append({
                "type": "score_drop",
                "severity": "critical",
                "title": f"Score dropped {drop} points",
                "message": f"{domain_data['domain']} score fell from {old_score} to {new_score} (−{drop} points)."
            })
        elif drop >= 5:
            changes.append({
                "type": "score_drop",
                "severity": "warning",
                "title": f"Score dropped {drop} points",
                "message": f"{domain_data['domain']} score fell from {old_score} to {new_score} (−{drop} points)."
            })

    # ── Score below threshold ──
    if new_score < alert_threshold and (old_score is None or old_score >= alert_threshold):
        changes.append({
            "type": "score_drop",
            "severity": "critical",
            "title": f"Score below threshold ({alert_threshold})",
            "message": f"{domain_data['domain']} score is {new_score}, below your alert threshold of {alert_threshold}."
        })

    # ── Compare individual check statuses if we have old scan data ──
    if old_scan and old_scan.get("results"):
        old_results = old_scan["results"]
        old_checks = {}
        new_checks = {}

        # Build lookup by check name
        for c in old_results.get("checks", []):
            old_checks[c["name"]] = c
        for c in new_result.get("checks", []):
            new_checks[c["name"]] = c

        # Detect check status changes
        for name, new_c in new_checks.items():
            old_c = old_checks.get(name)
            if not old_c:
                continue

            # Check went from pass/warn to fail
            if old_c["status"] in ("pass", "warn") and new_c["status"] == "fail":
                change_type = "dns_change"
                severity = "warning"

                # Determine specific change type
                if "blacklist" in name.lower():
                    change_type = "blacklist_added"
                    severity = "critical"
                elif "dmarc" in name.lower():
                    change_type = "dmarc_change"
                    severity = "critical"
                elif "spf" in name.lower():
                    change_type = "spf_change"
                    severity = "critical"
                elif "tls" in name.lower() or "ssl" in name.lower():
                    change_type = "cert_expiry"
                    severity = "warning"

                changes.append({
                    "type": change_type,
                    "severity": severity,
                    "title": f"{new_c['title']} — now failing",
                    "message": f"{domain_data['domain']}: {name} changed from {old_c['status']} to fail. {new_c.get('detail', '')[:200]}"
                })

            # Blacklist: check went from fail to pass (delisted)
            if "blacklist" in name.lower() and old_c["status"] == "fail" and new_c["status"] == "pass":
                changes.append({
                    "type": "blacklist_removed",
                    "severity": "info",
                    "title": "Removed from blacklists",
                    "message": f"{domain_data['domain']} is no longer listed on any checked blacklists."
                })

    return changes


def monitor_single_domain(domain_data: dict):
    """
    Run a monitoring scan for a single domain.
    Compares results, creates alerts, and logs the run.
    """
    domain = domain_data["domain"]
    domain_id = domain_data["id"]
    user_id = domain_data["user_id"]
    old_score = domain_data.get("latest_score")

    print(f"[Monitor] Scanning {domain} for user {user_id[:8]}...")

    try:
        # Run the scan (unified orchestrator, INBOX-21)
        scan_result = run_full_scan(domain, source="monitor")
        new_score = scan_result["score"]

        # Save the scan to database (as a monitoring scan).
        # INBOX-22 (2026-04-21): scan_type="scheduled" (matches schema CHECK constraint);
        # ip_address=None because this is a background job, not an HTTP request.
        # The prior value ip_address="monitor" was silently rejected by the INET column
        # type, causing zero monitor scans to persist for 42+ days (INBOX-1 root cause).
        saved = save_scan(
            domain=domain,
            score=new_score,
            results=scan_result,
            ip_address=None,
            user_id=user_id,
            scan_type="scheduled",
        )

        scan_id = saved["id"] if saved else None

        # Get previous scan details for comparison
        old_scan = None
        if domain_data.get("latest_scan_id"):
            old_scan = get_scan_detail(domain_data["latest_scan_id"])

        # Compare and detect changes
        changes = compare_scan_results(old_scan, scan_result, domain_data)

        # Create alerts for detected changes
        alerts_created = 0
        for change in changes:
            alert = create_alert(
                user_id=user_id,
                alert_type=change["type"],
                severity=change["severity"],
                title=change["title"],
                message=change["message"],
                domain_id=domain_id,
                domain=domain,
            )
            if alert:
                alerts_created += 1

        # Update domain record
        if scan_id:
            update_domain_after_monitor_scan(domain_id, new_score, scan_id)

        # INBOX-205: refresh the dedicated blacklist_results table so the
        # /blacklist Monitor page reflects fresh data on every scheduled
        # cycle. Wrapped in its own try/except so a DNSBL hiccup doesn't
        # poison the rest of the monitoring step.
        # INBOX-229 phase 2: provider selection (dnsbl vs hetrix) is now
        # delegated to blacklist_provider.get_full_blacklist_check_fn()
        # which reads USE_HETRIX_BL + HETRIX_CANARY_USER_IDS at call time.
        # When hetrix is selected, we also gate the call on a 23h
        # freshness window so we don't burn a credit every 6h.
        try:
            # Freshness gate — only applies on the hetrix path (always
            # False for dnsbl). Reads the existing cached row's
            # checked_at; if recent, skip the API call and keep the
            # current cached data (it's already < 23h old).
            existing = get_blacklist_results(user_id, domain) or {}
            existing_checked_at = (
                existing.get("checked_at")
                if isinstance(existing, dict) else None
            )
            if should_skip_blacklist_refresh(user_id, domain, existing_checked_at):
                logger.info("monitor.blacklist_skip_fresh", extra={
                    "domain": domain,
                    "user_id_prefix": user_id[:8] if user_id else None,
                    "last_checked_at": existing_checked_at,
                })
            else:
                full_blacklist_check = get_full_blacklist_check_fn(user_id)
                user_domain_ips = get_ips_for_domain(user_id, domain) or []
                ips = sorted(set(user_domain_ips))
                bl_result = full_blacklist_check(domain, ips)
                for ip_result in bl_result.get("ip_results", []):
                    ip_result["source"] = "Sending IPs"
                save_blacklist_results(user_id, domain, bl_result)
        except Exception:
            logger.exception("monitor.blacklist_results_save_failed", extra={
                "domain": domain,
                "user_id_prefix": user_id[:8] if user_id else None,
            })

        # Log the monitoring run
        save_monitoring_log(
            domain_id=domain_id,
            user_id=user_id,
            domain=domain,
            old_score=old_score,
            new_score=new_score,
            scan_id=scan_id,
            changes_detected=changes,
            alerts_created=alerts_created,
        )

        status = "changes detected" if changes else "no changes"
        print(f"[Monitor] {domain}: score {old_score} → {new_score} ({status}, {alerts_created} alerts)")

    except Exception:
        # INBOX-28: logger.exception ships to Sentry via LoggingIntegration.
        # Previously print(e) dropped the traceback silently — INBOX-1 class bug.
        logger.exception("monitor.scan_error", extra={
            "domain": domain,
            "domain_id": domain_id,
            "user_id_prefix": user_id[:8] if user_id else None,
        })


def run_monitoring_cycle():
    """
    Main monitoring job — called by the scheduler.
    Finds all domains due for scanning and processes them.
    """
    if not is_db_available():
        print("[Monitor] Database not available, skipping cycle")
        return

    # INBOX-16: heartbeat so the watchdog can detect silent scheduler failures
    from heartbeat import record_start, record_end
    hb_id = record_start("monitor")
    domains_processed = 0
    errors_count = 0

    try:
        domains = get_domains_due_for_scan()
        if not domains:
            print("[Monitor] No domains due for scanning")
            record_end(hb_id, domains_processed=0, errors_count=0, notes="no domains due")
            return

        print(f"[Monitor] Starting monitoring cycle: {len(domains)} domains due")

        # INBOX-210 (2026-05-13): Stub Free users don't get scheduled
        # monitoring — they're either lapsed trials or cancelled subs.
        # Their domains stay visible in the dashboard (frozen) but the
        # scheduler doesn't re-scan them. Cache plans per user across
        # the loop to avoid hammering get_user_plan() for users with
        # multiple domains.
        from db import get_user_plan as _get_user_plan
        plan_cache: dict = {}
        skipped_stub = 0

        for domain_data in domains:
            try:
                user_id = domain_data.get("user_id")
                if user_id:
                    if user_id not in plan_cache:
                        plan_cache[user_id] = _get_user_plan(user_id)
                    if plan_cache[user_id] == "stub":
                        skipped_stub += 1
                        continue

                monitor_single_domain(domain_data)
                domains_processed += 1
                # Small delay between scans to be polite to DNS servers
                time.sleep(2)
            except Exception:
                errors_count += 1
                # INBOX-28: emit to Sentry via LoggingIntegration.
                logger.exception("monitor.domain_processing_error", extra={
                    "domain": domain_data.get("domain", "?"),
                    "domain_id": domain_data.get("id"),
                })
                continue

        if skipped_stub:
            print(f"[Monitor] Skipped {skipped_stub} domains belonging to "
                  f"stub-plan users (INBOX-210)")

        print(f"[Monitor] Monitoring cycle complete: "
              f"{domains_processed}/{len(domains)} domains processed, {errors_count} errors")
        record_end(hb_id, domains_processed=domains_processed, errors_count=errors_count)

    except Exception as e:
        errors_count += 1
        # INBOX-28: logger.exception captures traceback + ships to Sentry.
        # A crashed cycle is the most severe failure mode — watchdog detects
        # staleness eventually, but Sentry catches the exception immediately.
        logger.exception("monitor.cycle_crashed", extra={
            "domains_processed": domains_processed,
            "errors_count": errors_count,
        })
        record_end(hb_id, domains_processed=domains_processed, errors_count=errors_count,
                   notes=f"cycle crashed: {str(e)[:200]}")
