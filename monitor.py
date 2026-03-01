"""
InboxScore - Domain Monitoring Scheduler
Background job that re-scans monitored domains and creates alerts on changes.
"""

import time
import concurrent.futures
from datetime import datetime

from db import (
    is_db_available, get_domains_due_for_scan, save_scan,
    update_domain_after_monitor_scan, save_monitoring_log,
    create_alert, get_scan_detail
)


def run_domain_scan(domain: str) -> dict:
    """
    Run a full scan on a domain (same checks as the API endpoint).
    Returns the scan result dict with score, checks, etc.
    Imports check functions from app module to avoid circular imports.
    """
    from app import (
        check_mx_records, check_spf, check_dkim, check_dmarc,
        check_blacklists, check_tls, check_reverse_dns, check_bimi,
        check_mta_sts, check_tls_rpt, check_sender_detection,
        check_domain_age, generate_summary
    )

    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_mx = executor.submit(check_mx_records, domain)
        future_spf = executor.submit(check_spf, domain)
        future_dkim = executor.submit(check_dkim, domain)
        future_dmarc = executor.submit(check_dmarc, domain)
        future_blacklists = executor.submit(check_blacklists, domain)
        future_tls = executor.submit(check_tls, domain)
        future_rdns = executor.submit(check_reverse_dns, domain)
        future_bimi = executor.submit(check_bimi, domain)
        future_mta_sts = executor.submit(check_mta_sts, domain)
        future_tls_rpt = executor.submit(check_tls_rpt, domain)
        future_senders = executor.submit(check_sender_detection, domain)
        future_age = executor.submit(check_domain_age, domain)

        checks = [
            future_mx.result(timeout=20),
            future_spf.result(timeout=20),
            future_dkim.result(timeout=20),
            future_dmarc.result(timeout=20),
            future_blacklists.result(timeout=25),
            future_tls.result(timeout=15),
            future_rdns.result(timeout=10),
            future_bimi.result(timeout=10),
            future_mta_sts.result(timeout=12),
            future_tls_rpt.result(timeout=10),
            future_senders.result(timeout=10),
            future_age.result(timeout=12),
        ]

    total_points = sum(c.points for c in checks)
    max_points = sum(c.max_points for c in checks if c.max_points > 0)
    score = round((total_points / max_points * 100)) if max_points > 0 else 0

    summary = generate_summary(domain, score, checks)
    scan_time = round(time.time() - start_time, 1)

    return {
        "domain": domain,
        "score": score,
        "summary": summary,
        "checks": [c.dict() for c in checks],
        "scan_time": scan_time,
        "scanned_at": datetime.utcnow().isoformat(),
    }


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
        # Run the scan
        scan_result = run_domain_scan(domain)
        new_score = scan_result["score"]

        # Save the scan to database (as a monitoring scan)
        saved = save_scan(
            domain=domain,
            score=new_score,
            results=scan_result,
            ip_address="monitor",
            user_id=user_id,
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

    except Exception as e:
        print(f"[Monitor] Error scanning {domain}: {e}")


def run_monitoring_cycle():
    """
    Main monitoring job — called by the scheduler.
    Finds all domains due for scanning and processes them.
    """
    if not is_db_available():
        print("[Monitor] Database not available, skipping cycle")
        return

    try:
        domains = get_domains_due_for_scan()
        if not domains:
            print("[Monitor] No domains due for scanning")
            return

        print(f"[Monitor] Starting monitoring cycle: {len(domains)} domains due")

        for domain_data in domains:
            try:
                monitor_single_domain(domain_data)
                # Small delay between scans to be polite to DNS servers
                time.sleep(2)
            except Exception as e:
                print(f"[Monitor] Error processing {domain_data.get('domain', '?')}: {e}")
                continue

        print(f"[Monitor] Monitoring cycle complete: {len(domains)} domains processed")

    except Exception as e:
        print(f"[Monitor] Monitoring cycle error: {e}")
