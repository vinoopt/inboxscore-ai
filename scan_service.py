"""
InboxScore — unified scan orchestrator.

This module is the single source of truth for running a full domain
deliverability scan. Both the HTTP handler (`app.py::_run_scan`) and the
monitoring scheduler (`monitor.py::monitor_single_domain`) call
`run_full_scan` instead of composing checks themselves.

Behaviour preserved from the previous `app.py::_run_scan` implementation:
- 13 checks submitted in parallel (including `check_ip_reputation`)
- Each check wrapped with `safe_result` so one timeout never kills the scan
- Score capped at 100 via `min(100, ...)`
- Tight timeouts (DNS 8s; blacklists 12s; TLS 10s; age/ip 10s)

INBOX-21 (Phase 1 Foundation Audit, 2026-04-20) — extracted to kill the
previously-divergent `monitor.py::run_domain_scan` path (12 checks, no
wrapper, uncapped score) which was the root-cause enabler for INBOX-3.

Nothing in here knows about FastAPI, the database, auth, or the
scheduler. Pure scan composition + summary generation.
"""

import concurrent.futures
import time
from datetime import datetime, timezone

from checks import (
    CheckResult,
    check_mx_records,
    check_spf,
    check_dkim,
    check_dmarc,
    check_blacklists,
    check_domain_blacklists,  # INBOX-42
    check_tls,
    check_reverse_dns,
    check_bimi,
    check_mta_sts,
    check_tls_rpt,
    check_sender_detection,
    check_domain_age,
    check_ip_reputation,
)


# ─── SCAN ORCHESTRATION ────────────────────────────────────────────

# Canonical max_points per check — used by `_safe_result` to ensure a
# crashed scoring check keeps its denominator slot instead of silently
# dropping out (INBOX-23 fix).
#
# Checks intentionally valued at 0 are informational only (BIMI /
# MTA-STS / TLS-RPT / sender detection). They do NOT contribute to the
# denominator, which is preserved by the `if c.max_points > 0` filter
# in `run_full_scan` below.
#
# If a new check is added in `checks.py`, its canonical max_points MUST
# be registered here. A guard test in `test_scan_service.py` enforces
# that every check name returned by `run_full_scan` has an entry.
CANONICAL_MAX_POINTS = {
    "mx_records": 10,
    "spf": 15,
    "dkim": 15,
    "dmarc": 15,
    "blacklists": 15,
    "domain_blacklists": 10,  # INBOX-42 — new reputation check
    "tls": 10,
    "reverse_dns": 5,
    "domain_age": 3,
    "ip_reputation": 8,
    "bimi": 0,
    "mta_sts": 5,             # INBOX-70 — was 0, now scored (Google et al pass enforce)
    "tls_rpt": 3,             # INBOX-70 — was 0, now scored (rewards visibility into TLS failures)
    "sender_detection": 0,
}


def _safe_result(future, name, title, category, timeout_sec, domain):
    """Collect a check result; return a safe fallback if it crashes.

    Mirrors the inner `safe_result` from the old `app.py::_run_scan` —
    one timeout or crash must never kill the whole scan.

    INBOX-23 (2026-04-22): on crash, `max_points` is now the check's
    canonical value (from `CANONICAL_MAX_POINTS`) instead of 0, so the
    scan denominator stays honest. Previously a crashed scoring check
    silently dropped out of the denominator, inflating the score
    whenever a scanner had an outage.
    """
    check_start = time.time()
    try:
        result = future.result(timeout=timeout_sec)
        elapsed = round(time.time() - check_start, 2)
        if elapsed > 3:
            print(f"[SCAN] Check '{name}' for {domain} took {elapsed}s (slow)")
        return result
    except Exception as e:
        elapsed = round(time.time() - check_start, 2)
        print(f"[SCAN] Check '{name}' failed for {domain} after {elapsed}s: {e}")
        return CheckResult(
            name=name, category=category, status="warn", title=title,
            detail="Could not complete this check (timeout or service error)",
            points=0,
            max_points=CANONICAL_MAX_POINTS.get(name, 0),
        )


def run_full_scan(domain: str, source: str = "api") -> dict:
    """Run all 13 deliverability checks for `domain` and return a result dict.

    Args:
        domain: normalised domain (caller strips scheme / path / www).
        source: "api" (website scan) or "monitor" (scheduler). Purely a
                tag for logs/telemetry today; will become a column in
                INBOX-23.

    Returns:
        dict shaped as the existing response contract consumed by
        `app.py` and persisted by `save_scan`:
            { domain, score, summary, checks, scan_time, scanned_at }
    """
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=13) as executor:
        future_mx = executor.submit(check_mx_records, domain)
        future_spf = executor.submit(check_spf, domain)
        future_dkim = executor.submit(check_dkim, domain)
        future_dmarc = executor.submit(check_dmarc, domain)
        future_blacklists = executor.submit(check_blacklists, domain)
        future_domain_bl = executor.submit(check_domain_blacklists, domain)
        future_tls = executor.submit(check_tls, domain)
        future_rdns = executor.submit(check_reverse_dns, domain)
        future_bimi = executor.submit(check_bimi, domain)
        future_mta_sts = executor.submit(check_mta_sts, domain)
        future_tls_rpt = executor.submit(check_tls_rpt, domain)
        future_senders = executor.submit(check_sender_detection, domain)
        future_age = executor.submit(check_domain_age, domain)
        future_ip_rep = executor.submit(check_ip_reputation, domain)

        # Timeouts: DNS-only checks get 8s, network-heavy checks get 12s.
        checks = [
            _safe_result(future_mx, "mx_records", "MX Records", "infrastructure", 8, domain),
            _safe_result(future_spf, "spf", "SPF Record", "authentication", 8, domain),
            _safe_result(future_dkim, "dkim", "DKIM", "authentication", 8, domain),
            _safe_result(future_dmarc, "dmarc", "DMARC Policy", "authentication", 8, domain),
            _safe_result(future_blacklists, "blacklists", "Blacklist Check", "reputation", 12, domain),
            _safe_result(future_domain_bl, "domain_blacklists", "Domain Blacklists", "reputation", 6, domain),
            _safe_result(future_tls, "tls", "TLS Encryption", "infrastructure", 10, domain),
            _safe_result(future_rdns, "reverse_dns", "Reverse DNS", "infrastructure", 8, domain),
            _safe_result(future_bimi, "bimi", "BIMI Record", "authentication", 8, domain),
            _safe_result(future_mta_sts, "mta_sts", "MTA-STS Policy", "infrastructure", 8, domain),
            _safe_result(future_tls_rpt, "tls_rpt", "TLS Reporting", "infrastructure", 8, domain),
            _safe_result(future_senders, "sender_detection", "Email Provider", "infrastructure", 8, domain),
            _safe_result(future_age, "domain_age", "Domain Age", "reputation", 10, domain),
            _safe_result(future_ip_rep, "ip_reputation", "IP Reputation", "reputation", 10, domain),
        ]

    # Calculate total score — capped at 100.
    total_points = sum(c.points for c in checks)
    max_points = sum(c.max_points for c in checks if c.max_points > 0)
    score = min(100, round((total_points / max_points * 100))) if max_points > 0 else 0

    # Generate human-readable summary.
    summary = generate_summary(domain, score, checks)

    scan_time = round(time.time() - start_time, 1)

    return {
        "domain": domain,
        "score": score,
        "summary": summary,
        "checks": [c.dict() for c in checks],
        "scan_time": scan_time,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
    }


# ─── SUMMARY GENERATION ────────────────────────────────────────────
# Moved verbatim from `app.py` in INBOX-21 because both the HTTP handler
# and the monitor orchestrator need it; keeping one copy next to the
# scan composition is the natural home.

def generate_summary(domain: str, score: int, checks: list) -> dict:
    """Generate a human-readable summary based on check results."""
    failed = [c for c in checks if c.status == "fail"]
    warned = [c for c in checks if c.status == "warn"]
    passed = [c for c in checks if c.status == "pass"]

    if score >= 85:
        verdict = "Excellent"
        color = "good"
        summary = "Your domain has strong email deliverability. "
        if warned:
            summary += f"There {'is' if len(warned) == 1 else 'are'} {len(warned)} minor issue{'s' if len(warned) > 1 else ''} to address, but overall your emails should reliably reach the inbox."
        else:
            summary += "All major checks passed. Your emails should reliably reach the inbox."
    elif score >= 65:
        verdict = "Good"
        color = "good"
        summary = "Your email setup is solid but has room for improvement. "
        if failed:
            summary += f"Fix the {len(failed)} failed check{'s' if len(failed) > 1 else ''} to improve your score significantly."
        elif warned:
            summary += f"Address the {len(warned)} warning{'s' if len(warned) > 1 else ''} to strengthen your deliverability."
    elif score >= 40:
        verdict = "Needs Improvement"
        color = "moderate"
        issues = []
        for c in failed:
            if c.name == "blacklists":
                issues.append("blacklist listings")
            elif c.name == "dmarc":
                issues.append("missing DMARC protection")
            elif c.name == "spf":
                issues.append("SPF misconfiguration")
            elif c.name == "dkim":
                issues.append("missing DKIM")
            elif c.name == "ip_reputation":
                issues.append("poor IP reputation")
        summary = "Your domain has deliverability issues that are likely causing emails to land in spam. "
        if issues:
            summary += f"The main problems are: {', '.join(issues)}. Fix these to significantly improve inbox placement."
        else:
            summary += f"Address the {len(failed)} failed checks to improve your score."
    else:
        verdict = "Critical Issues"
        color = "danger"
        summary = "Your domain has serious deliverability problems. Most of your emails are likely going to spam or being rejected entirely. Immediate action is needed on the failed checks below."

    return {
        "verdict": verdict,
        "color": color,
        "summary": summary,
        "stats": {
            "passed": len(passed),
            "warnings": len(warned),
            "failed": len(failed)
        }
    }
