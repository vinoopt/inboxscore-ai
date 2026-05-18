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
    check_google_safe_browsing,  # INBOX-95
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
    "google_safe_browsing": 2,   # INBOX-95 — flagged = -2, clean = +2
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


# INBOX-199 (2026-05-11): depth selector for the public vs full scan
# split. Anonymous marketing-page scans skip the IP-based checks
# (check_blacklists, check_ip_reputation) because SPF-derived sending
# IPs for anonymous users are mostly shared ESP space (SendGrid, SES,
# Google Workspace, etc.) — listings there reflect noisy neighbours,
# not the user. Trying to assess "their" IP reputation when we don't
# know what their actual sending IPs are produces misleading data.
#
# Logged-in dashboard users keep the full check set because they can
# explicitly map their real sending IPs in the Domains page.
#
# Side benefits of the split:
#   - Anonymous scan time drops from ~30s to ~10s (1 hetrix call vs 6)
#   - Anonymous credit burn drops from 6 to 1 per scan
#   - Clean upsell narrative: "Sign up to scan your sending IPs"
_IP_LEVEL_CHECKS = frozenset({"blacklists", "ip_reputation"})


def run_full_scan(domain: str, source: str = "api",
                  depth: str = "full",
                  sending_ips: list = None) -> dict:
    """Run domain deliverability checks for `domain` and return a result dict.

    Args:
        domain: normalised domain (caller strips scheme / path / www).
        source: "api" (website scan) or "monitor" (scheduler). Purely a
                tag for logs/telemetry today; will become a column in
                INBOX-23.
        depth: "full" (default, 15 checks) or "public" (13 checks —
                drops IP-based blacklist + IP reputation). Public is
                meant for anonymous marketing scans; full for logged-in
                users + monitor cycles. See INBOX-199.
        sending_ips: list of IPs (str). INBOX-266: the user's mapped
                sending IPs for this domain. Drives check_reverse_dns
                (PTR on sending IPs, not on MX). Defaults to None which
                check_reverse_dns interprets as "no IPs mapped" — the
                PTR check skips gracefully (Info, 0/0 points, no
                score impact).

    Returns:
        dict shaped as the existing response contract consumed by
        `app.py` and persisted by `save_scan`:
            { domain, score, summary, checks, scan_time, scanned_at, depth }
    """
    start_time = time.time()
    include_ip_checks = (depth == "full")
    sending_ips = sending_ips or []

    with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
        # Submit all the checks that run regardless of depth.
        future_mx = executor.submit(check_mx_records, domain)
        future_spf = executor.submit(check_spf, domain)
        future_dkim = executor.submit(check_dkim, domain)
        future_dmarc = executor.submit(check_dmarc, domain)
        future_domain_bl = executor.submit(check_domain_blacklists, domain)
        future_tls = executor.submit(check_tls, domain)
        # INBOX-266: PTR now checks the user's mapped sending IPs, not MX.
        future_rdns = executor.submit(check_reverse_dns, domain, sending_ips)
        future_bimi = executor.submit(check_bimi, domain)
        future_mta_sts = executor.submit(check_mta_sts, domain)
        future_tls_rpt = executor.submit(check_tls_rpt, domain)
        future_senders = executor.submit(check_sender_detection, domain)
        future_age = executor.submit(check_domain_age, domain)
        future_gsb = executor.submit(check_google_safe_browsing, domain)  # INBOX-95

        # INBOX-199: IP-level checks only run when caller explicitly
        # asked for full depth (logged-in user + monitor path).
        future_blacklists = None
        future_ip_rep = None
        if include_ip_checks:
            future_blacklists = executor.submit(check_blacklists, domain)
            future_ip_rep = executor.submit(check_ip_reputation, domain)

        # Timeouts: DNS-only checks get 8s, network-heavy checks get 12s.
        # INBOX-229 (2026-05-11): blacklists + domain_blacklists now route
        # through HetrixTools (10-22s per call cold, 0.2s warm). Bumped to
        # 40s so cold scans complete instead of falling through to the
        # _safe_result error path. The scan is bounded by these two — every
        # other check completes in well under 10s.
        checks = [
            _safe_result(future_mx, "mx_records", "MX Records", "infrastructure", 8, domain),
            _safe_result(future_spf, "spf", "SPF Record", "authentication", 8, domain),
            _safe_result(future_dkim, "dkim", "DKIM", "authentication", 8, domain),
            _safe_result(future_dmarc, "dmarc", "DMARC Policy", "authentication", 8, domain),
        ]
        if include_ip_checks:
            checks.append(_safe_result(future_blacklists, "blacklists",
                                       "Blacklist Check", "reputation", 40, domain))
        checks.extend([
            _safe_result(future_domain_bl, "domain_blacklists", "Domain Blacklists", "reputation", 35, domain),
            _safe_result(future_tls, "tls", "TLS Encryption", "infrastructure", 10, domain),
            _safe_result(future_rdns, "reverse_dns", "Reverse DNS", "infrastructure", 8, domain),
            _safe_result(future_bimi, "bimi", "BIMI Record", "authentication", 8, domain),
            _safe_result(future_mta_sts, "mta_sts", "MTA-STS Policy", "infrastructure", 8, domain),
            _safe_result(future_tls_rpt, "tls_rpt", "TLS Reporting", "infrastructure", 8, domain),
            _safe_result(future_senders, "sender_detection", "Email Provider", "infrastructure", 8, domain),
            _safe_result(future_age, "domain_age", "Domain Age", "reputation", 10, domain),
        ])
        if include_ip_checks:
            checks.append(_safe_result(future_ip_rep, "ip_reputation",
                                       "IP Reputation", "reputation", 10, domain))
        checks.append(
            _safe_result(future_gsb, "google_safe_browsing", "Google Safe Browsing", "reputation", 10, domain)
        )

    # Calculate total score — capped at 100.
    # INBOX-199: omitted IP-level checks drop from BOTH numerator and
    # denominator, so the percentage stays honest. Public scan still
    # produces a meaningful 0-100 score.
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
        # INBOX-199: surface depth so the frontend can render an upsell
        # CTA ("Sign up to scan your sending IPs") next to the result
        # when depth == "public".
        "depth": depth,
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

    # INBOX-265: 5-band scheme. Only 90+ wears Excellent + green.
    # Previously 85+ was Excellent and 65+ was still "good" color —
    # both undersold InboxScore's value to buyers ("why pay if I'm
    # already great?"). Tighter bands force an honest signal.
    if score >= 90:
        verdict = "Excellent"
        color = "good"
        summary = "Top-tier email deliverability. "
        if warned:
            summary += f"There {'is' if len(warned) == 1 else 'are'} {len(warned)} minor issue{'s' if len(warned) > 1 else ''} to address, but overall your emails should reliably reach the inbox."
        else:
            summary += "All major checks passed. Your emails should reliably reach the inbox — keep monitoring to maintain it."
    elif score >= 75:
        verdict = "Good"
        color = "moderate"
        summary = "Solid deliverability with room to improve. "
        if failed:
            summary += f"Fix the {len(failed)} failed check{'s' if len(failed) > 1 else ''} to lift your score into the Excellent band."
        elif warned:
            summary += f"Address the {len(warned)} warning{'s' if len(warned) > 1 else ''} to strengthen your deliverability."
        else:
            summary += "All checks pass, but a few signals can be tightened to reach Excellent."
    elif score >= 60:
        verdict = "Fair"
        color = "moderate"
        summary = "Working but with visible gaps. "
        if failed:
            summary += f"Multiple signals are weaker than they should be — fix the {len(failed)} failing check{'s' if len(failed) > 1 else ''} to lift inbox placement."
        else:
            summary += f"Address the {len(warned)} warning{'s' if len(warned) > 1 else ''} below to improve placement."
    elif score >= 40:
        verdict = "Needs Work"
        color = "danger"
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
        summary = "Several signals are failing and your emails are at risk of landing in spam. "
        if issues:
            summary += f"The main problems are: {', '.join(issues)}. Fix these to significantly improve inbox placement."
        else:
            summary += f"Address the {len(failed)} failed checks to improve your score."
    else:
        verdict = "At Risk"
        color = "danger"
        summary = "Critical deliverability issues. Most of your emails are likely going to spam or being rejected entirely. Immediate action is needed on the failed checks below."

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
