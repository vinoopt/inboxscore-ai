#!/usr/bin/env python3
"""
Test the SPF-resolution → SNDS cross-reference idea on mailercloud.com.

Step 1: Recursively resolve mailercloud.com's SPF record into a set of IPs
Step 2: Pull the IPs that have appeared in your synced SNDS feed (snds_metrics)
Step 3: Compute the intersection — these are IPs we could auto-attribute to mailercloud.com
"""
import dns.resolver
import ipaddress
import urllib.request
import json
import sys
from collections import defaultdict

# ───────────────────────────────────────────────────────────────────
# 1. SPF RESOLVER — handles include:, redirect=, ip4:, ip6:, a, mx
# ───────────────────────────────────────────────────────────────────

resolver = dns.resolver.Resolver()
resolver.timeout = 5
resolver.lifetime = 10

def fetch_txt(domain):
    try:
        answers = resolver.resolve(domain, "TXT")
        return [b"".join(r.strings).decode("utf-8", "ignore") for r in answers]
    except Exception as e:
        return []

def fetch_a(host):
    try:
        return [str(r) for r in resolver.resolve(host, "A")]
    except Exception:
        return []

def fetch_mx_ips(domain):
    try:
        mxs = resolver.resolve(domain, "MX")
        ips = set()
        for mx in mxs:
            ips.update(fetch_a(str(mx.exchange).rstrip(".")))
        return ips
    except Exception:
        return set()

def find_spf(txts):
    for t in txts:
        if t.lower().startswith("v=spf1"):
            return t
    return None

def resolve_spf(domain, depth=0, seen=None, debug=None):
    """Return set of CIDR strings authorised to send for `domain`."""
    if seen is None: seen = set()
    if debug is None: debug = []
    if depth > 10 or domain in seen:
        return set()
    seen.add(domain)
    debug.append(f"{'  '*depth}→ resolving SPF for {domain}")
    txts = fetch_txt(domain)
    spf = find_spf(txts)
    if not spf:
        debug.append(f"{'  '*depth}  (no SPF found)")
        return set()
    debug.append(f"{'  '*depth}  SPF: {spf[:120]}{'…' if len(spf) > 120 else ''}")
    cidrs = set()
    for tok in spf.split():
        tok = tok.strip()
        if tok.startswith(("+", "-", "?", "~")):
            tok = tok[1:]
        low = tok.lower()
        if low.startswith("ip4:"):
            cidrs.add(tok[4:])
        elif low.startswith("ip6:"):
            cidrs.add(tok[4:])
        elif low.startswith("include:"):
            inc = tok[8:]
            cidrs |= resolve_spf(inc, depth + 1, seen, debug)
        elif low.startswith("redirect="):
            inc = tok.split("=", 1)[1]
            cidrs |= resolve_spf(inc, depth + 1, seen, debug)
        elif low == "a":
            for ip in fetch_a(domain):
                cidrs.add(ip + "/32")
        elif low.startswith("a:"):
            host = tok[2:]
            for ip in fetch_a(host):
                cidrs.add(ip + "/32")
        elif low == "mx":
            for ip in fetch_mx_ips(domain):
                cidrs.add(ip + "/32")
    return cidrs

def cidrs_to_networks(cidrs):
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
    return nets

def ip_in_any(ip_str, networks):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for n in networks:
        if ip.version == n.version and ip in n:
            return True
    return False

# ───────────────────────────────────────────────────────────────────
# 2. SNDS FETCH from Supabase
# ───────────────────────────────────────────────────────────────────

import os
SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_SECRET_KEY") or os.environ.get("SUPABASE_KEY")
if not (SUPABASE_URL and SUPABASE_KEY):
    raise SystemExit(
        "Set SUPABASE_URL and SUPABASE_SECRET_KEY env vars before running.\n"
        "  e.g.  source .env.supabase && python scripts/spf_snds_audit.py"
    )

def supabase_get(path):
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    req = urllib.request.Request(url)
    req.add_header("apikey", SUPABASE_KEY)
    req.add_header("Authorization", f"Bearer {SUPABASE_KEY}")
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read().decode())

def get_snds_ips_for_user(user_email):
    """Find user_id for the given email, then list distinct IPs from snds_metrics."""
    users = supabase_get(f"users?email=eq.{user_email}&select=id,email")
    if not users:
        return None, []
    user_id = users[0]["id"]
    rows = supabase_get(
        f"snds_metrics?user_id=eq.{user_id}&select=ip_address,metric_date,ip_status,complaint_rate,trap_hits&order=metric_date.desc&limit=2000"
    )
    return user_id, rows

# ───────────────────────────────────────────────────────────────────
# 3. RUN
# ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    DOMAIN = "mailercloud.com"
    USER_EMAIL = "vinoop@mailercloud.com"

    print(f"\n{'='*72}\n  SPF → SNDS CROSS-REFERENCE TEST\n{'='*72}\n")

    # ---- step 1: SPF
    print(f"[1/3] Resolving SPF chain for {DOMAIN} ...\n")
    debug = []
    cidrs = resolve_spf(DOMAIN, debug=debug)
    for line in debug:
        print(line)
    print()
    if not cidrs:
        print(f"  ❌ No SPF record found for {DOMAIN}. Stopping.")
        sys.exit(1)

    networks = cidrs_to_networks(cidrs)
    v4 = [n for n in networks if n.version == 4]
    v6 = [n for n in networks if n.version == 6]
    total_v4_ips = sum(n.num_addresses for n in v4)
    print(f"  ✅ Authorised CIDRs: {len(cidrs)}  (IPv4 networks: {len(v4)}, IPv6: {len(v6)})")
    print(f"     Total individual IPv4 addresses authorised: {total_v4_ips:,}")
    print(f"     Sample CIDRs: {sorted(cidrs)[:10]}")

    # ---- step 2: SNDS
    print(f"\n[2/3] Fetching synced SNDS metrics for {USER_EMAIL} ...")
    user_id, rows = get_snds_ips_for_user(USER_EMAIL)
    if user_id is None:
        print(f"  ❌ No user found for {USER_EMAIL}")
        sys.exit(1)
    print(f"  user_id: {user_id}")
    print(f"  Total snds_metrics rows (last 2000): {len(rows)}")
    snds_ips = sorted({r["ip_address"] for r in rows if r["ip_address"]})
    print(f"  Distinct IPs in SNDS feed: {len(snds_ips)}")

    # ---- step 3: cross-reference
    print(f"\n[3/3] Cross-referencing SNDS IPs vs SPF-authorised CIDRs ...\n")
    matched, unmatched = [], []
    for ip in snds_ips:
        if ip_in_any(ip, networks):
            matched.append(ip)
        else:
            unmatched.append(ip)

    pct = (len(matched) / len(snds_ips) * 100) if snds_ips else 0
    print(f"  ✅ SPF-matched IPs:   {len(matched):4d}  ({pct:.1f}%)")
    print(f"  ❌ Not in SPF chain:  {len(unmatched):4d}")

    print("\n  --- Sample SPF-matched IPs (first 10) ---")
    for ip in matched[:10]:
        # Find latest status for this IP for context
        latest = next((r for r in rows if r["ip_address"] == ip), None)
        if latest:
            print(f"    {ip:18s}  status={latest['ip_status']:6s}  complaint={latest['complaint_rate']}  traps={latest['trap_hits']}  date={latest['metric_date']}")

    if unmatched:
        print("\n  --- Sample IPs NOT in SPF (first 10) ---")
        print("      (these are IPs in your SNDS feed that mailercloud.com's SPF doesn't authorise)")
        for ip in unmatched[:10]:
            latest = next((r for r in rows if r["ip_address"] == ip), None)
            if latest:
                print(f"    {ip:18s}  status={latest['ip_status']:6s}  complaint={latest['complaint_rate']}  traps={latest['trap_hits']}  date={latest['metric_date']}")

    print(f"\n{'='*72}\n  CONCLUSION\n{'='*72}\n")
    if pct >= 80:
        print(f"  ✅ Auto-detection works — {pct:.0f}% of SNDS IPs match mailercloud.com's SPF.")
        print(f"     The {len(unmatched)} unmatched IPs are likely:")
        print(f"     - dedicated to other client domains (different SPF)")
        print(f"     - shared infra used for marketing emails not authorised on mailercloud.com")
        print(f"     - newly added IPs not yet in SPF")
    elif pct >= 30:
        print(f"  ⚠️  Partial match — {pct:.0f}%. SPF auto-detection viable but coverage incomplete.")
        print(f"     Manual mapping still needed for the other {100 - pct:.0f}%.")
    else:
        print(f"  ❌ Low match rate — {pct:.0f}%. SPF auto-detection alone won't work for mailercloud.com.")
        print(f"     Likely cause: SPF uses a wildcard include or the SNDS account covers IPs not in SPF.")
