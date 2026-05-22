"""
InboxScore — blocklist lookup table (INBOX-144, 2026-05-21)

Maps each DNSBL / domain-blocklist / IP-blocklist that HetrixTools checks
to a friendly description and a dynamic delisting URL template. Used by
notifier.py to render alert emails — the email body links each listing
to the specific delisting page (with the customer's domain or IP
pre-filled in the URL where possible) instead of a generic landing page.

Adding a new blocklist:
  1. Add an entry below
  2. Set `url_template` to the deepest URL that pre-fills domain/IP if
     such a URL exists — otherwise use the generic landing page
  3. Set `type` to 'domain', 'ip', or 'both'
  4. Keep `description` short and customer-facing (shown in email body)

Fallback behaviour:
  If a blocklist name we receive from HetrixTools isn't in this table,
  notifier.py uses get_blocklist_info() which returns a generic entry —
  the email still renders, the user gets a "Contact {{name}}'s removal
  process" line, and we file a follow-up ticket to add it here.

Coverage: top ~15 blocklists by HetrixTools weight + frequency. The long
tail can be added reactively from production data.
"""

from typing import Optional


# Each entry:
#   description     — short customer-facing blurb (1 line)
#   url_template    — string with optional {value} placeholder for the
#                     customer's domain or IP. If no {value}, the URL is
#                     a static landing page.
#   type            — 'domain' | 'ip' | 'both' (which value the URL
#                     accepts — drives notifier.py's substitution logic)
BLOCKLIST_LOOKUP = {
    # ─── Spamhaus family ─────────────────────────────────────────────
    "Spamhaus ZEN": {
        "description": "Spamhaus ZEN is the most widely-consulted spam blocklist — Gmail, Outlook, Yahoo, and most enterprise mail systems check it on every inbound message.",
        "url_template": "https://check.spamhaus.org/listed/?searchterm={value}",
        "type": "both",
    },
    "Spamhaus SBL": {
        "description": "Spamhaus SBL targets confirmed spam-source IP addresses.",
        "url_template": "https://check.spamhaus.org/listed/?searchterm={value}",
        "type": "ip",
    },
    "Spamhaus XBL": {
        "description": "Spamhaus XBL targets IPs running open proxies, exploits, and Trojans.",
        "url_template": "https://check.spamhaus.org/listed/?searchterm={value}",
        "type": "ip",
    },
    "Spamhaus PBL": {
        "description": "Spamhaus PBL targets IP ranges that should not be sending direct-to-MX mail.",
        "url_template": "https://check.spamhaus.org/listed/?searchterm={value}",
        "type": "ip",
    },
    "Spamhaus DBL": {
        "description": "Spamhaus DBL targets domains with poor reputation found in spam.",
        "url_template": "https://check.spamhaus.org/listed/?searchterm={value}",
        "type": "domain",
    },

    # ─── Other major blocklists ──────────────────────────────────────
    "Barracuda": {
        "description": "Barracuda's Reputation Block List is consulted by Outlook and most enterprise filters.",
        "url_template": "https://www.barracudacentral.org/lookups/lookup-reputation?rep=Reputation&rip={value}",
        "type": "ip",
    },
    "SpamCop": {
        "description": "SpamCop is a user-reported spam source list — listings reflect actual customer complaints.",
        "url_template": "https://www.spamcop.net/bl.shtml?{value}",
        "type": "ip",
    },
    "SURBL": {
        "description": "SURBL is a URI block list — listings target content patterns, not senders.",
        "url_template": "https://www.surbl.org/surbl-analysis",
        "type": "domain",
    },
    "URIBL": {
        "description": "URIBL is a domain-reputation block list consulted by enterprise mail filters.",
        "url_template": "http://lookup.uribl.com/?domain={value}",
        "type": "domain",
    },
    "PhishTank": {
        "description": "PhishTank is a community-driven phishing database — Gmail, Outlook, OpenDNS, and most security stacks check it.",
        "url_template": "https://www.phishtank.com/phish_search.php?Search=Search&search_text={value}",
        "type": "domain",
    },
    "SORBS": {
        "description": "SORBS tracks spam sources and open relays — primarily IP-based.",
        "url_template": "http://www.sorbs.net/lookup.shtml",
        "type": "ip",
    },
    "Invaluement": {
        "description": "Invaluement targets snowshoe-spam sending patterns.",
        "url_template": "https://www.invaluement.com/lookup/",
        "type": "ip",
    },
    "Mailspike": {
        "description": "Mailspike combines IP reputation with behavioural signals.",
        "url_template": "https://mailspike.org/iplookup.html",
        "type": "ip",
    },
    "Sender Score Block List": {
        "description": "Validity's Sender Score BL — IP reputation used by major filters.",
        "url_template": "https://senderscore.org/lookup/",
        "type": "ip",
    },
    "DNSWL": {
        "description": "DNSWL is an allow-list rather than a block list — being unlisted is not itself a problem.",
        "url_template": "https://www.dnswl.org/",
        "type": "ip",
    },
}


def get_blocklist_info(name: str) -> dict:
    """Return the BLOCKLIST_LOOKUP entry for ``name``, or a sane
    generic fallback if we don't have it catalogued yet.

    The fallback ensures alert emails always render — they just include
    a generic "Contact {{name}}'s removal process" line instead of a
    dynamic deep link.
    """
    if name in BLOCKLIST_LOOKUP:
        return BLOCKLIST_LOOKUP[name]
    return {
        "description": f"{name} is a third-party blocklist used by some mail providers.",
        "url_template": "",
        "type": "both",
    }


def render_delisting_url(name: str, domain: str, ip: Optional[str] = None) -> str:
    """Substitute the customer's domain or IP into a blocklist's URL
    template. Returns the substituted URL, or an empty string if the
    blocklist has no template (callers should hide the link).

    Falls back to ``domain`` if the blocklist accepts both types or if
    ``ip`` is None.
    """
    info = get_blocklist_info(name)
    template = info.get("url_template") or ""
    if not template:
        return ""
    if "{value}" not in template:
        # Static landing page — no substitution needed
        return template
    value = None
    bl_type = info.get("type", "both")
    if bl_type == "ip":
        value = ip
    elif bl_type == "domain":
        value = domain
    else:  # 'both' — prefer domain unless we only have IP
        value = domain or ip
    if not value:
        return ""
    return template.replace("{value}", value)
