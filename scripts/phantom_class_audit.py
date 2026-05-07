#!/usr/bin/env python3
"""Phantom CSS class detector for InboxScore V2 pages.

Catches two classes of design-system bugs:

  1. Truly phantom — class name used in HTML class="..." but never defined
     in any CSS rule referenced by the page (inline <style> or external
     <link rel="stylesheet">). Browser falls back to native rendering.

  2. Contextual-only — class is defined in CSS but ONLY as a descendant
     selector (e.g. ".parent .child"). When the HTML uses the class
     outside that parent, the rule never matches.

Both manifest as visually-broken UI states (unstyled buttons, default-
looking modals, etc.) that are easy to miss in QA when you only look
at the default state of a page.

Usage:
  python3 scripts/phantom_class_audit.py             # audit all V2 pages
  python3 scripts/phantom_class_audit.py --strict    # exit 1 if any
                                                       button is affected

Background: born after INBOX-192 / INBOX-197 — Vinoop spotted an unstyled
"Sync Now" button on /postmaster (gpm-state-nodata) on 2026-05-07. Root
cause: .cta-btn was only defined under .provider-cta and the state UI
rendered the button outside that ancestor.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

PAGES = [
    "dashboard.html", "postmaster.html", "microsoft.html", "blacklist.html",
    "domains.html", "sending-ips.html", "alerts.html", "settings.html",
]

# Repo layout — script lives in code/inboxscore/scripts/
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.normpath(os.path.join(SCRIPT_DIR, "..", "static"))
CSS_DIR = os.path.join(STATIC_DIR, "css")

# Classes that are intentionally just JS hooks or state flags.
ALLOWLIST = {
    "sr-only", "hidden", "visually-hidden", "noscroll",
    "active", "open", "show", "on", "selected", "disabled", "checked",
    "unread", "resolved", "expanded", "collapsed",
    # severity / status flags toggled at runtime; styled via compound
    # selectors like .al-chip.severity-critical which our regex can't
    # split cleanly.
    "connected", "done", "error", "pending",
    "critical", "warning", "info",
    # Common JS-only data flags
    "loading", "loaded",
}


def get_css_for_page(page_path: str) -> tuple[str, str]:
    """Return (full_html, all_css_referenced_by_the_page)."""
    with open(page_path) as f:
        html = f.read()
    inline = "\n".join(re.findall(r"<style[^>]*>([\s\S]*?)</style>", html, re.DOTALL))
    external = ""
    for m in re.finditer(r'<link[^>]+href=["\']([^"\']+\.css[^"\']*?)["\']', html):
        href = m.group(1).split("?")[0]
        css_path = os.path.join(CSS_DIR, href.split("/")[-1])
        if os.path.exists(css_path):
            with open(css_path) as cf:
                external += cf.read() + "\n"
    return html, inline + "\n" + external


def parse_css_rules(css: str) -> dict[str, list[list[str]]]:
    """For each class name, list every selector context it appears in.

    e.g. ".provider-cta .cta-btn"  -> { "cta-btn": [["provider-cta"]] }
         ".btn"                    -> { "btn":     [[]] }            # unconditional
         ".btn.primary"            -> { "btn":     [[]],
                                         "primary": [["btn"]] }      # compound,
                                                                     # but we treat
                                                                     # the leading
                                                                     # class as the
                                                                     # required
                                                                     # ancestor for
                                                                     # safety.
    """
    out: dict[str, list[list[str]]] = {}
    css = re.sub(r"/\*[\s\S]*?\*/", "", css)
    for m in re.finditer(r"([^{}/]+)\s*\{", css):
        sel_chunk = m.group(1).strip()
        if not sel_chunk or sel_chunk.startswith("@"):
            continue
        for sel in sel_chunk.split(","):
            sel = sel.strip()
            classes = re.findall(r"\.([a-zA-Z_][\w-]*)", sel)
            if not classes:
                continue
            target = classes[-1]
            ancestors = classes[:-1]
            out.setdefault(target, []).append(ancestors)
    return out


def audit_page(page_path: str) -> tuple[list[str], list[tuple[str, list[list[str]]]]]:
    html, css = get_css_for_page(page_path)
    # Strip JS template literals: class="${expr}" or class="abc ${expr}"
    html_clean = re.sub(r"\$\{[^}]*\}", "", html)

    used: set[str] = set()
    for m in re.finditer(r'class=["\']([^"\']+)["\']', html_clean):
        for c in m.group(1).split():
            if re.match(r"^[a-zA-Z][\w-]*$", c):
                used.add(c)

    rules = parse_css_rules(css)

    truly_phantom: list[str] = []
    contextual_only: list[tuple[str, list[list[str]]]] = []
    for cls in sorted(used - ALLOWLIST):
        if cls not in rules:
            truly_phantom.append(cls)
        elif not any(len(anc) == 0 for anc in rules[cls]):
            contextual_only.append((cls, rules[cls]))
    return truly_phantom, contextual_only


def is_button_use(html: str, cls: str) -> int:
    return len(re.findall(
        r'<button[^>]+class="[^"]*\b' + re.escape(cls) + r'\b[^"]*"', html
    ))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit 1 if any phantom is on a <button> element.",
    )
    args = parser.parse_args()

    print(f'{"Page":<22} {"Truly phantom":<35} {"Contextual-only":<35}')
    print("-" * 95)

    total_button_bugs = 0
    bug_details: list[str] = []

    for page in PAGES:
        path = os.path.join(STATIC_DIR, page)
        if not os.path.exists(path):
            continue
        truly, ctx = audit_page(path)
        truly_str = ", ".join(truly) if truly else "—"
        ctx_str = ", ".join(c for c, _ in ctx) if ctx else "—"
        print(f"{page:<22} {truly_str:<35} {ctx_str:<35}")

        with open(path) as f:
            html = f.read()
        for cls in truly:
            n = is_button_use(html, cls)
            if n > 0:
                total_button_bugs += n
                bug_details.append(f"  {page} → .{cls} on {n} <button> (no CSS rule)")
        for cls, contexts in ctx:
            n = is_button_use(html, cls)
            if n > 0:
                ancestors = sorted({" + ".join(a) for a in contexts if a})
                total_button_bugs += n
                bug_details.append(
                    f"  {page} → .{cls} on {n} <button> "
                    f"(only defined under: {ancestors})"
                )

    if bug_details:
        print()
        print("=" * 95)
        print("BUTTONS WITH POTENTIALLY UNSTYLED CSS:")
        print("=" * 95)
        for line in bug_details:
            print(line)
        print()
        print(f"Total: {total_button_bugs} buttons across the codebase.")

    if args.strict and total_button_bugs > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
