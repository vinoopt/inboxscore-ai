#!/usr/bin/env python3
"""
Foundation gate (Master Playbook 10): detect CSS rule-ordering hazards
where the EXACT SAME selector appears in two different rule blocks with
conflicting visual values.

Why this exists
---------------
INBOX-178 shipped a bug where the same selector was painted with
different `background` / `color` values in two different CSS rules. The
later rule won by source order — invisible to pytest, visible to humans.

This linter catches exactly that: an EXACT-DUPLICATE selector string
appearing in two rule blocks (same file or different files) with
conflicting `background`, `background-color`, or `color` values.

Intentional patterns NOT flagged
--------------------------------
* Modifier variants: `.btn.primary` vs `.btn.secondary` — different selectors
* State variants:    `.btn` vs `.btn:hover`              — different selectors
* Theme overrides:   `[data-theme=dark] .btn` vs `.btn`  — different selectors
* Descendant rules:  `.card .btn` vs `.list .btn`        — different selectors

Only flags
----------
* `.foo { background: red }` AND `.foo { background: blue }` — same selector,
  conflicting bg → ordering bug. Whichever loads last wins, silently.

Exit codes
----------
0 — no exact-duplicate selectors with conflicting visual values
1 — at least one collision; output names selector + the two file:line
"""
from __future__ import annotations

import pathlib
import re
import sys
from collections import defaultdict
from dataclasses import dataclass

# Match a CSS rule: selector { body }
RULE_RE = re.compile(r'([^{}]+?)\{([^{}]*)\}', re.DOTALL)

# Properties we treat as visual conflicts when they differ.
WATCH_PROPS = ('background', 'background-color', 'color')

# Strip @media / @keyframes wrappers (we don't lint inside at-rules).
AT_RULE_RE = re.compile(r'@[a-z-]+[^{]*\{(?:[^{}]|\{[^{}]*\})*\}', re.IGNORECASE)


@dataclass
class Rule:
    file: str
    selector_canonical: str  # whitespace-collapsed for exact-match comparison
    body: str
    line: int


def strip_at_rules(css: str) -> str:
    prev = None
    while css != prev:
        prev = css
        css = AT_RULE_RE.sub('', css)
    return css


def canonicalize_selector(sel: str) -> str:
    """Collapse whitespace and normalise so that `.foo .bar` and `.foo  .bar`
    compare equal — but `.foo.bar` and `.foo .bar` stay distinct."""
    return re.sub(r'\s+', ' ', sel.strip())


def parse_rules(css_path: pathlib.Path) -> list[Rule]:
    raw = css_path.read_text(encoding='utf-8', errors='replace')
    raw_no_comments = re.sub(r'/\*.*?\*/', '', raw, flags=re.DOTALL)
    cleaned = strip_at_rules(raw_no_comments)

    rules: list[Rule] = []
    for match in RULE_RE.finditer(cleaned):
        selector = match.group(1).strip()
        body = match.group(2).strip()
        line = raw[: match.start()].count('\n') + 1
        # Split comma-separated selector groups so `.a, .b { ... }` becomes
        # two rules with the same body.
        for part in selector.split(','):
            canonical = canonicalize_selector(part)
            if not canonical:
                continue
            rules.append(Rule(
                file=css_path.name,
                selector_canonical=canonical,
                body=body,
                line=line,
            ))
    return rules


def extract_visual_props(body: str) -> dict[str, str]:
    props: dict[str, str] = {}
    for line in body.split(';'):
        if ':' not in line:
            continue
        key, _, value = line.partition(':')
        key = key.strip().lower()
        value = value.strip().lower()
        if key in WATCH_PROPS and value:
            props[key] = value
    return props


def main() -> int:
    css_dir = pathlib.Path(__file__).resolve().parent.parent / 'static' / 'css'
    if not css_dir.is_dir():
        print(f'No CSS dir at {css_dir}; nothing to check.')
        return 0

    css_files = sorted(css_dir.glob('*.css'))
    if not css_files:
        print(f'No CSS files; nothing to check.')
        return 0

    # Collect all rules across all files, indexed by canonical selector.
    by_selector: dict[str, list[Rule]] = defaultdict(list)
    for css in css_files:
        for rule in parse_rules(css):
            by_selector[rule.selector_canonical].append(rule)

    collisions: list[str] = []
    total_dups = 0

    for selector, rules in by_selector.items():
        if len(rules) < 2:
            continue
        total_dups += 1
        # Compare visual props pairwise.
        props_per_rule = [(r, extract_visual_props(r.body)) for r in rules]
        # Skip rules with no watched props at all — duplicate selectors that
        # only set, e.g., `display` are fine.
        with_visual = [(r, p) for r, p in props_per_rule if p]
        if len(with_visual) < 2:
            continue
        for i in range(len(with_visual)):
            for j in range(i + 1, len(with_visual)):
                r1, v1 = with_visual[i]
                r2, v2 = with_visual[j]
                conflicts = []
                for prop in WATCH_PROPS:
                    if prop in v1 and prop in v2 and v1[prop] != v2[prop]:
                        conflicts.append(f'{prop}: "{v1[prop]}" vs "{v2[prop]}"')
                if conflicts:
                    collisions.append(
                        f'`{selector}` — '
                        f'{r1.file}:{r1.line} vs {r2.file}:{r2.line}\n'
                        + '\n'.join(f'    {c}' for c in conflicts)
                    )

    if collisions:
        print(f'\n✗ Class-collision check FAILED ({len(collisions)} conflict(s))\n')
        for c in collisions:
            print(f'  {c}\n')
        print('  Hint: the later rule silently overrides the earlier one. Either delete')
        print('  the duplicate, or rename one selector to make the intent explicit.')
        return 1

    total_unique = len(by_selector)
    print(
        f'✓ Class-collision check passed '
        f'({total_unique} unique selectors, {total_dups} appear in multiple rules)'
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
