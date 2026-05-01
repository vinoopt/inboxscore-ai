#!/usr/bin/env python3
"""
Foundation gate (Master Playbook 10): parse-check every inline <script>
block in static/*.html using Node.js's `node --check`.

Why this exists
---------------
INBOX-178 shipped 4 critical bugs in one commit because pytest cannot
catch JavaScript parse errors. Two were:

  * orphan HTML left inside a <script> block (truncation accident)
  * a render function that ended without its closing braces

Both crashed the entire dashboard JS bundle on load. This script extracts
inline JS from every static HTML file and pipes each block through
`node --check`, which validates syntax without executing. Any parse error
fails the build.

Excludes
--------
* <script src="..."> external scripts (no inline body)
* <script type="application/json"> data blocks (not executable JS)
* <script type="application/ld+json"> (structured data)

Exit codes
----------
0 — all inline JS blocks parsed successfully
1 — at least one parse error (output names file + line + reason)
2 — `node` not available on PATH
"""
from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile

# Match <script ...>...</script>, capture the opening tag attrs and the body.
SCRIPT_RE = re.compile(
    r'<script\b([^>]*)>(.*?)</script>',
    re.IGNORECASE | re.DOTALL,
)
# Detect non-JS script blocks we should skip (data-only).
NON_JS_TYPES = (
    'application/json',
    'application/ld+json',
    'text/template',
    'text/x-template',
)


def extract_inline_blocks(html_path: pathlib.Path) -> list[tuple[int, str]]:
    """Return a list of (line_number, js_body) for inline <script> blocks."""
    text = html_path.read_text(encoding='utf-8', errors='replace')
    blocks: list[tuple[int, str]] = []

    for match in SCRIPT_RE.finditer(text):
        attrs = match.group(1).lower()
        body = match.group(2)

        # Skip external scripts: <script src="..."> has no inline body.
        if 'src=' in attrs:
            continue
        # Skip non-JS data blocks (they're not executable JS).
        if any(f'type="{t}"' in attrs or f"type='{t}'" in attrs for t in NON_JS_TYPES):
            continue
        # Skip empty/whitespace-only bodies.
        if not body.strip():
            continue

        # Compute 1-indexed line number where the <script> tag opens.
        line_no = text.count('\n', 0, match.start()) + 1
        blocks.append((line_no, body))

    return blocks


def node_check(js_body: str) -> tuple[bool, str]:
    """Pipe a JS body through `node --check`. Return (ok, stderr)."""
    with tempfile.NamedTemporaryFile(
        mode='w', suffix='.js', delete=False, encoding='utf-8',
    ) as tmp:
        tmp.write(js_body)
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            ['node', '--check', tmp_path],
            capture_output=True,
            text=True,
            timeout=15,
        )
        return result.returncode == 0, result.stderr
    finally:
        os.unlink(tmp_path)


def main() -> int:
    if shutil.which('node') is None:
        print('ERROR: node is not on PATH — cannot parse-check inline JS', file=sys.stderr)
        return 2

    static_dir = pathlib.Path(__file__).resolve().parent.parent / 'static'
    if not static_dir.is_dir():
        print(f'ERROR: static dir not found at {static_dir}', file=sys.stderr)
        return 2

    html_files = sorted(static_dir.glob('*.html'))
    if not html_files:
        print(f'No HTML files under {static_dir}; nothing to check.')
        return 0

    total_blocks = 0
    failures: list[str] = []

    for html in html_files:
        blocks = extract_inline_blocks(html)
        for line_no, body in blocks:
            total_blocks += 1
            ok, stderr = node_check(body)
            if not ok:
                # First non-empty stderr line usually has the parse error.
                first_err = next(
                    (line.strip() for line in stderr.splitlines() if line.strip()),
                    '(no detail)',
                )
                failures.append(f'{html.name}:{line_no} — {first_err}')

    if failures:
        print(f'\n✗ Inline JS parse-check FAILED ({len(failures)} of {total_blocks} blocks)\n')
        for f in failures:
            print(f'  {f}')
        return 1

    print(f'✓ Inline JS parse-check passed ({total_blocks} blocks across {len(html_files)} files)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
