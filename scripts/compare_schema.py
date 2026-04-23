#!/usr/bin/env python3
"""Schema drift checker used by the CI schema-drift-check job (INBOX-32).

Inputs:
    --replayed   Path to pg_dump --schema-only output from a fresh Postgres
                 that replayed db/supabase-schema.sql + every migration.
    --prod       Path to the canonical prod dump (db/prod-schema-2026-04-22.sql),
                 which is column-level data pulled from Supabase PostgREST
                 OpenAPI using the service-role key.

Behaviour:
    - Parses CREATE TABLE public.<name> (...) blocks out of both files.
    - For each table in either file, extracts the set of columns and a
      normalized type per column.
    - Reports drift in three buckets:
        * tables_missing_in_replay   (prod has them, migrations don't)
        * columns_missing_in_replay  (prod has cols migrations don't)
        * type_mismatches            (same col, different normalized type)
    - Intentionally ignores DEFAULT expressions and NOT NULL markers: the
      prod dump is PostgREST-derived and has lossy defaults/nullability
      that pg_dump doesn't; comparing them produces noise without signal.
    - Also intentionally TOLERATES tables or columns present in replay but
      absent from prod. A migration that adds something new to Supabase
      is fine as long as every column the app reads is declared.

Exits:
    0   clean
    1   drift detected (details printed to stderr)
"""

from __future__ import annotations

import argparse
import re
import sys
from typing import Dict, Set, Tuple

# ----------------------------------------------------------------------
# Type normalizer
# ----------------------------------------------------------------------

# Map every type we've seen in either dump style to a canonical token.
# We only track the column kind — length/precision modifiers ignored.
_TYPE_ALIASES = {
    "integer": "int",
    "int": "int",
    "int4": "int",
    "int8": "bigint",
    "bigint": "bigint",
    "smallint": "smallint",
    "int2": "smallint",
    "boolean": "bool",
    "bool": "bool",
    "real": "real",
    "float4": "real",
    "double": "double",            # "double precision" collapses to "double"
    "float": "double",             # bare 'float' in Postgres = double precision (float8)
    "float8": "double",
    "numeric": "numeric",
    "text": "text",
    "varchar": "text",             # character varying -> text (lossy but acceptable)
    "character": "text",
    "uuid": "uuid",
    "jsonb": "jsonb",
    "json": "jsonb",               # we treat both the same for drift purposes
    "date": "date",
    "time": "time",
    "timestamp": "timestamptz",    # assume TZ variant by default
    "timestamptz": "timestamptz",
    "inet": "inet",
    "cidr": "inet",
    "bytea": "bytea",
}


def normalize_type(raw: str) -> str:
    """Collapse a type phrase like 'timestamp with time zone' to 'timestamptz'."""
    r = raw.strip().lower()
    # common multi-token types
    if "timestamp" in r and "time zone" in r:
        return "timestamptz"
    if r.startswith("double precision"):
        return "double"
    if r.startswith("character varying"):
        return "text"
    if r.startswith("character"):
        return "text"
    # first word
    first = r.split()[0].rstrip("(,")
    return _TYPE_ALIASES.get(first, first)


# ----------------------------------------------------------------------
# CREATE TABLE parser
# ----------------------------------------------------------------------

# Only tables in the public schema are in scope; everything else (auth, extensions) is stub territory.
_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?(\w+)\s*\((.*?)\n\s*\)\s*;",
    re.IGNORECASE | re.DOTALL,
)


_ALTER_ADD_RE = re.compile(
    r"ALTER\s+TABLE\s+(?:ONLY\s+)?(?:public\.)?(\w+)\s+"
    r"ADD\s+COLUMN\s+(?:IF\s+NOT\s+EXISTS\s+)?\"?(\w+)\"?\s+([^,;]+?)(?=\s*(?:DEFAULT|NOT\s+NULL|REFERENCES|UNIQUE|CHECK|;|$))",
    re.IGNORECASE,
)


def _strip_line_comments(sql: str) -> str:
    """Remove `-- ... \\n` comments. Conservative: skips stripping inside single-quoted strings.

    Necessary because migrations like 003_postmaster_tables.sql have inline
    trailing comments after commas, which confuse _smart_split / _parse_column_list.
    """
    out: list[str] = []
    i = 0
    in_str = False
    while i < len(sql):
        ch = sql[i]
        if ch == "'" and (i == 0 or sql[i-1] != "\\"):
            in_str = not in_str
            out.append(ch)
            i += 1
            continue
        if not in_str and ch == "-" and i + 1 < len(sql) and sql[i+1] == "-":
            # skip to end of line
            while i < len(sql) and sql[i] != "\n":
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def parse_tables(sql: str) -> Dict[str, Dict[str, str]]:
    """Return {table_name: {col_name: normalized_type}} for every public table.

    Picks up both CREATE TABLE blocks AND `ALTER TABLE ... ADD COLUMN` so that
    a simulated concat-replay (migrations piped one after another without an
    actual Postgres) still reflects the final column set.
    """
    sql = _strip_line_comments(sql)
    tables: Dict[str, Dict[str, str]] = {}
    for m in _TABLE_RE.finditer(sql):
        name = m.group(1).lower()
        body = m.group(2)
        cols = _parse_column_list(body)
        if cols:
            tables.setdefault(name, {}).update(cols)
    for m in _ALTER_ADD_RE.finditer(sql):
        name = m.group(1).lower()
        col = m.group(2).lower()
        type_phrase = m.group(3).strip()
        tables.setdefault(name, {})[col] = normalize_type(type_phrase)
    return tables


def _parse_column_list(body: str) -> Dict[str, str]:
    """Best-effort column extractor. Skips table-level constraints."""
    # Split on commas that are NOT inside parentheses (handles NUMERIC(10,2) etc).
    parts = _smart_split(body)
    cols: Dict[str, str] = {}
    for raw in parts:
        line = raw.strip().rstrip(",")
        if not line:
            continue
        upper = line.upper()
        # Skip table-level constraint rows.
        if upper.startswith(("CONSTRAINT ", "PRIMARY KEY", "UNIQUE ", "UNIQUE(",
                             "FOREIGN KEY", "CHECK ", "CHECK(", "EXCLUDE ")):
            continue
        tokens = line.split(None, 2)
        if len(tokens) < 2:
            continue
        col = tokens[0].strip('"').lower()
        # Second+ tokens form the type phrase up to the first keyword modifier.
        rest = " ".join(tokens[1:])
        cols[col] = normalize_type(rest)
    return cols


def _smart_split(body: str) -> list[str]:
    """Split on commas at paren-depth 0."""
    depth = 0
    cur: list[str] = []
    parts: list[str] = []
    for ch in body:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


# ----------------------------------------------------------------------
# Diff
# ----------------------------------------------------------------------

def diff(
    prod: Dict[str, Dict[str, str]],
    replay: Dict[str, Dict[str, str]],
) -> Tuple[Set[str], Dict[str, Set[str]], Dict[str, Set[Tuple[str, str, str]]]]:
    """Return drift buckets. Only prod-side missing items count as failures."""
    tables_missing = set(prod.keys()) - set(replay.keys())

    columns_missing: Dict[str, Set[str]] = {}
    type_mismatches: Dict[str, Set[Tuple[str, str, str]]] = {}

    for t, prod_cols in prod.items():
        if t not in replay:
            continue
        replay_cols = replay[t]
        missing = set(prod_cols.keys()) - set(replay_cols.keys())
        if missing:
            columns_missing[t] = missing
        for col, prod_type in prod_cols.items():
            if col in replay_cols and replay_cols[col] != prod_type:
                type_mismatches.setdefault(t, set()).add(
                    (col, prod_type, replay_cols[col])
                )
    return tables_missing, columns_missing, type_mismatches


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--replayed", required=True, help="pg_dump output from migration replay")
    ap.add_argument("--prod", required=True, help="canonical prod schema dump")
    args = ap.parse_args()

    prod_sql = open(args.prod, encoding="utf-8").read()
    replay_sql = open(args.replayed, encoding="utf-8").read()

    prod = parse_tables(prod_sql)
    replay = parse_tables(replay_sql)

    tables_missing, columns_missing, type_mismatches = diff(prod, replay)

    print(f"[schema-drift] prod tables:   {len(prod)}")
    print(f"[schema-drift] replay tables: {len(replay)}")

    drift = False

    if tables_missing:
        drift = True
        print("::error::Tables present in prod but NOT created by migrations:", file=sys.stderr)
        for t in sorted(tables_missing):
            print(f"  - {t}", file=sys.stderr)

    if columns_missing:
        drift = True
        print("::error::Columns present in prod but NOT created by migrations:", file=sys.stderr)
        for t in sorted(columns_missing):
            for c in sorted(columns_missing[t]):
                print(f"  - {t}.{c}", file=sys.stderr)

    if type_mismatches:
        drift = True
        print("::error::Column type mismatches (prod -> replay):", file=sys.stderr)
        for t in sorted(type_mismatches):
            for col, pt, rt in sorted(type_mismatches[t]):
                print(f"  - {t}.{col}: prod={pt} replay={rt}", file=sys.stderr)

    # Extras in replay are tolerated but logged so reviewers notice.
    extras = set(replay.keys()) - set(prod.keys())
    if extras:
        print(f"[schema-drift] NOTE: tables in replay not seen in prod dump ({len(extras)}): "
              f"{sorted(extras)}")

    if drift:
        print("[schema-drift] FAIL — migrations do not reproduce prod column set.", file=sys.stderr)
        return 1
    print("[schema-drift] OK — every prod table and column is declared by migrations.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
