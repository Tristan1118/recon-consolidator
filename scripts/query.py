#!/usr/bin/env python3
import argparse
import csv
import io
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from recon_consolidator.db import get_connection
from recon_consolidator.queries import QUERIES, run_query, run_sql


def format_table(columns, rows):
    """Simple column-aligned table output."""
    if not rows:
        return "(no results)"
    # Convert sqlite3.Row to tuples if needed
    str_rows = [[str(v) if v is not None else "" for v in row] for row in rows]
    widths = [len(c) for c in columns]
    for row in str_rows:
        for i, val in enumerate(row):
            widths[i] = max(widths[i], len(val))

    header = "  ".join(c.ljust(widths[i]) for i, c in enumerate(columns))
    separator = "  ".join("-" * w for w in widths)
    lines = [header, separator]
    for row in str_rows:
        lines.append("  ".join(val.ljust(widths[i]) for i, val in enumerate(row)))
    return "\n".join(lines)


def format_csv(columns, rows):
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(columns)
    for row in rows:
        writer.writerow(row)
    return buf.getvalue()


def format_json(columns, rows):
    records = []
    for row in rows:
        records.append(dict(zip(columns, row)))
    return json.dumps(records, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(description="Query the recon database.")
    parser.add_argument("db_path", help="Path to the SQLite database file")
    parser.add_argument("query", help=f"Query name ({', '.join(QUERIES.keys())}) or 'sql'")
    parser.add_argument("sql_string", nargs="?", help="Raw SQL (when query is 'sql')")
    parser.add_argument("--csv", dest="fmt", action="store_const", const="csv", help="CSV output")
    parser.add_argument("--json", dest="fmt", action="store_const", const="json", help="JSON output")
    args = parser.parse_args()

    if not os.path.exists(args.db_path):
        print(f"Database not found: {args.db_path}", file=sys.stderr)
        sys.exit(1)

    conn = get_connection(args.db_path)

    try:
        if args.query == "sql":
            if not args.sql_string:
                print("Usage: query.py <db> sql \"SELECT ...\"", file=sys.stderr)
                sys.exit(1)
            columns, rows = run_sql(conn, args.sql_string)
        elif args.query in QUERIES:
            description, columns, rows = run_query(conn, args.query)
            if args.fmt is None:
                print(f"-- {description} --\n")
        else:
            print(f"Unknown query: {args.query}", file=sys.stderr)
            print(f"Available: {', '.join(QUERIES.keys())}, sql", file=sys.stderr)
            sys.exit(1)

        fmt = args.fmt or "table"
        if fmt == "csv":
            print(format_csv(columns, rows), end="")
        elif fmt == "json":
            print(format_json(columns, rows))
        else:
            print(format_table(columns, rows))
    finally:
        conn.close()


if __name__ == "__main__":
    main()
