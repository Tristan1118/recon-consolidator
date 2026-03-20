#!/usr/bin/env python3
import argparse
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from recon_consolidator.parsers.subfinder import SubfinderParser
from recon_consolidator.parsers.nmap_xml import NmapXmlParser

PARSERS = {
    "subfinder": SubfinderParser,
    "nmap": NmapXmlParser,
}


def main():
    parser = argparse.ArgumentParser(description="Ingest tool output into the recon database.")
    parser.add_argument("db_path", help="Path to the SQLite database file")
    parser.add_argument("parser_name", choices=PARSERS.keys(), help="Parser to use")
    parser.add_argument("file", help="Path to the tool output file")
    parser.add_argument("--scan-profile", help="Scan profile tag (nmap only)")
    args = parser.parse_args()

    if not os.path.exists(args.file):
        print(f"File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    parser_cls = PARSERS[args.parser_name]
    if args.parser_name == "nmap":
        ingestor = parser_cls(args.db_path, scan_profile=args.scan_profile)
    else:
        ingestor = parser_cls(args.db_path)

    try:
        ingestor.ingest(args.file)
    finally:
        ingestor.close()


if __name__ == "__main__":
    main()
