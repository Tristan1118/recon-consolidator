#!/usr/bin/env python3
import argparse
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from recon_consolidator.schema import init_db


def main():
    parser = argparse.ArgumentParser(description="Initialize a recon engagement database.")
    parser.add_argument("db_path", help="Path to the SQLite database file to create")
    args = parser.parse_args()

    init_db(args.db_path)
    print(f"Database initialized: {args.db_path}")


if __name__ == "__main__":
    main()
