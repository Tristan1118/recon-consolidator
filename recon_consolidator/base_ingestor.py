import hashlib
import os

from recon_consolidator.db import get_connection
from recon_consolidator.schema import init_db


class BaseIngestor:
    """
    Base class for all tool-specific parsers.

    Subclasses must implement:
        - tool_name: str class attribute
        - parse(filepath) -> list[dict]
    """

    tool_name = None

    def __init__(self, db_path):
        init_db(db_path)
        self.conn = get_connection(db_path)

    def close(self):
        self.conn.close()

    def _file_hash(self, filepath):
        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    def _already_imported(self, file_hash):
        row = self.conn.execute(
            "SELECT id FROM raw_imports WHERE file_hash = ?", (file_hash,)
        ).fetchone()
        return row is not None

    def _log_import(self, filepath, file_hash, row_count):
        self.conn.execute(
            "INSERT INTO raw_imports (filename, file_hash, tool, row_count) VALUES (?, ?, ?, ?)",
            (os.path.basename(filepath), file_hash, self.tool_name, row_count),
        )

    def ingest(self, filepath):
        """Main entry point. Hash-checks, parses, inserts, and logs the import."""
        file_hash = self._file_hash(filepath)
        if self._already_imported(file_hash):
            print(f"Already imported (same hash): {filepath}")
            return 0

        try:
            records = self.parse(filepath)
            row_count = self._insert(records)
            self._log_import(filepath, file_hash, row_count)
            self.conn.commit()
            print(f"Ingested {row_count} records from {filepath}")
            return row_count
        except Exception:
            self.conn.rollback()
            raise

    def parse(self, filepath):
        """Subclasses must implement this. Return a list of dicts."""
        raise NotImplementedError("Subclasses must implement parse()")

    def _insert(self, records):
        """Subclasses should override this to call the appropriate insert method.
        Default calls insert_subdomains."""
        return self.insert_subdomains(records)

    def insert_subdomains(self, records):
        """Bulk upsert into subdomains table."""
        count = 0
        for rec in records:
            fqdn = rec["fqdn"].strip().lower().rstrip(".")
            source = rec.get("source", self.tool_name)
            existing = self.conn.execute(
                "SELECT id, source FROM subdomains WHERE fqdn = ?", (fqdn,)
            ).fetchone()
            if existing:
                existing_sources = existing["source"] or ""
                if source and source not in existing_sources.split(", "):
                    new_source = f"{existing_sources}, {source}" if existing_sources else source
                    self.conn.execute(
                        "UPDATE subdomains SET last_seen = CURRENT_TIMESTAMP, source = ? WHERE id = ?",
                        (new_source, existing["id"]),
                    )
                else:
                    self.conn.execute(
                        "UPDATE subdomains SET last_seen = CURRENT_TIMESTAMP WHERE id = ?",
                        (existing["id"],),
                    )
            else:
                self.conn.execute(
                    "INSERT INTO subdomains (fqdn, source) VALUES (?, ?)",
                    (fqdn, source),
                )
            count += 1
        return count

    def insert_dns_records(self, records):
        """Bulk insert into dns_records. Auto-creates subdomains as needed."""
        count = 0
        for rec in records:
            fqdn = rec["fqdn"].strip().lower().rstrip(".")
            source = rec.get("source", self.tool_name)
            # Ensure subdomain exists
            row = self.conn.execute(
                "SELECT id FROM subdomains WHERE fqdn = ?", (fqdn,)
            ).fetchone()
            if row:
                subdomain_id = row["id"]
            else:
                cursor = self.conn.execute(
                    "INSERT INTO subdomains (fqdn, source) VALUES (?, ?)",
                    (fqdn, source),
                )
                subdomain_id = cursor.lastrowid

            try:
                self.conn.execute(
                    "INSERT INTO dns_records (subdomain_id, record_type, value, ttl, source) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (subdomain_id, rec["record_type"], rec["value"], rec.get("ttl"), source),
                )
                count += 1
            except Exception:
                # Duplicate (subdomain_id, record_type, value), skip
                pass
        return count

    def insert_ports(self, records):
        """Bulk insert into ports table."""
        count = 0
        for rec in records:
            try:
                self.conn.execute(
                    "INSERT INTO ports (ip, port, protocol, state, service, banner, version, scan_profile) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        rec["ip"],
                        rec["port"],
                        rec.get("protocol", "tcp"),
                        rec.get("state"),
                        rec.get("service"),
                        rec.get("banner"),
                        rec.get("version"),
                        rec.get("scan_profile"),
                    ),
                )
                count += 1
            except Exception:
                # Duplicate (ip, port, protocol, scan_profile), skip
                pass
        return count

    def insert_rows(self, table, records):
        """Generic INSERT OR IGNORE for any table."""
        if not records:
            return 0
        columns = list(records[0].keys())
        placeholders = ", ".join(["?"] * len(columns))
        col_names = ", ".join(columns)
        count = 0
        for rec in records:
            try:
                self.conn.execute(
                    f"INSERT OR IGNORE INTO {table} ({col_names}) VALUES ({placeholders})",
                    [rec[c] for c in columns],
                )
                count += 1
            except Exception:
                pass
        return count
