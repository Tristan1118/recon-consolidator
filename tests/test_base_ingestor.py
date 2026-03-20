import os
import tempfile
import sqlite3
import pytest

from recon_consolidator.base_ingestor import BaseIngestor


class StubIngestor(BaseIngestor):
    """Test subclass that returns hardcoded subdomain records."""
    tool_name = "stub-tool"

    def parse(self, filepath):
        with open(filepath) as f:
            lines = [line.strip() for line in f if line.strip()]
        return [{"fqdn": line, "source": self.tool_name} for line in lines]


class ErrorIngestor(BaseIngestor):
    """Test subclass that raises during parse."""
    tool_name = "error-tool"

    def parse(self, filepath):
        raise ValueError("intentional parse failure")


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


@pytest.fixture
def sample_file(tmp_path):
    f = tmp_path / "sample.txt"
    f.write_text("Example.COM.\nfoo.example.com\nBAR.example.com\n")
    return str(f)


def test_ingest_inserts_records(db_path, sample_file):
    ing = StubIngestor(db_path)
    count = ing.ingest(sample_file)
    assert count == 3
    rows = ing.conn.execute("SELECT fqdn FROM subdomains ORDER BY fqdn").fetchall()
    fqdns = [r["fqdn"] for r in rows]
    assert fqdns == ["bar.example.com", "example.com", "foo.example.com"]
    ing.close()


def test_duplicate_file_skipped(db_path, sample_file):
    ing = StubIngestor(db_path)
    ing.ingest(sample_file)
    count = ing.ingest(sample_file)
    assert count == 0
    imports = ing.conn.execute("SELECT COUNT(*) as c FROM raw_imports").fetchone()
    assert imports["c"] == 1
    ing.close()


def test_rollback_on_parse_error(db_path, sample_file):
    ing = ErrorIngestor(db_path)
    with pytest.raises(ValueError):
        ing.ingest(sample_file)
    rows = ing.conn.execute("SELECT COUNT(*) as c FROM subdomains").fetchone()
    assert rows["c"] == 0
    imports = ing.conn.execute("SELECT COUNT(*) as c FROM raw_imports").fetchone()
    assert imports["c"] == 0
    ing.close()


def test_fqdn_normalization(db_path, sample_file):
    ing = StubIngestor(db_path)
    ing.ingest(sample_file)
    row = ing.conn.execute("SELECT fqdn FROM subdomains WHERE fqdn = 'example.com'").fetchone()
    assert row is not None  # "Example.COM." was normalized
    ing.close()


def test_upsert_appends_source(db_path, tmp_path):
    f1 = tmp_path / "f1.txt"
    f1.write_text("test.example.com\n")
    f2 = tmp_path / "f2.txt"
    f2.write_text("test.example.com\n# from tool-b\n")  # different content = different hash

    class Tool1(BaseIngestor):
        tool_name = "tool-a"
        def parse(self, filepath):
            return [{"fqdn": "test.example.com", "source": "tool-a"}]

    class Tool2(BaseIngestor):
        tool_name = "tool-b"
        def parse(self, filepath):
            return [{"fqdn": "test.example.com", "source": "tool-b"}]

    ing1 = Tool1(db_path)
    ing1.ingest(str(f1))
    ing1.close()

    ing2 = Tool2(db_path)
    ing2.ingest(str(f2))
    ing2.close()

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT source FROM subdomains WHERE fqdn = 'test.example.com'").fetchone()
    assert "tool-a" in row["source"]
    assert "tool-b" in row["source"]
    conn.close()


def test_insert_dns_records(db_path, tmp_path):
    f = tmp_path / "dns.txt"
    f.write_text("placeholder\n")

    class DnsIngestor(BaseIngestor):
        tool_name = "dns-tool"
        def parse(self, filepath):
            return [
                {"fqdn": "test.example.com", "record_type": "A", "value": "1.2.3.4"},
                {"fqdn": "test.example.com", "record_type": "AAAA", "value": "::1"},
            ]
        def _insert(self, records):
            return self.insert_dns_records(records)

    ing = DnsIngestor(db_path)
    count = ing.ingest(str(f))
    assert count == 2
    # Subdomain was auto-created
    sub = ing.conn.execute("SELECT id FROM subdomains WHERE fqdn = 'test.example.com'").fetchone()
    assert sub is not None
    dns = ing.conn.execute("SELECT COUNT(*) as c FROM dns_records").fetchone()
    assert dns["c"] == 2
    ing.close()


def test_insert_ports(db_path, tmp_path):
    f = tmp_path / "ports.txt"
    f.write_text("placeholder\n")

    class PortIngestor(BaseIngestor):
        tool_name = "port-tool"
        def parse(self, filepath):
            return [
                {"ip": "1.2.3.4", "port": 80, "protocol": "tcp", "state": "open", "service": "http"},
                {"ip": "1.2.3.4", "port": 443, "protocol": "tcp", "state": "open", "service": "https"},
            ]
        def _insert(self, records):
            return self.insert_ports(records)

    ing = PortIngestor(db_path)
    count = ing.ingest(str(f))
    assert count == 2
    ports = ing.conn.execute("SELECT COUNT(*) as c FROM ports").fetchone()
    assert ports["c"] == 2
    ing.close()
