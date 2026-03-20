import os
import pytest

from recon_consolidator.parsers.subfinder import SubfinderParser

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


def test_parse_normalization(db_path):
    parser = SubfinderParser(db_path)
    records = parser.parse(os.path.join(FIXTURES, "subfinder_sample.txt"))
    fqdns = [r["fqdn"] for r in records]
    # Comment and empty lines skipped, but parse returns raw lines (normalization happens on insert)
    assert len(records) == 6  # www, api, mail, API (dup), dev, blog
    parser.close()


def test_ingest_deduplicates(db_path):
    parser = SubfinderParser(db_path)
    count = parser.ingest(os.path.join(FIXTURES, "subfinder_sample.txt"))
    # api.example.com appears twice (mixed case), should deduplicate on insert
    rows = parser.conn.execute("SELECT fqdn FROM subdomains ORDER BY fqdn").fetchall()
    fqdns = [r["fqdn"] for r in rows]
    assert "api.example.com" in fqdns
    assert "www.example.com" in fqdns
    assert "mail.example.com" in fqdns
    assert "dev.example.com" in fqdns
    assert "blog.example.com" in fqdns
    # No uppercase or trailing dot versions
    assert all(f == f.lower() for f in fqdns)
    assert all(not f.endswith(".") for f in fqdns)
    parser.close()


def test_ingest_count(db_path):
    parser = SubfinderParser(db_path)
    count = parser.ingest(os.path.join(FIXTURES, "subfinder_sample.txt"))
    # 6 records parsed, but api.example.com appears twice so 6 total parse calls
    # (insert_subdomains handles dedup via upsert, count reflects parse output size)
    assert count == 6
    unique = parser.conn.execute("SELECT COUNT(*) as c FROM subdomains").fetchone()
    assert unique["c"] == 5  # 5 unique FQDNs
    parser.close()
