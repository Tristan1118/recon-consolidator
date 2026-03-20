import os
import pytest

from recon_consolidator.parsers.nmap_xml import NmapXmlParser

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test.db")


def test_parse_ports(db_path):
    parser = NmapXmlParser(db_path, scan_profile="light")
    parsed = parser.parse(os.path.join(FIXTURES, "nmap_sample.xml"))
    ports = parsed["ports"]
    assert len(ports) == 5  # 3 from first host, 2 from second
    # Check a specific port
    http = [p for p in ports if p["port"] == 80][0]
    assert http["ip"] == "10.0.0.1"
    assert http["state"] == "open"
    assert http["service"] == "http"
    assert "nginx" in http["version"]
    assert http["scan_profile"] == "light"
    parser.close()


def test_parse_hostnames(db_path):
    parser = NmapXmlParser(db_path)
    parsed = parser.parse(os.path.join(FIXTURES, "nmap_sample.xml"))
    subs = parsed["subdomains"]
    fqdns = [s["fqdn"] for s in subs]
    assert "web.example.com" in fqdns
    assert "mail.example.com" in fqdns
    parser.close()


def test_ingest_populates_db(db_path):
    parser = NmapXmlParser(db_path, scan_profile="light")
    total = parser.ingest(os.path.join(FIXTURES, "nmap_sample.xml"))
    assert total == 7  # 5 ports + 2 subdomains

    ports = parser.conn.execute("SELECT COUNT(*) as c FROM ports").fetchone()
    assert ports["c"] == 5

    subs = parser.conn.execute("SELECT COUNT(*) as c FROM subdomains").fetchone()
    assert subs["c"] == 2

    # Verify scan_profile was set
    profile = parser.conn.execute(
        "SELECT DISTINCT scan_profile FROM ports"
    ).fetchone()
    assert profile["scan_profile"] == "light"
    parser.close()


def test_scan_profile_default_none(db_path):
    parser = NmapXmlParser(db_path)
    parsed = parser.parse(os.path.join(FIXTURES, "nmap_sample.xml"))
    for p in parsed["ports"]:
        assert p["scan_profile"] is None
    parser.close()
