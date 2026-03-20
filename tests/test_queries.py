import os
import pytest

from recon_consolidator.db import get_connection
from recon_consolidator.schema import init_db
from recon_consolidator.queries import QUERIES, run_query, run_sql


@pytest.fixture
def conn(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)
    c = get_connection(db_path)
    # Populate sample data
    c.execute("INSERT INTO subdomains (fqdn, source) VALUES ('web.example.com', 'subfinder')")
    c.execute("INSERT INTO subdomains (fqdn, source) VALUES ('api.example.com', 'subfinder, bbot')")
    c.execute("INSERT INTO subdomains (fqdn, source) VALUES ('orphan.example.com', 'subfinder')")
    c.execute(
        "INSERT INTO dns_records (subdomain_id, record_type, value, source) VALUES (1, 'A', '10.0.0.1', 'dig')"
    )
    c.execute(
        "INSERT INTO dns_records (subdomain_id, record_type, value, source) VALUES (2, 'CNAME', 'lb.example.com', 'dig')"
    )
    c.execute(
        "INSERT INTO ports (ip, hostname, port, protocol, state, service, scan_profile) "
        "VALUES ('10.0.0.1', 'web.example.com', 80, 'tcp', 'open', 'http', 'light')"
    )
    c.execute(
        "INSERT INTO ports (ip, hostname, port, protocol, state, service, scan_profile) "
        "VALUES ('10.0.0.1', 'web.example.com', 443, 'tcp', 'open', 'https', 'light')"
    )
    c.execute(
        "INSERT INTO raw_imports (filename, file_hash, tool, row_count) "
        "VALUES ('subfinder.txt', 'abc123', 'subfinder', 3)"
    )
    c.commit()
    yield c
    c.close()


def test_all_queries_execute(conn):
    """Every named query should run without SQL errors."""
    for name in QUERIES:
        desc, cols, rows = run_query(conn, name)
        assert isinstance(cols, list)
        assert isinstance(rows, list)


def test_unresolved(conn):
    desc, cols, rows = run_query(conn, "unresolved")
    fqdns = [r[0] for r in rows]
    assert "orphan.example.com" in fqdns
    assert "web.example.com" not in fqdns


def test_cname_chains(conn):
    desc, cols, rows = run_query(conn, "cname-chains")
    assert len(rows) == 1
    assert rows[0][0] == "api.example.com"


def test_single_source(conn):
    desc, cols, rows = run_query(conn, "single-source")
    fqdns = [r[0] for r in rows]
    assert "web.example.com" in fqdns
    assert "api.example.com" not in fqdns  # has two sources


def test_open_ports(conn):
    desc, cols, rows = run_query(conn, "open-ports")
    assert len(rows) == 2
    # Column order: ip, hostname, port, protocol, ...
    ports = [r[2] for r in rows]
    assert 80 in ports
    assert 443 in ports


def test_open_ports_hostname_only(conn):
    """Port with hostname but no IP should still resolve to its subdomain."""
    conn.execute("INSERT INTO subdomains (fqdn, source) VALUES ('cdn.example.com', 'manual')")
    conn.execute(
        "INSERT INTO ports (hostname, port, protocol, state, service, scan_profile) "
        "VALUES ('cdn.example.com', 8080, 'tcp', 'open', 'http-alt', 'light')"
    )
    conn.commit()
    desc, cols, rows = run_query(conn, "open-ports")
    # Find the hostname-only row
    cdn_rows = [r for r in rows if r[2] == 8080]
    assert len(cdn_rows) == 1
    assert cdn_rows[0][0] == "(none)"  # ip is COALESCE'd to (none)
    assert cdn_rows[0][1] == "cdn.example.com"


def test_summary(conn):
    desc, cols, rows = run_query(conn, "summary")
    assert len(rows) == 1
    row = rows[0]
    assert row[0] == 3  # subdomains
    assert row[2] == 2  # ports


def test_run_sql(conn):
    cols, rows = run_sql(conn, "SELECT fqdn FROM subdomains ORDER BY fqdn")
    assert cols == ["fqdn"]
    assert len(rows) == 3


def test_unknown_query(conn):
    with pytest.raises(ValueError, match="Unknown query"):
        run_query(conn, "nonexistent")
