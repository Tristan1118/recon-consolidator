import csv
import io
import json
import os
import subprocess
import sys
import sqlite3
import pytest

SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "scripts")
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def run_cli(*args):
    result = subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "query.py"), *args],
        capture_output=True, text=True,
    )
    return result


@pytest.fixture
def db_path(tmp_path):
    """Create and populate a test DB."""
    db = str(tmp_path / "test.db")
    # Init
    subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "init_db.py"), db],
        capture_output=True,
    )
    # Ingest subfinder
    subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "ingest.py"), db, "subfinder",
         os.path.join(FIXTURES, "subfinder_sample.txt")],
        capture_output=True,
    )
    # Ingest nmap
    subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "ingest.py"), db, "nmap",
         os.path.join(FIXTURES, "nmap_sample.xml"), "--scan-profile", "light"],
        capture_output=True,
    )
    return db


def test_named_query_table(db_path):
    result = run_cli(db_path, "summary")
    assert result.returncode == 0
    assert "subdomains" in result.stdout


def test_named_query_csv(db_path):
    result = run_cli(db_path, "summary", "--csv")
    assert result.returncode == 0
    reader = csv.reader(io.StringIO(result.stdout))
    rows = list(reader)
    assert len(rows) >= 2  # header + at least one data row


def test_named_query_json(db_path):
    result = run_cli(db_path, "summary", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert len(data) >= 1


def test_raw_sql(db_path):
    result = run_cli(db_path, "sql", "SELECT fqdn FROM subdomains ORDER BY fqdn LIMIT 3")
    assert result.returncode == 0
    assert "example.com" in result.stdout


def test_raw_sql_json(db_path):
    result = run_cli(db_path, "sql", "SELECT COUNT(*) as cnt FROM subdomains", "--json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert data[0]["cnt"] > 0


def test_unknown_query(db_path):
    result = run_cli(db_path, "nonexistent")
    assert result.returncode != 0
    assert "Unknown query" in result.stderr


def test_open_ports_query(db_path):
    result = run_cli(db_path, "open-ports")
    assert result.returncode == 0
    # nmap sample has open ports
    assert "80" in result.stdout or "open" in result.stdout.lower()


def test_unresolved_query(db_path):
    result = run_cli(db_path, "unresolved")
    assert result.returncode == 0
    # subfinder subdomains without DNS should show up
    assert "example.com" in result.stdout
