import os
import subprocess
import sys
import sqlite3
import pytest

SCRIPTS = os.path.join(os.path.dirname(__file__), "..", "scripts")
FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


def run_cli(*args):
    result = subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "ingest.py"), *args],
        capture_output=True, text=True,
    )
    return result


@pytest.fixture
def db_path(tmp_path):
    db = str(tmp_path / "test.db")
    subprocess.run(
        [sys.executable, os.path.join(SCRIPTS, "init_db.py"), db],
        capture_output=True,
    )
    return db


def test_subfinder_ingest(db_path):
    result = run_cli(db_path, "subfinder", os.path.join(FIXTURES, "subfinder_sample.txt"))
    assert result.returncode == 0
    assert "Ingested" in result.stdout

    conn = sqlite3.connect(db_path)
    count = conn.execute("SELECT COUNT(*) FROM subdomains").fetchone()[0]
    assert count == 5
    conn.close()


def test_nmap_ingest_with_profile(db_path):
    result = run_cli(
        db_path, "nmap", os.path.join(FIXTURES, "nmap_sample.xml"),
        "--scan-profile", "light",
    )
    assert result.returncode == 0
    assert "ports" in result.stdout

    conn = sqlite3.connect(db_path)
    ports = conn.execute("SELECT COUNT(*) FROM ports").fetchone()[0]
    assert ports == 5
    profile = conn.execute("SELECT DISTINCT scan_profile FROM ports").fetchone()[0]
    assert profile == "light"
    conn.close()


def test_duplicate_skip(db_path):
    run_cli(db_path, "subfinder", os.path.join(FIXTURES, "subfinder_sample.txt"))
    result = run_cli(db_path, "subfinder", os.path.join(FIXTURES, "subfinder_sample.txt"))
    assert result.returncode == 0
    assert "Already imported" in result.stdout


def test_unknown_parser(db_path):
    result = run_cli(db_path, "nonexistent", os.path.join(FIXTURES, "subfinder_sample.txt"))
    assert result.returncode != 0


def test_missing_file(db_path):
    result = run_cli(db_path, "subfinder", "/nonexistent/file.txt")
    assert result.returncode != 0
    assert "not found" in result.stderr.lower() or "File not found" in result.stderr
