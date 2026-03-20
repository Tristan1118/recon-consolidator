# recon-consolidator

A lightweight Python CLI tool for consolidating external reconnaissance data into a single SQLite database. Ingest output from multiple tools, deduplicate findings, and query across all data in one place.

Python 3, stdlib only. No external dependencies.

## Quick Start

```bash
# 1. Create a new database
python scripts/init_db.py engagement.db

# 2. Ingest tool output
python scripts/ingest.py engagement.db subfinder results/subfinder.txt
python scripts/ingest.py engagement.db nmap results/scan.xml --scan-profile light

# 3. Query the data
python scripts/query.py engagement.db summary
python scripts/query.py engagement.db open-ports
python scripts/query.py engagement.db unresolved --json
python scripts/query.py engagement.db sql "SELECT * FROM subdomains" --csv
```

## Available Queries

| Name | Description |
|------|-------------|
| `summary` | Counts per table and import stats |
| `unresolved` | Subdomains with no DNS records |
| `open-ports` | Open ports joined to subdomains |
| `cname-chains` | Subdomains with CNAME records |
| `by-provider` | Subdomains grouped by hosting provider |
| `single-source` | Subdomains found by only one tool |
| `no-hosting` | IPs with DNS records but no hosting classification |

Output formats: `--csv`, `--json`, or default table.

## Writing a Custom Parser

Copy `parser_template.py`, implement `parse()`, and run it directly or register it in `scripts/ingest.py`.

```python
from recon_consolidator.base_ingestor import BaseIngestor

class MyToolParser(BaseIngestor):
    tool_name = "my-tool"

    def parse(self, filepath):
        records = []
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                records.append({"fqdn": line, "source": self.tool_name})
        return records
```

Available insert methods: `insert_subdomains()`, `insert_dns_records()`, `insert_ports()`, `insert_rows()`.

## Schema

Tables: `subdomains`, `dns_records`, `whois_data`, `hosting`, `ports`, `raw_imports`.

File deduplication is handled via SHA256 hash tracking in `raw_imports`.

## Tests

```bash
pip install pytest
pytest
```
