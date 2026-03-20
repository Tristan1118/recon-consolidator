"""
Parser template: copy this file and fill in the parse logic for your tool.

Usage:
    python my_parser.py <db_path> <tool_output_file>
"""
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
                # TODO: parse line into a dict matching your target table
                # records.append({"fqdn": line, "source": self.tool_name})
                pass
        return records

    # Override _insert if you're targeting a table other than subdomains:
    # def _insert(self, records):
    #     return self.insert_ports(records)
    #     return self.insert_dns_records(records)
    #     return self.insert_rows("table_name", records)


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <db_path> <tool_output_file>")
        sys.exit(1)
    parser = MyToolParser(sys.argv[1])
    parser.ingest(sys.argv[2])
    parser.close()
