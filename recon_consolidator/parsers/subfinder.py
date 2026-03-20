from recon_consolidator.base_ingestor import BaseIngestor


class SubfinderParser(BaseIngestor):
    tool_name = "subfinder"

    def parse(self, filepath):
        records = []
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                records.append({"fqdn": line, "source": self.tool_name})
        return records
