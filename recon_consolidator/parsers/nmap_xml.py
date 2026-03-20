import xml.etree.ElementTree as ET

from recon_consolidator.base_ingestor import BaseIngestor


class NmapXmlParser(BaseIngestor):
    tool_name = "nmap"

    def __init__(self, db_path, scan_profile=None):
        super().__init__(db_path)
        self.scan_profile = scan_profile

    def parse(self, filepath):
        tree = ET.parse(filepath)
        root = tree.getroot()
        port_records = []
        subdomain_records = []

        for host in root.findall("host"):
            ip = None
            addr = host.find("address[@addrtype='ipv4']")
            if addr is None:
                addr = host.find("address[@addrtype='ipv6']")
            if addr is not None:
                ip = addr.get("addr")

            # Extract hostnames
            first_hostname = None
            hostnames = host.find("hostnames")
            if hostnames is not None:
                for hostname in hostnames.findall("hostname"):
                    name = hostname.get("name")
                    if name:
                        if first_hostname is None:
                            first_hostname = name
                        subdomain_records.append({
                            "fqdn": name,
                            "source": self.tool_name,
                        })

            if ip is None and first_hostname is None:
                continue

            # Extract ports
            ports_elem = host.find("ports")
            if ports_elem is None:
                continue
            for port_elem in ports_elem.findall("port"):
                protocol = port_elem.get("protocol", "tcp")
                portid = int(port_elem.get("portid"))

                state_elem = port_elem.find("state")
                state = state_elem.get("state") if state_elem is not None else None

                service_elem = port_elem.find("service")
                service = None
                version = None
                if service_elem is not None:
                    service = service_elem.get("name")
                    version_parts = []
                    for attr in ("product", "version", "extrainfo"):
                        val = service_elem.get(attr)
                        if val:
                            version_parts.append(val)
                    version = " ".join(version_parts) if version_parts else None

                port_records.append({
                    "ip": ip,
                    "hostname": first_hostname,
                    "port": portid,
                    "protocol": protocol,
                    "state": state,
                    "service": service,
                    "version": version,
                    "scan_profile": self.scan_profile,
                })

        return {"ports": port_records, "subdomains": subdomain_records}

    def ingest(self, filepath):
        """Override to handle both ports and subdomains."""
        file_hash = self._file_hash(filepath)
        if self._already_imported(file_hash):
            print(f"Already imported (same hash): {filepath}")
            return 0

        try:
            parsed = self.parse(filepath)
            port_count = self.insert_ports(parsed["ports"])
            sub_count = self.insert_subdomains(parsed["subdomains"])
            total = port_count + sub_count
            self._log_import(filepath, file_hash, total)
            self.conn.commit()
            print(f"Ingested {port_count} ports, {sub_count} subdomains from {filepath}")
            return total
        except Exception:
            self.conn.rollback()
            raise
