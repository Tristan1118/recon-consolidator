# Pre-built queries for common recon analysis tasks.
# Each entry maps a name to (description, SQL).

QUERIES = {
    "unresolved": (
        "Subdomains with no DNS records",
        """
        SELECT s.fqdn, s.source, s.first_seen
        FROM subdomains s
        LEFT JOIN dns_records d ON s.id = d.subdomain_id
        WHERE d.id IS NULL
        ORDER BY s.fqdn
        """,
    ),
    "cname-chains": (
        "Subdomains with CNAME records",
        """
        SELECT s.fqdn, d.value AS cname_target, d.source
        FROM subdomains s
        JOIN dns_records d ON s.id = d.subdomain_id
        WHERE d.record_type = 'CNAME'
        ORDER BY s.fqdn
        """,
    ),
    "by-provider": (
        "Subdomains grouped by hosting provider",
        """
        SELECT h.provider, COUNT(DISTINCT s.fqdn) AS subdomain_count,
               GROUP_CONCAT(DISTINCT s.fqdn) AS subdomains
        FROM subdomains s
        LEFT JOIN dns_records d ON s.id = d.subdomain_id AND d.record_type IN ('A', 'AAAA')
        JOIN hosting h ON (d.value IS NOT NULL AND d.value = h.ip)
            OR (h.hostname IS NOT NULL AND s.fqdn = h.hostname)
        GROUP BY h.provider
        ORDER BY subdomain_count DESC
        """,
    ),
    "open-ports": (
        "Open ports joined to subdomains",
        """
        SELECT COALESCE(p.ip, '(none)') AS ip, p.hostname, p.port, p.protocol,
               p.service, p.version, p.scan_profile,
               GROUP_CONCAT(DISTINCT s.fqdn) AS subdomains
        FROM ports p
        LEFT JOIN dns_records d ON p.ip IS NOT NULL AND p.ip = d.value AND d.record_type IN ('A', 'AAAA')
        LEFT JOIN subdomains s ON d.subdomain_id = s.id
            OR (p.hostname IS NOT NULL AND s.fqdn = LOWER(p.hostname))
        WHERE p.state = 'open'
        GROUP BY p.ip, p.hostname, p.port, p.protocol, p.scan_profile
        ORDER BY COALESCE(p.ip, p.hostname), p.port
        """,
    ),
    "single-source": (
        "Subdomains found by only one tool (potential false positives)",
        """
        SELECT fqdn, source, first_seen
        FROM subdomains
        WHERE source NOT LIKE '%, %'
        ORDER BY source, fqdn
        """,
    ),
    "no-hosting": (
        "IPs/hostnames with DNS records but no hosting classification",
        """
        SELECT DISTINCT d.value AS ip, s.fqdn, d.record_type
        FROM dns_records d
        JOIN subdomains s ON d.subdomain_id = s.id
        LEFT JOIN hosting h ON (d.value = h.ip) OR (s.fqdn = h.hostname)
        WHERE d.record_type IN ('A', 'AAAA')
          AND h.id IS NULL
        ORDER BY d.value
        """,
    ),
    "summary": (
        "Engagement overview with counts per table",
        """
        SELECT
            (SELECT COUNT(*) FROM subdomains) AS subdomains,
            (SELECT COUNT(*) FROM dns_records) AS dns_records,
            (SELECT COUNT(*) FROM ports) AS ports,
            (SELECT COUNT(*) FROM ports WHERE state = 'open') AS open_ports,
            (SELECT COUNT(*) FROM hosting) AS hosting_entries,
            (SELECT COUNT(*) FROM whois_data) AS whois_entries,
            (SELECT COUNT(*) FROM raw_imports) AS imports
        """,
    ),
}


def run_query(conn, query_name):
    """Run a named query and return (description, column_names, rows)."""
    if query_name not in QUERIES:
        raise ValueError(f"Unknown query: {query_name}. Available: {', '.join(QUERIES.keys())}")
    description, sql = QUERIES[query_name]
    cursor = conn.execute(sql)
    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    return description, columns, rows


def run_sql(conn, sql):
    """Run raw SQL and return (column_names, rows)."""
    cursor = conn.execute(sql)
    columns = [desc[0] for desc in cursor.description]
    rows = cursor.fetchall()
    return columns, rows
