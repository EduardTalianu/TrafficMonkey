# capture_fields.py
import logging

# Configure logging
logger = logging.getLogger('capture_fields')

CAPTURE_FIELDS = [
    # Basic fields
    {
        "tshark_field": "frame.time_epoch",
        "category": "frame",
        "db_mapping": {"table": "_all_", "column": "timestamp"},
        "data_type": "REAL",
        "required": True,
        "description": "Packet capture timestamp"
    },
    {
        "tshark_field": "ip.src",
        "category": "ip",
        "db_mapping": {"table": "connections", "column": "src_ip"},
        "data_type": "TEXT",
        "required": True,
        "description": "Source IP address"
    },
    {
        "tshark_field": "ip.dst",
        "category": "ip",
        "db_mapping": {"table": "connections", "column": "dst_ip"},
        "data_type": "TEXT",
        "required": True,
        "description": "Destination IP address"
    },
    {
        "tshark_field": "ipv6.src",
        "category": "ip",
        "db_mapping": {"table": "connections", "column": "src_ip"},
        "data_type": "TEXT",
        "required": False,
        "description": "Source IPv6 address"
    },
    {
        "tshark_field": "ipv6.dst",
        "category": "ip",
        "db_mapping": {"table": "connections", "column": "dst_ip"},
        "data_type": "TEXT",
        "required": False,
        "description": "Destination IPv6 address"
    },
    {
        "tshark_field": "tcp.srcport",
        "category": "tcp",
        "db_mapping": {"table": "connections", "column": "src_port"},
        "data_type": "INTEGER",
        "required": False,
        "description": "TCP source port"
    },
    {
        "tshark_field": "tcp.dstport",
        "category": "tcp",
        "db_mapping": {"table": "connections", "column": "dst_port"},
        "data_type": "INTEGER",
        "required": False,
        "description": "TCP destination port"
    },
    {
        "tshark_field": "udp.srcport",
        "category": "udp",
        "db_mapping": {"table": "connections", "column": "src_port"},
        "data_type": "INTEGER",
        "required": False,
        "description": "UDP source port"
    },
    {
        "tshark_field": "udp.dstport",
        "category": "udp",
        "db_mapping": {"table": "connections", "column": "dst_port"},
        "data_type": "INTEGER",
        "required": False,
        "description": "UDP destination port"
    },
    {
        "tshark_field": "frame.len",
        "category": "frame",
        "db_mapping": {"table": "connections", "column": "total_bytes"},
        "data_type": "INTEGER",
        "required": True,
        "description": "Frame length in bytes"
    },
    # DNS fields
    {
        "tshark_field": "dns.qry.name",
        "category": "dns",
        "db_mapping": {"table": "dns_queries", "column": "query_domain"},
        "data_type": "TEXT",
        "required": False,
        "description": "DNS query domain name"
    },
    {
        "tshark_field": "dns.qry.type",
        "category": "dns",
        "db_mapping": {"table": "dns_queries", "column": "query_type"},
        "data_type": "TEXT",
        "required": False,
        "description": "DNS query type"
    },
    {
        "tshark_field": "dns.resp.name",
        "category": "dns",
        "db_mapping": {"table": "dns_queries", "column": "response_domain"},
        "data_type": "TEXT",
        "required": False,
        "description": "DNS response domain name"
    },
    {
        "tshark_field": "dns.resp.type",
        "category": "dns",
        "db_mapping": {"table": "dns_queries", "column": "response_type"},
        "data_type": "TEXT",
        "required": False,
        "description": "DNS response type"
    },
    {
        "tshark_field": "dns.resp.ttl",
        "category": "dns",
        "db_mapping": {"table": "dns_queries", "column": "ttl"},
        "data_type": "INTEGER",
        "required": False,
        "description": "DNS response time-to-live value"
    },
    {
        "tshark_field": "dns.cname",
        "category": "dns",
        "db_mapping": {"table": "dns_queries", "column": "cname_record"},
        "data_type": "TEXT",
        "required": False,
        "description": "DNS CNAME record"
    },
    {
        "tshark_field": "dns.ns",
        "category": "dns",
        "db_mapping": {"table": "dns_queries", "column": "ns_record"},
        "data_type": "TEXT",
        "required": False,
        "description": "DNS NS record"
    },
    {
        "tshark_field": "dns.a",
        "category": "dns",
        "db_mapping": {"table": "dns_queries", "column": "a_record"},
        "data_type": "TEXT",
        "required": False,
        "description": "DNS A record (IPv4 address)"
    },
    {
        "tshark_field": "dns.aaaa",
        "category": "dns",
        "db_mapping": {"table": "dns_queries", "column": "aaaa_record"},
        "data_type": "TEXT",
        "required": False,
        "description": "DNS AAAA record (IPv6 address)"
    },
    # ICMP fields
    {
        "tshark_field": "icmp.type",
        "category": "icmp",
        "db_mapping": {"table": "icmp_packets", "column": "icmp_type"},
        "data_type": "INTEGER",
        "required": False,
        "description": "ICMP message type"
    },
    # HTTP fields
    {
        "tshark_field": "http.host",
        "category": "http",
        "db_mapping": {"table": "http_requests", "column": "host"},
        "data_type": "TEXT",
        "required": False,
        "description": "HTTP host header"
    },
    {
        "tshark_field": "http.request.method",
        "category": "http",
        "db_mapping": {"table": "http_requests", "column": "method"},
        "data_type": "TEXT",
        "required": False,
        "description": "HTTP request method"
    },
    {
        "tshark_field": "http.request.uri",
        "category": "http",
        "db_mapping": {"table": "http_requests", "column": "uri"},
        "data_type": "TEXT",
        "required": False,
        "description": "HTTP request URI"
    },
    {
        "tshark_field": "http.response.code",
        "category": "http",
        "db_mapping": {"table": "http_responses", "column": "status_code"},
        "data_type": "INTEGER",
        "required": False,
        "description": "HTTP response status code"
    },
    {
        "tshark_field": "http.user_agent",
        "category": "http",
        "db_mapping": {"table": "http_requests", "column": "user_agent"},
        "data_type": "TEXT",
        "required": False,
        "description": "HTTP User-Agent header"
    },
    {
        "tshark_field": "http.server",
        "category": "http",
        "db_mapping": {"table": "http_responses", "column": "server"},
        "data_type": "TEXT",
        "required": False,
        "description": "HTTP Server header"
    },
    {
        "tshark_field": "http.content_type",
        "category": "http",
        "db_mapping": {"table": "http_responses", "column": "content_type"},
        "data_type": "TEXT",
        "required": False,
        "description": "HTTP Content-Type header"
    },
    {
        "tshark_field": "http.content_length",
        "category": "http",
        "db_mapping": {"table": "http_responses", "column": "content_length"},
        "data_type": "INTEGER",
        "required": False,
        "description": "HTTP Content-Length header"
    },
    {
        "tshark_field": "http.referer",
        "category": "http",
        "db_mapping": {"table": "http_requests", "column": "referer"},
        "data_type": "TEXT",
        "required": False,
        "description": "HTTP Referer header"
    },
    {
        "tshark_field": "http.x_forwarded_for",
        "category": "http",
        "db_mapping": {"table": "http_requests", "column": "x_forwarded_for"},
        "data_type": "TEXT",
        "required": False,
        "description": "HTTP X-Forwarded-For header"
    },
    # TLS fields
    {
        "tshark_field": "tls.handshake.type",
        "category": "tls",
        "db_mapping": {"table": None, "column": None},  # Used for detection only
        "data_type": None,
        "required": False,
        "description": "TLS handshake type"
    },
    {
        "tshark_field": "tls.handshake.version",
        "category": "tls",
        "db_mapping": {"table": "tls_connections", "column": "tls_version"},
        "data_type": "TEXT",
        "required": False,
        "description": "TLS version"
    },
    {
        "tshark_field": "tls.handshake.ciphersuite",
        "category": "tls",
        "db_mapping": {"table": "tls_connections", "column": "cipher_suite"},
        "data_type": "TEXT",
        "required": False,
        "description": "TLS cipher suite"
    },
    {
        "tshark_field": "tls.handshake.extensions_server_name",
        "category": "tls",
        "db_mapping": {"table": "tls_connections", "column": "server_name"},
        "data_type": "TEXT",
        "required": False,
        "description": "TLS Server Name Indication (SNI)"
    },
    {
        "tshark_field": "tls.record.content_type",
        "category": "tls",
        "db_mapping": {"table": "tls_connections", "column": "record_content_type"},
        "data_type": "INTEGER",
        "required": False,
        "description": "TLS record content type"
    },
    {
        "tshark_field": "ssl.handshake.session_id",
        "category": "tls",
        "db_mapping": {"table": "tls_connections", "column": "session_id"},
        "data_type": "TEXT",
        "required": False,
        "description": "SSL/TLS session ID"
    },
    {
        "tshark_field": "ip.ttl",
        "category": "ip",
        "db_mapping": {"table": "connections", "column": "ttl"},
        "data_type": "INTEGER",
        "required": False,
        "description": "IP Time-to-Live value"
    },
    {
        "tshark_field": "ipv6.hlim",
        "category": "ip",
        "db_mapping": {"table": "connections", "column": "ttl"},
        "data_type": "INTEGER",
        "required": False,
        "description": "IPv6 Hop Limit value (equivalent to TTL)"
    },
    # ARP fields
    {
        "tshark_field": "arp.src.proto_ipv4",
        "category": "arp",
        "db_mapping": {"table": "arp_data", "column": "src_ip"},
        "data_type": "TEXT",
        "required": False,
        "description": "ARP source IP address"
    },
    {
        "tshark_field": "arp.dst.proto_ipv4",
        "category": "arp",
        "db_mapping": {"table": "arp_data", "column": "dst_ip"},
        "data_type": "TEXT",
        "required": False,
        "description": "ARP target IP address"
    },
    {
        "tshark_field": "arp.src.hw_mac",
        "category": "arp",
        "db_mapping": {"table": "arp_data", "column": "src_mac"},
        "data_type": "TEXT",
        "required": False,
        "description": "ARP source MAC address"
    },
    {
        "tshark_field": "arp.opcode",
        "category": "arp",
        "db_mapping": {"table": "arp_data", "column": "operation"},
        "data_type": "INTEGER",
        "required": False,
        "description": "ARP operation (1=request, 2=reply)"
    },
    {
        "tshark_field": "eth.src",
        "category": "ethernet",
        "db_mapping": {"table": "connections", "column": "src_mac"},
        "data_type": "TEXT",
        "required": False,
        "description": "Ethernet source MAC address"
    },
    {
        "tshark_field": "smb2.filename",
        "category": "smb",
        "db_mapping": {"table": "smb_files", "column": "filename"},
        "data_type": "TEXT",
        "required": False,
        "description": "SMB2 accessed filename"
    },
    {
        "tshark_field": "data.data",
        "category": "data",
        "db_mapping": {"table": None, "column": None},  
        "data_type": None,
        "required": False,
        "description": "Raw data content"
    }
]

# Manually add tables that don't directly map to capture fields
TABLE_DEFINITIONS = {
    "connections": [
        {"name": "connection_key", "type": "TEXT PRIMARY KEY", "required": True},
        {"name": "src_ip", "type": "TEXT", "required": True},
        {"name": "dst_ip", "type": "TEXT", "required": True},
        {"name": "src_port", "type": "INTEGER", "required": False},
        {"name": "dst_port", "type": "INTEGER", "required": False},
        {"name": "src_mac", "type": "TEXT", "required": False},
        {"name": "total_bytes", "type": "INTEGER DEFAULT 0", "required": False},
        {"name": "packet_count", "type": "INTEGER DEFAULT 0", "required": False},
        {"name": "timestamp", "type": "REAL", "required": True},
        {"name": "vt_result", "type": "TEXT DEFAULT 'unknown'", "required": False},
        {"name": "is_rdp_client", "type": "BOOLEAN DEFAULT 0", "required": False},
        {"name": "protocol", "type": "TEXT", "required": False},
        {"name": "ttl", "type": "INTEGER", "required": False}
    ],
    "icmp_packets": [
        {"name": "id", "type": "INTEGER PRIMARY KEY AUTOINCREMENT", "required": True},
        {"name": "src_ip", "type": "TEXT", "required": True},
        {"name": "dst_ip", "type": "TEXT", "required": True},
        {"name": "icmp_type", "type": "INTEGER", "required": True},
        {"name": "timestamp", "type": "REAL", "required": True}
    ],
    "dns_queries": [
        {"name": "id", "type": "INTEGER PRIMARY KEY AUTOINCREMENT", "required": True},
        {"name": "timestamp", "type": "REAL", "required": True},
        {"name": "src_ip", "type": "TEXT", "required": True},
        {"name": "query_domain", "type": "TEXT", "required": True},
        {"name": "query_type", "type": "TEXT", "required": False},
        {"name": "response_domain", "type": "TEXT", "required": False},
        {"name": "response_type", "type": "TEXT", "required": False},
        {"name": "ttl", "type": "INTEGER", "required": False},
        {"name": "cname_record", "type": "TEXT", "required": False},
        {"name": "ns_record", "type": "TEXT", "required": False},
        {"name": "a_record", "type": "TEXT", "required": False},
        {"name": "aaaa_record", "type": "TEXT", "required": False}
    ],
    "smb_files": [
        {"name": "id", "type": "INTEGER PRIMARY KEY AUTOINCREMENT", "required": True},
        {"name": "connection_key", "type": "TEXT", "required": True},
        {"name": "timestamp", "type": "REAL", "required": True},
        {"name": "filename", "type": "TEXT", "required": True},
        {"name": "operation", "type": "TEXT", "required": False},
        {"name": "size", "type": "INTEGER", "required": False}
    ],
    "http_requests": [
        {"name": "id", "type": "INTEGER PRIMARY KEY AUTOINCREMENT", "required": True},
        {"name": "connection_key", "type": "TEXT", "required": True},
        {"name": "timestamp", "type": "REAL", "required": True},
        {"name": "method", "type": "TEXT", "required": False},
        {"name": "host", "type": "TEXT", "required": False},
        {"name": "uri", "type": "TEXT", "required": False},
        {"name": "version", "type": "TEXT", "required": False},
        {"name": "user_agent", "type": "TEXT", "required": False},
        {"name": "referer", "type": "TEXT", "required": False},
        {"name": "x_forwarded_for", "type": "TEXT", "required": False},
        {"name": "content_type", "type": "TEXT", "required": False},
        {"name": "request_headers", "type": "TEXT", "required": False},
        {"name": "request_size", "type": "INTEGER DEFAULT 0", "required": False}
    ],
    "http_responses": [
        {"name": "id", "type": "INTEGER PRIMARY KEY AUTOINCREMENT", "required": True},
        {"name": "http_request_id", "type": "INTEGER", "required": True},
        {"name": "status_code", "type": "INTEGER", "required": False},
        {"name": "content_type", "type": "TEXT", "required": False},
        {"name": "content_length", "type": "INTEGER", "required": False},
        {"name": "server", "type": "TEXT", "required": False},
        {"name": "response_headers", "type": "TEXT", "required": False},
        {"name": "timestamp", "type": "REAL", "required": True}
    ],
    "http_headers": [
        {"name": "id", "type": "INTEGER PRIMARY KEY AUTOINCREMENT", "required": True},
        {"name": "connection_key", "type": "TEXT", "required": True},
        {"name": "request_id", "type": "INTEGER", "required": True},
        {"name": "header_name", "type": "TEXT", "required": True},
        {"name": "header_value", "type": "TEXT", "required": False},
        {"name": "is_request", "type": "BOOLEAN", "required": True},
        {"name": "timestamp", "type": "REAL", "required": True}
    ],
    "tls_connections": [
        {"name": "id", "type": "INTEGER PRIMARY KEY AUTOINCREMENT", "required": True},
        {"name": "connection_key", "type": "TEXT", "required": True},
        {"name": "timestamp", "type": "REAL", "required": True},
        {"name": "tls_version", "type": "TEXT", "required": False},
        {"name": "cipher_suite", "type": "TEXT", "required": False},
        {"name": "server_name", "type": "TEXT", "required": False},
        {"name": "ja3_fingerprint", "type": "TEXT", "required": False},
        {"name": "ja3s_fingerprint", "type": "TEXT", "required": False},
        {"name": "record_content_type", "type": "INTEGER", "required": False},
        {"name": "session_id", "type": "TEXT", "required": False},
        {"name": "certificate_issuer", "type": "TEXT", "required": False},
        {"name": "certificate_subject", "type": "TEXT", "required": False},
        {"name": "certificate_validity_start", "type": "TEXT", "required": False},
        {"name": "certificate_validity_end", "type": "TEXT", "required": False},
        {"name": "certificate_serial", "type": "TEXT", "required": False}
    ],
    "port_scan_timestamps": [
        {"name": "src_ip", "type": "TEXT", "required": True},
        {"name": "dst_ip", "type": "TEXT", "required": True},
        {"name": "dst_port", "type": "INTEGER", "required": True},
        {"name": "timestamp", "type": "REAL", "required": True}
    ],
    "app_protocols": [
        {"name": "connection_key", "type": "TEXT PRIMARY KEY", "required": True},
        {"name": "app_protocol", "type": "TEXT", "required": True},
        {"name": "protocol_details", "type": "TEXT", "required": False},
        {"name": "detection_method", "type": "TEXT", "required": False},
        {"name": "timestamp", "type": "REAL", "required": True}
    ],
    "arp_data": [
        {"name": "id", "type": "INTEGER PRIMARY KEY AUTOINCREMENT", "required": True},
        {"name": "timestamp", "type": "REAL", "required": True},
        {"name": "src_ip", "type": "TEXT", "required": True},
        {"name": "src_mac", "type": "TEXT", "required": False},
        {"name": "dst_ip", "type": "TEXT", "required": False},
        {"name": "operation", "type": "INTEGER", "required": False}
    ],
    "alerts": [
        {"name": "id", "type": "INTEGER PRIMARY KEY AUTOINCREMENT", "required": True},
        {"name": "ip_address", "type": "TEXT", "required": True},
        {"name": "alert_message", "type": "TEXT", "required": True},
        {"name": "rule_name", "type": "TEXT", "required": True},
        {"name": "timestamp", "type": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP", "required": True}
    ]
}

# Track schema version for migrations
SCHEMA_VERSION = 2

# Database management functions
def table_exists(cursor, table_name):
    """Check if a table exists in the database"""
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table_name,)
    )
    return cursor.fetchone() is not None

def get_table_columns(cursor, table_name):
    """Get column information for a table"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    return cursor.fetchall()

def create_database_schema(cursor, include_tables=None, exclude_tables=None):
    """
    Create database schema based on TABLE_DEFINITIONS
    
    Parameters:
    - cursor: SQLite cursor to use for operations
    - include_tables: List of table names to include (None means include all)
    - exclude_tables: List of table names to exclude
    
    Returns:
    - List of tables created
    """
    include_tables = include_tables or list(TABLE_DEFINITIONS.keys())
    exclude_tables = exclude_tables or []
    
    tables_created = []
    
    # Process each table in the definitions
    for table_name, columns in TABLE_DEFINITIONS.items():
        # Skip if table is excluded or not in included list
        if table_name in exclude_tables or table_name not in include_tables:
            continue
            
        # Prepare column definitions
        column_defs = []
        
        # Add primary key if it's not defined and table needs one
        if not any(col["name"] == "id" for col in columns if "PRIMARY KEY" in col.get("type", "")):
            has_pk = any("PRIMARY KEY" in col.get("type", "") for col in columns)
            if not has_pk:
                column_defs.append("id INTEGER PRIMARY KEY AUTOINCREMENT")
        
        # Add each column
        for column in columns:
            # Skip if already added (e.g., id column)
            if column["name"] == "id" and "id INTEGER PRIMARY KEY AUTOINCREMENT" in column_defs:
                continue
                
            nullable = "" if column.get("required", False) else " DEFAULT NULL"
            column_defs.append(f"{column['name']} {column['type']}{nullable}")
        
        # Add timestamp if not already included
        if not any(col["name"] == "timestamp" for col in columns):
            column_defs.append("timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
        
        # Create the table
        create_table_sql = f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                {', '.join(column_defs)}
            )
        """
        cursor.execute(create_table_sql)
        tables_created.append(table_name)
        
    return tables_created

def create_standard_indices(cursor):
    """Create standard indices for the database tables"""
    
    # First check which tables exist
    existing_tables = set()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    for row in cursor.fetchall():
        existing_tables.add(row[0])
    
    # Only create indices for tables that exist
    
    # Connections table indices
    if 'connections' in existing_tables:
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_ips 
            ON connections(src_ip, dst_ip)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_ports 
            ON connections(src_port, dst_port)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_bytes 
            ON connections(total_bytes DESC)
        """)
    
    # Alerts table indices
    if 'alerts' in existing_tables:
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_ip 
            ON alerts(ip_address)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_rule
            ON alerts(rule_name)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_timestamp 
            ON alerts(timestamp DESC)
        """)
    
    # DNS queries indices
    if 'dns_queries' in existing_tables:
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_dns_queries_domain 
            ON dns_queries(query_domain)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_dns_queries_src 
            ON dns_queries(src_ip)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_dns_queries_time 
            ON dns_queries(timestamp)
        """)
    
    # HTTP requests indices
    if 'http_requests' in existing_tables:
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_http_requests_conn 
            ON http_requests(connection_key)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_http_requests_host 
            ON http_requests(host)
        """)
    
    # HTTP responses index
    if 'http_responses' in existing_tables:
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_http_responses_req 
            ON http_responses(http_request_id)
        """)
    
    # TLS connections indices
    if 'tls_connections' in existing_tables:
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_tls_connections_conn 
            ON tls_connections(connection_key)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_tls_connections_server 
            ON tls_connections(server_name)
        """)
    
    # ICMP packets index
    if 'icmp_packets' in existing_tables:
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_icmp_packets_src_dst 
            ON icmp_packets(src_ip, dst_ip)
        """)
    
    # ARP data index
    if 'arp_data' in existing_tables:
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_arp_data_src_dst 
            ON arp_data(src_ip, dst_ip)
        """)
    
    # SMB files indices
    if 'smb_files' in existing_tables:
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_smb_files_conn 
            ON smb_files(connection_key)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_smb_files_filename 
            ON smb_files(filename)
        """)
    
    # HTTP headers indices - this is the problematic one
    if 'http_headers' in existing_tables:
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_http_headers_conn 
            ON http_headers(connection_key)
        """)
        
        # This index is causing the error - replace request_id with the correct column name
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_http_headers_req 
            ON http_headers(request_id)
        """)

def create_extended_indices(cursor, extended_tables):
    """Create indices for extended tables"""
    if 'ip_geolocation' in extended_tables:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_geolocation_country ON ip_geolocation(country)")
    
    if 'ip_threat_intel' in extended_tables:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_score ON ip_threat_intel(threat_score DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_type ON ip_threat_intel(threat_type)")
    
    if 'traffic_patterns' in extended_tables:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_pattern_periodic ON traffic_patterns(periodic_score DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_pattern_class ON traffic_patterns(classification)")
    
    if 'connection_statistics' in extended_tables:
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_conn_stats_time ON connection_statistics(timestamp)")

def get_integrated_schema(extended_tables=None):
    """
    Get a complete schema including core and optionally extended tables
    
    Parameters:
    - extended_tables: Dictionary of extended table definitions
    
    Returns:
    - Merged schema dictionary
    """
    schema = dict(TABLE_DEFINITIONS)
    
    if extended_tables:
        # Merge extended tables, flagging any conflicts
        for table_name, columns in extended_tables.items():
            if table_name in schema:
                # Table exists in core schema - log potential conflict
                logger.warning(f"Table {table_name} exists in both core and extended schema")
                
                # Merge columns from both definitions, core schema takes precedence
                existing_columns = {col["name"]: col for col in schema[table_name]}
                for col in columns:
                    if col["name"] not in existing_columns:
                        schema[table_name].append(col)
            else:
                # New table, just add it
                schema[table_name] = columns
    
    return schema

# Helper functions
def get_tshark_fields():
    """Return all tshark field names to capture"""
    return [field["tshark_field"] for field in CAPTURE_FIELDS]

def get_fields_by_category(category):
    """Get all fields for a specific category"""
    return [f for f in CAPTURE_FIELDS if f["category"] == category]

def get_tables_schema():
    """Generate database schema from field definitions"""
    tables = {}
    
    # First add tables from field definitions
    for field in CAPTURE_FIELDS:
        if not field["db_mapping"]["table"] or field["db_mapping"]["table"] == "_all_":
            continue
            
        table_name = field["db_mapping"]["table"]
        if table_name not in tables:
            tables[table_name] = []
            
        column = {
            "name": field["db_mapping"]["column"],
            "type": field["data_type"],
            "required": field["required"]
        }
        
        # Check if column already exists in table definition
        if not any(c["name"] == column["name"] for c in tables[table_name]):
            tables[table_name].append(column)
    
    # Then add manually defined tables
    for table_name, columns in TABLE_DEFINITIONS.items():
        if table_name not in tables:
            tables[table_name] = columns
        else:
            # Merge with existing columns
            for column in columns:
                if not any(c["name"] == column["name"] for c in tables[table_name]):
                    tables[table_name].append(column)
    
    return tables

def get_field_by_tshark_name(tshark_field):
    """Get field definition by tshark field name"""
    for field in CAPTURE_FIELDS:
        if field["tshark_field"] == tshark_field:
            return field
    return None