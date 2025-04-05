# capture_fields.py

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
        "tshark_field": "arp.opcode",
        "category": "arp",
        "db_mapping": {"table": "arp_data", "column": "operation"},
        "data_type": "INTEGER",
        "required": False,
        "description": "ARP operation (1=request, 2=reply)"
    }
]

# Manually add tables that don't directly map to capture fields
TABLE_DEFINITIONS = {
    "icmp_packets": [
        {"name": "src_ip", "type": "TEXT", "required": True},
        {"name": "dst_ip", "type": "TEXT", "required": True},
        {"name": "icmp_type", "type": "INTEGER", "required": True},
        {"name": "timestamp", "type": "REAL", "required": True}
    ],
    "dns_queries": [
        {"name": "timestamp", "type": "REAL", "required": True},
        {"name": "src_ip", "type": "TEXT", "required": True},
        {"name": "query_domain", "type": "TEXT", "required": True},
        {"name": "query_type", "type": "TEXT", "required": False},
        {"name": "response_domain", "type": "TEXT", "required": False},
        {"name": "response_type", "type": "TEXT", "required": False}
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
    ]

}

# Track schema version for migrations
SCHEMA_VERSION = 1

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