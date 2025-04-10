# Rule class is injected by the RuleLoader
import logging
import time
import re
from collections import defaultdict

class LegacyProtocolFinderRule(Rule):
    """Rule that identifies outdated or insecure protocols still in use"""
    def __init__(self):
        super().__init__(
            name="Legacy Protocol Finder",
            description="Identifies outdated or insecure protocols and authentication mechanisms"
        )
        # Track detected legacy protocols
        self.detected_protocols = set()
        
        # Define legacy protocols and versions
        self.legacy_protocols = {
            # TLS versions
            "tls": {
                "legacy": ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1", "TLSv1", "TLSv1.1", "SSLv2", "SSLv3"],
                "severity": "high",
                "reason": "Vulnerable to known attacks like POODLE, BEAST, CRIME"
            },
            # Legacy authentication protocols
            "authentication": {
                "legacy": ["NTLM", "NTLMv1", "Digest", "Basic"],
                "severity": "high",
                "reason": "Weak or vulnerable authentication mechanisms"
            },
            # HTTP (not HTTPS)
            "http": {
                "legacy": ["HTTP/1.0"],
                "severity": "medium",
                "reason": "Unencrypted data transmission"
            },
            # Weak cipher suites
            "cipher_suites": {
                "legacy": ["NULL", "EXPORT", "DES", "RC4", "MD5", "anon"],
                "severity": "high",
                "reason": "Cryptographically weak algorithms"
            }
        }
        
        # Track services by port
        self.services_by_port = defaultdict(set)
        
        # Last analysis time
        self.last_analysis_time = 0
        # Analysis interval in seconds
        self.analysis_interval = 900  # 15 minutes
    
    def analyze(self, db_cursor):
        alerts = []
        
        current_time = time.time()
        if current_time - self.last_analysis_time < self.analysis_interval:
            return []
            
        self.last_analysis_time = current_time
        
        try:
            # Check for legacy TLS versions
            db_cursor.execute("""
                SELECT tc.connection_key, tc.tls_version, tc.cipher_suite, 
                       c.src_ip, c.dst_ip, c.dst_port, tc.server_name
                FROM tls_connections tc
                JOIN connections c ON tc.connection_key = c.connection_key
                WHERE tc.tls_version IS NOT NULL
                ORDER BY tc.timestamp DESC
            """)
            
            for row in db_cursor.fetchall():
                connection_key, tls_version, cipher_suite, src_ip, dst_ip, dst_port, server_name = row
                
                # Skip if no TLS version
                if not tls_version:
                    continue
                
                # Check for legacy TLS versions
                legacy_tls = False
                for legacy_version in self.legacy_protocols["tls"]["legacy"]:
                    if legacy_version.lower() in tls_version.lower():
                        legacy_tls = True
                        break
                
                if legacy_tls:
                    # Create a unique key for this legacy protocol
                    protocol_key = f"LegacyTLS:{dst_ip}:{dst_port}:{tls_version}"
                    
                    # Skip if already detected
                    if protocol_key in self.detected_protocols:
                        continue
                        
                    self.detected_protocols.add(protocol_key)
                    
                    # Format server name if available
                    server_info = f" ({server_name})" if server_name else ""
                    
                    alert_msg = f"Legacy TLS version detected: {tls_version} on {dst_ip}:{dst_port}{server_info}"
                    alerts.append(alert_msg)
                    
                    # Add detailed alert
                    reason = self.legacy_protocols["tls"]["reason"]
                    detailed_msg = f"Insecure protocol: {tls_version} on {dst_ip}:{dst_port}{server_info} - {reason}"
                    self.add_alert(dst_ip, detailed_msg)
                    
                    # Store protocol information
                    self._store_legacy_protocol(dst_ip, dst_port, "tls", tls_version, server_name)
                
                # Also check for weak cipher suites
                if cipher_suite:
                    weak_cipher = False
                    matching_pattern = None
                    
                    for weak_pattern in self.legacy_protocols["cipher_suites"]["legacy"]:
                        if weak_pattern.lower() in cipher_suite.lower():
                            weak_cipher = True
                            matching_pattern = weak_pattern
                            break
                    
                    if weak_cipher:
                        # Create a unique key for this weak cipher
                        cipher_key = f"WeakCipher:{dst_ip}:{dst_port}:{matching_pattern}"
                        
                        # Skip if already detected
                        if cipher_key in self.detected_protocols:
                            continue
                            
                        self.detected_protocols.add(cipher_key)
                        
                        # Format server name if available
                        server_info = f" ({server_name})" if server_name else ""
                        
                        alert_msg = f"Weak cipher detected: {cipher_suite} on {dst_ip}:{dst_port}{server_info}"
                        alerts.append(alert_msg)
                        
                        # Add detailed alert
                        reason = self.legacy_protocols["cipher_suites"]["reason"]
                        detailed_msg = f"Weak cryptography: {matching_pattern} cipher on {dst_ip}:{dst_port}{server_info} - {reason}"
                        self.add_alert(dst_ip, detailed_msg)
                        
                        # Store protocol information
                        self._store_legacy_protocol(dst_ip, dst_port, "cipher", cipher_suite, server_name)
            
            # Check for plain HTTP (not HTTPS)
            db_cursor.execute("""
                SELECT r.connection_key, r.host, r.version, c.src_ip, c.dst_ip, c.dst_port
                FROM http_requests r
                JOIN connections c ON r.connection_key = c.connection_key
                WHERE c.dst_port = 80
                GROUP BY c.dst_ip, c.dst_port
            """)
            
            for row in db_cursor.fetchall():
                connection_key, host, http_version, src_ip, dst_ip, dst_port = row
                
                # Create a unique key for unencrypted HTTP
                protocol_key = f"PlainHTTP:{dst_ip}:{dst_port}"
                
                # Skip if already detected
                if protocol_key in self.detected_protocols:
                    continue
                    
                self.detected_protocols.add(protocol_key)
                
                # Check for legacy HTTP version
                version_note = ""
                if http_version and http_version.lower() in [v.lower() for v in self.legacy_protocols["http"]["legacy"]]:
                    version_note = f" (Legacy version: {http_version})"
                
                alert_msg = f"Unencrypted HTTP detected on {host or dst_ip}:{dst_port}{version_note}"
                alerts.append(alert_msg)
                
                # Add detailed alert
                reason = "Unencrypted data transmission vulnerable to interception"
                detailed_msg = f"Insecure protocol: Plain HTTP on {host or dst_ip}:{dst_port} - {reason}"
                self.add_alert(dst_ip, detailed_msg)
                
                # Store protocol information
                protocol_version = http_version if http_version else "HTTP"
                self._store_legacy_protocol(dst_ip, dst_port, "http", protocol_version, host)
            
            # Check for legacy authentication mechanisms
            db_cursor.execute("""
                SELECT h.connection_key, h.header_name, h.header_value, c.src_ip, c.dst_ip, c.dst_port,
                       r.host, r.uri
                FROM http_headers h
                JOIN connections c ON h.connection_key = c.connection_key
                LEFT JOIN http_requests r ON h.request_id = r.id
                WHERE h.header_name = 'Authorization' OR h.header_name = 'WWW-Authenticate'
                ORDER BY h.timestamp DESC
            """)
            
            for row in db_cursor.fetchall():
                connection_key, header_name, header_value, src_ip, dst_ip, dst_port, host, uri = row
                
                # Skip if header value is missing
                if not header_value:
                    continue
                
                # Check for legacy authentication mechanisms
                legacy_auth = False
                matching_auth = None
                
                for auth_type in self.legacy_protocols["authentication"]["legacy"]:
                    if auth_type.lower() in header_value.lower():
                        legacy_auth = True
                        matching_auth = auth_type
                        break
                
                if legacy_auth:
                    # Create a unique key for this legacy auth
                    auth_key = f"LegacyAuth:{dst_ip}:{dst_port}:{matching_auth}"
                    
                    # Skip if already detected
                    if auth_key in self.detected_protocols:
                        continue
                        
                    self.detected_protocols.add(auth_key)
                    
                    # Format URI if available
                    uri_info = f"{uri}" if uri else ""
                    
                    alert_msg = f"Legacy authentication detected: {matching_auth} on {host or dst_ip}:{dst_port}{uri_info}"
                    alerts.append(alert_msg)
                    
                    # Add detailed alert
                    reason = self.legacy_protocols["authentication"]["reason"]
                    detailed_msg = f"Insecure authentication: {matching_auth} on {host or dst_ip}:{dst_port} - {reason}"
                    self.add_alert(dst_ip, detailed_msg)
                    
                    # Store protocol information
                    self._store_legacy_protocol(dst_ip, dst_port, "authentication", matching_auth, host)
            
            # Check for other legacy protocols based on port
            db_cursor.execute("""
                SELECT c.src_ip, c.dst_ip, c.dst_port, COUNT(*) as conn_count
                FROM connections c
                WHERE c.dst_port IN (21, 23, 25, 110, 143, 161, 512, 513, 514, 530, 2049)
                GROUP BY c.dst_ip, c.dst_port
            """)
            
            for row in db_cursor.fetchall():
                src_ip, dst_ip, dst_port, conn_count = row
                
                # Map port to protocol
                protocol_map = {
                    21: "FTP (unencrypted)",
                    23: "Telnet",
                    25: "SMTP (unencrypted)",
                    110: "POP3 (unencrypted)",
                    143: "IMAP (unencrypted)",
                    161: "SNMP v1/v2",
                    512: "Rexec",
                    513: "Rlogin",
                    514: "RSH",
                    530: "RPC",
                    2049: "NFS"
                }
                
                if dst_port in protocol_map:
                    protocol = protocol_map[dst_port]
                    
                    # Create a unique key for this legacy protocol
                    protocol_key = f"LegacyPort:{dst_ip}:{dst_port}:{protocol}"
                    
                    # Skip if already detected
                    if protocol_key in self.detected_protocols:
                        continue
                        
                    self.detected_protocols.add(protocol_key)
                    
                    alert_msg = f"Legacy protocol detected: {protocol} on {dst_ip}:{dst_port}"
                    alerts.append(alert_msg)
                    
                    # Add detailed alert
                    detailed_msg = f"Insecure legacy protocol: {protocol} on {dst_ip}:{dst_port} - Lacks encryption or has known vulnerabilities"
                    self.add_alert(dst_ip, detailed_msg)
                    
                    # Store protocol information
                    self._store_legacy_protocol(dst_ip, dst_port, "legacy_port", protocol, None)
            
            # Prevent the set from growing too large
            if len(self.detected_protocols) > 1000:
                self.detected_protocols = set(list(self.detected_protocols)[-500:])
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Legacy Protocol Finder: {e}"
            logging.error(error_msg)
            return [error_msg]
    
    def _store_legacy_protocol(self, ip, port, protocol_type, protocol_version, hostname):
        """Store legacy protocol information in the database for later exploitation"""
        try:
            # If we have an analysis_manager, store data in x_ip_threat_intel
            if hasattr(self, 'analysis_manager') and self.analysis_manager:
                # Determine severity based on protocol type
                severity = "medium"
                for proto_category, info in self.legacy_protocols.items():
                    if protocol_type in proto_category or proto_category in protocol_type:
                        severity = info.get("severity", "medium")
                        break
                
                # Create threat intel entry for this protocol
                threat_data = {
                    "score": 8.0 if severity == "high" else 5.0,  # Score based on severity
                    "type": "legacy_protocol",
                    "confidence": 0.9,
                    "source": self.name,
                    "details": {
                        "protocol_type": protocol_type,
                        "protocol_version": protocol_version,
                        "hostname": hostname,
                        "port": port,
                        "severity": severity,
                        "discovery_time": time.time()
                    },
                    "protocol": protocol_type.upper(),
                    "destination_port": port,
                    "detection_method": "protocol_analysis"
                }
                
                # Store in the threat_intel table
                self.analysis_manager.update_threat_intel(ip, threat_data)
        except Exception as e:
            logging.error(f"Error storing legacy protocol information: {e}")
    
    def get_params(self):
        return {
            "analysis_interval": {
                "type": "int",
                "default": 900,
                "current": self.analysis_interval,
                "description": "Interval between analyses (seconds)"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "analysis_interval":
            self.analysis_interval = int(value)
            return True
        return False