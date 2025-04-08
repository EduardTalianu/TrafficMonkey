# tls_analysis.py - Analyzes TLS/SSL traffic patterns
import time
import logging
import socket
import json

logger = logging.getLogger('tls_analysis')

class TLSAnalyzer(AnalysisBase):
    """Analyzes TLS connections for suspicious patterns and resolves domains"""
    
    def __init__(self):
        super().__init__(
            name="TLS Traffic Analysis",
            description="Analyzes TLS/SSL connections and resolves domain names"
        )
        self.unusual_ports = {443}  # 443 is normal, others are unusual
        for p in range(1, 65536):
            if p != 443 and p != 8443:  # Common SSL ports
                self.unusual_ports.add(p)
                
        self.suspicious_ciphers = [
            "TLS_RSA_WITH_NULL",
            "TLS_RSA_EXPORT",
            "SSL_RSA_EXPORT",
            "TLS_DH_anon",
            "SSL_DH_anon"
        ]
        
        self.outdated_tls_versions = [
            "SSLv2",
            "SSLv3",
            "TLSv1.0",
            "TLSv1"
        ]
        
        self.last_dns_resolve_time = 0
        self.dns_resolve_interval = 1800  # 30 minutes
    
    def initialize(self):
        # Create or update required tables
        cursor = self.analysis_manager.get_cursor()
        try:
            # TLS analysis results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tls_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_key TEXT UNIQUE,
                    server_name TEXT,
                    suspicious_score REAL DEFAULT 0,
                    cipher_issues BOOLEAN DEFAULT 0,
                    version_issues BOOLEAN DEFAULT 0,
                    port_issues BOOLEAN DEFAULT 0,
                    first_seen REAL,
                    last_seen REAL,
                    detection_details TEXT
                )
            """)
            
            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_analysis_server ON tls_analysis(server_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_analysis_score ON tls_analysis(suspicious_score DESC)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("TLS analysis tables initialized")
        except Exception as e:
            logger.error(f"Error initializing TLS analysis tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process a TLS packet for analysis"""
        # Get the layers
        layers = packet_data.get("layers", {})
        if not layers:
            return False
        
        # Check if this is a TLS packet
        if not self.analysis_manager._has_tls_data(layers):
            return False
        
        try:
            # Extract TLS data
            src_ip = self.analysis_manager._get_layer_value(layers, "ip_src") or self.analysis_manager._get_layer_value(layers, "ipv6_src")
            dst_ip = self.analysis_manager._get_layer_value(layers, "ip_dst") or self.analysis_manager._get_layer_value(layers, "ipv6_dst")
            
            src_port, dst_port = self.analysis_manager._extract_ports(layers)
            
            # Create connection key
            if src_port and dst_port:
                connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            else:
                connection_key = f"{src_ip}->{dst_ip}"
            
            # Extract TLS fields
            tls_version = self.analysis_manager._get_layer_value(layers, "tls_handshake_version")
            cipher_suite = self.analysis_manager._get_layer_value(layers, "tls_handshake_ciphersuite")
            server_name = self.analysis_manager._get_layer_value(layers, "tls_handshake_extensions_server_name")
            
            # Set defaults if needed
            if not tls_version:
                if dst_port == 443:
                    tls_version = "TLSv1.2 (assumed)"
                else:
                    tls_version = "Unknown"
            
            if not server_name:
                server_name = dst_ip
            
            # Calculate suspicion score
            suspicious_score = 0
            cipher_issues = False
            version_issues = False
            port_issues = False
            detection_details = {}
            
            # Check for unusual port (not 443/8443)
            if dst_port and dst_port != 443 and dst_port != 8443:
                suspicious_score += 2
                port_issues = True
                detection_details["unusual_port"] = dst_port
            
            # Check for outdated/insecure TLS version
            if any(old_ver in tls_version for old_ver in self.outdated_tls_versions):
                suspicious_score += 3
                version_issues = True
                detection_details["outdated_tls"] = tls_version
            
            # Check for weak cipher suites
            if cipher_suite and any(weak_cipher in cipher_suite for weak_cipher in self.suspicious_ciphers):
                suspicious_score += 4
                cipher_issues = True
                detection_details["weak_cipher"] = cipher_suite
            
            # Store analysis results
            current_time = time.time()
            cursor = self.analysis_manager.get_cursor()
            
            try:
                # Check if connection exists in analysis
                cursor.execute("SELECT first_seen FROM tls_analysis WHERE connection_key = ?", (connection_key,))
                result = cursor.fetchone()
                
                if result:
                    # Update existing connection
                    cursor.execute("""
                        UPDATE tls_analysis
                        SET server_name = ?,
                            suspicious_score = ?,
                            cipher_issues = ?,
                            version_issues = ?,
                            port_issues = ?,
                            last_seen = ?,
                            detection_details = ?
                        WHERE connection_key = ?
                    """, (
                        server_name,
                        suspicious_score,
                        cipher_issues,
                        version_issues,
                        port_issues,
                        current_time,
                        json.dumps(detection_details),
                        connection_key
                    ))
                else:
                    # Insert new connection analysis
                    cursor.execute("""
                        INSERT INTO tls_analysis
                        (connection_key, server_name, suspicious_score, cipher_issues, 
                         version_issues, port_issues, first_seen, last_seen, detection_details)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        connection_key,
                        server_name,
                        suspicious_score,
                        cipher_issues,
                        version_issues,
                        port_issues,
                        current_time,
                        current_time,
                        json.dumps(detection_details)
                    ))
                
                # Create alerts for suspicious TLS connections
                if suspicious_score >= 4:
                    # Prepare alert message
                    alert_parts = []
                    if version_issues:
                        alert_parts.append(f"outdated TLS version ({tls_version})")
                    if cipher_issues:
                        alert_parts.append(f"weak cipher suite ({cipher_suite})")
                    if port_issues:
                        alert_parts.append(f"unusual SSL port ({dst_port})")
                    
                    alert_reason = ", ".join(alert_parts)
                    alert_message = f"Suspicious TLS connection to {server_name}: {alert_reason}"
                    
                    self.analysis_manager.add_alert(src_ip, alert_message, "TLS_Security_Analyzer")
                
                self.analysis_manager.analysis1_conn.commit()
            finally:
                cursor.close()
            
            return True
        except Exception as e:
            logger.error(f"Error analyzing TLS packet: {e}")
            return False
    
    def run_periodic_analysis(self):
        """Run periodic TLS analysis, including domain name resolution"""
        current_time = time.time()
        
        # Check if it's time to run DNS resolution
        if current_time - self.last_dns_resolve_time >= self.dns_resolve_interval:
            self.last_dns_resolve_time = current_time
            self.resolve_domain_names()
        
        return True
    
    def resolve_domain_names(self):
        """Resolve IP addresses to domain names for TLS connections"""
        try:
            cursor = self.analysis_manager.get_cursor()
            
            # Get all TLS connections with server names that look like IP addresses
            cursor.execute("""
                SELECT id, server_name, connection_key
                FROM tls_connections
                WHERE server_name LIKE '%\\.%\\.%\\.%' 
                OR server_name IS NULL
                LIMIT 100
            """)
            
            rows = cursor.fetchall()
            updates = 0
            
            for row in rows:
                tls_id, server_name, connection_key = row
                
                # Extract destination IP from connection key
                try:
                    dst_ip = connection_key.split('->')[1].split(':')[0]
                except IndexError:
                    continue
                    
                # Skip if we already have a non-IP server name
                if server_name and not self.analysis_manager._is_ip_address(server_name):
                    continue
                    
                # Try reverse DNS lookup
                try:
                    hostname, _, _ = socket.gethostbyaddr(dst_ip)
                    if hostname and hostname != dst_ip and not self.analysis_manager._is_ip_address(hostname):
                        # Update the server name in the database
                        cursor.execute("""
                            UPDATE tls_connections
                            SET server_name = ?
                            WHERE id = ?
                        """, (hostname, tls_id))
                        
                        # Also update the analysis table
                        cursor.execute("""
                            UPDATE tls_analysis
                            SET server_name = ?
                            WHERE connection_key = ?
                        """, (hostname, connection_key))
                        
                        updates += 1
                        logger.info(f"Resolved {dst_ip} to {hostname}")
                except (socket.herror, socket.gaierror):
                    # If reverse lookup fails, that's okay
                    pass
                    
            if updates > 0:
                logger.info(f"Resolved {updates} domain names for TLS connections")
                self.analysis_manager.analysis1_conn.commit()
            
            cursor.close()
            return updates
            
        except Exception as e:
            logger.error(f"Error in resolve_domain_names: {e}")
            return 0