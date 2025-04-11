class ServiceEnumerationRule(Rule):
    """Rule that identifies and maps services running on the network"""
    def __init__(self):
        super().__init__(
            name="Service Enumeration Detector",
            description="Identifies running services across hosts to build attack surface map"
        )
        # Store service information
        self.services = defaultdict(dict)
        # Default port-to-service mapping
        self.port_service_map = {
            # Web services
            80: "HTTP", 443: "HTTPS", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
            # Email
            25: "SMTP", 587: "SMTP-TLS", 465: "SMTPS", 110: "POP3", 143: "IMAP", 993: "IMAPS", 995: "POP3S",
            # File sharing
            21: "FTP", 22: "SSH/SFTP", 445: "SMB", 139: "NetBIOS",
            # Directory services
            389: "LDAP", 636: "LDAPS", 3268: "Global Catalog", 3269: "Global Catalog SSL",
            # Database
            1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB",
            # Remote management
            3389: "RDP", 5900: "VNC", 5985: "WinRM", 5986: "WinRM-HTTPS",
            # Authentication
            88: "Kerberos", 464: "Kerberos Change/Set",
            # Other
            53: "DNS", 67: "DHCP", 123: "NTP", 161: "SNMP", 179: "BGP", 389: "LDAP",
            514: "Syslog", 1433: "MSSQL", 1521: "Oracle", 1900: "SSDP", 5060: "SIP", 5061: "SIP-TLS"
        }
        # Last analysis time
        self.last_analysis_time = 0
        # Analysis interval in seconds
        self.analysis_interval = 600  # 10 minutes
        # Track already reported services
        self.reported_services = set()
        # Service risk ratings - used to determine severity
        self.service_risk_ratings = {
            # High risk services
            "RDP": "high", "VNC": "high", "Telnet": "high", "FTP": "high",
            "Redis": "high", "MongoDB": "high", "Elasticsearch": "high",
            # Medium risk services
            "SMB": "medium", "MSSQL": "medium", "Oracle": "medium", "MySQL": "medium", 
            "PostgreSQL": "medium", "LDAP": "medium", "SMTP": "medium", "HTTP": "medium",
            # Lower risk services
            "HTTPS": "low", "HTTPS-ALT": "low", "SSH/SFTP": "low", "LDAPS": "low", "IMAPS": "low",
            "POP3S": "low", "SMTPS": "low", "DNS": "low", "NTP": "low"
        }
    
    def analyze(self, db_cursor):
        alerts = []
        
        current_time = time.time()
        if current_time - self.last_analysis_time < self.analysis_interval:
            return []
            
        self.last_analysis_time = current_time
        
        try:
            # Get all connections to identify services
            db_cursor.execute("""
                SELECT dst_ip, dst_port, protocol, COUNT(*) as conn_count
                FROM connections
                WHERE dst_port IS NOT NULL
                GROUP BY dst_ip, dst_port
                ORDER BY dst_ip, dst_port
            """)
            
            # Process connections
            for row in db_cursor.fetchall():
                dst_ip, dst_port, protocol, conn_count = row
                
                # Skip if port is null or zero
                if not dst_port:
                    continue
                
                # Determine service based on port
                service = protocol or self.port_service_map.get(dst_port, f"Unknown-{dst_port}")
                
                # Create service key
                service_key = f"{dst_ip}:{dst_port}"
                
                # Skip if we've already reported this service
                if service_key in self.reported_services:
                    continue
                
                # Store service information
                if dst_ip not in self.services:
                    self.services[dst_ip] = {}
                
                self.services[dst_ip][dst_port] = {
                    "service": service,
                    "connection_count": conn_count,
                    "protocol_detected": protocol is not None
                }
            
            # Get HTTP server information
            db_cursor.execute("""
                SELECT res.server, r.host, c.dst_ip, c.dst_port, COUNT(*) as req_count
                FROM http_responses res
                JOIN http_requests r ON res.http_request_id = r.id
                JOIN connections c ON r.connection_key = c.connection_key
                WHERE res.server IS NOT NULL
                GROUP BY c.dst_ip, c.dst_port
            """)
            
            for row in db_cursor.fetchall():
                server, host, dst_ip, dst_port, req_count = row
                
                service_key = f"{dst_ip}:{dst_port}"
                
                # Update service information with HTTP server details
                if dst_ip in self.services and dst_port in self.services[dst_ip]:
                    self.services[dst_ip][dst_port]["http_server"] = server
                    self.services[dst_ip][dst_port]["hostname"] = host
                    self.services[dst_ip][dst_port]["request_count"] = req_count
            
            # Get TLS certificate information
            db_cursor.execute("""
                SELECT c.dst_ip, c.dst_port, t.tls_version, t.cipher_suite, t.server_name,
                       t.certificate_issuer, t.certificate_subject
                FROM tls_connections t
                JOIN connections c ON t.connection_key = c.connection_key
                WHERE t.server_name IS NOT NULL OR t.certificate_subject IS NOT NULL
            """)
            
            for row in db_cursor.fetchall():
                dst_ip, dst_port, tls_version, cipher_suite, server_name, cert_issuer, cert_subject = row
                
                service_key = f"{dst_ip}:{dst_port}"
                
                # Update service information with TLS details
                if dst_ip in self.services and dst_port in self.services[dst_ip]:
                    self.services[dst_ip][dst_port]["tls_version"] = tls_version
                    self.services[dst_ip][dst_port]["server_name"] = server_name
                    self.services[dst_ip][dst_port]["certificate_subject"] = cert_subject
                    self.services[dst_ip][dst_port]["certificate_issuer"] = cert_issuer
            
            # Generate reports on the services
            for ip, ports in self.services.items():
                for port, details in ports.items():
                    service_key = f"{ip}:{port}"
                    
                    # Skip if we've already reported this service
                    if service_key in self.reported_services:
                        continue
                    
                    self.reported_services.add(service_key)
                    
                    # Determine if this is an interesting service to report
                    is_interesting = False
                    reason = ""
                    
                    # Web server is always interesting
                    if details.get("service") in ["HTTP", "HTTPS", "HTTP-ALT", "HTTPS-ALT"]:
                        is_interesting = True
                        reason = "Web server"
                    
                    # Database servers are interesting
                    elif details.get("service") in ["MSSQL", "Oracle", "MySQL", "PostgreSQL", "MongoDB"]:
                        is_interesting = True
                        reason = "Database server"
                    
                    # Directory services are interesting
                    elif details.get("service") in ["LDAP", "LDAPS", "Global Catalog"]:
                        is_interesting = True
                        reason = "Directory service"
                    
                    # Remote access is interesting
                    elif details.get("service") in ["RDP", "VNC", "SSH/SFTP"]:
                        is_interesting = True
                        reason = "Remote access"
                    
                    # File sharing is interesting
                    elif details.get("service") in ["SMB", "FTP"]:
                        is_interesting = True
                        reason = "File sharing"
                    
                    # High connection count is interesting
                    elif details.get("connection_count", 0) > 100:
                        is_interesting = True
                        reason = "High traffic volume"
                    
                    # If we have detailed server information, it's interesting
                    elif details.get("http_server") or details.get("certificate_subject"):
                        is_interesting = True
                        reason = "Detailed service information available"
                    
                    if is_interesting:
                        # Create service information string
                        service_info = f"{details.get('service')} on port {port}"
                        if details.get("http_server"):
                            service_info += f" - Server: {details.get('http_server')}"
                        if details.get("hostname"):
                            service_info += f" - Host: {details.get('hostname')}"
                        if details.get("tls_version"):
                            service_info += f" - TLS: {details.get('tls_version')}"
                        
                        alert_msg = f"Service discovered: {service_info} on {ip} ({reason})"
                        alerts.append(alert_msg)
                        
                        # Store service details in the database
                        self._store_service_info(ip, port, details)
                        
                        # Add to red team findings directly
                        self._add_service_to_red_findings(ip, port, details, reason)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Service Enumeration Detector: {e}"
            logging.error(error_msg)
            return [error_msg]
    
    def _add_service_to_red_findings(self, ip, port, details, reason):
        """Add the discovered service to red team findings using the new integrated method"""
        try:
            # Extract service and additional info
            service_name = details.get('service', f"Unknown-{port}")
            
            # Determine severity based on service risk
            severity = self.service_risk_ratings.get(service_name, "medium")
            
            # Increase severity for unencrypted services on the internet
            if service_name in ["HTTP", "FTP", "Telnet", "SMTP", "POP3", "IMAP", "LDAP", "MongoDB", "Redis"]:
                # Check if server software version is available and potentially vulnerable
                if details.get("http_server") and any(v in details.get("http_server", "") for v in ["2.2", "2.4.10", "5.0", "1.0"]):
                    severity = "high"
                    
            # Create detailed information for the finding
            details_dict = {
                "service": service_name,
                "port": port,
                "discovery_reason": reason,
                "connection_count": details.get("connection_count", 0)
            }
            
            # Add HTTP server details if available
            if details.get("http_server"):
                details_dict["http_server"] = details.get("http_server")
                details_dict["hostname"] = details.get("hostname", "")
                details_dict["request_count"] = details.get("request_count", 0)
            
            # Add TLS details if available
            if details.get("tls_version"):
                details_dict["tls_version"] = details.get("tls_version")
                details_dict["server_name"] = details.get("server_name", "")
                details_dict["certificate_subject"] = details.get("certificate_subject", "")
                details_dict["certificate_issuer"] = details.get("certificate_issuer", "")
            
            # Create finding description based on service type
            description = f"Discovered {service_name} service on {ip}:{port}"
            
            # Create remediation guidance based on service type
            remediation = "Review if this service is necessary and properly secured."
            
            # Customize remediation based on service
            if service_name in ["HTTP", "HTTP-ALT"]:
                remediation = "Consider migrating to HTTPS. Ensure web server is patched and properly configured."
            elif service_name in ["RDP", "VNC", "SSH/SFTP"]:
                remediation = "Ensure remote access is restricted to authorized IPs only. Use strong authentication, timeout policies, and consider multi-factor authentication."
            elif service_name in ["MSSQL", "Oracle", "MySQL", "PostgreSQL", "MongoDB", "Redis"]:
                remediation = "Database services should not be directly exposed to untrusted networks. Implement network controls, strong authentication, and ensure databases are patched."
            elif service_name in ["SMB", "FTP"]:
                remediation = "File sharing protocols should be restricted to authorized users and networks. Consider encrypted alternatives like SFTP instead of FTP."
            elif service_name in ["LDAP"]:
                remediation = "Use LDAPS (LDAP over SSL/TLS) instead of unencrypted LDAP. Restrict directory service access to authenticated users only."
            
            # Add red finding directly using our built-in method
            self.add_red_finding(
                src_ip="N/A",  # No specific source IP for service discovery
                dst_ip=ip,
                description=description,
                severity=severity,
                details=details_dict,
                connection_key=None,
                remediation=remediation
            )
            
            logging.info(f"Successfully added red finding for {service_name} service")
        except Exception as e:
            logging.error(f"Error adding service to red findings: {e}", exc_info=True)
    
    def _store_service_info(self, ip, port, details):
        """Store the service information in the database for later exploitation"""
        try:
            # Store directly in the captures table instead of relying on analysis_manager
            if self.db_manager and hasattr(self.db_manager, 'capture_conn'):
                # Create threat intel entry for this service
                threat_data = {
                    "score": 0,  # Not a threat, just information
                    "type": "service_discovery",
                    "confidence": 0.9,
                    "source": self.name,
                    "details": {
                        "ip": ip,
                        "port": port,
                        "service": details.get("service"),
                        "http_server": details.get("http_server"),
                        "hostname": details.get("hostname"),
                        "tls_version": details.get("tls_version"),
                        "certificate_subject": details.get("certificate_subject"),
                        "certificate_issuer": details.get("certificate_issuer"),
                        "connection_count": details.get("connection_count"),
                        "discovery_time": time.time()
                    },
                    "protocol": details.get("service", "UNKNOWN"),
                    "destination_port": port,
                    "detection_method": "traffic_analysis"
                }
                
                # Store in the database directly
                cursor = self.db_manager.capture_conn.cursor()
                try:
                    # Try to create the table if it doesn't exist
                    cursor.execute("""
                        CREATE TABLE IF NOT EXISTS x_ip_threat_intel (
                            ip_address TEXT PRIMARY KEY,
                            threat_score REAL DEFAULT 0,
                            threat_type TEXT,
                            confidence REAL DEFAULT 0,
                            source TEXT,
                            first_seen TIMESTAMP,
                            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                            details TEXT,
                            protocol TEXT,
                            destination_ip TEXT,
                            destination_port INTEGER,
                            bytes_transferred INTEGER,
                            detection_method TEXT,
                            encoding_type TEXT,
                            packet_count INTEGER,
                            timing_variance REAL,
                            alert_count INTEGER DEFAULT 1
                        )
                    """)
                    
                    # Basic index
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_threat_score ON x_ip_threat_intel(threat_score DESC)")
                    
                    # Insert or update the record
                    cursor.execute("""
                        INSERT OR REPLACE INTO x_ip_threat_intel
                        (ip_address, threat_score, threat_type, confidence, source, first_seen, 
                        last_seen, details, protocol, destination_port, detection_method)
                        VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?)
                    """, (
                        ip, 
                        threat_data.get('score', 0), 
                        threat_data.get('type'),
                        threat_data.get('confidence', 0),
                        threat_data.get('source'),
                        time.time(),
                        json.dumps(threat_data.get('details', {})),
                        threat_data.get('protocol'),
                        threat_data.get('destination_port'),
                        threat_data.get('detection_method')
                    ))
                    
                    # Update alert count if this is an existing record
                    cursor.execute("""
                        UPDATE x_ip_threat_intel 
                        SET alert_count = alert_count + 1
                        WHERE ip_address = ? AND alert_count IS NOT NULL
                    """, (ip,))
                    
                    self.db_manager.capture_conn.commit()
                    
                except Exception as e:
                    logging.error(f"Error creating x_ip_threat_intel table or inserting data: {e}")
                finally:
                    cursor.close()
        except Exception as e:
            logging.error(f"Error storing service information: {e}")
    
    def get_params(self):
        return {
            "analysis_interval": {
                "type": "int",
                "default": 600,
                "current": self.analysis_interval,
                "description": "Interval between analyses (seconds)"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "analysis_interval":
            self.analysis_interval = int(value)
            return True
        return False