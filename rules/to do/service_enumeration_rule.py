# Rule class is injected by the RuleLoader
import logging
from collections import defaultdict
import time
import json

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
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Service Enumeration Detector: {e}"
            logging.error(error_msg)
            return [error_msg]
    
    def _store_service_info(self, ip, port, details):
        """Store the service information in the database for later exploitation"""
        try:
            # If we have an analysis_manager, store data in x_ip_threat_intel
            if hasattr(self, 'analysis_manager') and self.analysis_manager:
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
                
                # Store in the threat_intel table
                self.analysis_manager.update_threat_intel(ip, threat_data)
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