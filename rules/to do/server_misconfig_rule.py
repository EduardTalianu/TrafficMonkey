# Rule class is injected by the RuleLoader
import json
import re
import logging

class ServerMisconfigurationRule(Rule):
    """Rule to detect server misconfigurations and security issues in HTTP responses"""
    def __init__(self):
        super().__init__(
            name="Server Misconfiguration Detector",
            description="Identifies security issues and misconfigurations in server responses"
        )
        
        # Track detected misconfigurations to avoid duplicates
        self.detected_misconfigs = set()
        
        # Security headers that should be present
        self.security_headers = [
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options", 
            "X-XSS-Protection",
            "Strict-Transport-Security"
        ]
        
        # Version disclosure patterns
        self.version_disclosure_patterns = [
            # Apache
            r"Apache/(\d+\.\d+\.\d+)",
            # Nginx
            r"nginx/(\d+\.\d+\.\d+)",
            # IIS
            r"Microsoft-IIS/(\d+\.\d+)",
            # Tomcat
            r"Apache Tomcat/(\d+\.\d+\.\d+)",
            # PHP
            r"PHP/(\d+\.\d+\.\d+)",
            # Node.js
            r"Node\.js/(\d+\.\d+\.\d+)",
            # JBoss/WildFly
            r"JBoss/(\d+\.\d+\.\d+)",
            r"WildFly/(\d+\.\d+\.\d+)"
        ]
        
        # Known vulnerable server versions
        self.vulnerable_versions = {
            "Apache": {
                "2.4.49": "CVE-2021-41773 - Path Traversal",
                "2.4.50": "CVE-2021-42013 - Path Traversal"
            },
            "Nginx": {
                "1.20.0": "CVE-2021-23017 - Heap Buffer Overflow",
                "1.18.0": "Multiple vulnerabilities"
            },
            "Microsoft-IIS": {
                "7.5": "Multiple vulnerabilities",
                "8.0": "Multiple vulnerabilities"
            },
            "PHP": {
                "5.": "Obsolete and vulnerable",
                "7.0.": "Obsolete and vulnerable",
                "7.1.": "Obsolete and vulnerable",
                "7.2.": "End of Life - Upgrade"
            }
        }
        
        # Error message patterns that might reveal sensitive information
        self.error_patterns = [
            r"(?:syntax|parse) error",
            r"(?:notice|warning):.+(?:on line \d+|in /.+\.php)",
            r"(?:SQL|mysql|MariaDB) error",
            r"at .+\.java:\d+\)",
            r"ORA-\d+",
            r"ODBC Error",
            r"JDBC Error",
            r"stack trace:",
            r"Exception in thread",
            r"<b>Warning</b>: .+\.php on line \d+",
            r"<b>Fatal error</b>:",
            r"Caused by: "
        ]
    
    def analyze(self, db_cursor):
        alerts = []
        try:
            # Query for HTTP responses
            db_cursor.execute("""
                SELECT r.connection_key, r.method, r.host, r.uri, res.status_code, res.server, res.response_headers
                FROM http_requests r
                JOIN http_responses res ON r.id = res.http_request_id
                WHERE res.response_headers IS NOT NULL
            """)
            
            for row in db_cursor.fetchall():
                connection_key, method, host, uri, status_code, server, response_headers = row
                
                # Skip if we've already detected this host+uri
                host_key = f"{host}:{uri}"
                if host_key in self.detected_misconfigs:
                    continue
                
                # Extract source and destination IPs from connection key
                src_ip = connection_key.split('->')[0].split(':')[0]
                dst_ip = connection_key.split('->')[1].split(':')[0]
                
                # Parse response headers
                try:
                    headers = json.loads(response_headers)
                except json.JSONDecodeError:
                    headers = {}
                
                # Check for missing security headers
                missing_headers = []
                for header in self.security_headers:
                    if header not in headers and header.lower() not in [h.lower() for h in headers]:
                        missing_headers.append(header)
                
                if missing_headers:
                    # Only report hosts that are missing multiple security headers
                    if len(missing_headers) >= 2:
                        self.detected_misconfigs.add(host_key)
                        
                        alert_msg = f"Missing security headers on {host}: {', '.join(missing_headers)}"
                        alerts.append(alert_msg)
                        
                        # Add to alerts database
                        self.add_alert(dst_ip, alert_msg)
                
                # Check for version disclosure in server header
                if server:
                    for pattern in self.version_disclosure_patterns:
                        match = re.search(pattern, server)
                        if match:
                            version = match.group(1)
                            server_type = pattern.split('(')[0].strip('/\\').strip()
                            
                            # Check if this is a known vulnerable version
                            is_vulnerable = False
                            vulnerability = ""
                            
                            for vuln_server, vuln_versions in self.vulnerable_versions.items():
                                if vuln_server in server:
                                    for vuln_ver, vuln_desc in vuln_versions.items():
                                        if version.startswith(vuln_ver):
                                            is_vulnerable = True
                                            vulnerability = vuln_desc
                                            break
                            
                            if is_vulnerable:
                                self.detected_misconfigs.add(host_key)
                                
                                alert_msg = f"Vulnerable server version detected on {host}: {server} - {vulnerability}"
                                alerts.append(alert_msg)
                                
                                # Add to alerts database
                                self.add_alert(dst_ip, alert_msg)
                            else:
                                # Just report the version disclosure
                                self.detected_misconfigs.add(host_key)
                                
                                alert_msg = f"Server version disclosure on {host}: {server}"
                                alerts.append(alert_msg)
                                
                                # Add to alerts database
                                self.add_alert(dst_ip, alert_msg)
                
                # Check for error messages in content
                try:
                    db_cursor.execute("""
                        SELECT file_data FROM http_file_data 
                        WHERE connection_key = ? 
                        ORDER BY id DESC LIMIT 1
                    """, (connection_key,))
                    
                    result = db_cursor.fetchone()
                    if result and result[0]:
                        content = result[0]
                        
                        for pattern in self.error_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                self.detected_misconfigs.add(host_key)
                                
                                alert_msg = f"Error message disclosure detected on {host}{uri}: {pattern}"
                                alerts.append(alert_msg)
                                
                                # Add to alerts database
                                self.add_alert(dst_ip, alert_msg)
                                break
                except Exception as e:
                    logging.error(f"Error checking file data: {e}")
            
            # Prevent the detected set from growing too large
            if len(self.detected_misconfigs) > 1000:
                # Clear out half the old entries
                self.detected_misconfigs = set(list(self.detected_misconfigs)[-500:])
            
            return alerts
            
        except Exception as e:
            alerts.append(f"Error in Server Misconfiguration Detector: {e}")
            logging.error(f"Error in Server Misconfiguration Detector: {e}")
            return alerts
    
    def get_params(self):
        return {
            "security_headers": {
                "type": "str",
                "default": ", ".join(self.security_headers),
                "current": ", ".join(self.security_headers),
                "description": "Comma-separated list of security headers to check"
            },
            "error_patterns": {
                "type": "str",
                "default": ", ".join(self.error_patterns[:5]) + "...",  # First 5 for brevity
                "current": ", ".join(self.error_patterns[:5]) + "...",
                "description": "Comma-separated list of error message patterns"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "security_headers":
            self.security_headers = [h.strip() for h in value.split(",")]
            return True
        elif param_name == "error_patterns":
            self.error_patterns = [p.strip() for p in value.split(",")]
            return True
        return False