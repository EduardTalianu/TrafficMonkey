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
        
        # Security headers and their recommended values
        self.security_header_recommendations = {
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "SAMEORIGIN or DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=()",
            "Cache-Control": "no-store, max-age=0"
        }
        
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
                        
                        # Add to red findings
                        self._add_missing_headers_to_red_findings(
                            dst_ip, 
                            host, 
                            uri, 
                            missing_headers, 
                            connection_key
                        )
                
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
                                
                                # Add to red findings
                                self._add_vulnerable_server_to_red_findings(
                                    dst_ip,
                                    host,
                                    uri,
                                    server,
                                    vulnerability,
                                    connection_key,
                                    is_vulnerable=True
                                )
                            else:
                                # Just report the version disclosure
                                self.detected_misconfigs.add(host_key)
                                
                                alert_msg = f"Server version disclosure on {host}: {server}"
                                alerts.append(alert_msg)
                                
                                # Add to alerts database
                                self.add_alert(dst_ip, alert_msg)
                                
                                # Add to red findings
                                self._add_vulnerable_server_to_red_findings(
                                    dst_ip,
                                    host,
                                    uri,
                                    server,
                                    "Version disclosure",
                                    connection_key,
                                    is_vulnerable=False
                                )
                
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
                            match = re.search(pattern, content, re.IGNORECASE)
                            if match:
                                self.detected_misconfigs.add(host_key)
                                
                                # Extract the specific error message
                                error_msg = match.group(0)
                                
                                alert_msg = f"Error message disclosure detected on {host}{uri}: {error_msg}"
                                alerts.append(alert_msg)
                                
                                # Add to alerts database
                                self.add_alert(dst_ip, alert_msg)
                                
                                # Add to red findings
                                self._add_error_disclosure_to_red_findings(
                                    dst_ip, 
                                    host, 
                                    uri, 
                                    error_msg, 
                                    pattern, 
                                    connection_key, 
                                    status_code
                                )
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
    
    def _add_missing_headers_to_red_findings(self, dst_ip, host, uri, missing_headers, connection_key):
        """Add missing security headers to red team findings"""
        try:
            # Determine severity based on number and importance of missing headers
            severity = "low"
            critical_headers = ["Content-Security-Policy", "Strict-Transport-Security"]
            important_headers = ["X-Frame-Options", "X-Content-Type-Options"]
            
            # Check if any critical headers are missing
            critical_missing = [header for header in missing_headers if header in critical_headers]
            important_missing = [header for header in missing_headers if header in important_headers]
            
            if len(missing_headers) >= 4 or len(critical_missing) >= 1:
                severity = "medium"
            if len(critical_missing) >= 2 or (len(important_missing) >= 2 and len(critical_missing) >= 1):
                severity = "high"
            
            # Create description
            description = f"Missing security headers on {host}: {', '.join(missing_headers[:3])}"
            if len(missing_headers) > 3:
                description += f" and {len(missing_headers) - 3} more"
            
            # Create details with header information
            details = {
                "host": host,
                "uri": uri,
                "missing_headers": missing_headers,
                "total_missing": len(missing_headers)
            }
            
            # Add recommendations for each missing header
            recommendations = {}
            for header in missing_headers:
                if header in self.security_header_recommendations:
                    recommendations[header] = self.security_header_recommendations[header]
            
            if recommendations:
                details["recommended_values"] = recommendations
            
            # Create remediation advice
            remediation = "Implement the following security headers in your server configuration:\n\n"
            for header in missing_headers:
                if header in self.security_header_recommendations:
                    remediation += f"- {header}: {self.security_header_recommendations[header]}\n"
                else:
                    remediation += f"- {header}: Consult documentation for appropriate values\n"
                    
            remediation += "\nFor web servers like Apache, these can be added to .htaccess or httpd.conf. For Nginx, add them to your server or location blocks. For application servers, add them to your response headers in code."
            
            # Add to red findings directly
            self.add_red_finding(
                src_ip="N/A",  # No specific source IP for this finding
                dst_ip=dst_ip,
                description=description,
                severity=severity,
                details=details,
                connection_key=connection_key,
                remediation=remediation
            )
            
        except Exception as e:
            logging.error(f"Error adding missing headers to red findings: {e}")
    
    def _add_vulnerable_server_to_red_findings(self, dst_ip, host, uri, server, vulnerability, connection_key, is_vulnerable=False):
        """Add vulnerable server version to red team findings"""
        try:
            # Extract server type and version
            server_type = server.split('/')[0] if '/' in server else server
            version = server.split('/')[-1] if '/' in server else "unknown"
            
            # Determine severity based on vulnerability status
            if is_vulnerable:
                severity = "high"
                description = f"Vulnerable {server_type} version ({version}) on {host}"
            else:
                severity = "low"
                description = f"Server version disclosure on {host}: {server}"
            
            # Create details dictionary
            details = {
                "host": host,
                "uri": uri,
                "server": server,
                "server_type": server_type,
                "version": version,
                "is_known_vulnerable": is_vulnerable
            }
            
            # Add vulnerability details if available
            if vulnerability and vulnerability != "Version disclosure":
                details["vulnerability"] = vulnerability
            
            # Create appropriate remediation advice
            if is_vulnerable:
                remediation = f"Upgrade {server_type} to the latest stable version immediately. The current version ({version}) is vulnerable to {vulnerability}.\n\n"
                remediation += "Immediate steps to take:\n"
                remediation += "1. Schedule an update of the server software\n"
                remediation += "2. Apply any available security patches\n"
                remediation += "3. Implement temporary mitigations like web application firewalls or access restrictions\n"
                remediation += "4. After upgrading, review server configuration for security best practices"
            else:
                remediation = f"Remove or hide the Server header to prevent version disclosure. This can be done via:\n\n"
                remediation += "- For Apache: Use mod_headers to set ServerTokens to 'Prod' and ServerSignature to 'Off'\n"
                remediation += "- For Nginx: Set server_tokens off; in your configuration\n"
                remediation += "- For IIS: Use URLScan to remove the Server header\n"
                remediation += "- For application servers: Configure the server to remove or modify the header in responses"
            
            # Add to red findings directly
            self.add_red_finding(
                src_ip="N/A",  # No specific source IP for this finding
                dst_ip=dst_ip,
                description=description,
                severity=severity,
                details=details,
                connection_key=connection_key,
                remediation=remediation
            )
            
        except Exception as e:
            logging.error(f"Error adding vulnerable server to red findings: {e}")
    
    def _add_error_disclosure_to_red_findings(self, dst_ip, host, uri, error_msg, pattern, connection_key, status_code):
        """Add error message disclosure to red team findings"""
        try:
            # Determine error type
            error_type = "Unknown"
            if "SQL" in pattern or "mysql" in pattern or "MariaDB" in pattern or "ORA-" in pattern:
                error_type = "SQL Error"
            elif "php" in pattern or "syntax error" in pattern or "parse error" in pattern:
                error_type = "PHP Error"
            elif "java" in pattern or "Exception" in pattern:
                error_type = "Java Exception"
            elif "ODBC" in pattern or "JDBC" in pattern:
                error_type = "Database Connection Error"
            
            # Determine severity based on error type and content
            severity = "medium"
            if "SQL" in error_type or "Database" in error_type:
                severity = "high"  # SQL errors can reveal database structure
            if "stack trace" in error_msg.lower() or "at " in error_msg and ".java:" in error_msg:
                severity = "high"  # Stack traces reveal code paths
            
            # Limit error message to reasonable length
            short_error = error_msg[:100] + ("..." if len(error_msg) > 100 else "")
            
            # Create description
            description = f"{error_type} disclosure on {host}"
            
            # Create details dictionary
            details = {
                "host": host,
                "uri": uri,
                "error_type": error_type,
                "error_message": short_error,
                "status_code": status_code
            }
            
            # Create remediation advice based on error type
            if error_type == "SQL Error":
                remediation = (
                    "Disable detailed SQL error messages in production. Configure proper error handling to catch "
                    "database exceptions and display generic error messages instead. Review application code to "
                    "ensure proper parameterized queries are used to prevent SQL injection."
                )
            elif error_type == "PHP Error":
                remediation = (
                    "Disable display_errors in php.ini for production environments. Set error_reporting to exclude "
                    "notices and warnings. Implement proper exception handling in application code to catch and log "
                    "errors without displaying them to users."
                )
            elif error_type == "Java Exception":
                remediation = (
                    "Configure the application server to disable stack traces in error responses. Implement proper "
                    "exception handling with custom error pages. Use a global exception handler that logs details "
                    "but only displays generic messages to users."
                )
            else:
                remediation = (
                    "Implement proper error handling to prevent disclosure of technical details. Configure the "
                    "application and server to display generic error pages instead of detailed error messages. "
                    "Ensure all errors are logged securely for troubleshooting without exposing details to users."
                )
            
            # Add to red findings directly
            self.add_red_finding(
                src_ip="N/A",  # No specific source IP for this finding
                dst_ip=dst_ip,
                description=description,
                severity=severity,
                details=details,
                connection_key=connection_key,
                remediation=remediation
            )
            
        except Exception as e:
            logging.error(f"Error adding error disclosure to red findings: {e}")
    
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