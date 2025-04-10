# Rule class is injected by the RuleLoader
import base64
import re
import logging

class HTTPBasicAuthRule(Rule):
    """Rule to detect and extract HTTP Basic Authentication credentials"""
    def __init__(self):
        super().__init__(
            name="HTTP Basic Auth Detector",
            description="Detects and extracts HTTP Basic Authentication credentials"
        )
        self.detected_auths = set()  # Track already detected auth to avoid duplicates
        
    def analyze(self, db_cursor):
        alerts = []
        try:
            # Query for HTTP request headers containing Basic auth
            db_cursor.execute("""
                SELECT h.connection_key, h.header_value, h.header_name, r.host, r.uri, c.dst_ip, c.src_ip, c.dst_port
                FROM http_headers h
                JOIN connections c ON h.connection_key = c.connection_key
                LEFT JOIN http_requests r ON h.request_id = r.id
                WHERE h.header_name = 'Authorization' AND h.header_value LIKE 'Basic %'
            """)
            
            for row in db_cursor.fetchall():
                connection_key, auth_header, header_name, host, uri, dst_ip, src_ip, dst_port = row
                
                # Skip if we've already detected this auth header
                if auth_header in self.detected_auths:
                    continue
                    
                self.detected_auths.add(auth_header)
                
                # Extract the base64 encoded credentials
                encoded_creds = auth_header.split(' ')[1]
                
                # Decode the base64 data
                try:
                    decoded = base64.b64decode(encoded_creds).decode('utf-8', errors='ignore')
                    
                    if ':' in decoded:
                        username, password = decoded.split(':', 1)
                        
                        # Format URI and host if available
                        endpoint = ""
                        if host:
                            endpoint += host
                        if uri:
                            endpoint += uri
                        endpoint_info = f" ({endpoint})" if endpoint else ""
                        
                        alert_msg = f"HTTP Basic Auth detected from {src_ip} to {dst_ip}{endpoint_info}: {username}:{password}"
                        alerts.append(alert_msg)
                        
                        # Also add to the alerts database
                        self.add_alert(dst_ip, alert_msg)
                        
                        # Add to red findings
                        self._add_basic_auth_to_red_findings(
                            src_ip, 
                            dst_ip, 
                            dst_port,
                            username, 
                            password, 
                            host, 
                            uri, 
                            connection_key,
                            is_https=(dst_port == 443)
                        )
                        
                        # Prevent the detected set from growing too large
                        if len(self.detected_auths) > 1000:
                            # Clear out half the old entries
                            self.detected_auths = set(list(self.detected_auths)[-500:])
                except Exception as e:
                    logging.error(f"Error decoding Basic auth: {e}")
                    
            # Try an alternate approach - direct query for Authorization header in request_headers
            db_cursor.execute("""
                SELECT r.connection_key, r.request_headers, r.host, r.uri, c.dst_ip, c.src_ip, c.dst_port
                FROM http_requests r
                JOIN connections c ON r.connection_key = c.connection_key
                WHERE r.request_headers LIKE '%Authorization": "Basic %'
            """)
            
            for row in db_cursor.fetchall():
                connection_key, headers_json, host, uri, dst_ip, src_ip, dst_port = row
                
                # Extract the Authorization header from the JSON string
                auth_match = re.search(r'"Authorization":\s*"Basic\s+([A-Za-z0-9+/=]+)"', headers_json)
                if auth_match:
                    encoded_creds = auth_match.group(1)
                    
                    # Skip if we've already detected this auth header
                    auth_key = f"Basic {encoded_creds}"
                    if auth_key in self.detected_auths:
                        continue
                        
                    self.detected_auths.add(auth_key)
                    
                    try:
                        # Decode the base64 data
                        decoded = base64.b64decode(encoded_creds).decode('utf-8', errors='ignore')
                        
                        if ':' in decoded:
                            username, password = decoded.split(':', 1)
                            
                            # Format URI and host if available
                            endpoint = ""
                            if host:
                                endpoint += host
                            if uri:
                                endpoint += uri
                            endpoint_info = f" ({endpoint})" if endpoint else ""
                            
                            alert_msg = f"HTTP Basic Auth detected from {src_ip} to {dst_ip}{endpoint_info}: {username}:{password}"
                            alerts.append(alert_msg)
                            
                            # Also add to the alerts database
                            self.add_alert(dst_ip, alert_msg)
                            
                            # Add to red findings
                            self._add_basic_auth_to_red_findings(
                                src_ip, 
                                dst_ip, 
                                dst_port,
                                username, 
                                password, 
                                host, 
                                uri, 
                                connection_key,
                                is_https=(dst_port == 443 or (host and host.startswith("https://")))
                            )
                    except Exception as e:
                        logging.error(f"Error decoding Basic auth: {e}")
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in HTTP Basic Auth Detector: {e}"
            logging.error(error_msg)
            return [error_msg]
    
    def _add_basic_auth_to_red_findings(self, src_ip, dst_ip, dst_port, username, password, host, uri, connection_key, is_https=False):
        """Add detected HTTP Basic Authentication to red team findings"""
        try:
            # Format endpoint for display
            endpoint = ""
            if host:
                endpoint += host
            if uri:
                endpoint += uri
            
            # Determine if this is a sensitive endpoint
            sensitive_keywords = ["admin", "manage", "config", "setup", "control", "dashboard", "private", "secure"]
            is_sensitive = any(keyword in (uri or "").lower() or keyword in (host or "").lower() for keyword in sensitive_keywords)
            
            # Create description
            description = f"HTTP Basic Authentication credentials captured on {host or dst_ip}"
            if uri:
                description += f"{uri}"
            
            # Determine severity based on security context
            if not is_https:
                # Unencrypted Basic Auth is a critical finding
                severity = "critical"
                context = "unencrypted HTTP"
            elif is_sensitive:
                # Even encrypted Basic Auth on sensitive endpoints is high severity
                severity = "high"
                context = "sensitive endpoint"
            else:
                # Encrypted Basic Auth is medium severity
                severity = "medium"
                context = "authenticated endpoint"
            
            # Create masked credentials for display
            masked_username = username[:2] + "*" * (len(username) - 2) if len(username) > 2 else "***"
            masked_password = "*" * len(password) if len(password) > 0 else "***"
            
            # Create detailed information for the finding
            details = {
                "host": host or dst_ip,
                "uri": uri or "/",
                "port": dst_port,
                "protocol": "HTTPS" if is_https else "HTTP",
                "username": masked_username,
                "password_length": len(password),
                "context": context,
                "encryption_status": "encrypted" if is_https else "unencrypted"
            }
            
            # Create security analysis based on context
            if not is_https:
                details["security_analysis"] = "Basic authentication credentials transmitted in clear text, subject to interception and MITM attacks"
            else:
                details["security_analysis"] = "Basic authentication credentials are encrypted in transit, but still stored in base64 encoding which is easily reversible"
            
            # Create remediation guidance based on context
            if not is_https:
                remediation = (
                    "Immediately implement HTTPS with a valid certificate. Never send credentials over unencrypted connections. "
                    "Consider implementing a modern token-based authentication system like OAuth2 or JWT. "
                    "If Basic Auth must be used, require HTTPS and implement strong password policies."
                )
            else:
                remediation = (
                    "Consider replacing Basic Authentication with a more secure authentication method such as token-based authentication (OAuth, JWT). "
                    "Implement proper session management with secure, HttpOnly, SameSite cookies. "
                    "Implement strong password policies and rate limiting to prevent brute force attacks."
                )
            
            # Add to red findings
            self.add_red_finding(
                src_ip=src_ip,
                dst_ip=dst_ip,
                description=description,
                severity=severity,
                details=details,
                connection_key=connection_key,
                remediation=remediation
            )
            
        except Exception as e:
            logging.error(f"Error adding Basic Auth to red findings: {e}")
    
    def get_params(self):
        # No configurable parameters for this rule
        return {}