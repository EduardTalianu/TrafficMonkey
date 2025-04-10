# Rule class is injected by the RuleLoader
import re
import logging
import time
import json

class UnencryptedDataDetectorRule(Rule):
    """Rule that identifies sensitive unencrypted data in network traffic"""
    def __init__(self):
        super().__init__(
            name="Unencrypted Data Detector",
            description="Identifies sensitive data transmitted without encryption"
        )
        # Define sensitive data patterns
        self.sensitive_patterns = {
            "credit_card": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "email_password": r"(?:password|passwd|pwd|auth)[\s:=]+[^&\s]{4,}",
            "api_key": r"(?:api[-_]?key|access[-_]?token|auth[-_]?token)[\s:=]+[A-Za-z0-9_\-\.]{16,64}",
            "private_key": r"-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----",
            "aws_key": r"(?:AKIA|ASIA)[A-Z0-9]{16,}"
        }
        
        # Severity mapping for different data types
        self.data_severity = {
            "credit_card": "critical",
            "ssn": "critical",
            "private_key": "critical",
            "aws_key": "high",
            "api_key": "high",
            "email_password": "high"
        }
        
        # Track already detected data
        self.detected_data = set()
        
        # Track HTTP services still using plain HTTP
        self.plain_http_services = set()
        
        # Last analysis time
        self.last_analysis_time = 0
        # Analysis interval in seconds
        self.analysis_interval = 300  # 5 minutes
    
    def analyze(self, db_cursor):
        alerts = []
        
        current_time = time.time()
        if current_time - self.last_analysis_time < self.analysis_interval:
            return []
            
        self.last_analysis_time = current_time
        
        try:
            # Look for HTTP (not HTTPS) traffic first
            db_cursor.execute("""
                SELECT c.connection_key, c.src_ip, c.dst_ip, c.dst_port, r.host, r.uri
                FROM connections c
                JOIN http_requests r ON c.connection_key = r.connection_key
                WHERE c.dst_port = 80
                ORDER BY c.timestamp DESC
                LIMIT 1000
            """)
            
            for row in db_cursor.fetchall():
                connection_key, src_ip, dst_ip, dst_port, host, uri = row
                
                # Skip already reported services
                http_key = f"HTTP:{dst_ip}:{host}"
                if http_key in self.plain_http_services:
                    continue
                
                self.plain_http_services.add(http_key)
                
                # Alert on unencrypted HTTP
                alert_msg = f"Unencrypted HTTP traffic detected to {host or dst_ip} from {src_ip} - Consider data interception"
                alerts.append(alert_msg)
                
                # Add detailed alert
                detailed_msg = f"Potential for data interception: {host or dst_ip} is using unencrypted HTTP on port 80"
                self.add_alert(dst_ip, detailed_msg)
                
                # Add as red finding
                details = {
                    "host": host or dst_ip,
                    "port": dst_port,
                    "uri": uri or "/",
                    "protocol": "HTTP",
                    "risk": "Data transmitted over HTTP can be intercepted and read by attackers"
                }
                
                remediation = "Implement HTTPS by obtaining and configuring SSL/TLS certificates. Redirect all HTTP traffic to HTTPS using 301 redirects. Consider implementing HTTP Strict Transport Security (HSTS)."
                
                self.add_red_finding(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    description=f"Unencrypted HTTP traffic to {host or dst_ip}",
                    severity="medium",
                    details=details,
                    connection_key=connection_key,
                    remediation=remediation
                )
            
            # Search for sensitive data in HTTP content
            db_cursor.execute("""
                SELECT connection_key, file_data
                FROM http_file_data
                ORDER BY timestamp DESC
                LIMIT 1000
            """)
            
            for row in db_cursor.fetchall():
                connection_key, file_data = row
                
                # Skip if no data
                if not file_data:
                    continue
                
                # Extract source and destination IPs from connection key
                try:
                    src_ip = connection_key.split('->')[0].split(':')[0]
                    dst_ip = connection_key.split('->')[1].split(':')[0]
                except:
                    src_ip = "unknown"
                    dst_ip = "unknown"
                
                # Check each pattern
                for data_type, pattern in self.sensitive_patterns.items():
                    matches = re.findall(pattern, file_data)
                    for match in matches:
                        # Skip empty matches or those too short
                        if not match or len(match) < 4:
                            continue
                            
                        # Create a unique key to avoid duplicates
                        match_key = f"{data_type}:{connection_key}:{match[:10]}"
                        if match_key in self.detected_data:
                            continue
                            
                        self.detected_data.add(match_key)
                        
                        # Mask the match for security in logs
                        masked_match = self._mask_sensitive_data(match, data_type)
                        
                        alert_msg = f"Sensitive data ({data_type}) detected in HTTP traffic from {src_ip} to {dst_ip}: {masked_match}"
                        alerts.append(alert_msg)
                        
                        # Add detailed alert
                        self.add_alert(dst_ip, f"Sensitive {data_type} transmitted in clear text: {masked_match}")
                        
                        # Add as red finding
                        severity = self.data_severity.get(data_type, "medium")
                        
                        details = {
                            "data_type": data_type,
                            "masked_data": masked_match,
                            "detection_location": "http_body",
                            "connection_key": connection_key,
                            "encryption": "none"
                        }
                        
                        # Create appropriate remediation advice
                        if data_type == "credit_card":
                            remediation = "Implement PCI-DSS compliant handling of credit card data. Never transmit full card numbers without encryption. Consider tokenization solutions."
                        elif data_type == "ssn":
                            remediation = "Implement encryption for all Personally Identifiable Information (PII). Review data handling policies and implement data minimization practices."
                        elif data_type == "private_key":
                            remediation = "Immediately rotate compromised private keys. Never transmit private keys over the network. Consider using secure key management solutions."
                        elif data_type == "api_key" or data_type == "aws_key":
                            remediation = "Rotate exposed API keys immediately. Implement secure key management and limit key permissions to only what is necessary."
                        elif data_type == "email_password":
                            remediation = "Implement secure authentication methods that don't transmit credentials in plaintext. Use HTTPS for all authentication endpoints."
                        else:
                            remediation = "Implement encryption for all sensitive data transmission. Review application security practices around data handling."
                        
                        self.add_red_finding(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            description=f"Unencrypted {data_type} detected in HTTP traffic",
                            severity=severity,
                            details=details,
                            connection_key=connection_key,
                            remediation=remediation
                        )
            
            # Also check HTTP headers for sensitive data
            db_cursor.execute("""
                SELECT connection_key, header_name, header_value
                FROM http_headers
                WHERE header_value IS NOT NULL
                ORDER BY timestamp DESC
                LIMIT 1000
            """)
            
            for row in db_cursor.fetchall():
                connection_key, header_name, header_value = row
                
                # Skip if no value
                if not header_value:
                    continue
                
                # Extract source and destination IPs from connection key
                try:
                    src_ip = connection_key.split('->')[0].split(':')[0]
                    dst_ip = connection_key.split('->')[1].split(':')[0]
                except:
                    src_ip = "unknown"
                    dst_ip = "unknown"
                
                # Check if this is an Authorization header (common source of creds)
                if header_name.lower() == "authorization" and "basic " in header_value.lower():
                    # Basic auth contains credentials
                    match_key = f"BasicAuth:{connection_key}"
                    if match_key not in self.detected_data:
                        self.detected_data.add(match_key)
                        
                        alert_msg = f"HTTP Basic Authentication detected from {src_ip} to {dst_ip} - Credentials transmitted in clear text"
                        alerts.append(alert_msg)
                        
                        # Add detailed alert
                        self.add_alert(dst_ip, f"HTTP Basic Authentication credentials exposed in {connection_key}")
                        
                        # Extract and decode credentials if possible
                        auth_value = header_value.replace("Basic ", "").strip()
                        credentials = "unknown:unknown"
                        try:
                            import base64
                            decoded = base64.b64decode(auth_value).decode('utf-8')
                            if ':' in decoded:
                                credentials = decoded
                        except:
                            pass
                        
                        # Add as red finding
                        details = {
                            "header_name": header_name,
                            "auth_type": "Basic Authentication",
                            "masked_credentials": self._mask_credential_pair(credentials),
                            "detection_location": "auth_header",
                            "encryption": "none"
                        }
                        
                        remediation = "Implement token-based authentication instead of Basic Authentication. If Basic Authentication must be used, ensure it's only over HTTPS. Consider implementing multi-factor authentication."
                        
                        self.add_red_finding(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            description="HTTP Basic Authentication credentials exposed",
                            severity="high",
                            details=details,
                            connection_key=connection_key,
                            remediation=remediation
                        )
                
                # Also check other headers for sensitive data patterns
                for data_type, pattern in self.sensitive_patterns.items():
                    matches = re.findall(pattern, header_value)
                    for match in matches:
                        # Skip empty matches or those too short
                        if not match or len(match) < 4:
                            continue
                            
                        # Create a unique key to avoid duplicates
                        match_key = f"{data_type}:{connection_key}:{header_name}"
                        if match_key in self.detected_data:
                            continue
                            
                        self.detected_data.add(match_key)
                        
                        # Mask the match for security in logs
                        masked_match = self._mask_sensitive_data(match, data_type)
                        
                        alert_msg = f"Sensitive data ({data_type}) detected in HTTP header {header_name} from {src_ip} to {dst_ip}: {masked_match}"
                        alerts.append(alert_msg)
                        
                        # Add detailed alert
                        self.add_alert(dst_ip, f"Sensitive {data_type} transmitted in header {header_name}: {masked_match}")
                        
                        # Add as red finding
                        severity = self.data_severity.get(data_type, "medium")
                        
                        details = {
                            "data_type": data_type,
                            "header_name": header_name,
                            "masked_data": masked_match,
                            "detection_location": "http_header",
                            "encryption": "none"
                        }
                        
                        # Create appropriate remediation advice based on data type and location
                        if data_type == "api_key" or data_type == "aws_key":
                            remediation = "Rotate exposed keys immediately. Consider using secure token exchange or OAuth flows instead of static API keys in headers."
                        else:
                            remediation = "Implement HTTPS for all traffic. Review application security to ensure sensitive information is not placed in HTTP headers."
                        
                        self.add_red_finding(
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            description=f"Sensitive {data_type} exposed in HTTP header",
                            severity=severity,
                            details=details,
                            connection_key=connection_key,
                            remediation=remediation
                        )
            
            # Prevent the detected sets from growing too large
            if len(self.detected_data) > 1000:
                self.detected_data = set(list(self.detected_data)[-500:])
            
            if len(self.plain_http_services) > 500:
                self.plain_http_services = set(list(self.plain_http_services)[-250:])
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Unencrypted Data Detector: {e}"
            logging.error(error_msg)
            return [error_msg]
    
    def _mask_sensitive_data(self, data, data_type):
        """Mask sensitive data for safe display in logs"""
        if not data:
            return "[empty]"
            
        # Credit card - show first 6 and last 4 digits
        if data_type == "credit_card" and len(data) >= 12:
            return f"{data[:6]}******{data[-4:]}"
        
        # SSN - show only last 4
        elif data_type == "ssn" and len(data) >= 9:
            return f"XXX-XX-{data[-4:]}"
        
        # API keys and tokens - show first 4 and last 4
        elif data_type in ["api_key", "aws_key"] and len(data) >= 10:
            return f"{data[:4]}...{data[-4:]}"
        
        # Private key - just indicate presence
        elif data_type == "private_key":
            return "[PRIVATE KEY MATERIAL]"
        
        # Default - show first 1/3 and mask the rest
        else:
            visible_chars = max(4, len(data) // 3)
            return f"{data[:visible_chars]}{'*' * (len(data) - visible_chars)}"
    
    def _mask_credential_pair(self, credential_pair):
        """Mask username:password credential pair"""
        if not credential_pair or ":" not in credential_pair:
            return "***:***"  # Correctly indented inside the 'if'

        # These lines execute if the 'if' condition is false
        username, password = credential_pair.split(":", 1)

        # Show first 2 chars of username and mask the rest
        masked_username = username[:2] + "*" * (len(username) - 2) if len(username) > 2 else "***"

        # Mask password completely
        masked_password = "*" * len(password) if len(password) > 0 else "***"

        return f"{masked_username}:{masked_password}"
    
    def get_params(self):
        return {
            "analysis_interval": {
                "type": "int",
                "default": 300,
                "current": self.analysis_interval,
                "description": "Interval between analyses (seconds)"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "analysis_interval":
            self.analysis_interval = int(value)
            return True
        return False