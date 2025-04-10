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