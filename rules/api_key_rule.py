# Rule class is injected by the RuleLoader
import re
import json
import logging

class APIKeyDetectorRule(Rule):
    """Rule to detect API keys, tokens, and secrets in HTTP traffic"""
    def __init__(self):
        super().__init__(
            name="API Key Detector",
            description="Detects API keys, tokens, and secrets in HTTP traffic"
        )
        
        # Define regex patterns for common API keys and tokens
        self.api_key_patterns = {
            "AWS Access Key": r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])",
            "AWS Secret Key": r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])",
            "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
            "Firebase API Key": r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}",
            "GitHub Token": r"github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}",
            "GitHub OAuth": r"gho_[a-zA-Z0-9]{36}",
            "GitHub App Token": r"ghu_[a-zA-Z0-9]{36}",
            "Generic API Key": r"api[-_]?key[=: \"'\]]\s*([a-zA-Z0-9]{16,64})",
            "Generic Secret": r"secret[=: \"'\]]\s*([a-zA-Z0-9/+=_-]{16,64})",
            "Generic Token": r"token[=: \"'\]]\s*([a-zA-Z0-9/+=_-]{16,64})",
            "Bearer Token": r"bearer\s+([a-zA-Z0-9/+=_-]{30,})",
            "JWT Token": r"eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}"
        }
        
        # Common API key parameter names (case insensitive)
        self.api_key_params = [
            "api_key", "apikey", "api-key", "key", "token", "access_token", 
            "auth_token", "secret", "client_secret", "app_secret",
            "consumer_key", "consumer_secret", "oauth_token", "refresh_token"
        ]
        
        # Track detected API keys to avoid duplicates
        self.detected_api_keys = set()
        
    def analyze(self, db_cursor):
        alerts = []
        try:
            # Query for HTTP requests with headers
            db_cursor.execute("""
                SELECT connection_key, method, host, uri, request_headers
                FROM http_requests
                WHERE request_headers IS NOT NULL
            """)
            
            for row in db_cursor.fetchall():
                connection_key, method, host, uri, headers_json = row
                
                # Skip if we don't have header data
                if not headers_json:
                    continue
                
                # Extract source and destination IPs from connection key
                src_ip = connection_key.split('->')[0].split(':')[0]
                dst_ip = connection_key.split('->')[1].split(':')[0]
                
                # Search for API keys in URI
                if uri:
                    for key_type, pattern in self.api_key_patterns.items():
                        matches = re.findall(pattern, uri)
                        for match in matches:
                            # Create unique key for this detection
                            detection_key = f"{key_type}:{match}:{host}"
                            if detection_key in self.detected_api_keys:
                                continue
                                
                            self.detected_api_keys.add(detection_key)
                            
                            # Mask part of the key for security
                            masked_key = self._mask_key(match)
                            alert_msg = f"Possible {key_type} detected in URI from {src_ip} to {dst_ip} ({host}): {masked_key}"
                            alerts.append(alert_msg)
                            
                            # Add to alerts database
                            self.add_alert(dst_ip, alert_msg)
                            
                            # Also add as a red finding with more details
                            severity = "high" if "Secret" in key_type or "Token" in key_type else "medium"
                            details = {
                                "key_type": key_type,
                                "masked_key": masked_key,
                                "host": host,
                                "method": method,
                                "uri": uri
                            }
                            remediation = "Revoke the exposed API key and ensure secrets are not included in URLs"
                            self.add_red_finding(
                                src_ip, dst_ip, 
                                f"API Key Exposure ({key_type})", 
                                severity=severity,
                                details=details,
                                connection_key=connection_key,
                                remediation=remediation
                            )
                
                # Search for API keys in headers
                try:
                    headers = json.loads(headers_json)
                    for header_name, header_value in headers.items():
                        if not isinstance(header_value, str):
                            continue
                            
                        # Check for API keys in header value
                        for key_type, pattern in self.api_key_patterns.items():
                            matches = re.findall(pattern, header_value)
                            for match in matches:
                                # Create unique key for this detection
                                detection_key = f"{key_type}:{match}:{header_name}"
                                if detection_key in self.detected_api_keys:
                                    continue
                                    
                                self.detected_api_keys.add(detection_key)
                                
                                # Mask part of the key for security
                                masked_key = self._mask_key(match)
                                alert_msg = f"Possible {key_type} detected in '{header_name}' header from {src_ip} to {dst_ip} ({host}): {masked_key}"
                                alerts.append(alert_msg)
                                
                                # Add to alerts database
                                self.add_alert(dst_ip, alert_msg)
                                
                                # Also add as a red finding with more details
                                severity = "high" if "Secret" in key_type or "Token" in key_type else "medium"
                                details = {
                                    "key_type": key_type,
                                    "header_name": header_name,
                                    "masked_key": masked_key,
                                    "host": host,
                                    "method": method
                                }
                                remediation = "Revoke the exposed API key and ensure secrets are not included in HTTP headers"
                                self.add_red_finding(
                                    src_ip, dst_ip, 
                                    f"API Key Exposure in Header ({key_type})", 
                                    severity=severity,
                                    details=details,
                                    connection_key=connection_key,
                                    remediation=remediation
                                )
                        
                        # Check if header name looks like an API key parameter
                        header_lower = header_name.lower()
                        for param in self.api_key_params:
                            if param in header_lower:
                                # Create unique key for this detection
                                detection_key = f"Header:{header_name}:{header_value}"
                                if detection_key in self.detected_api_keys:
                                    continue
                                    
                                self.detected_api_keys.add(detection_key)
                                
                                # Mask part of the value for security
                                masked_value = self._mask_key(header_value)
                                alert_msg = f"Possible API key in '{header_name}' header from {src_ip} to {dst_ip} ({host}): {masked_value}"
                                alerts.append(alert_msg)
                                
                                # Add to alerts database
                                self.add_alert(dst_ip, alert_msg)
                                
                                # Also add as a red finding with more details
                                details = {
                                    "param_type": "header_name",
                                    "param_name": header_name,
                                    "masked_value": masked_value,
                                    "host": host,
                                    "method": method
                                }
                                remediation = "Review if this API key is sensitive and should be properly secured"
                                self.add_red_finding(
                                    src_ip, dst_ip, 
                                    f"API Key Parameter in Header", 
                                    severity="medium",
                                    details=details,
                                    connection_key=connection_key,
                                    remediation=remediation
                                )
                                break
                    
                except json.JSONDecodeError:
                    # Not valid JSON
                    pass
                except Exception as e:
                    logging.error(f"Error processing headers JSON: {e}")
            
            # Prevent the detected set from growing too large
            if len(self.detected_api_keys) > 1000:
                # Clear out half the old entries
                self.detected_api_keys = set(list(self.detected_api_keys)[-500:])
            
            return alerts
            
        except Exception as e:
            alerts.append(f"Error in API Key Detector: {e}")
            logging.error(f"Error in API Key Detector: {e}")
            return alerts
        
    def _mask_key(self, key):
        """Mask part of the key for security in alerts"""
        if not key or len(key) < 8:
            return key
            
        # Show first 4 and last 4 characters, mask the rest
        return f"{key[:4]}{'*' * (len(key) - 8)}{key[-4:]}"
    
    def get_params(self):
        return {
            "api_key_params": {
                "type": "str",
                "default": ", ".join(self.api_key_params),
                "current": ", ".join(self.api_key_params),
                "description": "Comma-separated list of API key parameter names"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "api_key_params":
            self.api_key_params = [p.strip() for p in value.split(",")]
            return True
        return False