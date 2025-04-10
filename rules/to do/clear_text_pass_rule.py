# Rule class is injected by the RuleLoader
import re
import json
import logging

class ClearTextPasswordRule(Rule):
    """Rule to detect clear-text passwords in HTTP traffic"""
    def __init__(self):
        super().__init__(
            name="Clear-text Password Detector",
            description="Detects passwords and credentials in HTTP traffic"
        )
        # Common parameter names for credentials
        self.password_params = [
            'password', 'pass', 'pwd', 'passwd', 'secret',
            'creds', 'credential', 'auth', 'token', 'key',
            'api_key', 'apikey', 'api-key', 'access_token', 'accesstoken',
            'passcode', 'pin'
        ]
        
        self.username_params = [
            'username', 'user', 'uname', 'login', 'email',
            'userid', 'user_id', 'account', 'name', 'id'
        ]
        
        self.detected_credentials = set()  # Track already detected credentials
            
    def analyze(self, db_cursor):
        alerts = []
        try:
            # Query for HTTP POST requests with content
            db_cursor.execute("""
                SELECT r.connection_key, r.method, r.host, r.uri, r.request_headers, r.content_type, res.response_headers
                FROM http_requests r
                LEFT JOIN http_responses res ON r.id = res.http_request_id
                WHERE r.method = 'POST'
            """)
            
            for row in db_cursor.fetchall():
                connection_key, method, host, uri, req_headers, content_type, resp_headers = row
                
                # Skip if not POST or no content type
                if method != 'POST' or not content_type:
                    continue

                # Check if we have headers that might contain credentials
                content_check = [req_headers, resp_headers]
                
                for header_data in content_check:
                    if not header_data:
                        continue
                        
                    # Only proceed if the header data looks like JSON
                    if not (header_data.startswith('{') and header_data.endswith('}')):
                        continue
                        
                    try:
                        headers = json.loads(header_data)
                        
                        # Look for authentication-related headers with potential credentials
                        for key, value in headers.items():
                            key_lower = key.lower()
                            
                            # Skip checking empty values
                            if not value or value == "null" or value == "undefined":
                                continue
                                
                            # Check if this key looks like a credential field
                            for param in self.password_params:
                                if param in key_lower:
                                    # Found a potential password value
                                    src_ip = connection_key.split('->')[0].split(':')[0]
                                    dst_ip = connection_key.split('->')[1].split(':')[0]
                                    
                                    # Create a unique signature for this credential
                                    cred_sig = f"{key_lower}:{value}:{uri}"
                                    if cred_sig in self.detected_credentials:
                                        continue
                                        
                                    self.detected_credentials.add(cred_sig)
                                    
                                    alert_msg = f"Possible credential detected from {src_ip} to {dst_ip} ({host}{uri}): {key}={value}"
                                    alerts.append(alert_msg)
                                    
                                    # Also add to the alerts database
                                    self.add_alert(dst_ip, alert_msg)
                                    break
                    except json.JSONDecodeError:
                        # Not valid JSON, continue to next check
                        pass
                        
                # Also look for URL-encoded form data with credentials
                if content_type and "application/x-www-form-urlencoded" in content_type:
                    # We'll need to get the content from http_file_data or similar table
                    # This requires adding the http.file_data field to capture
                    db_cursor.execute("""
                        SELECT file_data FROM http_file_data WHERE connection_key = ? ORDER BY id DESC LIMIT 1
                    """, (connection_key,))
                    
                    result = db_cursor.fetchone()
                    if result and result[0]:
                        form_data = result[0]
                        
                        # Parse form data
                        try:
                            # Look for username/password pairs in URL encoded form data
                            params = form_data.split('&')
                            form_values = {}
                            
                            for param in params:
                                if '=' in param:
                                    key, value = param.split('=', 1)
                                    form_values[key.lower()] = value
                            
                            # Check for password parameters
                            for password_param in self.password_params:
                                if password_param in form_values:
                                    # Found password parameter
                                    password_value = form_values[password_param]
                                    
                                    # Try to find associated username
                                    username_value = "unknown"
                                    for username_param in self.username_params:
                                        if username_param in form_values:
                                            username_value = form_values[username_param]
                                            break
                                    
                                    # Extract source and destination IPs from connection key
                                    src_ip = connection_key.split('->')[0].split(':')[0]
                                    dst_ip = connection_key.split('->')[1].split(':')[0]
                                    
                                    # Create a unique signature for this credential
                                    cred_sig = f"{username_value}:{password_value}:{host}"
                                    if cred_sig in self.detected_credentials:
                                        continue
                                        
                                    self.detected_credentials.add(cred_sig)
                                    
                                    alert_msg = f"Form credentials detected from {src_ip} to {dst_ip} ({host}{uri}): {username_value}:{password_value}"
                                    alerts.append(alert_msg)
                                    
                                    # Also add to the alerts database
                                    self.add_alert(dst_ip, alert_msg)
                                    break
                        except Exception as e:
                            logging.error(f"Error parsing form data: {e}")
                            
            # Prevent the detected set from growing too large
            if len(self.detected_credentials) > 1000:
                # Clear out half the old entries
                self.detected_credentials = set(list(self.detected_credentials)[-500:])
                            
            return alerts
            
        except Exception as e:
            alerts.append(f"Error in Clear-text Password Detector: {e}")
            return alerts
            
    def get_params(self):
        return {
            "password_params": {
                "type": "str",
                "default": ",".join(self.password_params),
                "current": ",".join(self.password_params),
                "description": "Comma-separated list of password parameter names"
            },
            "username_params": {
                "type": "str",
                "default": ",".join(self.username_params),
                "current": ",".join(self.username_params),
                "description": "Comma-separated list of username parameter names"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "password_params":
            self.password_params = [p.strip() for p in value.split(",")]
            return True
        elif param_name == "username_params":
            self.username_params = [p.strip() for p in value.split(",")]
            return True
        return False