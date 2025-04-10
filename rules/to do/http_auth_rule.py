# Rule class is injected by the RuleLoader
import base64
import re

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
                SELECT connection_key, header_value, header_name
                FROM http_headers 
                WHERE header_name = 'Authorization' AND header_value LIKE 'Basic %'
            """)
            
            for row in db_cursor.fetchall():
                connection_key, auth_header, _ = row
                
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
                        
                        # Extract source and destination IPs from connection key
                        src_ip = connection_key.split('->')[0].split(':')[0]
                        dst_ip = connection_key.split('->')[1].split(':')[0]
                        
                        alert_msg = f"HTTP Basic Auth detected from {src_ip} to {dst_ip}: {username}:{password}"
                        alerts.append(alert_msg)
                        
                        # Also add to the alerts database
                        self.add_alert(dst_ip, alert_msg)
                        
                        # Prevent the detected set from growing too large
                        if len(self.detected_auths) > 1000:
                            # Clear out half the old entries
                            self.detected_auths = set(list(self.detected_auths)[-500:])
                except Exception as e:
                    alerts.append(f"Error decoding Basic auth: {e}")
                    
            # Try an alternate approach - direct query for Authorization header in request_headers
            db_cursor.execute("""
                SELECT connection_key, request_headers, host, uri 
                FROM http_requests 
                WHERE request_headers LIKE '%Authorization": "Basic %'
            """)
            
            for row in db_cursor.fetchall():
                connection_key, headers_json, host, uri = row
                
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
                            
                            # Extract source and destination IPs from connection key
                            src_ip = connection_key.split('->')[0].split(':')[0]
                            dst_ip = connection_key.split('->')[1].split(':')[0]
                            
                            alert_msg = f"HTTP Basic Auth detected from {src_ip} to {dst_ip} ({host}{uri}): {username}:{password}"
                            alerts.append(alert_msg)
                            
                            # Also add to the alerts database
                            self.add_alert(dst_ip, alert_msg)
                    except Exception as e:
                        alerts.append(f"Error decoding Basic auth: {e}")
            
            return alerts
            
        except Exception as e:
            alerts.append(f"Error in HTTP Basic Auth Detector: {e}")
            return alerts
            
    def get_params(self):
        # No configurable parameters for this rule
        return {}