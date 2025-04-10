# Rule class is injected by the RuleLoader
import re
import logging
import json
import base64
import time

class CloudTokenExtractorRule(Rule):
    """Rule that identifies and extracts cloud service tokens from network traffic"""
    def __init__(self):
        super().__init__(
            name="Cloud Service Token Extractor",
            description="Identifies and extracts tokens for AWS, Azure, GCP and other cloud services"
        )
        # AWS specific patterns
        self.aws_patterns = {
            "access_key": r"AKIA[0-9A-Z]{16}",
            "secret_key": r"[0-9a-zA-Z/+]{40}",
            "session_token": r"FQoG[a-zA-Z0-9/+]{300,}",
            "arn": r"arn:aws:[a-z0-9-]+:[a-z0-9-]+:\d{12}:[a-zA-Z0-9-/]+",
            "cognito_identity": r"us-east-1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        }
        
        # Azure specific patterns
        self.azure_patterns = {
            "connection_string": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;EndpointSuffix=core\.windows\.net",
            "sas_token": r"sv=\d{4}-\d{2}-\d{2}&s[^&]*&[^&]*&[^&]*",
            "tenant_id": r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
            "jwt": r"eyJ0[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
        }
        
        # GCP specific patterns
        self.gcp_patterns = {
            "api_key": r"AIza[0-9A-Za-z-_]{35}",
            "project_id": r"[a-z][a-z0-9-]{4,28}[a-z0-9]",
            "service_account": r"[a-z][a-z0-9-]*@[a-z][a-z0-9-]*\.iam\.gserviceaccount\.com"
        }
        
        # Track already detected tokens
        self.detected_tokens = set()
        
        # Last analysis time
        self.last_analysis_time = 0
        # Analysis interval in seconds
        self.analysis_interval = 600  # 10 minutes
    
    def analyze(self, db_cursor):
        alerts = []
        
        current_time = time.time()
        if current_time - self.last_analysis_time < self.analysis_interval:
            return []
            
        self.last_analysis_time = current_time
        
        try:
            # Search for tokens in HTTP headers
            db_cursor.execute("""
                SELECT connection_key, header_name, header_value
                FROM http_headers
                WHERE header_value IS NOT NULL AND 
                     (header_name LIKE '%Authorization%' OR 
                      header_name LIKE '%Token%' OR 
                      header_name LIKE '%API%' OR
                      header_name LIKE '%Key%' OR
                      header_name LIKE '%Credential%')
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
                
                # Check for JWT tokens first
                if "eyJ" in header_value:
                    # Extract the JWT token
                    jwt_match = re.search(r"(eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)", header_value)
                    if jwt_match:
                        jwt_token = jwt_match.group(1)
                        
                        # Create a unique key
                        token_key = f"JWT:{connection_key}:{jwt_token[:20]}"
                        
                        # Skip if already detected
                        if token_key in self.detected_tokens:
                            continue
                        
                        self.detected_tokens.add(token_key)
                        
                        # Try to parse the JWT token for more info
                        token_info = self._parse_jwt(jwt_token)
                        token_type = token_info.get("token_type", "Unknown")
                        
                        alert_msg = f"Cloud {token_type} JWT token detected in {header_name} from {src_ip} to {dst_ip}"
                        alerts.append(alert_msg)
                        
                        # Add detailed alert
                        detailed_msg = f"JWT token details: {json.dumps(token_info)[:200]}..."
                        self.add_alert(dst_ip, detailed_msg)
                        
                        # Store token information
                        self._store_token_info(dst_ip, "JWT", token_type, token_info)
                
                # Check for AWS tokens
                for token_type, pattern in self.aws_patterns.items():
                    matches = re.findall(pattern, header_value)
                    for match in matches:
                        # Create a unique key
                        token_key = f"AWS:{token_type}:{match}"
                        
                        # Skip if already detected
                        if token_key in self.detected_tokens:
                            continue
                        
                        self.detected_tokens.add(token_key)
                        
                        # Mask the token value for display
                        masked_token = self._mask_token(match)
                        
                        alert_msg = f"AWS {token_type} detected in {header_name} header: {masked_token}"
                        alerts.append(alert_msg)
                        
                        # Add detailed alert
                        self.add_alert(dst_ip, f"AWS {token_type} discovered: {masked_token}")
                        
                        # Store token information
                        self._store_token_info(dst_ip, "AWS", token_type, {"token": match})
                
                # Check for Azure tokens
                for token_type, pattern in self.azure_patterns.items():
                    matches = re.findall(pattern, header_value)
                    for match in matches:
                        # Create a unique key
                        token_key = f"Azure:{token_type}:{match[:20]}"
                        
                        # Skip if already detected
                        if token_key in self.detected_tokens:
                            continue
                        
                        self.detected_tokens.add(token_key)
                        
                        # Mask the token value for display
                        masked_token = self._mask_token(match)
                        
                        alert_msg = f"Azure {token_type} detected in {header_name} header: {masked_token}"
                        alerts.append(alert_msg)
                        
                        # Add detailed alert
                        self.add_alert(dst_ip, f"Azure {token_type} discovered: {masked_token}")
                        
                        # Store token information
                        self._store_token_info(dst_ip, "Azure", token_type, {"token": match})
                
                # Check for GCP tokens
                for token_type, pattern in self.gcp_patterns.items():
                    matches = re.findall(pattern, header_value)
                    for match in matches:
                        # Create a unique key
                        token_key = f"GCP:{token_type}:{match}"
                        
                        # Skip if already detected
                        if token_key in self.detected_tokens:
                            continue
                        
                        self.detected_tokens.add(token_key)
                        
                        # Mask the token value for display
                        masked_token = self._mask_token(match)
                        
                        alert_msg = f"GCP {token_type} detected in {header_name} header: {masked_token}"
                        alerts.append(alert_msg)
                        
                        # Add detailed alert
                        self.add_alert(dst_ip, f"GCP {token_type} discovered: {masked_token}")
                        
                        # Store token information
                        self._store_token_info(dst_ip, "GCP", token_type, {"token": match})
            
            # Also check HTTP body content
            db_cursor.execute("""
                SELECT connection_key, file_data
                FROM http_file_data
                ORDER BY timestamp DESC
                LIMIT 500
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
                
                # Look for JSON data with tokens
                if file_data.startswith('{') and file_data.endswith('}'):
                    try:
                        json_data = json.loads(file_data)
                        self._scan_json_for_tokens(json_data, connection_key, src_ip, dst_ip, alerts)
                    except json.JSONDecodeError:
                        pass  # Not valid JSON
            
            # Prevent the detected tokens set from growing too large
            if len(self.detected_tokens) > 1000:
                self.detected_tokens = set(list(self.detected_tokens)[-500:])
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Cloud Token Extractor: {e}"
            logging.error(error_msg)
            return [error_msg]
    
    def _scan_json_for_tokens(self, json_data, connection_key, src_ip, dst_ip, alerts):
        """Recursively scan JSON data for tokens"""
        if isinstance(json_data, dict):
            for key, value in json_data.items():
                # Check if key suggests token
                token_key = key.lower()
                
                if isinstance(value, str):
                    # Check if key suggests a cloud token
                    is_token_key = any(k in token_key for k in [
                        'token', 'key', 'auth', 'cred', 'secret', 'password', 'session'
                    ])
                    
                    if is_token_key:
                        # Examine this value more carefully
                        self._check_token_string(value, token_key, connection_key, src_ip, dst_ip, alerts)
                    else:
                        # Still check for common token formats regardless of key name
                        # For example, check for JWTs
                        if value.startswith('eyJ') and '.' in value:
                            self._check_token_string(value, "jwt", connection_key, src_ip, dst_ip, alerts)
                        
                        # Check for AWS access key pattern
                        elif re.match(self.aws_patterns['access_key'], value):
                            self._check_token_string(value, "aws_access_key", connection_key, src_ip, dst_ip, alerts)
                
                # Recurse into nested structures
                elif isinstance(value, (dict, list)):
                    self._scan_json_for_tokens(value, connection_key, src_ip, dst_ip, alerts)
                    
        elif isinstance(json_data, list):
            for item in json_data:
                if isinstance(item, (dict, list)):
                    self._scan_json_for_tokens(item, connection_key, src_ip, dst_ip, alerts)
    
    def _check_token_string(self, value, key_name, connection_key, src_ip, dst_ip, alerts):
        """Check a string value for token patterns"""
        # Generate a unique token key
        token_key = f"JSON:{key_name}:{value[:20]}"
        
        # Skip if already detected
        if token_key in self.detected_tokens:
            return
        
        self.detected_tokens.add(token_key)
        
        # Determine token type based on key and value
        cloud_type = "Unknown"
        token_type = key_name
        
        # Try to detect cloud provider
        if key_name in ["aws_access_key", "aws_secret_key", "aws_session_token"]:
            cloud_type = "AWS"
        elif key_name in ["tenant_id", "sas_token", "azure_token"]:
            cloud_type = "Azure"
        elif key_name in ["gcp_key", "google_api"]:
            cloud_type = "GCP"
        else:
            # Try to infer from patterns
            if re.match(self.aws_patterns['access_key'], value):
                cloud_type = "AWS"
                token_type = "access_key"
            elif "AccountKey=" in value:
                cloud_type = "Azure"
                token_type = "connection_string"
            elif value.startswith("AIza"):
                cloud_type = "GCP"
                token_type = "api_key"
        
        # Handle JWT tokens specially
        if value.startswith('eyJ') and '.' in value:
            token_info = self._parse_jwt(value)
            if "iss" in token_info:
                # Check issuer to identify cloud provider
                issuer = token_info["iss"]
                if "amazon" in issuer.lower() or "aws" in issuer.lower():
                    cloud_type = "AWS"
                elif "azure" in issuer.lower() or "microsoft" in issuer.lower():
                    cloud_type = "Azure"
                elif "google" in issuer.lower() or "gcp" in issuer.lower():
                    cloud_type = "GCP"
            
            token_type = token_info.get("token_type", "JWT")
            
            # Store the JWT info
            self._store_token_info(dst_ip, cloud_type, token_type, token_info)
        else:
            # Store regular token info
            self._store_token_info(dst_ip, cloud_type, token_type, {"token": value})
        
        # Mask token for display
        masked_token = self._mask_token(value)
        
        # Create alert
        alert_msg = f"{cloud_type} {token_type} token found in JSON from {src_ip} to {dst_ip}: {masked_token}"
        alerts.append(alert_msg)
        
        # Add detailed alert
        self.add_alert(dst_ip, f"{cloud_type} {token_type} token discovered: {masked_token}")
    
    def _parse_jwt(self, jwt_token):
        """Parse a JWT token to extract useful information"""
        try:
            parts = jwt_token.split('.')
            if len(parts) != 3:
                return {"error": "Invalid JWT format"}
            
            # Decode header and payload
            def decode_part(part):
                # Fix padding for base64 decoding
                padding_needed = 4 - (len(part) % 4)
                if padding_needed < 4:
                    part += '=' * padding_needed
                
                # Handle URL-safe base64
                part = part.replace('-', '+').replace('_', '/')
                
                try:
                    decoded = base64.b64decode(part)
                    return json.loads(decoded)
                except:
                    return {}
            
            header = decode_part(parts[0])
            payload = decode_part(parts[1])
            
            # Combine into result
            result = {
                "token_type": header.get("typ", "JWT"),
                "algorithm": header.get("alg", "unknown")
            }
            
            # Add important payload fields
            for field in ["iss", "sub", "aud", "exp", "iat", "azp", "scope", "email"]:
                if field in payload:
                    result[field] = payload[field]
            
            # Add token info based on contents
            if "cognito:username" in payload:
                result["token_type"] = "AWS Cognito"
            elif "tid" in payload and "appid" in payload:
                result["token_type"] = "Azure AD"
            elif "gcloud" in str(payload):
                result["token_type"] = "GCP"
            
            return result
        except Exception as e:
            logging.error(f"Error parsing JWT: {e}")
            return {"error": str(e)}
    
    def _mask_token(self, token):
        """Mask a token for safe display in logs"""
        if not token:
            return "[empty]"
            
        if len(token) <= 8:
            return "****"
        
        return f"{token[:4]}...{token[-4:]}"
    
    def _store_token_info(self, ip, cloud_type, token_type, token_info):
        """Store token information in database"""
        try:
            # If we have an analysis_manager, store data in x_ip_threat_intel
            if hasattr(self, 'analysis_manager') and self.analysis_manager:
                # Create threat intel entry for the token
                threat_data = {
                    "score": 8.0,  # High score for cloud credentials
                    "type": "cloud_credential",
                    "confidence": 0.9,
                    "source": self.name,
                    "details": {
                        "cloud_provider": cloud_type,
                        "token_type": token_type,
                        "token_info": token_info,
                        "discovery_time": time.time()
                    },
                    "detection_method": "content_analysis"
                }
                
                # Store in the threat_intel table
                self.analysis_manager.update_threat_intel(ip, threat_data)
        except Exception as e:
            logging.error(f"Error storing token information: {e}")
    
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