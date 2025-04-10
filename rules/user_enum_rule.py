# Rule class is injected by the RuleLoader
import logging
import time
from collections import defaultdict

class UserEnumerationDetectorRule(Rule):
    """Rule that identifies user enumeration opportunities in applications"""
    def __init__(self):
        super().__init__(
            name="User Enumeration Opportunity Detector",
            description="Identifies applications that leak valid usernames through error messages"
        )
        # Track detected opportunities
        self.detected_opportunities = set()
        
        # Track response patterns per host/URI
        self.response_patterns = defaultdict(lambda: defaultdict(int))
        
        # Track response sizes for potential user enumeration
        self.response_sizes = defaultdict(lambda: defaultdict(list))
        
        # Track authentication URIs
        self.auth_uris = set()
        
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
            # First, identify potential authentication endpoints
            db_cursor.execute("""
                SELECT r.connection_key, r.host, r.uri, r.method, c.dst_ip,
                       h.header_value AS auth_header
                FROM http_requests r
                JOIN connections c ON r.connection_key = c.connection_key
                LEFT JOIN http_headers h ON r.id = h.request_id AND h.header_name = 'Authorization'
                WHERE r.uri LIKE '%login%' OR r.uri LIKE '%auth%' OR r.uri LIKE '%sign%'
                   OR h.header_value IS NOT NULL
                   OR (r.method = 'POST' AND r.content_type LIKE '%form%')
                ORDER BY r.timestamp DESC
                LIMIT 1000
            """)
            
            for row in db_cursor.fetchall():
                connection_key, host, uri, method, dst_ip, auth_header = row
                
                # Skip if URI is None
                if not uri:
                    continue
                
                # Create a key for this auth endpoint
                endpoint_key = f"{host or dst_ip}:{uri}"
                
                # Add to auth URIs
                self.auth_uris.add(endpoint_key)
            
            # Look for responses that might indicate user enumeration
            db_cursor.execute("""
                SELECT r.connection_key, r.host, r.uri, r.method, c.dst_ip,
                       res.status_code, res.content_length
                FROM http_requests r
                JOIN connections c ON r.connection_key = c.connection_key
                JOIN http_responses res ON res.http_request_id = r.id
                WHERE res.status_code IS NOT NULL
                ORDER BY r.timestamp DESC
                LIMIT 2000
            """)
            
            for row in db_cursor.fetchall():
                connection_key, host, uri, method, dst_ip, status_code, content_length = row
                
                # Skip if URI is None
                if not uri:
                    continue
                
                # Create a key for this endpoint
                endpoint_key = f"{host or dst_ip}:{uri}"
                
                # Focus on authentication endpoints
                is_auth_endpoint = False
                for auth_uri in self.auth_uris:
                    if endpoint_key.startswith(auth_uri):
                        is_auth_endpoint = True
                        break
                
                # Also consider endpoints with certain keywords
                if not is_auth_endpoint:
                    auth_keywords = ['login', 'auth', 'signin', 'account', 'user', 'password', 'forgot']
                    for keyword in auth_keywords:
                        if keyword in uri.lower():
                            is_auth_endpoint = True
                            break
                
                if is_auth_endpoint:
                    # Track response status codes
                    self.response_patterns[endpoint_key][status_code] += 1
                    
                    # Track response sizes if content length is available
                    if content_length is not None:
                        self.response_sizes[endpoint_key][status_code].append(content_length)
                    
                    # Analyze if we have enough data (at least 3 responses)
                    if sum(self.response_patterns[endpoint_key].values()) >= 3:
                        # Create a unique key for this opportunity
                        opportunity_key = f"UserEnum:{endpoint_key}"
                        
                        # Skip if already detected
                        if opportunity_key in self.detected_opportunities:
                            continue
                            
                        # Check if we have different status codes
                        status_codes = list(self.response_patterns[endpoint_key].keys())
                        if len(status_codes) >= 2:
                            self.detected_opportunities.add(opportunity_key)
                            
                            # Get the counts
                            status_code_counts = ", ".join([f"{sc}: {count}" for sc, count in self.response_patterns[endpoint_key].items()])
                            
                            alert_msg = f"Potential user enumeration at {host or dst_ip}{uri} - Status codes: {status_code_counts}"
                            alerts.append(alert_msg)
                            
                            # Add detailed alert
                            detailed_msg = (f"User enumeration opportunity: {host or dst_ip}{uri} returns different "
                                           f"status codes - potential for user discovery")
                            self.add_alert(dst_ip, detailed_msg)
                            
                            # Store exploitation information
                            self._store_opportunity(dst_ip, uri, host, "status_code_variations", status_code_counts)
                            
                            # Add as red finding
                            self._add_enum_to_red_findings(
                                dst_ip, 
                                host, 
                                uri, 
                                "status_code_variations", 
                                f"Different status codes: {status_code_counts}",
                                connection_key
                            )
                        
                        # If we have consistent status codes but different response sizes
                        elif 200 in self.response_patterns[endpoint_key] and len(self.response_sizes[endpoint_key][200]) >= 3:
                            # Check if response sizes vary significantly
                            sizes = self.response_sizes[endpoint_key][200]
                            size_min, size_max = min(sizes), max(sizes)
                            
                            # If max size is at least 20% larger than min, it might indicate different responses
                            if size_max > size_min * 1.2:
                                self.detected_opportunities.add(opportunity_key)
                                
                                alert_msg = f"Potential user enumeration at {host or dst_ip}{uri} - Response size varies: {size_min} to {size_max} bytes"
                                alerts.append(alert_msg)
                                
                                # Add detailed alert
                                detailed_msg = (f"User enumeration opportunity: {host or dst_ip}{uri} returns different "
                                               f"response sizes - potential for user discovery")
                                self.add_alert(dst_ip, detailed_msg)
                                
                                # Store exploitation information
                                self._store_opportunity(dst_ip, uri, host, "response_size_variations", f"{size_min}-{size_max} bytes")
                                
                                # Add as red finding
                                self._add_enum_to_red_findings(
                                    dst_ip, 
                                    host, 
                                    uri, 
                                    "response_size_variations", 
                                    f"Response size varies: {size_min} to {size_max} bytes",
                                    connection_key
                                )
            
            # Look for error messages that might leak user information
            db_cursor.execute("""
                SELECT r.connection_key, r.host, r.uri, c.dst_ip,
                       res.status_code, fd.file_data
                FROM http_requests r
                JOIN connections c ON r.connection_key = c.connection_key
                JOIN http_responses res ON res.http_request_id = r.id
                LEFT JOIN http_file_data fd ON fd.connection_key = r.connection_key
                WHERE (res.status_code = 401 OR res.status_code = 403 OR res.status_code = 404) 
                   AND fd.file_data IS NOT NULL
                ORDER BY r.timestamp DESC
                LIMIT 500
            """)
            
            for row in db_cursor.fetchall():
                connection_key, host, uri, dst_ip, status_code, file_data = row
                
                # Skip if URI is None or file_data is None
                if not uri or not file_data:
                    continue
                
                # Create a key for this endpoint
                endpoint_key = f"{host or dst_ip}:{uri}"
                
                # Create a unique key for this opportunity
                opportunity_key = f"ErrorLeak:{endpoint_key}"
                
                # Skip if already detected
                if opportunity_key in self.detected_opportunities:
                    continue
                
                # Look for common error messages that might leak user info
                error_patterns = [
                    "user not found", "no such user", "invalid username", 
                    "unknown account", "user doesn't exist", "no account found",
                    "user unknown", "account not found", "invalid user"
                ]
                
                error_found = False
                matching_pattern = None
                
                for pattern in error_patterns:
                    if pattern.lower() in file_data.lower():
                        error_found = True
                        matching_pattern = pattern
                        break
                
                if error_found:
                    self.detected_opportunities.add(opportunity_key)
                    
                    alert_msg = f"User information leakage at {host or dst_ip}{uri} - Error message: '{matching_pattern}'"
                    alerts.append(alert_msg)
                    
                    # Add detailed alert
                    detailed_msg = f"User enumeration through error message: {host or dst_ip}{uri} reveals user existence"
                    self.add_alert(dst_ip, detailed_msg)
                    
                    # Store exploitation information
                    self._store_opportunity(dst_ip, uri, host, "error_message_leakage", matching_pattern)
                    
                    # Add as red finding
                    self._add_enum_to_red_findings(
                        dst_ip, 
                        host, 
                        uri, 
                        "error_message_leakage", 
                        f"Error message leaks user information: '{matching_pattern}'",
                        connection_key,
                        status_code=status_code
                    )
            
            # Prevent the sets from growing too large
            if len(self.detected_opportunities) > 500:
                self.detected_opportunities = set(list(self.detected_opportunities)[-250:])
            
            if len(self.auth_uris) > 200:
                self.auth_uris = set(list(self.auth_uris)[-100:])
            
            # Clean up response tracking dictionaries
            if len(self.response_patterns) > 100:
                # Keep only the most recent entries
                keys_to_keep = list(self.response_patterns.keys())[-50:]
                self.response_patterns = {k: self.response_patterns[k] for k in keys_to_keep}
                self.response_sizes = {k: self.response_sizes[k] for k in keys_to_keep if k in self.response_sizes}
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in User Enumeration Detector: {e}"
            logging.error(error_msg)
            return [error_msg]
    
    def _add_enum_to_red_findings(self, dst_ip, host, uri, enum_type, details_str, connection_key, status_code=None):
        """Add user enumeration opportunity to red team findings"""
        try:
            # Create a suitable description based on enumeration type
            if enum_type == "error_message_leakage":
                description = f"Username enumeration via error messages at {host or dst_ip}{uri}"
                severity = "medium"
            elif enum_type == "status_code_variations":
                description = f"Username enumeration via status codes at {host or dst_ip}{uri}"
                severity = "medium"
            elif enum_type == "response_size_variations":
                description = f"Username enumeration via response size at {host or dst_ip}{uri}"
                severity = "low"
            else:
                description = f"Username enumeration opportunity at {host or dst_ip}{uri}"
                severity = "low"
            
            # Create detailed information
            details = {
                "host": host or dst_ip,
                "uri": uri,
                "enumeration_type": enum_type,
                "enumeration_details": details_str,
                "auth_endpoint": True,
                "recommendation": "Test with valid and invalid usernames to confirm vulnerability"
            }
            
            # Add HTTP status code if available
            if status_code:
                details["status_code"] = status_code
            
            # Determine if this endpoint is more interesting (login, reset, etc.)
            high_value_endpoint = False
            high_value_keywords = ["login", "signin", "auth", "password/reset", "forgotpassword", "account/recovery"]
            for keyword in high_value_keywords:
                if keyword in uri.lower():
                    high_value_endpoint = True
                    details["high_value_endpoint"] = True
                    break
            
            # Increase severity for high-value endpoints
            if high_value_endpoint and severity == "low":
                severity = "medium"
            elif high_value_endpoint and severity == "medium":
                severity = "high"
            
            # Create remediation guidance
            remediation = (
                "Implement consistent error messages that don't reveal whether a username exists. "
                "Use the same response size, status code, and timing for both valid and invalid username attempts. "
                "Consider rate limiting and CAPTCHA for authentication attempts to prevent automated enumeration."
            )
            
            # Add to red findings
            self.add_red_finding(
                src_ip="N/A",  # No specific source IP for this type of finding
                dst_ip=dst_ip,
                description=description,
                severity=severity,
                details=details,
                connection_key=connection_key,
                remediation=remediation
            )
            
        except Exception as e:
            logging.error(f"Error adding enumeration to red findings: {e}")
    
    def _store_opportunity(self, ip, uri, host, opportunity_type, details):
        """Store user enumeration opportunity information in the database"""
        try:
            # If we have an analysis_manager, store data in x_ip_threat_intel
            if hasattr(self, 'analysis_manager') and self.analysis_manager:
                # Create threat intel entry for this opportunity
                threat_data = {
                    "score": 6.0,  # Medium-high score for user enumeration
                    "type": "user_enumeration",
                    "confidence": 0.7,
                    "source": self.name,
                    "details": {
                        "host": host or ip,
                        "uri": uri,
                        "opportunity_type": opportunity_type,
                        "details": details,
                        "discovery_time": time.time()
                    },
                    "protocol": "HTTP",
                    "detection_method": "response_analysis"
                }
                
                # Store in the threat_intel table
                self.analysis_manager.update_threat_intel(ip, threat_data)
        except Exception as e:
            logging.error(f"Error storing user enumeration information: {e}")
    
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