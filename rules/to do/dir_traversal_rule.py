# Rule class is injected by the RuleLoader
import logging
import re
import time

class DirectoryTraversalFinderRule(Rule):
    """Rule that identifies directory traversal opportunities in web requests"""
    def __init__(self):
        super().__init__(
            name="Directory Traversal Finder",
            description="Identifies potential directory traversal vulnerabilities in web applications"
        )
        # Common directory traversal patterns
        self.traversal_patterns = [
            r'\.\./', r'\.\.\\', r'\.\.%2f', r'\.\.%5c',
            r'%2e%2e%2f', r'%2e%2e/', r'..;/', r'%c0%ae%c0%ae%c0%af'
        ]
        
        # File extensions that might be interesting for traversal
        self.sensitive_files = [
            '.conf', '.config', '.ini', '.env', '.xml', '.json', '.yml', '.yaml',
            'passwd', 'shadow', '.db', '.sqlite', '.php', '.jsp', '.asp', '.aspx',
            '.log', '.bak', '.old', '.zip', '.tar', '.gz', '.sh', '.bat', '.ps1'
        ]
        
        # Track already detected opportunities
        self.detected_opportunities = set()
        
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
            # Look for HTTP URIs with directory traversal patterns
            traversal_pattern_regex = '|'.join(self.traversal_patterns)
            file_pattern_regex = '|'.join(self.sensitive_files)
            
            # First, find URIs that have directory traversal patterns
            db_cursor.execute("""
                SELECT r.connection_key, r.host, r.uri, c.src_ip, c.dst_ip, r.method
                FROM http_requests r
                JOIN connections c ON r.connection_key = c.connection_key
                WHERE r.uri IS NOT NULL
                ORDER BY r.timestamp DESC
                LIMIT 5000
            """)
            
            for row in db_cursor.fetchall():
                connection_key, host, uri, src_ip, dst_ip, method = row
                
                # Skip if URI is None
                if not uri:
                    continue
                
                # Check for directory traversal patterns
                has_traversal = False
                matching_pattern = None
                
                for pattern in self.traversal_patterns:
                    if re.search(pattern, uri):
                        has_traversal = True
                        matching_pattern = pattern
                        break
                
                if has_traversal:
                    # Create a unique key for this opportunity
                    opportunity_key = f"DirTraversal:{dst_ip}:{uri[:50]}"
                    
                    # Skip if already detected
                    if opportunity_key in self.detected_opportunities:
                        continue
                        
                    self.detected_opportunities.add(opportunity_key)
                    
                    alert_msg = f"Potential directory traversal opportunity in {host or dst_ip} - URI: {uri} (pattern: {matching_pattern})"
                    alerts.append(alert_msg)
                    
                    # Add detailed alert
                    detailed_msg = f"Directory traversal pattern detected in {method} request to {host or dst_ip}{uri}"
                    self.add_alert(dst_ip, detailed_msg)
                    
                    # Store exploitation information
                    self._store_opportunity(dst_ip, uri, host, "directory_traversal", matching_pattern)
            
            # Next, look for file access patterns that might indicate vulnerable applications
            db_cursor.execute("""
                SELECT r.connection_key, r.host, r.uri, c.src_ip, c.dst_ip, r.method, res.status_code
                FROM http_requests r
                JOIN connections c ON r.connection_key = c.connection_key
                LEFT JOIN http_responses res ON res.http_request_id = r.id
                WHERE r.uri LIKE '%.%' AND r.uri NOT LIKE '%.js' AND r.uri NOT LIKE '%.css' AND r.uri NOT LIKE '%.jpg' 
                    AND r.uri NOT LIKE '%.png' AND r.uri NOT LIKE '%.gif' AND r.uri NOT LIKE '%.ico'
                ORDER BY r.timestamp DESC
                LIMIT 2000
            """)
            
            for row in db_cursor.fetchall():
                connection_key, host, uri, src_ip, dst_ip, method, status_code = row
                
                # Skip if URI is None
                if not uri:
                    continue
                
                # Check if this URI has interesting file patterns
                has_sensitive_extension = False
                matching_extension = None
                
                for ext in self.sensitive_files:
                    if ext in uri.lower():
                        has_sensitive_extension = True
                        matching_extension = ext
                        break
                
                # Check if we have a status code that indicates successful access
                is_successful = status_code and (200 <= status_code < 300)
                
                if has_sensitive_extension and is_successful:
                    # Create a unique key for this opportunity
                    opportunity_key = f"SensitiveFile:{dst_ip}:{uri[:50]}"
                    
                    # Skip if already detected
                    if opportunity_key in self.detected_opportunities:
                        continue
                        
                    self.detected_opportunities.add(opportunity_key)
                    
                    alert_msg = f"Potential sensitive file access on {host or dst_ip} - URI: {uri} (extension: {matching_extension})"
                    alerts.append(alert_msg)
                    
                    # Add detailed alert
                    detailed_msg = f"Sensitive file access detected in {method} request to {host or dst_ip}{uri} - Status: {status_code}"
                    self.add_alert(dst_ip, detailed_msg)
                    
                    # Store exploitation information
                    self._store_opportunity(dst_ip, uri, host, "sensitive_file", matching_extension)
                    
                # Check if we have parameters that might be used for file inclusion
                file_param_pattern = r'[?&](file|path|include|require|doc|template|folder|dir|load|read)=([^&]+)'
                file_param_matches = re.findall(file_param_pattern, uri)
                
                if file_param_matches:
                    for param_name, param_value in file_param_matches:
                        # Create a unique key for this opportunity
                        opportunity_key = f"FileParam:{dst_ip}:{param_name}:{param_value[:20]}"
                        
                        # Skip if already detected
                        if opportunity_key in self.detected_opportunities:
                            continue
                            
                        self.detected_opportunities.add(opportunity_key)
                        
                        alert_msg = f"Potential file inclusion parameter on {host or dst_ip} - {param_name}={param_value}"
                        alerts.append(alert_msg)
                        
                        # Add detailed alert
                        detailed_msg = f"File inclusion parameter detected in request to {host or dst_ip}{uri}"
                        self.add_alert(dst_ip, detailed_msg)
                        
                        # Store exploitation information
                        self._store_opportunity(dst_ip, uri, host, "file_parameter", f"{param_name}={param_value}")
            
            # Prevent the detected set from growing too large
            if len(self.detected_opportunities) > 1000:
                self.detected_opportunities = set(list(self.detected_opportunities)[-500:])
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Directory Traversal Finder: {e}"
            logging.error(error_msg)
            return [error_msg]
    
    def _store_opportunity(self, ip, uri, host, opportunity_type, pattern):
        """Store directory traversal opportunity information in the database"""
        try:
            # If we have an analysis_manager, store data in x_ip_threat_intel
            if hasattr(self, 'analysis_manager') and self.analysis_manager:
                # Create threat intel entry for this vulnerability
                threat_data = {
                    "score": 7.5,  # High score for directory traversal
                    "type": "traversal_opportunity",
                    "confidence": 0.7,
                    "source": self.name,
                    "details": {
                        "host": host or ip,
                        "uri": uri,
                        "opportunity_type": opportunity_type,
                        "pattern": pattern,
                        "discovery_time": time.time()
                    },
                    "protocol": "HTTP",
                    "detection_method": "uri_analysis"
                }
                
                # Store in the threat_intel table
                self.analysis_manager.update_threat_intel(ip, threat_data)
        except Exception as e:
            logging.error(f"Error storing directory traversal information: {e}")
    
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