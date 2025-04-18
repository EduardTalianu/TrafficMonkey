# Rule class is injected by the RuleLoader
import re
import logging
import json
import time

class SuspiciousHTTPRule(Rule):
    """Rule that detects suspicious HTTP traffic patterns"""
    def __init__(self):
        super().__init__("Suspicious HTTP Traffic", "Detects unusual HTTP traffic patterns and suspicious User-Agent strings")
        self.min_bytes = 1000  # Minimum bytes to consider a significant connection
        self.suspicious_user_agents = [
            "zgrab", "curl", "python", "go-http", "scanner", "nikto", "nmap", "masscan",
            "wget", "burp", "nessus", "sqlmap", "vulnerability", "dirbuster", "gobuster",
            "zap"
        ]
        self.suspicious_paths = [
            "/admin", "/wp-admin", "/phpmyadmin", "/manager", "/administrator", 
            "/.env", "/.git", "/config", "/backup", "/shell", "/cmd", "/passwd",
            "/wp-login", "/login", "/jenkins", "/solr", "/jmx-console", "/server-status",
            "/.svn", "/actuator", "/api/v1/pods", "/console"
        ]
        self.analysis_manager = None  # Will be set by access to db_manager.analysis_manager
    
    def analyze(self, db_cursor):
        # Ensure analysis_manager is linked
        if not self.analysis_manager and hasattr(self.db_manager, 'analysis_manager'):
            self.analysis_manager = self.db_manager.analysis_manager
        
        # Return early if analysis_manager is not available
        if not self.analysis_manager:
            logging.error(f"Cannot run {self.name} rule: analysis_manager not available")
            return [f"ERROR: {self.name} rule requires analysis_manager"]
        
        # Local list for returning alerts to UI immediately
        alerts = []
        
        try:
            # Query for HTTP traffic on non-standard ports by joining http_requests with connections
            db_cursor.execute("""
                SELECT c.src_ip, c.dst_ip, c.src_port, c.dst_port, c.total_bytes,
                       r.method, r.host, r.uri, r.user_agent, r.request_headers
                FROM connections c
                JOIN http_requests r ON c.connection_key = r.connection_key
                WHERE (c.dst_port != 80 AND c.dst_port != 443 AND c.dst_port != 8080 AND c.dst_port != 8443)
                AND c.total_bytes > ?
            """, (self.min_bytes,))
            
            unusual_port_http = db_cursor.fetchall()
            
            for row in unusual_port_http:
                src_ip, dst_ip, src_port, dst_port, total_bytes, method, host, path, user_agent, headers_json = row
                
                # Look for suspicious HTTP traffic on non-standard ports
                alert_msg = f"HTTP traffic on non-standard port: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({method} {host}{path})"
                alerts.append(alert_msg)
                self.add_alert(dst_ip, alert_msg)
                
                # Add threat intelligence
                self._add_threat_intel(src_ip, {
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "bytes": total_bytes,
                    "method": method,
                    "host": host,
                    "path": path,
                    "detection_type": "unusual_port"
                })
                
                # Parse headers if available
                headers = {}
                if headers_json:
                    try:
                        headers = json.loads(headers_json)
                    except json.JSONDecodeError:
                        pass
                        
                # Check for suspicious user agent
                if user_agent:
                    lower_ua = user_agent.lower()
                    for suspicious_ua in self.suspicious_user_agents:
                        if suspicious_ua.lower() in lower_ua:
                            alert_msg = f"Suspicious User-Agent detected: {src_ip} -> {dst_ip} (UA: {user_agent})"
                            alerts.append(alert_msg)
                            self.add_alert(dst_ip, alert_msg)
                            
                            # Add specific threat intelligence
                            self._add_threat_intel(src_ip, {
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "bytes": total_bytes,
                                "user_agent": user_agent,
                                "detection_type": "suspicious_user_agent"
                            })
                            break
                            
                # Check for suspicious paths
                if path:
                    lower_path = path.lower()
                    for suspicious_path in self.suspicious_paths:
                        if suspicious_path.lower() in lower_path:
                            alert_msg = f"Suspicious HTTP request path: {src_ip} -> {dst_ip} ({method} {host}{path})"
                            alerts.append(alert_msg)
                            self.add_alert(dst_ip, alert_msg)
                            
                            # Add specific threat intelligence
                            self._add_threat_intel(src_ip, {
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "bytes": total_bytes,
                                "path": path,
                                "detection_type": "suspicious_path"
                            })
                            break
            
            # Query all HTTP requests for check of suspicious content (not just non-standard ports)
            db_cursor.execute("""
                SELECT c.src_ip, c.dst_ip, c.src_port, c.dst_port, c.total_bytes,
                       r.method, r.host, r.uri, r.user_agent
                FROM connections c
                JOIN http_requests r ON c.connection_key = r.connection_key
                WHERE c.total_bytes > ?
            """, (self.min_bytes,))
            
            http_connections = db_cursor.fetchall()
            
            # Check for SQL injection attempts in all HTTP traffic
            sql_patterns = [
                r"'(\s|%20)*or(\s|%20)*'", r"(\s|%20)+and(\s|%20)+", r"--(\s|%20)",
                r"union(\s|%20)+select", r"exec(\s|%20)+", r"'(\s|%20)*;", r"drop(\s|%20)+table"
            ]
            
            for row in http_connections:
                src_ip, dst_ip, src_port, dst_port, total_bytes, method, host, path, user_agent = row
                
                if path:
                    # Check path for SQL injection patterns
                    for pattern in sql_patterns:
                        if re.search(pattern, path, re.IGNORECASE):
                            alert_msg = f"Possible SQL injection attempt: {src_ip} -> {dst_ip} ({method} {host}{path})"
                            alerts.append(alert_msg)
                            self.add_alert(dst_ip, alert_msg)
                            
                            # Add high-severity threat intelligence
                            self._add_threat_intel(src_ip, {
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "bytes": total_bytes,
                                "path": path,
                                "method": method,
                                "detection_type": "sql_injection_attempt",
                                "severity": "high"
                            }, score=8.5)
                            break
                
                # If user_agent not checked in the first query (for non-standard ports),
                # check it here for all HTTP connections
                if user_agent and src_ip not in [a[0] for a in unusual_port_http]:
                    lower_ua = user_agent.lower()
                    for suspicious_ua in self.suspicious_user_agents:
                        if suspicious_ua.lower() in lower_ua:
                            alert_msg = f"Suspicious User-Agent detected: {src_ip} -> {dst_ip} (UA: {user_agent})"
                            alerts.append(alert_msg)
                            self.add_alert(dst_ip, alert_msg)
                            
                            # Add specific threat intelligence
                            self._add_threat_intel(src_ip, {
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "bytes": total_bytes,
                                "user_agent": user_agent,
                                "detection_type": "suspicious_user_agent"
                            })
                            break
            
            return alerts
        except Exception as e:
            error_msg = f"Error in Suspicious HTTP rule: {str(e)}"
            logging.error(error_msg)
            self.add_alert("127.0.0.1", error_msg)
            return [error_msg]
    
    def add_alert(self, ip_address, alert_message):
        """Add an alert to the x_alerts table"""
        if self.analysis_manager:
            return self.analysis_manager.add_alert(ip_address, alert_message, self.name)
        return False
    
    def _add_threat_intel(self, ip_address, details_dict, score=6.5):
        """Store threat intelligence data in x_ip_threat_intel"""
        try:
            # Create threat intelligence data
            threat_data = {
                "score": score,  # Severity score (0-10)
                "type": "suspicious_http", 
                "confidence": 0.8,  # Confidence level (0-1)
                "source": self.name,  # Rule name as source
                "first_seen": time.time(),
                "details": {
                    # Detailed JSON information 
                    "detection_details": details_dict
                },
                # Extended columns for easy querying
                "protocol": "HTTP",
                "destination_ip": details_dict.get("dst_ip"),
                "destination_port": details_dict.get("dst_port"),
                "bytes_transferred": details_dict.get("bytes"),
                "detection_method": "http_analysis",
                "packet_count": details_dict.get("packet_count")
            }
            
            # Update threat intelligence in x_ip_threat_intel
            return self.analysis_manager.update_threat_intel(ip_address, threat_data)
        except Exception as e:
            logging.error(f"Error adding threat intelligence data: {e}")
            return False
    
    def get_params(self):
        return {
            "min_bytes": {
                "type": "int",
                "default": 1000,
                "current": self.min_bytes,
                "description": "Minimum bytes for a significant HTTP connection"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "min_bytes":
            self.min_bytes = int(value)
            return True
        return False