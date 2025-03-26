# Rule class is injected by the RuleLoader
import re
import logging

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
    
    def analyze(self, db_cursor):
        # Local list for returning alerts to UI immediately
        alerts = []
        
        # List for storing alerts to be queued after analysis is complete
        pending_alerts = []
        
        try:
            # Check if http_headers table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='http_headers'
            """)
            
            if not db_cursor.fetchone():
                error_msg = "Suspicious HTTP rule requires http_headers table which doesn't exist"
                return [error_msg]
            
            # Query for HTTP traffic on non-standard ports
            db_cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port, total_bytes
                FROM connections
                WHERE (dst_port != 80 AND dst_port != 443 AND dst_port != 8080 AND dst_port != 8443)
                AND total_bytes > ?
            """, (self.min_bytes,))
            
            # Store results locally
            unusual_port_http = []
            for row in db_cursor.fetchall():
                unusual_port_http.append(row)
            
            for src_ip, dst_ip, src_port, dst_port, total_bytes in unusual_port_http:
                # Look for HTTP headers in the http_headers table
                conn_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                db_cursor.execute("""
                    SELECT user_agent, host, path, method
                    FROM http_headers
                    WHERE connection_key = ?
                """, (conn_key,))
                
                headers_result = db_cursor.fetchone()
                
                if headers_result:
                    user_agent, host, path, method = headers_result
                    
                    # Look for suspicious HTTP traffic on non-standard ports
                    if dst_port not in (80, 443, 8080, 8443):
                        alert_msg = f"HTTP traffic on non-standard port: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({method} {host}{path})"
                        alerts.append(alert_msg)
                        pending_alerts.append((dst_ip, alert_msg, self.name))
                
            # Query for connections with suspicious user agents
            db_cursor.execute("""
                SELECT http_headers.connection_key, src_ip, dst_ip, user_agent, host, path, method
                FROM http_headers
                JOIN connections ON http_headers.connection_key = connections.connection_key
                WHERE total_bytes > ?
            """, (self.min_bytes,))
            
            # Store results locally 
            http_connections = []
            for row in db_cursor.fetchall():
                http_connections.append(row)
            
            for connection_key, src_ip, dst_ip, user_agent, host, path, method in http_connections:
                if user_agent:
                    # Check for suspicious user agents
                    lower_ua = user_agent.lower()
                    for suspicious_ua in self.suspicious_user_agents:
                        if suspicious_ua.lower() in lower_ua:
                            alert_msg = f"Suspicious User-Agent detected: {src_ip} -> {dst_ip} (UA: {user_agent})"
                            alerts.append(alert_msg)
                            pending_alerts.append((dst_ip, alert_msg, self.name))
                            break
                
                if path:
                    # Check for suspicious paths
                    lower_path = path.lower()
                    for suspicious_path in self.suspicious_paths:
                        if suspicious_path.lower() in lower_path:
                            alert_msg = f"Suspicious HTTP request path: {src_ip} -> {dst_ip} ({method} {host}{path})"
                            alerts.append(alert_msg)
                            pending_alerts.append((dst_ip, alert_msg, self.name))
                            break
            
            # Check for SQL injection attempts
            sql_patterns = [
                r"'(\s|%20)*or(\s|%20)*'", r"(\s|%20)+and(\s|%20)+", r"--(\s|%20)",
                r"union(\s|%20)+select", r"exec(\s|%20)+", r"'(\s|%20)*;", r"drop(\s|%20)+table"
            ]
            
            for connection_key, src_ip, dst_ip, user_agent, host, path, method in http_connections:
                if path:
                    # Check path for SQL injection patterns
                    for pattern in sql_patterns:
                        if re.search(pattern, path, re.IGNORECASE):
                            alert_msg = f"Possible SQL injection attempt: {src_ip} -> {dst_ip} ({method} {host}{path})"
                            alerts.append(alert_msg)
                            pending_alerts.append((dst_ip, alert_msg, self.name))
                            break
            
            # Queue all pending alerts AFTER all database operations are complete
            for ip, msg, rule_name in pending_alerts:
                try:
                    self.db_manager.queue_alert(ip, msg, rule_name)
                except Exception as e:
                    logging.error(f"Error queueing alert: {e}")
            
            return alerts
        except Exception as e:
            error_msg = f"Error in Suspicious HTTP rule: {str(e)}"
            logging.error(error_msg)
            # Try to queue the error alert
            try:
                self.db_manager.queue_alert("127.0.0.1", error_msg, self.name)
            except:
                pass
            return [error_msg]
    
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