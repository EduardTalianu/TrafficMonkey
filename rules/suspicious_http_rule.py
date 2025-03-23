# Rule class is injected by the RuleLoader
import re

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
        alerts = []
        
        try:
            # Create a table to store extracted HTTP headers if it doesn't exist
            db_cursor.execute("""
                CREATE TABLE IF NOT EXISTS http_headers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_key TEXT,
                    user_agent TEXT,
                    host TEXT,
                    path TEXT,
                    method TEXT,
                    timestamp REAL
                )
            """)
            
            # Query for HTTP traffic on non-standard ports
            db_cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port, total_bytes
                FROM connections
                WHERE (dst_port != 80 AND dst_port != 443 AND dst_port != 8080 AND dst_port != 8443)
                AND total_bytes > ?
            """, (self.min_bytes,))
            
            unusual_port_http = db_cursor.fetchall()
            
            for src_ip, dst_ip, src_port, dst_port, total_bytes in unusual_port_http:
                # Look for HTTP headers in the http_headers table
                db_cursor.execute("""
                    SELECT user_agent, host, path, method
                    FROM http_headers
                    WHERE connection_key = ?
                """, (f"{src_ip}:{src_port}->{dst_ip}:{dst_port}",))
                
                headers = db_cursor.fetchone()
                
                if headers:
                    user_agent, host, path, method = headers
                    
                    # Look for suspicious HTTP traffic on non-standard ports
                    if dst_port not in (80, 443, 8080, 8443):
                        alerts.append(f"HTTP traffic on non-standard port: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({method} {host}{path})")
                
            # Query for connections with suspicious user agents
            db_cursor.execute("""
                SELECT http_headers.connection_key, src_ip, dst_ip, user_agent, host, path, method
                FROM http_headers
                JOIN connections ON http_headers.connection_key = connections.connection_key
                WHERE total_bytes > ?
            """, (self.min_bytes,))
            
            http_connections = db_cursor.fetchall()
            
            for connection_key, src_ip, dst_ip, user_agent, host, path, method in http_connections:
                if user_agent:
                    # Check for suspicious user agents
                    lower_ua = user_agent.lower()
                    for suspicious_ua in self.suspicious_user_agents:
                        if suspicious_ua.lower() in lower_ua:
                            alerts.append(f"Suspicious User-Agent detected: {src_ip} -> {dst_ip} (UA: {user_agent})")
                            break
                
                if path:
                    # Check for suspicious paths
                    lower_path = path.lower()
                    for suspicious_path in self.suspicious_paths:
                        if suspicious_path.lower() in lower_path:
                            alerts.append(f"Suspicious HTTP request path: {src_ip} -> {dst_ip} ({method} {host}{path})")
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
                            alerts.append(f"Possible SQL injection attempt: {src_ip} -> {dst_ip} ({method} {host}{path})")
                            break
            
            return alerts
        except Exception as e:
            return [f"Error in Suspicious HTTP rule: {str(e)}"]
    
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