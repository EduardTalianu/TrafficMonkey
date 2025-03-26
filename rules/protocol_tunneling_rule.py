# Updated ProtocolTunnelingRule
# Rule class is injected by the RuleLoader
import time
import math
import logging

class ProtocolTunnelingRule(Rule):
    """Rule that detects protocol tunneling (one protocol encapsulated in another, excluding DNS)"""
    def __init__(self):
        super().__init__("Protocol Tunneling Detection", "Detects when one protocol is being tunneled inside another (focusing on HTTP, ICMP and SSH tunneling)")
        self.check_interval = 600  # Seconds between rule checks
        self.min_http_content_length = 5000  # Minimum HTTP content length to analyze
        self.http_timing_variance_threshold = 0.3  # Threshold for HTTP timing variance
        self.unusual_user_agent_patterns = ["tun", "vpn", "shell", "proxy", "tunnel"]
        self.last_check_time = 0
    
    def analyze_http_tunneling(self, db_cursor):
        """Analyze HTTP traffic for tunneling indicators"""
        alerts = []
        
        try:
            # Check if http_headers table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='http_headers'
            """)
            
            if not db_cursor.fetchone():
                return []  # HTTP headers table doesn't exist, skip this check
            
            # Look for suspicious HTTP traffic that might indicate tunneling
            db_cursor.execute("""
                SELECT h.connection_key, c.src_ip, c.dst_ip, c.dst_port, h.host, h.path, h.user_agent, c.total_bytes
                FROM http_headers h
                JOIN connections c ON h.connection_key = c.connection_key
                WHERE c.total_bytes > ?
                AND c.timestamp > datetime('now', '-1 hour')
            """, (self.min_http_content_length,))
            
            # Store results locally
            http_connections = []
            for row in db_cursor.fetchall():
                http_connections.append(row)
            
            for conn_key, src_ip, dst_ip, dst_port, host, path, user_agent, total_bytes in http_connections:
                suspicious = False
                reasons = []
                
                # Check 1: Suspicious user agent
                if user_agent:
                    for pattern in self.unusual_user_agent_patterns:
                        if pattern.lower() in user_agent.lower():
                            suspicious = True
                            reasons.append(f"suspicious user-agent containing '{pattern}'")
                            break
                
                # Check 2: Base64 encoded data in URLs
                if path and len(path) > 100:
                    # Simple check for Base64-like strings (long strings of alphanumeric + /+= characters)
                    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
                    path_chars = set(path)
                    
                    # If most characters are Base64 alphabet and path is long, it's suspicious
                    if len(path_chars.intersection(b64_chars)) / len(path_chars) > 0.9 and len(path) > 200:
                        suspicious = True
                        reasons.append("long Base64-like URL path")
                
                # Check 3: Non-standard port for HTTP
                if dst_port and dst_port not in (80, 443, 8080, 8443, 8000, 8008):
                    suspicious = True
                    reasons.append(f"unusual HTTP port ({dst_port})")
                
                # Alert if any checks triggered
                if suspicious:
                    alert_msg = f"Possible HTTP tunneling: {src_ip} to {dst_ip}:{dst_port} ({total_bytes/1024:.1f} KB) - {', '.join(reasons)}"
                    alerts.append(alert_msg)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in HTTP tunneling analysis: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def analyze_icmp_tunneling(self, db_cursor):
        """Analyze ICMP traffic for tunneling indicators"""
        alerts = []
        
        try:
            # Check if icmp_packets table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='icmp_packets'
            """)
            
            if not db_cursor.fetchone():
                return []  # ICMP table doesn't exist, skip this check
            
            # Look for unusual ICMP traffic
            db_cursor.execute("""
                SELECT src_ip, dst_ip, COUNT(*) as packet_count, AVG(timestamp) as avg_time
                FROM icmp_packets
                WHERE timestamp > ?
                GROUP BY src_ip, dst_ip
                HAVING packet_count > 20
            """, (time.time() - 3600,))  # Last hour
            
            # Store results locally
            icmp_connections = []
            for row in db_cursor.fetchall():
                icmp_connections.append(row)
            
            for src_ip, dst_ip, packet_count, avg_time in icmp_connections:
                # Check for regular timing patterns in ICMP
                db_cursor.execute("""
                    SELECT timestamp
                    FROM icmp_packets
                    WHERE src_ip = ? AND dst_ip = ? AND timestamp > ?
                    ORDER BY timestamp
                """, (src_ip, dst_ip, time.time() - 3600))
                
                timestamps = [row[0] for row in db_cursor.fetchall()]
                
                if len(timestamps) >= 10:
                    # Calculate intervals between packets
                    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                    
                    # Check for consistent intervals (indicating potential tunneling)
                    if len(intervals) >= 5:
                        avg_interval = sum(intervals) / len(intervals)
                        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
                        cv = (math.sqrt(variance) / avg_interval) if avg_interval > 0 else float('inf')
                        
                        # Low coefficient of variation indicates regular timing
                        if cv < 0.5 and avg_interval < 60:  # Less than 60 seconds between packets
                            alert_msg = f"Possible ICMP tunneling: {src_ip} sent {packet_count} ICMP packets to {dst_ip} with regular timing (variance: {cv:.2f})"
                            alerts.append(alert_msg)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in ICMP tunneling analysis: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def analyze_ssh_tunneling(self, db_cursor):
        """Analyze SSH traffic for tunneling indicators"""
        alerts = []
        
        try:
            # Look for SSH connections with unusual traffic patterns
            db_cursor.execute("""
                SELECT src_ip, dst_ip, total_bytes, packet_count
                FROM connections
                WHERE (dst_port = 22 OR src_port = 22)
                AND total_bytes > 100000  -- More than 100KB
                AND timestamp > datetime('now', '-1 hour')
            """)
            
            # Store results locally
            ssh_connections = []
            for row in db_cursor.fetchall():
                ssh_connections.append(row)
            
            for src_ip, dst_ip, total_bytes, packet_count in ssh_connections:
                # Calculate bytes per packet - high values can indicate bulk data transfer over SSH
                if packet_count > 10:
                    bytes_per_packet = total_bytes / packet_count
                    
                    # Very high bytes per packet can indicate tunneling (instead of interactive SSH)
                    if bytes_per_packet > 1000:  # More than 1KB per packet average
                        alert_msg = f"Possible SSH tunneling: {src_ip} to {dst_ip} with {total_bytes/1024:.1f} KB transferred ({bytes_per_packet:.1f} bytes/packet)"
                        alerts.append(alert_msg)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in SSH tunneling analysis: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def analyze(self, db_cursor):
        alerts = []
        current_time = time.time()
        
        # Only run this rule periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Run the different protocol tunneling detection methods (excluding DNS)
            http_alerts = self.analyze_http_tunneling(db_cursor)
            icmp_alerts = self.analyze_icmp_tunneling(db_cursor)
            ssh_alerts = self.analyze_ssh_tunneling(db_cursor)
            
            alerts.extend(http_alerts)
            alerts.extend(icmp_alerts)
            alerts.extend(ssh_alerts)
            
            return alerts
        except Exception as e:
            error_msg = f"Error in Protocol Tunneling rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def get_params(self):
        return {
            "check_interval": {
                "type": "int",
                "default": 600,
                "current": self.check_interval,
                "description": "Seconds between rule checks"
            },
            "min_http_content_length": {
                "type": "int",
                "default": 5000,
                "current": self.min_http_content_length,
                "description": "Minimum HTTP content length for analysis"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "check_interval":
            self.check_interval = int(value)
            return True
        elif param_name == "min_http_content_length":
            self.min_http_content_length = int(value)
            return True
        return False