# Rule class is injected by the RuleLoader
import time

class ConnectionPatternRule(Rule):
    """Rule that detects specific patterns in connection establishment"""
    def __init__(self):
        super().__init__("Connection Pattern Detection", "Identifies specific patterns in connection establishment indicating potential attacks")
        self.scan_threshold = 5  # Number of consecutive ports to detect a port scan
        self.horizontal_scan_threshold = 5  # Number of similar ports across different hosts for horizontal scan
        self.time_window = 60  # Time window in seconds for pattern detection
        self.min_bytes = 50  # Minimum bytes for a significant connection
        self.check_interval = 600  # Seconds between rule checks (10 minutes)
        self.last_check_time = 0
    
    def analyze(self, db_cursor):
        alerts = []
        current_time = time.time()
        
        # Only run this rule periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Check if port_scan_timestamps table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='port_scan_timestamps'
            """)
            
            if not db_cursor.fetchone():
                return ["Connection Pattern rule requires port_scan_timestamps table"]
            
            # Look for vertical port scans (sequential ports on same host)
            db_cursor.execute("""
                SELECT src_ip, dst_ip, GROUP_CONCAT(dst_port) as ports
                FROM port_scan_timestamps
                WHERE timestamp > ?
                GROUP BY src_ip, dst_ip
            """, (current_time - self.time_window,))
            
            port_groups = db_cursor.fetchall()
            
            for src_ip, dst_ip, ports_str in port_groups:
                if not ports_str:
                    continue
                    
                # Convert ports to integers for analysis
                try:
                    ports = [int(p) for p in ports_str.split(',')]
                except (ValueError, AttributeError):
                    continue
                
                ports.sort()
                
                # Check for sequential ports (vertical scan)
                sequential_count = 1
                max_sequential = 1
                for i in range(1, len(ports)):
                    if ports[i] == ports[i-1] + 1:
                        sequential_count += 1
                        max_sequential = max(max_sequential, sequential_count)
                    else:
                        sequential_count = 1
                
                if max_sequential >= self.scan_threshold:
                    alerts.append(f"Vertical port scan detected: {src_ip} scanned {len(ports)} ports on {dst_ip} with {max_sequential} sequential ports")
            
            # Look for horizontal port scans (same port across multiple hosts)
            db_cursor.execute("""
                SELECT src_ip, dst_port, COUNT(DISTINCT dst_ip) as host_count
                FROM port_scan_timestamps
                WHERE timestamp > ?
                GROUP BY src_ip, dst_port
                HAVING host_count >= ?
            """, (current_time - self.time_window, self.horizontal_scan_threshold))
            
            horizontal_scans = db_cursor.fetchall()
            
            for src_ip, dst_port, host_count in horizontal_scans:
                # Get the list of scanned hosts
                db_cursor.execute("""
                    SELECT dst_ip
                    FROM port_scan_timestamps
                    WHERE src_ip = ? AND dst_port = ? AND timestamp > ?
                    GROUP BY dst_ip
                """, (src_ip, dst_port, current_time - self.time_window))
                
                hosts = [row[0] for row in db_cursor.fetchall()]
                
                alerts.append(f"Horizontal scan detected: {src_ip} scanned port {dst_port} on {host_count} hosts")
                
                # List sample hosts
                if len(hosts) <= 5:
                    alerts.append(f"  Hosts: {', '.join(hosts)}")
                else:
                    alerts.append(f"  Sample hosts: {', '.join(hosts[:5])}...")
            
            # Check for connection attempts followed by data transfer (potential exploit)
            db_cursor.execute("""
                SELECT c.src_ip, c.dst_ip, c.dst_port, c.total_bytes, c.packet_count
                FROM connections c
                JOIN port_scan_timestamps p ON c.src_ip = p.src_ip AND c.dst_ip = p.dst_ip
                WHERE c.timestamp > datetime('now', ? || ' seconds')
                AND p.timestamp > ?
                AND c.total_bytes > ?
                ORDER BY c.total_bytes DESC
            """, (f"-{self.time_window}", current_time - self.time_window, self.min_bytes * 10))
            
            potential_exploits = db_cursor.fetchall()
            
            for src_ip, dst_ip, dst_port, total_bytes, packet_count in potential_exploits:
                # This pattern suggests a potential successful exploit after scanning
                alerts.append(f"Potential exploit: {src_ip} transferred {total_bytes/1024:.1f} KB to {dst_ip}:{dst_port} after port scanning activity")
            
            return alerts
        except Exception as e:
            return [f"Error in Connection Pattern rule: {str(e)}"]
    
    def get_params(self):
        return {
            "scan_threshold": {
                "type": "int",
                "default": 5,
                "current": self.scan_threshold,
                "description": "Consecutive ports needed to identify a vertical scan"
            },
            "horizontal_scan_threshold": {
                "type": "int",
                "default": 5,
                "current": self.horizontal_scan_threshold,
                "description": "Hosts needed to identify a horizontal scan"
            },
            "time_window": {
                "type": "int",
                "default": 60,
                "current": self.time_window,
                "description": "Time window in seconds for pattern detection"
            },
            "min_bytes": {
                "type": "int",
                "default": 50,
                "current": self.min_bytes,
                "description": "Minimum bytes for a significant connection"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "scan_threshold":
            self.scan_threshold = int(value)
            return True
        elif param_name == "horizontal_scan_threshold":
            self.horizontal_scan_threshold = int(value)
            return True
        elif param_name == "time_window":
            self.time_window = int(value)
            return True
        elif param_name == "min_bytes":
            self.min_bytes = int(value)
            return True
        return False