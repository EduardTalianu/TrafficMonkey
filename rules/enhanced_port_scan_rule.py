# Enhanced merged port scan rule
# Rule class is injected by the RuleLoader
import time
import logging

class EnhancedPortScanRule(Rule):
    """Rule that detects various port scanning patterns"""
    def __init__(self):
        super().__init__("Enhanced Port Scan Detection", "Detects vertical, horizontal, and rapid port scanning activity")
        # Vertical scan parameters
        self.vertical_scan_threshold = 5  # Number of sequential ports to detect
        # Horizontal scan parameters
        self.horizontal_scan_threshold = 5  # Number of hosts for horizontal scan
        # Rapid scan parameters
        self.time_window = 60  # Time window in seconds
        self.port_threshold = 10  # Number of different ports accessed
        self.interval_threshold = 5  # Time interval for rapid access
        # Common parameters
        self.check_interval = 600  # Seconds between rule checks
        self.last_check_time = 0
        self.last_alert_time = {}  # Track last alert time by IP pair
    
    def analyze(self, db_cursor):
        alerts = []
        # Add this list to store alerts that will be queued
        pending_alerts = []
        
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
                return ["Port Scan rule requires port_scan_timestamps table which doesn't exist"]
                
            # Detection 1: Vertical scan (sequential ports on same host)
            db_cursor.execute("""
                SELECT src_ip, dst_ip, GROUP_CONCAT(dst_port) as ports
                FROM port_scan_timestamps
                WHERE timestamp > ?
                GROUP BY src_ip, dst_ip
            """, (current_time - self.time_window,))
            
            port_groups = []
            for row in db_cursor.fetchall():
                port_groups.append(row)
            
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
                
                if max_sequential >= self.vertical_scan_threshold:
                    ip_pair = f"{src_ip}->{dst_ip}"
                    if ip_pair in self.last_alert_time and (current_time - self.last_alert_time[ip_pair]) < 300:
                        continue  # Skip if alerted recently
                        
                    self.last_alert_time[ip_pair] = current_time
                    alert_msg = f"Vertical port scan detected: {src_ip} scanned {len(ports)} ports on {dst_ip} with {max_sequential} sequential ports"
                    alerts.append(alert_msg)
                    # Add the alert to pending_alerts for queueing - use source IP
                    pending_alerts.append((src_ip, alert_msg, self.name))
            
            # Detection 2: Horizontal scan (same port across multiple hosts)
            db_cursor.execute("""
                SELECT src_ip, dst_port, COUNT(DISTINCT dst_ip) as host_count
                FROM port_scan_timestamps
                WHERE timestamp > ?
                GROUP BY src_ip, dst_port
                HAVING host_count >= ?
            """, (current_time - self.time_window, self.horizontal_scan_threshold))
            
            horizontal_scans = []
            for row in db_cursor.fetchall():
                horizontal_scans.append(row)
            
            for src_ip, dst_port, host_count in horizontal_scans:
                # Get the list of scanned hosts
                db_cursor.execute("""
                    SELECT dst_ip
                    FROM port_scan_timestamps
                    WHERE src_ip = ? AND dst_port = ? AND timestamp > ?
                    GROUP BY dst_ip
                """, (src_ip, dst_port, current_time - self.time_window))
                
                hosts = [row[0] for row in db_cursor.fetchall()]
                
                if src_ip in self.last_alert_time and (current_time - self.last_alert_time[src_ip]) < 300:
                    continue  # Skip if alerted recently
                    
                self.last_alert_time[src_ip] = current_time
                alert_msg = f"Horizontal scan detected: {src_ip} scanned port {dst_port} on {host_count} hosts"
                alerts.append(alert_msg)
                # Add the alert to pending_alerts for queueing - use source IP
                pending_alerts.append((src_ip, alert_msg, self.name))
                
                # List sample hosts
                if len(hosts) <= 5:
                    host_msg = f"  Hosts: {', '.join(hosts)}"
                    alerts.append(host_msg)
                    # Add as a supplementary alert for the same IP
                    pending_alerts.append((src_ip, host_msg, self.name))
                else:
                    host_msg = f"  Sample hosts: {', '.join(hosts[:5])}..."
                    alerts.append(host_msg)
                    # Add as a supplementary alert for the same IP
                    pending_alerts.append((src_ip, host_msg, self.name))
            
            # Detection 3: Rapid scanning (many ports in short time)
            db_cursor.execute("""
                SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) as port_count
                FROM port_scan_timestamps
                WHERE timestamp > ?
                GROUP BY src_ip, dst_ip
                HAVING port_count >= ?
            """, (current_time - self.time_window, self.port_threshold))
            
            rapid_scan_results = []
            for row in db_cursor.fetchall():
                rapid_scan_results.append(row)
            
            for src_ip, dst_ip, port_count in rapid_scan_results:
                # Get timestamps for rapid scanning detection
                db_cursor.execute("""
                    SELECT timestamp
                    FROM port_scan_timestamps
                    WHERE src_ip = ? AND dst_ip = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (src_ip, dst_ip, port_count))
                
                timestamps = [row[0] for row in db_cursor.fetchall()]
                
                if len(timestamps) >= 2:
                    time_span = max(timestamps) - min(timestamps)
                    
                    if time_span < self.interval_threshold:
                        ip_pair = f"{src_ip}->{dst_ip}"
                        if ip_pair in self.last_alert_time and (current_time - self.last_alert_time[ip_pair]) < 300:
                            continue  # Skip if alerted recently
                            
                        self.last_alert_time[ip_pair] = current_time
                        alert_msg = f"Rapid port scan: {src_ip} scanned {port_count} ports on {dst_ip} in {time_span:.2f} seconds"
                        alerts.append(alert_msg)
                        # Add the alert to pending_alerts for queueing - use source IP
                        pending_alerts.append((src_ip, alert_msg, self.name))
            
            # Queue all pending alerts
            for ip, msg, rule_name in pending_alerts:
                try:
                    self.db_manager.queue_alert(ip, msg, rule_name)
                except Exception as e:
                    logging.error(f"Error queueing alert: {e}")
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Enhanced Port Scan rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def get_params(self):
        return {
            "vertical_scan_threshold": {
                "type": "int",
                "default": 5,
                "current": self.vertical_scan_threshold,
                "description": "Sequential ports needed for vertical scan detection"
            },
            "horizontal_scan_threshold": {
                "type": "int",
                "default": 5,
                "current": self.horizontal_scan_threshold,
                "description": "Hosts needed for horizontal scan detection"
            },
            "port_threshold": {
                "type": "int",
                "default": 10,
                "current": self.port_threshold,
                "description": "Number of ports for rapid scan detection"
            },
            "interval_threshold": {
                "type": "int",
                "default": 5,
                "current": self.interval_threshold,
                "description": "Time window (seconds) for rapid scan detection"
            },
            "time_window": {
                "type": "int",
                "default": 60,
                "current": self.time_window,
                "description": "Overall time window for detection (seconds)"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "vertical_scan_threshold":
            self.vertical_scan_threshold = int(value)
            return True
        elif param_name == "horizontal_scan_threshold":
            self.horizontal_scan_threshold = int(value)
            return True
        elif param_name == "port_threshold":
            self.port_threshold = int(value)
            return True
        elif param_name == "interval_threshold":
            self.interval_threshold = int(value)
            return True
        elif param_name == "time_window":
            self.time_window = int(value)
            return True
        return False