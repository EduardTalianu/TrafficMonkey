# Rule class is injected by the RuleLoader
import time
import logging

class PortScanRule(Rule):
    """Rule that detects potential port scanning activity"""
    def __init__(self):
        super().__init__("Port Scan Detection", "Detects potential port scanning activity")
        self.time_window = 60  # Time window in seconds
        self.port_threshold = 10  # Number of ports accessed to be considered a scan
        self.interval_threshold = 5  # Time interval (seconds) to check for rapid access
        self.configurable_params = {
            "time_window": {
                "description": "Time window to check for port scanning (seconds)",
                "type": "int",
                "default": 60,
                "current": self.time_window
            },
            "port_threshold": {
                "description": "Number of different ports accessed to be considered a scan",
                "type": "int",
                "default": 10,
                "current": self.port_threshold
            },
            "interval_threshold": {
                "description": "Time interval threshold for rapid port access (seconds)",
                "type": "int",
                "default": 5,
                "current": self.interval_threshold
            }
        }
        self.last_scan_time = {}  # Track last alert time by IP to prevent alert flooding
    
    def analyze(self, db_cursor):
        alerts = []
        current_time = time.time()
        
        try:
            # Check if port_scan_timestamps table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='port_scan_timestamps'
            """)
            
            if not db_cursor.fetchone():
                return ["Port Scan rule requires port_scan_timestamps table which doesn't exist"]
            
            # First, let's check for multiple destination ports from same source to same target
            db_cursor.execute("""
                SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) as port_count
                FROM port_scan_timestamps
                WHERE timestamp > ?
                GROUP BY src_ip, dst_ip
                HAVING port_count >= ?
            """, (current_time - self.time_window, self.port_threshold))
            
            # Store results locally
            port_scan_results = []
            for row in db_cursor.fetchall():
                port_scan_results.append(row)
            
            for src_ip, dst_ip, port_count in port_scan_results:
                # Check if we've already alerted on this IP pair recently
                ip_pair = f"{src_ip}->{dst_ip}"
                if ip_pair in self.last_scan_time and (current_time - self.last_scan_time[ip_pair]) < 300:  # 5 minutes
                    continue  # Skip this alert to prevent flooding
                    
                # Check for rapid scanning (many ports in short interval)
                db_cursor.execute("""
                    SELECT timestamp
                    FROM port_scan_timestamps
                    WHERE src_ip = ? AND dst_ip = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """, (src_ip, dst_ip, port_count))
                
                # Store results locally
                timestamps_result = db_cursor.fetchall()
                timestamps = [row[0] for row in timestamps_result]
                
                if len(timestamps) >= 2:
                    time_span = max(timestamps) - min(timestamps)
                    if time_span < self.interval_threshold and port_count >= self.port_threshold:
                        alert_msg = f"Potential Port Scan: {src_ip} scanned {port_count} ports on {dst_ip} in {time_span:.2f} seconds"
                        alerts.append(alert_msg)
                        self.last_scan_time[ip_pair] = current_time
            
            return alerts
        except Exception as e:
            error_msg = f"Error in Port Scan rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def update_param(self, param_name, value):
        """Update a configurable parameter"""
        if param_name in self.configurable_params:
            if param_name == "time_window":
                self.time_window = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
            elif param_name == "port_threshold":
                self.port_threshold = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
            elif param_name == "interval_threshold":
                self.interval_threshold = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
        return False
    
    def get_params(self):
        """Get configurable parameters"""
        return self.configurable_params