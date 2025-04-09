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
        
        # Store reference to analysis_manager (will be set later when analysis_manager is available)
        self.analysis_manager = None
    
    def analyze(self, db_cursor):
        # Ensure analysis_manager is linked
        if not self.analysis_manager and hasattr(self.db_manager, 'analysis_manager'):
            self.analysis_manager = self.db_manager.analysis_manager
        
        # Return early if analysis_manager is not available
        if not self.analysis_manager:
            logging.error("Cannot run Enhanced Port Scan rule: analysis_manager not available")
            return ["ERROR: Enhanced Port Scan rule requires analysis_manager"]
        
        alerts = []
        # Add this list to store alerts that will be written to analysis_1.db
        pending_alerts = []
        
        current_time = time.time()
        
        # Only run this rule periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Check if x_port_scans table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='x_port_scans'
            """)
            
            if not db_cursor.fetchone():
                return ["Port Scan rule requires x_port_scans table which doesn't exist"]
                
            # Detection 1: Vertical scan (sequential ports on same host)
            db_cursor.execute("""
                SELECT src_ip, dst_ip, GROUP_CONCAT(dst_port) as ports
                FROM x_port_scans
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
                    
                    # Add threat intelligence to analysis_1.db
                    self._add_vertical_scan_data(src_ip, dst_ip, ports, max_sequential)
                    
                    # Add alert using the new method
                    self.add_alert(src_ip, alert_msg)
            
            # Detection 2: Horizontal scan (same port across multiple hosts)
            db_cursor.execute("""
                SELECT src_ip, dst_port, COUNT(DISTINCT dst_ip) as host_count
                FROM x_port_scans
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
                    FROM x_port_scans
                    WHERE src_ip = ? AND dst_port = ? AND timestamp > ?
                    GROUP BY dst_ip
                """, (src_ip, dst_port, current_time - self.time_window))
                
                hosts = [row[0] for row in db_cursor.fetchall()]
                
                if src_ip in self.last_alert_time and (current_time - self.last_alert_time[src_ip]) < 300:
                    continue  # Skip if alerted recently
                    
                self.last_alert_time[src_ip] = current_time
                alert_msg = f"Horizontal scan detected: {src_ip} scanned port {dst_port} on {host_count} hosts"
                alerts.append(alert_msg)
                
                # Add alert using the new method
                self.add_alert(src_ip, alert_msg)
                
                # Add threat intelligence to analysis_1.db
                self._add_horizontal_scan_data(src_ip, dst_port, hosts)
                
                # List sample hosts
                if len(hosts) <= 5:
                    host_msg = f"  Hosts: {', '.join(hosts)}"
                    alerts.append(host_msg)
                    # Add as a supplementary alert for the same IP
                    self.add_alert(src_ip, host_msg)
                else:
                    host_msg = f"  Sample hosts: {', '.join(hosts[:5])}..."
                    alerts.append(host_msg)
                    # Add as a supplementary alert for the same IP
                    self.add_alert(src_ip, host_msg)
            
            # Detection 3: Rapid scanning (many ports in short time)
            db_cursor.execute("""
                SELECT src_ip, dst_ip, COUNT(DISTINCT dst_port) as port_count
                FROM x_port_scans
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
                    FROM x_port_scans
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
                        
                        # Add alert using the new method
                        self.add_alert(src_ip, alert_msg)
                        
                        # Add threat intelligence to analysis_1.db
                        self._add_rapid_scan_data(src_ip, dst_ip, port_count, time_span)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Enhanced Port Scan rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def add_alert(self, ip_address, alert_message):
        """Add an alert to the x_alerts table"""
        if self.analysis_manager:
            return self.analysis_manager.add_alert(ip_address, alert_message, self.name)
        return False
    
    def _add_vertical_scan_data(self, src_ip, dst_ip, ports, max_sequential):
        """Add vertical port scan data to analysis_1.db"""
        try:
            # Build threat intelligence data
            threat_data = {
                "score": 6.0,  # Medium-high score for port scanning
                "type": "port_scanning",
                "confidence": 0.8,
                "source": "Port_Scan_Rule",
                "first_seen": time.time(),
                "details": {
                    "scan_type": "vertical",
                    "target": dst_ip,
                    "ports_scanned": len(ports),
                    "max_sequential_ports": max_sequential,
                    "detection_method": "sequential_port_analysis"
                },
                # Extended columns for easy querying
                "protocol": "TCP",
                "destination_ip": dst_ip,
                "detection_method": "sequential_port_analysis",
                "packet_count": len(ports)
            }
            
            # Update threat intelligence in analysis_1.db
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding vertical scan data: {e}")
            return False
    
    def _add_horizontal_scan_data(self, src_ip, dst_port, hosts):
        """Add horizontal port scan data to analysis_1.db"""
        try:
            # Build threat intelligence data
            threat_data = {
                "score": 7.0,  # High score for horizontal scanning (more suspicious)
                "type": "port_scanning",
                "confidence": 0.9,
                "source": "Port_Scan_Rule",
                "first_seen": time.time(),
                "details": {
                    "scan_type": "horizontal",
                    "port": dst_port,
                    "hosts_scanned": len(hosts),
                    "target_sample": hosts[:5] if len(hosts) > 5 else hosts,
                    "detection_method": "multiple_host_analysis"
                },
                # Extended columns for easy querying
                "protocol": "TCP",
                "destination_port": dst_port,
                "detection_method": "multiple_host_analysis",
                "packet_count": len(hosts)
            }
            
            # Update threat intelligence in analysis_1.db
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding horizontal scan data: {e}")
            return False
    
    def _add_rapid_scan_data(self, src_ip, dst_ip, port_count, time_span):
        """Add rapid port scan data to analysis_1.db"""
        try:
            # Build threat intelligence data
            threat_data = {
                "score": 8.0,  # High score for rapid scanning (very suspicious)
                "type": "port_scanning",
                "confidence": 0.9,
                "source": "Port_Scan_Rule",
                "first_seen": time.time(),
                "details": {
                    "scan_type": "rapid",
                    "target": dst_ip,
                    "ports_scanned": port_count,
                    "time_span_seconds": time_span,
                    "scan_rate": port_count / time_span if time_span > 0 else 0,
                    "detection_method": "timing_analysis"
                },
                # Extended columns for easy querying
                "protocol": "TCP",
                "destination_ip": dst_ip,
                "detection_method": "timing_analysis",
                "packet_count": port_count,
                "timing_variance": time_span
            }
            
            # Update threat intelligence in analysis_1.db
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding rapid scan data: {e}")
            return False
    
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