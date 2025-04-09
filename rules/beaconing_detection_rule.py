# Rule class is injected by the RuleLoader
import time
import statistics
from collections import defaultdict
import logging

class BeaconingDetectionRule(Rule):
    """Rule that detects periodic connection patterns typical of C2 beaconing"""
    def __init__(self):
        super().__init__("Beaconing Connection Detection", "Detects regular, periodic connection attempts that might indicate C2 traffic")
        self.min_connections = 5  # Minimum connections needed to establish a pattern
        self.max_variance = 20   # Maximum percentage of variance in timing allowed
        self.time_window = 7200  # Time window to look for patterns (2 hours)
        self.min_interval = 30   # Minimum seconds between connections to consider
        self.check_interval = 900  # Seconds between checks (15 minutes)
        self.last_check_time = 0
        self.detected_beacons = set()  # Track beacons we've already reported
        
        # Store reference to analysis_manager (will be set later when analysis_manager is available)
        self.analysis_manager = None
    
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
        
        current_time = time.time()
        
        # Only run this rule periodically to avoid constant database load
        if current_time - self.last_check_time < self.check_interval:
            return []
        
        self.last_check_time = current_time
        
        try:
            # First check if the connections table exists
            # We'll use the main connections table instead of trying to use connection_timestamps
            db_cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='connections'")
            if not db_cursor.fetchone():
                return ["Beaconing Detection rule skipped: connections table not found"]
            
            # Get source/destination pairs that have multiple connections within our time window
            # We'll use the connections table that we know exists instead of connection_timestamps
            window_start = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(current_time - self.time_window))
            
            db_cursor.execute("""
                SELECT src_ip, dst_ip, COUNT(*) as conn_count
                FROM connections
                WHERE timestamp > ?
                GROUP BY src_ip, dst_ip
                HAVING conn_count >= ?
            """, (window_start, self.min_connections))
            
            # Store results locally to avoid keeping the cursor active
            connection_pairs = []
            for row in db_cursor.fetchall():
                connection_pairs.append(row)
            
            # If no connection pairs found, return early
            if not connection_pairs:
                return []
            
            for src_ip, dst_ip, count in connection_pairs:
                # Skip if we've already detected this beacon
                beacon_key = f"{src_ip}->{dst_ip}"
                if beacon_key in self.detected_beacons:
                    continue
                
                # Get all connections for this pair to analyze timing patterns
                db_cursor.execute("""
                    SELECT timestamp
                    FROM connections
                    WHERE src_ip = ? AND dst_ip = ? AND timestamp > ?
                    ORDER BY timestamp
                """, (src_ip, dst_ip, window_start))
                
                # Convert timestamps to epoch times for easier math
                results = db_cursor.fetchall()
                if not results:
                    continue
                    
                # Convert all timestamps to floating-point epoch time
                try:
                    timestamps = []
                    for row in results:
                        # Handle potential timestamp format differences
                        ts = row[0]
                        if isinstance(ts, str):
                            # Convert string timestamp to epoch time
                            import datetime
                            dt = datetime.datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                            timestamps.append(dt.timestamp())
                        elif isinstance(ts, (int, float)):
                            # Already a numeric timestamp
                            timestamps.append(float(ts))
                    
                    # Need at least min_connections timestamps
                    if len(timestamps) < self.min_connections:
                        continue
                    
                    # Calculate intervals between connections
                    intervals = []
                    for i in range(1, len(timestamps)):
                        interval = timestamps[i] - timestamps[i-1]
                        if interval >= self.min_interval:
                            intervals.append(interval)
                    
                    # Need at least a few intervals to analyze
                    if len(intervals) < self.min_connections - 1:
                        continue
                    
                    # Calculate statistics
                    avg_interval = statistics.mean(intervals)
                    # Skip very long intervals
                    if avg_interval > 3600:  # Skip intervals longer than an hour
                        continue
                        
                    # Calculate coefficient of variation (standard deviation / mean)
                    # This gives us a normalized measure of variation
                    stdev = statistics.stdev(intervals) if len(intervals) > 1 else 0
                    cv = (stdev / avg_interval) * 100 if avg_interval > 0 else 100
                    
                    # Check if intervals are consistent (low variance)
                    if cv <= self.max_variance and len(intervals) >= 3:
                        # This looks like a beaconing pattern
                        self.detected_beacons.add(beacon_key)
                        
                        # Format interval for display
                        interval_str = f"{avg_interval:.1f} seconds"
                        if avg_interval > 60:
                            interval_str = f"{avg_interval/60:.1f} minutes"
                        
                        alert_msg = (f"Potential beaconing detected: {src_ip} connecting to {dst_ip} at regular "
                                    f"intervals of {interval_str} (variance: {cv:.1f}%, connections: {len(timestamps)})")
                        
                        # Add to immediate alerts list for UI
                        alerts.append(alert_msg)
                        
                        # Add alert to the x_alerts table
                        self.add_alert(dst_ip, alert_msg)
                        
                        # Add threat intelligence to analysis_1.db
                        self._add_beaconing_data(src_ip, dst_ip, avg_interval, cv, len(timestamps))
                        
                        # Prevent the detected set from growing too large
                        if len(self.detected_beacons) > 1000:
                            # Clear out half the old entries when we hit the limit
                            self.detected_beacons = set(list(self.detected_beacons)[-500:])
                
                except Exception as e:
                    # Log this specific error
                    logging.error(f"Error processing timestamp data: {e}")
                    continue
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Beaconing Detection rule: {str(e)}"
            logging.error(error_msg)
            # Try to add the error alert to analysis_1.db
            try:
                self.add_alert("127.0.0.1", error_msg)
            except:
                pass
            return [error_msg]
    
    def add_alert(self, ip_address, alert_message):
        """Add an alert to the x_alerts table"""
        if self.analysis_manager:
            return self.analysis_manager.add_alert(ip_address, alert_message, self.name)
        return False
    
    def _add_beaconing_data(self, src_ip, dst_ip, interval, variance, connection_count):
        """Add beaconing detection data to analysis_1.db"""
        try:
            # Build threat intelligence data
            threat_data = {
                "score": 7.0,  # High score for beaconing (strong C2 indicator)
                "type": "command_and_control",
                "confidence": 0.8,
                "source": self.name,
                "first_seen": time.time(),
                "details": {
                    "beacon_interval": interval,
                    "interval_variance": variance,
                    "destination": dst_ip,
                    "connection_count": connection_count,
                    "detection_method": "timing_analysis"
                },
                # Extended columns for better queryability
                "protocol": "TCP",
                "destination_ip": dst_ip,
                "bytes_transferred": 0,  # Not tracking bytes in this rule
                "detection_method": "timing_analysis",
                "timing_variance": variance
            }
            
            # Update threat intelligence in x_ip_threat_intel
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            
            # Also add info about the destination as a potential C2 server
            server_threat_data = {
                "score": 7.5,  # Slightly higher score for C2 server
                "type": "command_and_control_server",
                "confidence": 0.8,
                "source": self.name,
                "first_seen": time.time(),
                "details": {
                    "beacon_interval": interval,
                    "interval_variance": variance,
                    "client": src_ip,
                    "detection_method": "timing_analysis"
                },
                # Extended columns for better queryability
                "protocol": "TCP",
                "destination_ip": src_ip,  # The IP connecting to this server
                "detection_method": "timing_analysis",
                "timing_variance": variance
            }
            self.analysis_manager.update_threat_intel(dst_ip, server_threat_data)
            
            return True
        except Exception as e:
            logging.error(f"Error adding beaconing data: {e}")
            return False
            
    def get_params(self):
        return {
            "min_connections": {
                "type": "int",
                "default": 5,
                "current": self.min_connections,
                "description": "Minimum connections to establish a pattern"
            },
            "max_variance": {
                "type": "float",
                "default": 20,
                "current": self.max_variance,
                "description": "Maximum percentage variance in interval timing"
            },
            "time_window": {
                "type": "int",
                "default": 7200,
                "current": self.time_window,
                "description": "Time window to analyze (seconds)"
            },
            "min_interval": {
                "type": "int",
                "default": 30,
                "current": self.min_interval,
                "description": "Minimum interval between connections (seconds)"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "min_connections":
            self.min_connections = int(value)
            return True
        elif param_name == "max_variance":
            self.max_variance = float(value)
            return True
        elif param_name == "time_window":
            self.time_window = int(value)
            return True
        elif param_name == "min_interval":
            self.min_interval = int(value)
            return True
        return False