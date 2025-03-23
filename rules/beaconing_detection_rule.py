# Rule class is injected by the RuleLoader
import time
import statistics
from collections import defaultdict

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
    
    def analyze(self, db_cursor):
        alerts = []
        current_time = time.time()
        
        # Only run this rule periodically to avoid constant database load
        if current_time - self.last_check_time < self.check_interval:
            return []
        
        self.last_check_time = current_time
        
        try:
            # Create a table to track connection timestamps if it doesn't exist
            db_cursor.execute("""
                CREATE TABLE IF NOT EXISTS connection_timestamps (
                    src_ip TEXT,
                    dst_ip TEXT,
                    connection_time REAL,
                    PRIMARY KEY (src_ip, dst_ip, connection_time)
                )
            """)
            
            # Get source/destination pairs that have multiple connections
            db_cursor.execute("""
                SELECT src_ip, dst_ip, COUNT(*) as conn_count
                FROM connection_timestamps
                WHERE connection_time > ?
                GROUP BY src_ip, dst_ip
                HAVING conn_count >= ?
            """, (current_time - self.time_window, self.min_connections))
            
            connection_pairs = db_cursor.fetchall()
            
            for src_ip, dst_ip, count in connection_pairs:
                # Skip if we've already detected this beacon
                beacon_key = f"{src_ip}->{dst_ip}"
                if beacon_key in self.detected_beacons:
                    continue
                
                # Get all connection times for this pair
                db_cursor.execute("""
                    SELECT connection_time
                    FROM connection_timestamps
                    WHERE src_ip = ? AND dst_ip = ? AND connection_time > ?
                    ORDER BY connection_time
                """, (src_ip, dst_ip, current_time - self.time_window))
                
                timestamps = [row[0] for row in db_cursor.fetchall()]
                
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
                try:
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
                        alerts.append(alert_msg)
                        
                        # Prevent the detected set from growing too large
                        if len(self.detected_beacons) > 1000:
                            # Clear out half the old entries when we hit the limit
                            self.detected_beacons = set(list(self.detected_beacons)[-500:])
                
                except Exception as e:
                    # Skip statistics errors
                    continue
            
            return alerts
            
        except Exception as e:
            return [f"Error in Beaconing Detection rule: {str(e)}"]
            
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