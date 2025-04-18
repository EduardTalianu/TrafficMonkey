# Rule class is injected by the RuleLoader
import time
import logging
from datetime import datetime
from collections import defaultdict

class TimeBasedAccessRule(Rule):
    """Rule that detects connections occurring outside of normal operating hours"""
    def __init__(self):
        super().__init__("Time-Based Access Detection", "Detects connections occurring outside of expected operating hours")
        self.work_hours_start = 0   # 0:00 AM
        self.work_hours_end = 24    # 12:00 PM
        self.work_days = [0, 1, 2, 3, 4, 5, 6, 7]  # Monday through Friday (0=Monday, 6=Sunday)
        self.alert_threshold = 5    # Minimum number of out-of-hours connections to alert on
        self.check_interval = 900   # Run this rule every 15 minutes
        self.last_check_time = 0
        self.whitelist = []         # IPs allowed to connect any time
        self.min_bytes = 1000       # Minimum bytes to consider a significant connection
        self.analysis_manager = None  # Will be set when db_manager is set
    
    def is_work_hours(self, timestamp):
        """Check if a timestamp falls within defined work hours"""
        try:
            dt = datetime.fromtimestamp(timestamp)
            
            # Check if it's a workday (0=Monday in our system)
            weekday = dt.weekday()
            if weekday not in self.work_days:
                return False
                
            # Check if it's within work hours
            hour = dt.hour
            return self.work_hours_start <= hour < self.work_hours_end
            
        except Exception:
            # Default to assuming it's work hours on error
            return True
    
    def analyze(self, db_cursor):
        # Ensure analysis_manager is linked
        if not self.analysis_manager and hasattr(self.db_manager, 'analysis_manager'):
            self.analysis_manager = self.db_manager.analysis_manager
        
        # Local list for returning alerts to UI immediately
        alerts = []
        
        current_time = time.time()
        
        # Only run this rule periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Get IPs in whitelist
            whitelisted_ips = set(self.whitelist)
            
            # Check if timestamp is a proper datetime column
            timestamp_query = """
                SELECT typeof(timestamp) FROM connections LIMIT 1
            """
            
            db_cursor.execute(timestamp_query)
            result = db_cursor.fetchone()
            if result is None:
                # Handle the case where the query returned no results
                logging.warning("No connections found in database, using default timestamp type")
                timestamp_type = "text"  # Default to text as a safe option
            else:
                timestamp_type = result[0].lower()
            
            # Find recent connections outside of work hours
            # This is complex because SQLite doesn't have native time functions that match Python's
            # So we'll get the raw connections and filter in Python
            
            # Get all connections in the last 24 hours
            if 'text' in timestamp_type:
                # SQLite datetime string format
                recent_query = """
                    SELECT connection_key, src_ip, dst_ip, src_port, dst_port, total_bytes, 
                           strftime('%s', timestamp) as unix_time
                    FROM connections
                    WHERE julianday('now') - julianday(timestamp) < 1.0
                    AND total_bytes > ?
                """
            else:
                # Numeric timestamp
                recent_query = """
                    SELECT connection_key, src_ip, dst_ip, src_port, dst_port, total_bytes, 
                           timestamp as unix_time
                    FROM connections
                    WHERE timestamp > strftime('%s', 'now', '-1 day')
                    AND total_bytes > ?
                """
            
            db_cursor.execute(recent_query, (self.min_bytes,))
            
            # Store results locally
            recent_connections = []
            for row in db_cursor.fetchall():
                recent_connections.append(row)
            
            # Filter for connections outside work hours
            out_of_hours = defaultdict(list)
            
            for row in recent_connections:
                src_ip = row[1]
                dst_ip = row[2]
                connection_time = float(row[6])
                
                # Skip whitelisted IPs
                if src_ip in whitelisted_ips or dst_ip in whitelisted_ips:
                    continue
                    
                # Check if this is outside work hours
                if not self.is_work_hours(connection_time):
                    # Group by source IP for reporting
                    out_of_hours[src_ip].append(row)
            
            # Generate alerts for IPs with connections above threshold
            for src_ip, connections in out_of_hours.items():
                if len(connections) >= self.alert_threshold:
                    alert_msg = f"Out-of-hours access: {src_ip} made {len(connections)} connections outside of normal business hours"
                    alerts.append(alert_msg)
                    
                    # Add alert to x_alerts table
                    self.add_alert(src_ip, alert_msg)
                    
                    # Add threat intelligence for the source IP
                    self._add_threat_intel(src_ip, {
                        "connections_count": len(connections),
                        "recent_targets": [conn[2] for conn in connections[:5]],
                        "timestamps": [float(conn[6]) for conn in connections[:5]]
                    })
                    
                    # Add details for the most recent connections
                    details = []
                    for i, conn in enumerate(connections[:5]):
                        dst_ip = conn[2]
                        dst_port = conn[4]
                        bytes_transferred = conn[5]
                        time_str = datetime.fromtimestamp(float(conn[6])).strftime('%Y-%m-%d %H:%M:%S')
                        
                        detail_msg = f"  {time_str}: {src_ip} -> {dst_ip}:{dst_port} ({bytes_transferred/1024:.1f} KB)"
                        details.append(detail_msg)
                    
                    if details:
                        alerts.append("Recent connections:")
                        for detail in details:
                            alerts.append(detail)
                        
                    if len(connections) > 5:
                        more_msg = f"  ... and {len(connections) - 5} more"
                        alerts.append(more_msg)
            
            return alerts
        except Exception as e:
            error_msg = f"Error in Time-Based Access rule: {str(e)}"
            logging.error(error_msg)
            # Try to add the error alert
            try:
                self.add_alert("127.0.0.1", error_msg)
            except Exception as e:
                logging.error(f"Failed to add error alert: {e}")
            return [error_msg]
    
    def add_alert(self, ip_address, alert_message):
        """Add an alert to the x_alerts table"""
        if self.analysis_manager:
            return self.analysis_manager.add_alert(ip_address, alert_message, self.name)
        elif hasattr(self.db_manager, 'queue_alert'):
            # Fallback to old method
            return self.db_manager.queue_alert(ip_address, alert_message, self.name)
        return False
    
    def _add_threat_intel(self, ip_address, details_dict):
        """Store threat intelligence data in x_ip_threat_intel"""
        try:
            if not self.analysis_manager:
                return False
                
            # Create threat intelligence data
            threat_data = {
                "score": 5.0,  # Medium severity score (0-10)
                "type": "time_based_anomaly", 
                "confidence": 0.7,  # Confidence level (0-1)
                "source": self.name,  # Rule name as source
                "first_seen": time.time(),
                "details": {
                    # Detailed JSON information 
                    "detection_details": details_dict
                },
                # Extended columns for easy querying
                "protocol": "Multiple",
                "detection_method": "time_based_analysis",
                "alert_count": details_dict.get("connections_count", 0)
            }
            
            # Update threat intelligence in x_ip_threat_intel
            return self.analysis_manager.update_threat_intel(ip_address, threat_data)
        except Exception as e:
            logging.error(f"Error adding threat intelligence data: {e}")
            return False
    
    def get_params(self):
        return {
            "work_hours_start": {
                "type": "int",
                "default": 8,
                "current": self.work_hours_start,
                "description": "Work hours start time (24-hour format)"
            },
            "work_hours_end": {
                "type": "int",
                "default": 18,
                "current": self.work_hours_end,
                "description": "Work hours end time (24-hour format)"
            },
            "alert_threshold": {
                "type": "int",
                "default": 5,
                "current": self.alert_threshold,
                "description": "Minimum connections to trigger an alert"
            },
            "min_bytes": {
                "type": "int",
                "default": 1000,
                "current": self.min_bytes,
                "description": "Minimum bytes for a significant connection"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "work_hours_start":
            self.work_hours_start = int(value)
            return True
        elif param_name == "work_hours_end":
            self.work_hours_end = int(value)
            return True
        elif param_name == "alert_threshold":
            self.alert_threshold = int(value)
            return True
        elif param_name == "min_bytes":
            self.min_bytes = int(value)
            return True
        return False