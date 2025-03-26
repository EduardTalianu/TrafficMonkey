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
        # Local list for returning alerts to UI immediately
        alerts = []
        
        # List for storing alerts to be queued after analysis is complete
        pending_alerts = []
        
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
            timestamp_type = db_cursor.fetchone()[0].lower()
            
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
                    pending_alerts.append((src_ip, alert_msg, self.name))
                    
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
            
            # Queue all pending alerts AFTER all database operations are complete
            for ip, msg, rule_name in pending_alerts:
                try:
                    self.db_manager.queue_alert(ip, msg, rule_name)
                except Exception as e:
                    logging.error(f"Error queueing alert: {e}")
            
            return alerts
        except Exception as e:
            error_msg = f"Error in Time-Based Access rule: {str(e)}"
            logging.error(error_msg)
            # Try to queue the error alert
            try:
                self.db_manager.queue_alert("127.0.0.1", error_msg, self.name)
            except:
                pass
            return [error_msg]
    
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