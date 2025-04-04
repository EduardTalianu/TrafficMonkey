# Rule class is injected by the RuleLoader
import time
import logging
import threading

class ConnectionDurationRule(Rule):
    """Rule that detects connections with unusually long durations"""
    def __init__(self):
        super().__init__("Connection Duration Anomaly", "Detects connections that stay open for unusually long periods")
        self.long_duration_minutes = 60  # Duration in minutes to consider a long connection
        self.min_bytes = 500  # Minimum bytes to consider a significant connection
        self.check_interval = 600  # Seconds between checks (10 minutes)
        self.last_check_time = 0
        self.detected_connections = set()  # Track connections we've already detected
        self.alerts_to_queue = []  # Initialize the alerts_to_queue list
    
    def analyze(self, db_cursor):
        # Local list for returning alerts to UI immediately
        alerts = []
        
        # Clear previous alerts to queue
        self.alerts_to_queue = []
        
        current_time = time.time()
        
        # Only run this rule periodically to avoid constant database load
        if current_time - self.last_check_time < self.check_interval:
            return []
        
        self.last_check_time = current_time
        
        try:
            # Check if timestamp is a proper datetime column
            timestamp_query = """
                SELECT typeof(timestamp) FROM connections LIMIT 1
            """
            
            db_cursor.execute(timestamp_query)
            result = db_cursor.fetchone()
            if not result:
                return ["Connection Duration rule skipped: cannot determine timestamp type"]
                
            timestamp_type = result[0].lower()
            
            # Different queries depending on timestamp type
            if 'text' in timestamp_type:
                # SQLite datetime string format
                duration_query = """
                    SELECT connection_key, src_ip, dst_ip, src_port, dst_port, total_bytes,
                           julianday('now') - julianday(timestamp) as duration_days
                    FROM connections
                    WHERE total_bytes > ?
                    AND julianday('now') - julianday(timestamp) > ?
                    ORDER BY duration_days DESC
                """
                duration_param = self.long_duration_minutes / (24 * 60)  # Convert minutes to days
            else:
                # Numeric timestamp (likely timestamp format)
                duration_query = """
                    SELECT connection_key, src_ip, dst_ip, src_port, dst_port, total_bytes,
                           (strftime('%s', 'now') - timestamp) / 60 as duration_minutes
                    FROM connections
                    WHERE total_bytes > ?
                    AND (strftime('%s', 'now') - timestamp) / 60 > ?
                    ORDER BY duration_minutes DESC
                """
                duration_param = self.long_duration_minutes
            
            db_cursor.execute(duration_query, (self.min_bytes, duration_param))
            
            # Store results locally to avoid keeping the cursor active
            long_connections = []
            for row in db_cursor.fetchall():
                long_connections.append(row)
            
            # Process results after we're done with the cursor
            for row in long_connections:
                connection_key = row[0]
                src_ip = row[1]
                dst_ip = row[2]
                src_port = row[3]
                dst_port = row[4]
                total_bytes = row[5]
                
                if 'text' in timestamp_type:
                    duration = row[6] * 24 * 60  # Convert days to minutes
                else:
                    duration = row[6]  # Already in minutes
                
                # Skip connections we've already detected
                if connection_key in self.detected_connections:
                    continue
                
                # Format the connection info for the alert
                duration_str = f"{duration:.1f} minutes"
                if duration > 60:
                    duration_str = f"{duration/60:.1f} hours"
                
                connection_str = f"{src_ip}"
                if src_port:
                    connection_str += f":{src_port}"
                
                connection_str += f" -> {dst_ip}"
                if dst_port:
                    connection_str += f":{dst_port}"
                
                alert_msg = (f"Long duration connection: {connection_str} has been active for {duration_str} "
                            f"with {total_bytes/1024:.2f} KB transferred")
                
                # Add to immediate alerts list for UI
                alerts.append(alert_msg)
                
                # Save alert info for later queueing - use the destination as the alert target
                self.alerts_to_queue.append((dst_ip, alert_msg))
                
                # Add to detected set
                self.detected_connections.add(connection_key)
                
                # Prevent the detected set from growing too large
                if len(self.detected_connections) > 1000:
                    # Clear out half the old entries when we hit the limit
                    self.detected_connections = set(list(self.detected_connections)[-500:])
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Connection Duration rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
            
    def post_analyze_queue_alerts(self):
        """
        This method should be called by the RuleLoader after analyze() completes
        to queue any alerts without holding a database cursor.
        """
        if self.alerts_to_queue:
            for ip, msg in self.alerts_to_queue:
                try:
                    self.db_manager.queue_alert(ip, msg, self.name)
                except Exception as e:
                    logging.error(f"Error queueing alert: {e}")
            # Clear the queue after processing
            self.alerts_to_queue = []
    
    def get_params(self):
        return {
            "long_duration_minutes": {
                "type": "int",
                "default": 60,
                "current": self.long_duration_minutes,
                "description": "Connection duration threshold (minutes)"
            },
            "min_bytes": {
                "type": "int",
                "default": 500,
                "current": self.min_bytes,
                "description": "Minimum bytes for a significant connection"
            },
            "check_interval": {
                "type": "int",
                "default": 600,
                "current": self.check_interval,
                "description": "Seconds between rule checks"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "long_duration_minutes":
            self.long_duration_minutes = int(value)
            return True
        elif param_name == "min_bytes":
            self.min_bytes = int(value)
            return True
        elif param_name == "check_interval":
            self.check_interval = int(value)
            return True
        return False