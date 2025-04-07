# Rule class is injected by the RuleLoader
import time
import statistics
import logging

class BandwidthAnomalyRule(Rule):
    """Rule that detects anomalous bandwidth usage"""
    def __init__(self):
        super().__init__("Bandwidth Usage Anomaly", "Detects unusual spikes in bandwidth usage from specific IPs")
        self.threshold_mb = 10  # Megabytes threshold for a significant transfer
        self.deviation_factor = 3.0  # Standard deviations from average to trigger alert
        self.min_history = 5  # Minimum number of connections to establish baseline
        self.history_window = 3600  # Look back period in seconds (1 hour default)
        self.last_alert_time = {}  # Track last alert time by IP
    
    def analyze(self, db_cursor):
        # Local list for returning alerts to UI immediately
        alerts = []
        
        # List for storing alerts to be queued after analysis is complete
        pending_alerts = []
        
        current_time = time.time()
        
        try:
            # First get all active connections with significant data transfer
            db_cursor.execute("""
                SELECT src_ip, dst_ip, total_bytes, connection_key
                FROM connections 
                WHERE total_bytes > ? 
                AND timestamp > datetime('now', '-10 minutes')
                ORDER BY total_bytes DESC
                LIMIT 100
            """, (self.threshold_mb * 1024 * 1024,))  # Convert MB to bytes
            
            # Store results locally to avoid keeping the cursor active
            large_transfers = []
            for row in db_cursor.fetchall():
                large_transfers.append(row)
            
            for src_ip, dst_ip, total_bytes, connection_key in large_transfers:
                # Prevent alert flooding
                conn_key = f"{src_ip}->{dst_ip}"
                if conn_key in self.last_alert_time and (current_time - self.last_alert_time[conn_key]) < 300:  # 5 minutes
                    continue
                
                # Get historical data for this source IP
                db_cursor.execute("""
                    SELECT total_bytes 
                    FROM connections 
                    WHERE (src_ip = ? OR dst_ip = ?)
                    AND timestamp > datetime('now', ? || ' seconds')
                    AND connection_key != ?
                """, (src_ip, src_ip, f"-{self.history_window}", connection_key))
                
                history = [row[0] for row in db_cursor.fetchall()]
                
                # Skip if we don't have enough history
                if len(history) < self.min_history:
                    continue
                
                # Calculate statistics
                try:
                    avg_bytes = statistics.mean(history)
                    stddev_bytes = statistics.stdev(history)
                    
                    # Skip if the standard deviation is too low (not enough variation in the data)
                    if stddev_bytes < 1000:  # Arbitrary small value
                        continue
                    
                    z_score = (total_bytes - avg_bytes) / stddev_bytes
                    
                    # Alert if the transfer is significantly above average
                    if z_score > self.deviation_factor:
                        self.last_alert_time[conn_key] = current_time
                        
                        alert_msg = (f"Bandwidth anomaly: {src_ip}->{dst_ip} transferred " 
                                    f"{total_bytes/1024/1024:.2f} MB, " 
                                    f"{z_score:.1f}x standard deviations above average " 
                                    f"({avg_bytes/1024/1024:.2f} MB)")
                        
                        # Add to immediate alerts list for UI
                        alerts.append(alert_msg)
                        
                        # Add to pending alerts for queueing (use source IP as alert target)
                        pending_alerts.append((src_ip, alert_msg, self.name))
                        
                except Exception as e:
                    # Skip statistics errors
                    continue
            
            # Queue all pending alerts AFTER all database operations are complete
            for ip, msg, rule_name in pending_alerts:
                try:
                    # Use analysis_manager to add alerts to analysis_1.db
                    if hasattr(self.db_manager, 'analysis_manager') and self.db_manager.analysis_manager:
                        self.db_manager.analysis_manager.add_alert(ip, msg, rule_name)
                    else:
                        self.db_manager.queue_alert(ip, msg, rule_name)
                except Exception as e:
                    # Log error but continue processing
                    logging.error(f"Error queueing alert: {e}")
            
            return alerts
        except Exception as e:
            error_msg = f"Error in Bandwidth Anomaly rule: {str(e)}"
            # Try to queue the error alert
            try:
                # Use analysis_manager to add alerts to analysis_1.db
                if hasattr(self.db_manager, 'analysis_manager') and self.db_manager.analysis_manager:
                    self.db_manager.analysis_manager.add_alert("127.0.0.1", error_msg, self.name)
                else:
                    self.db_manager.queue_alert("127.0.0.1", error_msg, self.name)
            except:
                pass
            return [error_msg]
    
    def get_params(self):
        return {
            "threshold_mb": {
                "type": "int",
                "default": 10,
                "current": self.threshold_mb,
                "description": "Minimum transfer size to analyze (MB)"
            },
            "deviation_factor": {
                "type": "float",
                "default": 3.0,
                "current": self.deviation_factor,
                "description": "Standard deviations above average to trigger alert"
            },
            "history_window": {
                "type": "int",
                "default": 3600,
                "current": self.history_window,
                "description": "Historical lookback period (seconds)"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "threshold_mb":
            self.threshold_mb = int(value)
            return True
        elif param_name == "deviation_factor":
            self.deviation_factor = float(value)
            return True
        elif param_name == "history_window":
            self.history_window = int(value)
            return True
        return False