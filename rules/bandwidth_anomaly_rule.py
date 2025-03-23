# Rule class is injected by the RuleLoader
import time
import statistics

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
        alerts = []
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
            
            large_transfers = db_cursor.fetchall()
            
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
                        alerts.append(alert_msg)
                except Exception as e:
                    # Skip statistics errors
                    continue
            
            return alerts
        except Exception as e:
            return [f"Error in Bandwidth Anomaly rule: {str(e)}"]
    
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