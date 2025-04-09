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
        self.analysis_manager = None  # Will be set by access to db_manager.analysis_manager
    
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
                        
                        # Add alert to x_alerts
                        self.add_alert(src_ip, alert_msg)
                        
                        # Add threat intelligence data
                        self._add_threat_intel(src_ip, {
                            "dst_ip": dst_ip,
                            "total_bytes": total_bytes,
                            "avg_bytes": avg_bytes,
                            "stddev_bytes": stddev_bytes,
                            "z_score": z_score,
                            "connection_key": connection_key
                        })
                        
                except Exception as e:
                    # Skip statistics errors
                    continue
            
            return alerts
        except Exception as e:
            error_msg = f"Error in Bandwidth Anomaly rule: {str(e)}"
            logging.error(error_msg)
            self.add_alert("127.0.0.1", error_msg)
            return [error_msg]
    
    def add_alert(self, ip_address, alert_message):
        """Add an alert to the x_alerts table"""
        if self.analysis_manager:
            return self.analysis_manager.add_alert(ip_address, alert_message, self.name)
        return False
    
    def _add_threat_intel(self, ip_address, details_dict):
        """Store threat intelligence data in x_ip_threat_intel"""
        try:
            # Calculate severity based on z-score
            z_score = details_dict.get("z_score", 0)
            score = min(9.0, 5.0 + (z_score / 2))  # Scale from 5.0 to 9.0 based on z-score
            
            # Create threat intelligence data
            threat_data = {
                "score": score,  # Severity score (0-10)
                "type": "bandwidth_anomaly", 
                "confidence": 0.7 + min(0.25, (z_score / 20)),  # Higher confidence for extreme outliers
                "source": self.name,  # Rule name as source
                "first_seen": time.time(),
                "details": {
                    # Detailed JSON information 
                    "detection_details": details_dict
                },
                # Extended columns for easy querying
                "protocol": "UNKNOWN",
                "destination_ip": details_dict.get("dst_ip"),
                "bytes_transferred": details_dict.get("total_bytes"),
                "detection_method": "statistical_anomaly"
            }
            
            # Update threat intelligence in x_ip_threat_intel
            return self.analysis_manager.update_threat_intel(ip_address, threat_data)
        except Exception as e:
            logging.error(f"Error adding threat intelligence data: {e}")
            return False
    
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