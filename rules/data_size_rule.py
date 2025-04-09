# Rule class is injected by the RuleLoader
import logging
import time

class DataSizeRule(Rule):
    """Rule that detects very large data transfers based on absolute thresholds"""
    def __init__(self):
        super().__init__("Large Data Transfer Rule", "Detects exceptionally large data transfers based on fixed thresholds")
        self.threshold_mb = 500  # Default 500MB (much higher than BandwidthAnomalyRule thresholds)
        self.destination_threshold_mb = 200  # Lower threshold for single destinations
        self.alert_on_aggregate = True  # Alert on total transfer volume by source
        self.window_minutes = 60  # Time window to aggregate transfers
        self.analysis_manager = None  # Will be set when db_manager is set
        self.configurable_params = {
            "threshold_mb": {
                "description": "Threshold for large aggregate data transfers (in MB)",
                "type": "int",
                "default": 500,
                "current": self.threshold_mb
            },
            "destination_threshold_mb": {
                "description": "Threshold for large single-destination transfers (in MB)",
                "type": "int",
                "default": 200,
                "current": self.destination_threshold_mb
            },
            "alert_on_aggregate": {
                "description": "Alert on aggregate transfers by source IP",
                "type": "bool",
                "default": True,
                "current": self.alert_on_aggregate
            },
            "window_minutes": {
                "description": "Time window to aggregate transfers (minutes)",
                "type": "int",
                "default": 60,
                "current": self.window_minutes
            }
        }
    
    def analyze(self, db_cursor):
        # Ensure analysis_manager is linked
        if not self.analysis_manager and hasattr(self.db_manager, 'analysis_manager'):
            self.analysis_manager = self.db_manager.analysis_manager
        
        # Return early if analysis_manager is not available
        if not self.analysis_manager:
            logging.error(f"Cannot run {self.name} rule: analysis_manager not available")
            return [f"ERROR: {self.name} rule requires analysis_manager"]

        alerts = []
        
        try:
            # First, check for large single-destination transfers
            db_cursor.execute(
                """
                SELECT connection_key, src_ip, dst_ip, total_bytes, packet_count
                FROM connections 
                WHERE total_bytes > ? 
                ORDER BY total_bytes DESC
                LIMIT 100
                """, 
                (self.destination_threshold_mb * 1024 * 1024,)
            )
            
            # Store results locally
            large_transfers = []
            for row in db_cursor.fetchall():
                large_transfers.append(row)
            
            for row in large_transfers:
                connection_key = row[0]
                src_ip = row[1]
                dst_ip = row[2]
                total_bytes = row[3]
                packet_count = row[4]
                
                # Format to MB for better readability
                mb_size = total_bytes / (1024 * 1024)
                
                message = f"Large Single Transfer: {src_ip} to {dst_ip}, Size: {mb_size:.2f} MB, Packets: {packet_count}"
                alerts.append(message)
                
                # Add alert to x_alerts table
                self.add_alert(src_ip, message)
                
                # Add threat intelligence data for large transfer
                self._add_threat_intel(src_ip, dst_ip, {
                    "connection_key": connection_key,
                    "total_bytes": total_bytes,
                    "packet_count": packet_count,
                    "mb_size": mb_size,
                    "type": "single_transfer"
                })
            
            # Second, check for large aggregate transfers if enabled
            if self.alert_on_aggregate:
                db_cursor.execute(
                    """
                    SELECT src_ip, SUM(total_bytes) as total_volume, COUNT(*) as connection_count
                    FROM connections
                    WHERE timestamp > datetime('now', ? || ' minutes')
                    GROUP BY src_ip
                    HAVING total_volume > ?
                    ORDER BY total_volume DESC
                    LIMIT 50
                    """,
                    (f"-{self.window_minutes}", self.threshold_mb * 1024 * 1024)
                )
                
                # Store aggregate results
                aggregate_transfers = []
                for row in db_cursor.fetchall():
                    aggregate_transfers.append(row)
                
                for src_ip, total_volume, connection_count in aggregate_transfers:
                    # Format to MB for better readability
                    mb_size = total_volume / (1024 * 1024)
                    
                    # Get top destinations for this source
                    db_cursor.execute(
                        """
                        SELECT dst_ip, SUM(total_bytes) as bytes
                        FROM connections
                        WHERE src_ip = ? AND timestamp > datetime('now', ? || ' minutes')
                        GROUP BY dst_ip
                        ORDER BY bytes DESC
                        LIMIT 3
                        """,
                        (src_ip, f"-{self.window_minutes}")
                    )
                    
                    top_destinations = []
                    dst_details = []
                    for dst_row in db_cursor.fetchall():
                        dst_ip = dst_row[0]
                        dst_bytes = dst_row[1]
                        dst_mb = dst_bytes / (1024 * 1024)  # Convert to MB
                        top_destinations.append(f"{dst_ip} ({dst_mb:.2f} MB)")
                        dst_details.append({"ip": dst_ip, "bytes": dst_bytes, "mb": dst_mb})
                    
                    message = f"Large Aggregate Transfer: {src_ip} sent {mb_size:.2f} MB in {connection_count} connections over the last {self.window_minutes} minutes"
                    alerts.append(message)
                    
                    # Add alert to x_alerts table
                    self.add_alert(src_ip, message)
                    
                    # Add threat intelligence data for aggregate transfer
                    self._add_threat_intel(src_ip, None, {
                        "total_volume": total_volume,
                        "connection_count": connection_count,
                        "mb_size": mb_size,
                        "window_minutes": self.window_minutes,
                        "top_destinations": dst_details,
                        "type": "aggregate_transfer"
                    })
                    
                    if top_destinations:
                        dest_message = f"  Top destinations: {', '.join(top_destinations)}"
                        alerts.append(dest_message)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Large Data Transfer rule: {str(e)}"
            logging.error(error_msg)
            # Try to add the error alert to x_alerts
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
    
    def _add_threat_intel(self, src_ip, dst_ip, details_dict):
        """Store threat intelligence data in x_ip_threat_intel"""
        try:
            # Skip if source IP is None (shouldn't happen but just in case)
            if not src_ip:
                return False
                
            # Create threat intelligence data
            threat_data = {
                "score": 6.0,  # Medium-high severity score (0-10)
                "type": "data_exfiltration_risk", 
                "confidence": 0.75,  # Confidence level (0-1)
                "source": self.name,  # Rule name as source
                "first_seen": time.time(),
                "details": {
                    # Detailed JSON information 
                    "detection_details": details_dict
                },
                # Extended columns for easy querying
                "protocol": "TCP",
                "destination_ip": dst_ip,
                "bytes_transferred": details_dict.get("total_bytes", details_dict.get("total_volume", 0)),
                "detection_method": "volume_analysis",
                "packet_count": details_dict.get("packet_count", details_dict.get("connection_count", 0))
            }
            
            # Update threat intelligence in x_ip_threat_intel
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding threat intelligence data: {e}")
            return False
    
    def update_param(self, param_name, value):
        if param_name == "threshold_mb":
            self.threshold_mb = int(value)
            self.configurable_params[param_name]["current"] = int(value)
            return True
        elif param_name == "destination_threshold_mb":
            self.destination_threshold_mb = int(value)
            self.configurable_params[param_name]["current"] = int(value)
            return True
        elif param_name == "alert_on_aggregate":
            self.alert_on_aggregate = bool(value)
            self.configurable_params[param_name]["current"] = bool(value)
            return True
        elif param_name == "window_minutes":
            self.window_minutes = int(value)
            self.configurable_params[param_name]["current"] = int(value)
            return True
        return False
    
    def get_params(self):
        return self.configurable_params