# Updated DataSizeRule
# Rule class is injected by the RuleLoader
import logging

class DataSizeRule(Rule):
    """Rule that detects very large data transfers based on absolute thresholds"""
    def __init__(self):
        super().__init__("Large Data Transfer Rule", "Detects exceptionally large data transfers based on fixed thresholds")
        self.threshold_mb = 500  # Default 500MB (much higher than BandwidthAnomalyRule thresholds)
        self.destination_threshold_mb = 200  # Lower threshold for single destinations
        self.alert_on_aggregate = True  # Alert on total transfer volume by source
        self.window_minutes = 60  # Time window to aggregate transfers
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
        alerts = []
        
        try:
            # First, check for large single-destination transfers
            db_cursor.execute(
                """
                SELECT connection_key, src_ip, dst_ip, total_bytes, packet_count, vt_result 
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
                vt_result = row[5]
                
                # Format to MB for better readability
                mb_size = total_bytes / (1024 * 1024)
                
                message = f"Large Single Transfer: {src_ip} to {dst_ip}, Size: {mb_size:.2f} MB, Packets: {packet_count}"
                if vt_result and vt_result != "unknown":
                    message += f", VirusTotal: {vt_result}"
                    
                alerts.append(message)
            
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
                    for dst_row in db_cursor.fetchall():
                        dst_ip = dst_row[0]
                        dst_bytes = dst_row[1] / (1024 * 1024)  # Convert to MB
                        top_destinations.append(f"{dst_ip} ({dst_bytes:.2f} MB)")
                    
                    message = f"Large Aggregate Transfer: {src_ip} sent {mb_size:.2f} MB in {connection_count} connections over the last {self.window_minutes} minutes"
                    if top_destinations:
                        message += f"\n  Top destinations: {', '.join(top_destinations)}"
                    
                    alerts.append(message)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Large Data Transfer rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
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