# Rule class is injected by the RuleLoader
import logging

class DataSizeRule(Rule):
    """Rule that detects large data transfers"""
    def __init__(self):
        super().__init__("Data Size Rule", "Detects large data transfers")
        self.threshold = 1024*1024*100  # Default 100MB
        self.configurable_params = {
            "threshold": {
                "description": "Threshold for large data transfers (in bytes)",
                "type": "int",
                "default": 1024*1024*100,
                "current": self.threshold
            }
        }
    
    def analyze(self, db_cursor):
        alerts = []
        
        try:
            db_cursor.execute(
                "SELECT connection_key, src_ip, dst_ip, total_bytes, packet_count, vt_result FROM connections WHERE total_bytes > ?", 
                (self.threshold,)
            )
            
            # Store results locally
            anomalies = []
            for row in db_cursor.fetchall():
                anomalies.append(row)
            
            for row in anomalies:
                connection_key = row[0]
                
                # Extract source and destination IP for queuing purposes
                src_ip = row[1]
                dst_ip = row[2]
                total_bytes = row[3]
                packet_count = row[4]
                vt_result = row[5]
                
                # Format to MB for better readability
                mb_size = total_bytes / (1024 * 1024)
                
                message = f"Large Transfer: {connection_key}, Size: {mb_size:.2f} MB, Packets: {packet_count}"
                if vt_result:
                    message += f", VirusTotal: {vt_result}"
                    
                alerts.append(message)
                
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Data Size rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def update_param(self, param_name, value):
        if param_name == "threshold":
            self.threshold = int(value)
            self.configurable_params[param_name]["current"] = int(value)
            return True
        return False
    
    def get_params(self):
        return self.configurable_params