# Rule class is injected by the RuleLoader

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
        db_cursor.execute(
            "SELECT connection_key, total_bytes, packet_count, vt_result FROM connections WHERE total_bytes > ?", 
            (self.threshold,)
        )
        anomalies = db_cursor.fetchall()
        for connection_key, total_bytes, packet_count, vt_result in anomalies:
            message = f"Large Transfer: {connection_key}, Bytes: {total_bytes}, Packets: {packet_count}"
            if vt_result:
                message += f", VirusTotal: {vt_result}"
            alerts.append(message)
        return alerts
    
    def update_param(self, param_name, value):
        if param_name == "threshold":
            self.threshold = int(value)
            self.configurable_params[param_name]["current"] = int(value)
            return True
        return False
    
    def get_params(self):
        return self.configurable_params