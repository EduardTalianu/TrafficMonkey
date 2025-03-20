# Rule class is injected by the RuleLoader

class VirusTotalRule(Rule):
    """Rule that detects connections to malicious IPs"""
    def __init__(self):
        super().__init__("VirusTotal Rule", "Detects connections to malicious IPs")
        self.min_detections = 1
        self.configurable_params = {
            "min_detections": {
                "description": "Minimum number of VirusTotal detections to be considered malicious",
                "type": "int",
                "default": 1,
                "current": self.min_detections
            }
        }
    
    def analyze(self, db_cursor):
        alerts = []
        db_cursor.execute("SELECT connection_key, vt_result FROM connections WHERE vt_result = 'Malicious'")
        vt_alerts = db_cursor.fetchall()
        
        for connection_key, vt_result in vt_alerts:
            alerts.append(f"Potential Anomaly (VirusTotal): Connection {connection_key} has destination flagged as {vt_result}")
            
        return alerts
    
    def update_param(self, param_name, value):
        """Update a configurable parameter"""
        if param_name in self.configurable_params:
            if param_name == "min_detections":
                self.min_detections = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
        return False
    
    def get_params(self):
        """Get configurable parameters"""
        return self.configurable_params