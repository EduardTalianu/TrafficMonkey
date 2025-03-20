# Rule class is injected by the RuleLoader

class RDPRule(Rule):
    """Rule that detects simultaneous RDP connections"""
    def __init__(self):
        super().__init__("RDP Connection Rule", "Detects suspicious RDP connection patterns")
        self.threshold = 1
        self.configurable_params = {
            "threshold": {
                "description": "Minimum number of simultaneous RDP connections considered suspicious",
                "type": "int",
                "default": 1,
                "current": self.threshold
            }
        }
    
    def analyze(self, db_cursor):
        alerts = []
        db_cursor.execute("""
            SELECT src_ip
            FROM connections
            GROUP BY src_ip
            HAVING SUM(is_rdp_client) > 0 AND SUM(is_rdp_server) > 0 AND COUNT(DISTINCT dst_ip) >= ?
        """, (self.threshold,))
        
        rdp_anomalies = db_cursor.fetchall()
        for src_ip, in rdp_anomalies:
            alerts.append(f"Potential Anomaly (Simultaneous RDP): Device {src_ip} is both receiving and making RDP connections simultaneously.")
            
        return alerts
    
    def update_param(self, param_name, value):
        """Update a configurable parameter"""
        if param_name in self.configurable_params:
            if param_name == "threshold":
                self.threshold = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
        return False
    
    def get_params(self):
        """Get configurable parameters"""
        return self.configurable_params