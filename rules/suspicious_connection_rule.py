# This rule detects connections to suspicious IP addresses
# Note: Rule class is injected into the namespace by the RuleLoader

class SuspiciousConnectionRule(Rule):
    def __init__(self):
        super().__init__(
            name="Suspicious Connection Detector",
            description="Detects connections to potentially suspicious IP addresses and domains"
        )
        self.threshold = 10  # Default threshold for suspicious connections
        
    def analyze(self, db_cursor):
        alerts = []
        
        # Query the database for active connections
        db_cursor.execute("""
            SELECT src_ip, dst_ip, total_bytes, packet_count
            FROM connections
            WHERE total_bytes > ?
        """, (self.threshold * 1000,))  # Convert threshold to KB
        
        suspicious_connections = db_cursor.fetchall()
        
        for src_ip, dst_ip, total_bytes, packet_count in suspicious_connections:
            # Check for suspicious pattern (for demonstration purposes)
            if self._is_suspicious_ip(dst_ip):
                alerts.append(f"ALERT: Suspicious connection from {src_ip} to {dst_ip} ({total_bytes/1024:.2f} KB)")
                
        return alerts
    
    def _is_suspicious_ip(self, ip):
        # For demo purposes, consider any IP with specific patterns as suspicious
        suspicious_prefixes = ["203.0.", "10.0.0."]
        for prefix in suspicious_prefixes:
            if ip.startswith(prefix):
                return True
        return False
    
    def get_params(self):
        return {
            "threshold": {
                "type": "int",
                "default": 10,
                "current": self.threshold,
                "description": "Threshold in KB for suspicious connections"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "threshold":
            self.threshold = int(value)
            return True
        return False