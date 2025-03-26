# This rule detects connections to suspicious IP addresses
# Note: Rule class is injected into the namespace by the RuleLoader
import logging

class SuspiciousConnectionRule(Rule):
    def __init__(self):
        super().__init__(
            name="Suspicious Connection Detector",
            description="Detects connections to potentially suspicious IP addresses and domains"
        )
        self.threshold = 10  # Default threshold for suspicious connections
        
    def analyze(self, db_cursor):
        # Local list for returning alerts to UI immediately
        alerts = []
        
        # List for storing alerts to be queued after analysis is complete
        pending_alerts = []
        
        try:
            # Query the database for active connections
            db_cursor.execute("""
                SELECT src_ip, dst_ip, total_bytes, packet_count
                FROM connections
                WHERE total_bytes > ?
            """, (self.threshold * 1000,))  # Convert threshold to KB
            
            # Store results locally
            suspicious_connections = []
            for row in db_cursor.fetchall():
                suspicious_connections.append(row)
            
            for src_ip, dst_ip, total_bytes, packet_count in suspicious_connections:
                # Check for suspicious pattern (for demonstration purposes)
                if self._is_suspicious_ip(dst_ip):
                    alert_msg = f"ALERT: Suspicious connection from {src_ip} to {dst_ip} ({total_bytes/1024:.2f} KB)"
                    alerts.append(alert_msg)
                    pending_alerts.append((dst_ip, alert_msg, self.name))
            
            # Queue all pending alerts AFTER all database operations are complete
            for ip, msg, rule_name in pending_alerts:
                try:
                    self.db_manager.queue_alert(ip, msg, rule_name)
                except Exception as e:
                    logging.error(f"Error queueing alert: {e}")
            
            return alerts
        except Exception as e:
            error_msg = f"Error in Suspicious Connection rule: {str(e)}"
            logging.error(error_msg)
            # Try to queue the error alert
            try:
                self.db_manager.queue_alert("127.0.0.1", error_msg, self.name)
            except:
                pass
            return [error_msg]
    
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