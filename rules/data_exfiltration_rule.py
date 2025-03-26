# Rule class is injected by the RuleLoader
import logging
from collections import defaultdict

class DataExfiltrationRule(Rule):
    """Rule that detects potential data exfiltration patterns"""
    def __init__(self):
        super().__init__("Data Exfiltration Detection", "Detects patterns indicative of data being exfiltrated from the network")
        self.upload_threshold_mb = 50  # MB threshold for significant outbound transfer
        self.ratio_threshold = 5.0    # Outbound/inbound traffic ratio to trigger alert
        self.min_connections = 3      # Minimum connections to analyze
        self.exclude_common_ports = True  # Exclude common services (HTTP, HTTPS, etc.)
    
    def analyze(self, db_cursor):
        alerts = []
        pending_alerts = []
        
        try:
            # Group by source IP and calculate outbound/inbound ratio
            outbound_query = """
                SELECT src_ip, SUM(total_bytes) as outbound_bytes
                FROM connections
                WHERE src_ip LIKE '192.168.%' OR src_ip LIKE '10.%'
                GROUP BY src_ip
                HAVING COUNT(*) >= ?
            """
            
            inbound_query = """
                SELECT dst_ip, SUM(total_bytes) as inbound_bytes
                FROM connections
                WHERE dst_ip LIKE '192.168.%' OR dst_ip LIKE '10.%'
                GROUP BY dst_ip
                HAVING COUNT(*) >= ?
            """
            
            # Get outbound traffic by internal IP
            db_cursor.execute(outbound_query, (self.min_connections,))
            outbound_data = {row[0]: row[1] for row in db_cursor.fetchall()}
            
            # Get inbound traffic by internal IP
            db_cursor.execute(inbound_query, (self.min_connections,))
            inbound_data = {row[0]: row[1] for row in db_cursor.fetchall()}
            
            # Find IPs with high outbound to inbound ratio
            for ip in outbound_data:
                outbound = outbound_data.get(ip, 0)
                inbound = inbound_data.get(ip, 0)
                
                # Skip if outbound traffic is below threshold
                if outbound < (self.upload_threshold_mb * 1024 * 1024):
                    continue
                    
                # Handle case where inbound is 0
                if inbound == 0:
                    inbound = 1
                
                ratio = outbound / inbound
                
                if ratio > self.ratio_threshold:
                    # Check for common services if enabled
                    if self.exclude_common_ports:
                        # Get destination ports for this source IP
                        db_cursor.execute("""
                            SELECT dst_port, COUNT(*) as conn_count
                            FROM connections
                            WHERE src_ip = ?
                            GROUP BY dst_port
                        """, (ip,))
                        
                        ports = [row[0] for row in db_cursor.fetchall()]
                        common_ports = {80, 443, 8080, 8443, 25, 21}
                        
                        # Skip if all connections are to common ports
                        if all(port in common_ports for port in ports if port):
                            continue
                    
                    alert_msg = (f"Potential data exfiltration from {ip}: "
                                f"sent {outbound/1024/1024:.2f} MB, "
                                f"received {inbound/1024/1024:.2f} MB "
                                f"(ratio: {ratio:.1f}x)")
                    
                    alerts.append(alert_msg)
                    pending_alerts.append((ip, alert_msg, self.name))
            
            # Queue all pending alerts
            for ip, msg, rule_name in pending_alerts:
                try:
                    self.db_manager.queue_alert(ip, msg, rule_name)
                except Exception as e:
                    logging.error(f"Error queueing alert: {e}")
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Data Exfiltration rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def get_params(self):
        return {
            "upload_threshold_mb": {
                "type": "int",
                "default": 50,
                "current": self.upload_threshold_mb,
                "description": "Minimum outbound data in MB to trigger alert"
            },
            "ratio_threshold": {
                "type": "float",
                "default": 5.0,
                "current": self.ratio_threshold,
                "description": "Outbound/inbound traffic ratio threshold"
            },
            "exclude_common_ports": {
                "type": "bool",
                "default": True,
                "current": self.exclude_common_ports,
                "description": "Exclude common services to reduce false positives"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "upload_threshold_mb":
            self.upload_threshold_mb = int(value)
            return True
        elif param_name == "ratio_threshold":
            self.ratio_threshold = float(value)
            return True
        elif param_name == "exclude_common_ports":
            self.exclude_common_ports = bool(value)
            return True
        return False