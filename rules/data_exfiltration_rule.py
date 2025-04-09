# Rule class is injected by the RuleLoader
import logging
import time
from collections import defaultdict

class DataExfiltrationRule(Rule):
    """Rule that detects potential data exfiltration patterns"""
    def __init__(self):
        super().__init__("Data Exfiltration Detection", "Detects patterns indicative of data being exfiltrated from the network")
        self.upload_threshold_mb = 50  # MB threshold for significant outbound transfer
        self.ratio_threshold = 5.0    # Outbound/inbound traffic ratio to trigger alert
        self.min_connections = 3      # Minimum connections to analyze
        self.exclude_common_ports = True  # Exclude common services (HTTP, HTTPS, etc.)
        self.analysis_manager = None  # Will be set by access to db_manager.analysis_manager
    
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
                    self.add_alert(ip, alert_msg)
                    
                    # Add threat intelligence data
                    self._add_threat_intel(ip, {
                        "outbound_bytes": outbound,
                        "inbound_bytes": inbound,
                        "ratio": ratio,
                        "ports_used": ports
                    })
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Data Exfiltration rule: {str(e)}"
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
            # Create threat intelligence data
            threat_data = {
                "score": 7.5,  # Severity score (0-10)
                "type": "data_exfiltration", 
                "confidence": 0.75,  # Confidence level (0-1)
                "source": self.name,  # Rule name as source
                "first_seen": time.time(),
                "details": {
                    # Detailed JSON information 
                    "detection_details": details_dict
                },
                # Extended columns for easy querying
                "protocol": "MULTIPLE",
                "bytes_transferred": details_dict.get("outbound_bytes"),
                "detection_method": "traffic_ratio_analysis"
            }
            
            # Update threat intelligence in x_ip_threat_intel
            return self.analysis_manager.update_threat_intel(ip_address, threat_data)
        except Exception as e:
            logging.error(f"Error adding threat intelligence data: {e}")
            return False
    
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