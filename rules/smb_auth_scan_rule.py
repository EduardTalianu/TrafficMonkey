# Rule class is injected by the RuleLoader
import logging
import time

class SMBAuthScanRule(Rule):
    """Rule that detects SMB/Windows authentication scanning attempts"""
    def __init__(self):
        super().__init__("SMB Authentication Scanning", "Detects attempts to scan for open SMB shares or brute force authentication")
        self.smb_ports = [139, 445]
        self.threshold = 5  # Number of different hosts to trigger alert
        self.time_window = 300  # Time window in seconds (5 minutes)
        self.min_bytes = 200  # Minimum bytes to consider a significant connection
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
            # Find sources connecting to SMB ports on multiple destinations
            query = """
                SELECT src_ip, COUNT(DISTINCT dst_ip) as target_count, GROUP_CONCAT(DISTINCT dst_ip) as targets
                FROM connections
                WHERE dst_port IN (139, 445)
                AND total_bytes > ?
                AND timestamp > datetime('now', ? || ' seconds')
                GROUP BY src_ip
                HAVING target_count >= ?
            """
            
            db_cursor.execute(query, (self.min_bytes, f"-{self.time_window}", self.threshold))
            
            # Store results locally
            smb_scanners = []
            for row in db_cursor.fetchall():
                smb_scanners.append(row)
            
            for src_ip, target_count, targets in smb_scanners:
                # Prepare list of scanned IPs
                target_list = targets.split(',')
                sample_targets = target_list[:5]  # Show first 5 targets
                
                alert_msg = (f"SMB authentication scanning detected: {src_ip} connected to "
                           f"SMB ports on {target_count} different hosts in the past "
                           f"{self.time_window/60:.1f} minutes")
                
                targets_msg = f"Sample targets: {', '.join(sample_targets)}"
                if len(target_list) > 5:
                    targets_msg += f" and {len(target_list) - 5} more"
                
                alerts.append(alert_msg)
                alerts.append(targets_msg)
                
                # Add alerts to x_alerts
                self.add_alert(src_ip, alert_msg)
                self.add_alert(src_ip, targets_msg)
                
                # Add threat intelligence data
                self._add_threat_intel(src_ip, {
                    "target_count": target_count,
                    "target_list": target_list,
                    "time_window": self.time_window,
                    "ports": self.smb_ports
                })
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in SMB Authentication Scan rule: {str(e)}"
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
                "score": 7.0,  # Severity score (0-10)
                "type": "smb_scan", 
                "confidence": 0.85,  # Confidence level (0-1)
                "source": self.name,  # Rule name as source
                "first_seen": time.time(),
                "details": {
                    # Detailed JSON information 
                    "detection_details": details_dict
                },
                # Extended columns for easy querying
                "protocol": "SMB",
                "destination_port": 445,  # Use primary SMB port for record
                "detection_method": "auth_scan_detection",
                "packet_count": details_dict.get("target_count", 0)
            }
            
            # Update threat intelligence in x_ip_threat_intel
            return self.analysis_manager.update_threat_intel(ip_address, threat_data)
        except Exception as e:
            logging.error(f"Error adding threat intelligence data: {e}")
            return False
    
    def get_params(self):
        return {
            "threshold": {
                "type": "int",
                "default": 5,
                "current": self.threshold,
                "description": "Number of hosts to trigger alert"
            },
            "time_window": {
                "type": "int",
                "default": 300,
                "current": self.time_window,
                "description": "Time window in seconds"
            },
            "min_bytes": {
                "type": "int",
                "default": 200,
                "current": self.min_bytes,
                "description": "Minimum bytes for significant connections"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "threshold":
            self.threshold = int(value)
            return True
        elif param_name == "time_window":
            self.time_window = int(value)
            return True
        elif param_name == "min_bytes":
            self.min_bytes = int(value)
            return True
        return False