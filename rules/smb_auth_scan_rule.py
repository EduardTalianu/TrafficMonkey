# Rule class is injected by the RuleLoader
import logging

class SMBAuthScanRule(Rule):
    """Rule that detects SMB/Windows authentication scanning attempts"""
    def __init__(self):
        super().__init__("SMB Authentication Scanning", "Detects attempts to scan for open SMB shares or brute force authentication")
        self.smb_ports = [139, 445]
        self.threshold = 5  # Number of different hosts to trigger alert
        self.time_window = 300  # Time window in seconds (5 minutes)
        self.min_bytes = 200  # Minimum bytes to consider a significant connection
    
    def analyze(self, db_cursor):
        alerts = []
        pending_alerts = []
        
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
                
                pending_alerts.append((src_ip, alert_msg, self.name))
                pending_alerts.append((src_ip, targets_msg, self.name))
            
            # Queue all pending alerts
            for ip, msg, rule_name in pending_alerts:
                try:
                    # Use analysis_manager to add alerts to analysis_1.db
                    if hasattr(self.db_manager, 'analysis_manager') and self.db_manager.analysis_manager:
                        self.db_manager.analysis_manager.add_alert(ip, msg, rule_name)
                    else:
                        self.db_manager.queue_alert(ip, msg, rule_name)
                except Exception as e:
                    logging.error(f"Error queueing alert: {e}")
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in SMB Authentication Scan rule: {str(e)}"
            logging.error(error_msg)
            # Try to queue the error alert
            try:
                # Use analysis_manager to add alerts to analysis_1.db
                if hasattr(self.db_manager, 'analysis_manager') and self.db_manager.analysis_manager:
                    self.db_manager.analysis_manager.add_alert("127.0.0.1", error_msg, self.name)
                else:
                    self.db_manager.queue_alert("127.0.0.1", error_msg, self.name)
            except Exception as e:
                logging.error(f"Failed to queue error alert: {e}")
            return [error_msg]
    
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