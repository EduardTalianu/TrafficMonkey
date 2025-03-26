# Rule class is injected by the RuleLoader
import logging

class NetworkDiscoveryRule(Rule):
    """Rule that detects network service discovery attempts"""
    def __init__(self):
        super().__init__("Network Service Discovery", "Detects when a host is scanning for available services on the network")
        self.service_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 636, 1433, 3306, 3389, 5432, 5900]
        self.hit_threshold = 10  # Number of service ports accessed to trigger alert
        self.time_window = 300  # Time window in seconds (5 minutes)
        self.exclude_admins = True  # Exclude known admin workstations
        self.admin_ips = []  # List of admin IPs to exclude
    
    def analyze(self, db_cursor):
        alerts = []
        pending_alerts = []
        
        try:
            # Find sources that have connected to multiple service ports
            db_cursor.execute("""
                SELECT src_ip, GROUP_CONCAT(DISTINCT dst_port) as ports, COUNT(DISTINCT dst_port) as port_count
                FROM connections
                WHERE timestamp > datetime('now', ? || ' seconds')
                GROUP BY src_ip
                HAVING port_count >= ?
            """, (f"-{self.time_window}", self.hit_threshold))
            
            # Store results locally
            discovery_attempts = []
            for row in db_cursor.fetchall():
                discovery_attempts.append(row)
            
            for src_ip, ports_str, port_count in discovery_attempts:
                # Skip admin IPs if configured
                if self.exclude_admins and src_ip in self.admin_ips:
                    continue
                
                # Extract and check the ports
                if ports_str:
                    ports = [int(p) for p in ports_str.split(',') if p.isdigit()]
                    service_port_hits = [p for p in ports if p in self.service_ports]
                    
                    # Only alert if multiple service ports were accessed
                    if len(service_port_hits) >= self.hit_threshold:
                        service_port_str = ', '.join(str(p) for p in service_port_hits)
                        
                        alert_msg = (f"Network service discovery detected: {src_ip} probed "
                                   f"{len(service_port_hits)} different service ports within "
                                   f"{self.time_window/60:.1f} minutes: {service_port_str}")
                        
                        alerts.append(alert_msg)
                        pending_alerts.append((src_ip, alert_msg, self.name))
            
            # Queue all pending alerts
            for ip, msg, rule_name in pending_alerts:
                try:
                    self.db_manager.queue_alert(ip, msg, rule_name)
                except Exception as e:
                    logging.error(f"Error queueing alert: {e}")
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Network Discovery rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def get_params(self):
        return {
            "hit_threshold": {
                "type": "int",
                "default": 10,
                "current": self.hit_threshold,
                "description": "Number of service ports to trigger alert"
            },
            "time_window": {
                "type": "int",
                "default": 300,
                "current": self.time_window,
                "description": "Time window in seconds"
            },
            "exclude_admins": {
                "type": "bool",
                "default": True,
                "current": self.exclude_admins,
                "description": "Exclude admin IPs from detection"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "hit_threshold":
            self.hit_threshold = int(value)
            return True
        elif param_name == "time_window":
            self.time_window = int(value)
            return True
        elif param_name == "exclude_admins":
            self.exclude_admins = bool(value)
            return True
        return False