# Updated SuspiciousConnectionRule
# Note: Rule class is injected into the namespace by the RuleLoader
import logging
import os
import json

class SuspiciousConnectionRule(Rule):
    def __init__(self):
        super().__init__(
            name="Local Threat Intelligence",
            description="Detects connections to locally defined suspicious IP addresses and networks"
        )
        self.threshold_kb = 10  # Default threshold in KB for suspicious connections
        self.lists_updated = False
        
        # Set up threat intel file path in db directory
        try:
            # Try to locate the db directory
            if hasattr(self, 'db_manager') and hasattr(self.db_manager, 'app_root'):
                app_root = self.db_manager.app_root
                self.threat_intel_file = os.path.join(app_root, "db", "local_threat_intel.json")
            else:
                current_dir = os.getcwd()
                if os.path.exists(os.path.join(current_dir, "db")):
                    self.threat_intel_file = os.path.join(current_dir, "db", "local_threat_intel.json")
                elif os.path.exists(os.path.join(current_dir, "..", "db")):
                    self.threat_intel_file = os.path.join(current_dir, "..", "db", "local_threat_intel.json")
                else:
                    self.threat_intel_file = "local_threat_intel.json"
            
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.threat_intel_file), exist_ok=True)
                
        except Exception as e:
            logging.error(f"Error setting threat intel file path: {e}")
            self.threat_intel_file = "local_threat_intel.json"
        
        # Initialize threat intelligence data
        self.suspicious_ips = []
        self.suspicious_networks = []
        self.threat_categories = {}
        
        # Load threat intelligence data
        self.load_threat_intel()
    
    def load_threat_intel(self):
        """Load threat intelligence data from file"""
        try:
            if os.path.exists(self.threat_intel_file):
                with open(self.threat_intel_file, 'r') as f:
                    data = json.load(f)
                    self.suspicious_ips = data.get('suspicious_ips', [])
                    self.suspicious_networks = data.get('suspicious_networks', [])
                    self.threat_categories = data.get('threat_categories', {})
                logging.info(f"Loaded {len(self.suspicious_ips)} IPs and {len(self.suspicious_networks)} networks from threat intel file")
            else:
                # Create default threat intel file if it doesn't exist
                self._create_default_threat_intel()
                
            self.lists_updated = True
        except Exception as e:
            logging.error(f"Error loading threat intelligence data: {e}")
            self._create_default_threat_intel()
    
    def _create_default_threat_intel(self):
        """Create default threat intelligence data"""
        # Example threat intelligence data
        default_data = {
            "suspicious_ips": [
                "203.0.113.1",
                "198.51.100.1",
                "192.0.2.1"
            ],
            "suspicious_networks": [
                "203.0.113.0/24",
                "198.51.100.0/24",
                "192.0.2.0/24"
            ],
            "threat_categories": {
                "203.0.113.1": "Command & Control",
                "198.51.100.1": "Malware Distribution",
                "192.0.2.1": "Scanning",
                "203.0.113.0/24": "Known Botnet"
            }
        }
        
        self.suspicious_ips = default_data['suspicious_ips']
        self.suspicious_networks = default_data['suspicious_networks']
        self.threat_categories = default_data['threat_categories']
        
        try:
            with open(self.threat_intel_file, 'w') as f:
                json.dump(default_data, f, indent=2)
            logging.info(f"Created default threat intelligence file at {self.threat_intel_file}")
        except Exception as e:
            logging.error(f"Error creating default threat intelligence file: {e}")
    
    def is_suspicious_ip(self, ip):
        """Check if an IP is in our suspicious list"""
        # Direct IP match
        if ip in self.suspicious_ips:
            return True
            
        # Check network matches
        ip_parts = ip.split('.')
        if len(ip_parts) != 4:
            return False
            
        for network in self.suspicious_networks:
            if '/' in network:
                # Simple prefix matching - a proper implementation would use ipaddress module
                network_prefix = network.split('/')[0]
                prefix_parts = network_prefix.split('.')
                
                match = True
                for i, part in enumerate(prefix_parts):
                    if part != '*' and (i >= len(ip_parts) or ip_parts[i] != part):
                        match = False
                        break
                
                if match:
                    return True
            
        return False
    
    def get_threat_category(self, ip):
        """Get the threat category for an IP"""
        # Direct IP match
        if ip in self.threat_categories:
            return self.threat_categories[ip]
            
        # Check network matches
        for network in self.suspicious_networks:
            if network in self.threat_categories and self._ip_in_network(ip, network):
                return self.threat_categories[network]
                
        return "Unknown"
    
    def _ip_in_network(self, ip, network):
        """Simple check if IP is in network (not using ipaddress for compatibility)"""
        # This is a very simplified implementation
        if '/' not in network:
            return False
            
        network_prefix = network.split('/')[0]
        prefix_parts = network_prefix.split('.')
        ip_parts = ip.split('.')
        
        if len(ip_parts) != 4:
            return False
            
        match = True
        for i, part in enumerate(prefix_parts):
            if part != '*' and (i >= len(ip_parts) or ip_parts[i] != part):
                match = False
                break
        
        return match
    
    def analyze(self, db_cursor):
        # Local list for returning alerts to UI immediately
        alerts = []
        
        # List for storing alerts to be queued after analysis is complete
        pending_alerts = []
        
        try:
            # Make sure threat intel is loaded
            if not self.lists_updated:
                self.load_threat_intel()
            
            # Query the database for active connections
            db_cursor.execute("""
                SELECT src_ip, dst_ip, total_bytes, packet_count
                FROM connections
                WHERE total_bytes > ?
            """, (self.threshold_kb * 1024,))  # Convert KB to bytes
            
            # Store results locally
            connections = []
            for row in db_cursor.fetchall():
                connections.append(row)
            
            for src_ip, dst_ip, total_bytes, packet_count in connections:
                # Check source IP
                if self.is_suspicious_ip(src_ip):
                    category = self.get_threat_category(src_ip)
                    alert_msg = f"ALERT: Connection from suspicious IP {src_ip} to {dst_ip} ({total_bytes/1024:.2f} KB) - Category: {category}"
                    alerts.append(alert_msg)
                    pending_alerts.append((src_ip, alert_msg, self.name))
                
                # Check destination IP
                if self.is_suspicious_ip(dst_ip):
                    category = self.get_threat_category(dst_ip)
                    alert_msg = f"ALERT: Connection to suspicious IP {dst_ip} from {src_ip} ({total_bytes/1024:.2f} KB) - Category: {category}"
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
            error_msg = f"Error in Local Threat Intelligence rule: {str(e)}"
            logging.error(error_msg)
            # Try to queue the error alert
            try:
                self.db_manager.queue_alert("127.0.0.1", error_msg, self.name)
            except:
                pass
            return [error_msg]
    
    def get_params(self):
        return {
            "threshold_kb": {
                "type": "int",
                "default": 10,
                "current": self.threshold_kb,
                "description": "Threshold in KB for suspicious connections"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "threshold_kb":
            self.threshold_kb = int(value)
            return True
        return False