# Rule class is injected by the RuleLoader
import ipaddress
import logging

class NetworkSegmentationRule(Rule):
    """Rule that detects violations of network segmentation policies"""
    def __init__(self):
        super().__init__("Network Segmentation Violation", "Detects traffic between network segments that should be isolated")
        self.segments = {
            "DMZ": ["192.168.1.0/24"],
            "Servers": ["10.0.1.0/24", "10.0.2.0/24"],
            "Corporate": ["10.0.10.0/24", "10.0.11.0/24"],
            "IoT": ["10.0.20.0/24"],
            "Guest": ["192.168.10.0/24"]
        }
        self.forbidden_pairs = [
            ("Guest", "Servers"),
            ("Guest", "Corporate"),
            ("IoT", "Servers"),
            ("IoT", "Corporate")
        ]
        self.min_bytes = 1000  # Minimum bytes to trigger alert
    
    def get_segment(self, ip):
        """Determine which network segment an IP belongs to"""
        for segment, networks in self.segments.items():
            for network in networks:
                try:
                    if ipaddress.ip_address(ip) in ipaddress.ip_network(network):
                        return segment
                except ValueError:
                    # If IP has a port suffix or isn't valid
                    try:
                        clean_ip = ip.split(':')[0] if ':' in ip else ip
                        if ipaddress.ip_address(clean_ip) in ipaddress.ip_network(network):
                            return segment
                    except:
                        pass
        return "External"
    
    def analyze(self, db_cursor):
        alerts = []
        pending_alerts = []
        
        try:
            # Get all significant connections
            db_cursor.execute("""
                SELECT src_ip, dst_ip, total_bytes, connection_key
                FROM connections
                WHERE total_bytes > ?
            """, (self.min_bytes,))
            
            # Store results locally
            connections = []
            for row in db_cursor.fetchall():
                connections.append(row)
            
            for src_ip, dst_ip, total_bytes, connection_key in connections:
                src_segment = self.get_segment(src_ip)
                dst_segment = self.get_segment(dst_ip)
                
                # Skip if either segment is External
                if src_segment == "External" or dst_segment == "External":
                    continue
                
                # Check if this is a forbidden pair
                pair = (src_segment, dst_segment)
                pair_reversed = (dst_segment, src_segment)
                
                if pair in self.forbidden_pairs or pair_reversed in self.forbidden_pairs:
                    alert_msg = (f"Network segmentation violation: {src_ip} ({src_segment}) "
                               f"communicated with {dst_ip} ({dst_segment}), "
                               f"transferring {total_bytes/1024:.1f} KB")
                    
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
            error_msg = f"Error in Network Segmentation rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def get_params(self):
        return {
            "min_bytes": {
                "type": "int",
                "default": 1000,
                "current": self.min_bytes,
                "description": "Minimum bytes to trigger an alert"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "min_bytes":
            self.min_bytes = int(value)
            return True
        return False