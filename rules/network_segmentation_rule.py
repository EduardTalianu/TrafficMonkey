# Rule class is injected by the RuleLoader
import ipaddress
import logging
import time

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
        self.analysis_manager = None  # Will be set by access to db_manager.analysis_manager
    
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
        # Ensure analysis_manager is linked
        if not self.analysis_manager and hasattr(self.db_manager, 'analysis_manager'):
            self.analysis_manager = self.db_manager.analysis_manager
        
        # Return early if analysis_manager is not available
        if not self.analysis_manager:
            logging.error(f"Cannot run {self.name} rule: analysis_manager not available")
            return [f"ERROR: {self.name} rule requires analysis_manager"]
        
        alerts = []
        
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
                    self.add_alert(src_ip, alert_msg)
                    
                    # Add threat intelligence data
                    self._add_threat_intel(src_ip, {
                        "dst_ip": dst_ip,
                        "src_segment": src_segment,
                        "dst_segment": dst_segment,
                        "total_bytes": total_bytes,
                        "connection_key": connection_key
                    })
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Network Segmentation rule: {str(e)}"
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
                "score": 8.0,  # High severity for security policy violations
                "type": "segmentation_violation", 
                "confidence": 0.95,  # High confidence - network boundaries are clear
                "source": self.name,  # Rule name as source
                "first_seen": time.time(),
                "details": {
                    # Detailed JSON information 
                    "detection_details": details_dict
                },
                # Extended columns for easy querying
                "protocol": "UNKNOWN",
                "destination_ip": details_dict.get("dst_ip"),
                "bytes_transferred": details_dict.get("total_bytes"),
                "detection_method": "segment_boundary_analysis"
            }
            
            # Update threat intelligence in x_ip_threat_intel
            return self.analysis_manager.update_threat_intel(ip_address, threat_data)
        except Exception as e:
            logging.error(f"Error adding threat intelligence data: {e}")
            return False
    
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