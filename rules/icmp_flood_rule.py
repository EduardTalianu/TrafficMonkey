# Rule class is injected by the RuleLoader
import time
import logging

class ICMPFloodRule(Rule):
    """Rule that detects ICMP flood attacks"""
    def __init__(self):
        super().__init__("ICMP Flood Detection", "Detects potential ICMP flood attacks")
        self.threshold = 50  # Number of ICMP packets in time window
        self.time_window = 60  # Time window in seconds
        self.configurable_params = {
            "threshold": {
                "description": "Number of ICMP packets to be considered a flood",
                "type": "int",
                "default": 50,
                "current": self.threshold
            },
            "time_window": {
                "description": "Time window to check for ICMP flooding (seconds)",
                "type": "int",
                "default": 60,
                "current": self.time_window
            }
        }
        self.last_alert_time = {}  # Track last alert time by IP
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
        current_time = time.time()
        
        try:
            # Check if icmp_packets table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='icmp_packets'
            """)
            
            if not db_cursor.fetchone():
                return ["ICMP Flood rule requires icmp_packets table which doesn't exist"]
            
            # Look for ICMP flood patterns
            db_cursor.execute("""
                SELECT src_ip, dst_ip, COUNT(*) as packet_count
                FROM icmp_packets
                WHERE timestamp > ?
                GROUP BY src_ip, dst_ip
                HAVING packet_count > ?
            """, (current_time - self.time_window, self.threshold))
            
            # Store results locally
            icmp_floods = []
            for row in db_cursor.fetchall():
                icmp_floods.append(row)
            
            for src_ip, dst_ip, count in icmp_floods:
                # Prevent alert flooding by limiting alerts per source IP
                if src_ip in self.last_alert_time and (current_time - self.last_alert_time[src_ip]) < 300:  # 5 minutes
                    continue
                    
                alert_msg = f"Potential ICMP Flood Attack: {src_ip} sent {count} ICMP packets to {dst_ip} in {self.time_window} seconds"
                alerts.append(alert_msg)
                self.last_alert_time[src_ip] = current_time
                
                # Add alert to x_alerts
                self.add_alert(src_ip, alert_msg)
                
                # Get ICMP types distribution
                db_cursor.execute("""
                    SELECT icmp_type, COUNT(*) as type_count
                    FROM icmp_packets
                    WHERE src_ip = ? AND dst_ip = ? AND timestamp > ?
                    GROUP BY icmp_type
                    ORDER BY type_count DESC
                """, (src_ip, dst_ip, current_time - self.time_window))
                
                # Store results locally
                icmp_types = []
                for row in db_cursor.fetchall():
                    icmp_types.append(row)
                
                if icmp_types:
                    type_info = ", ".join([f"Type {t}: {c}" for t, c in icmp_types[:3]])  # Show top 3 types
                    type_detail_msg = f"  ICMP Type Distribution: {type_info}"
                    alerts.append(type_detail_msg)
                    
                    # Add details as a separate alert
                    self.add_alert(src_ip, type_detail_msg)
                
                # Add threat intelligence data
                self._add_threat_intel(src_ip, {
                    "dst_ip": dst_ip,
                    "packet_count": count,
                    "time_window": self.time_window,
                    "icmp_types": dict(icmp_types)
                })
            
            return alerts
        except Exception as e:
            error_msg = f"Error in ICMP Flood rule: {str(e)}"
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
                "type": "icmp_flood", 
                "confidence": 0.85,  # Confidence level (0-1)
                "source": self.name,  # Rule name as source
                "first_seen": time.time(),
                "details": {
                    # Detailed JSON information 
                    "detection_details": details_dict
                },
                # Extended columns for easy querying
                "protocol": "ICMP",
                "destination_ip": details_dict.get("dst_ip"),
                "packet_count": details_dict.get("packet_count"),
                "detection_method": "packet_frequency_analysis"
            }
            
            # Update threat intelligence in x_ip_threat_intel
            return self.analysis_manager.update_threat_intel(ip_address, threat_data)
        except Exception as e:
            logging.error(f"Error adding threat intelligence data: {e}")
            return False
    
    def update_param(self, param_name, value):
        """Update a configurable parameter"""
        if param_name in self.configurable_params:
            if param_name == "threshold":
                self.threshold = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
            elif param_name == "time_window":
                self.time_window = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
        return False
    
    def get_params(self):
        """Get configurable parameters"""
        return self.configurable_params