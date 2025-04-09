# Rule class is injected by the RuleLoader
import time
import logging

class DDoSDetectionRule(Rule):
    """Rule that detects distributed denial of service attacks"""
    def __init__(self):
        super().__init__("DDoS Attack Detection", "Detects patterns of distributed denial of service attacks")
        self.connection_threshold = 100  # Minimum connections to same destination to trigger alert
        self.time_window = 300           # Time window in seconds (5 minutes)
        self.min_unique_sources = 10     # Minimum unique source IPs to consider DDoS
        self.check_interval = 60         # Seconds between checks
        self.last_check_time = 0
        self.analysis_manager = None     # Will be set by access to db_manager.analysis_manager
    
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
        
        # Only run this rule periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Find destinations with high connection counts from multiple sources
            db_cursor.execute("""
                SELECT dst_ip, COUNT(*) as connection_count, COUNT(DISTINCT src_ip) as unique_sources
                FROM connections
                WHERE timestamp > datetime('now', ? || ' seconds')
                GROUP BY dst_ip
                HAVING connection_count > ? AND unique_sources > ?
            """, (f"-{self.time_window}", self.connection_threshold, self.min_unique_sources))
            
            # Store results locally
            potential_targets = []
            for row in db_cursor.fetchall():
                potential_targets.append(row)
            
            for dst_ip, conn_count, unique_sources in potential_targets:
                # Get the top source IPs
                db_cursor.execute("""
                    SELECT src_ip, COUNT(*) as conn_count
                    FROM connections
                    WHERE dst_ip = ? AND timestamp > datetime('now', ? || ' seconds')
                    GROUP BY src_ip
                    ORDER BY conn_count DESC
                    LIMIT 5
                """, (dst_ip, f"-{self.time_window}"))
                
                # Store source info for threat intel
                sources_data = {}
                for row in db_cursor.fetchall():
                    sources_data[row[0]] = row[1]
                
                top_sources = [f"{src} ({count} conns)" for src, count in sources_data.items()]
                
                alert_msg = (f"Potential DDoS attack detected: {dst_ip} received {conn_count} connections "
                           f"from {unique_sources} unique sources in the last {self.time_window/60:.1f} minutes")
                
                sources_msg = f"Top sources: {', '.join(top_sources)}"
                
                alerts.append(alert_msg)
                alerts.append(sources_msg)
                
                # Add alerts to x_alerts
                self.add_alert(dst_ip, alert_msg)
                self.add_alert(dst_ip, sources_msg)
                
                # Add threat intelligence data for the target
                self._add_threat_intel(dst_ip, {
                    "connection_count": conn_count,
                    "unique_sources": unique_sources,
                    "top_sources": sources_data,
                    "time_window": self.time_window,
                    "victim": True  # Mark as victim
                })
                
                # Also add threat intelligence for the top attackers
                for src_ip, conn_count in sources_data.items():
                    self._add_threat_intel(src_ip, {
                        "target_ip": dst_ip,
                        "connection_count": conn_count,
                        "total_attack_connections": conn_count,
                        "time_window": self.time_window,
                        "attacker": True  # Mark as attacker
                    }, is_attacker=True)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in DDoS Detection rule: {str(e)}"
            logging.error(error_msg)
            self.add_alert("127.0.0.1", error_msg)
            return [error_msg]
    
    def add_alert(self, ip_address, alert_message):
        """Add an alert to the x_alerts table"""
        if self.analysis_manager:
            return self.analysis_manager.add_alert(ip_address, alert_message, self.name)
        return False
    
    def _add_threat_intel(self, ip_address, details_dict, is_attacker=False):
        """Store threat intelligence data in x_ip_threat_intel"""
        try:
            # Set different scores based on whether this is victim or attacker
            score = 5.0 if details_dict.get("victim", False) else 7.5
            if is_attacker:
                score = 8.0  # Higher score for attackers
            
            # Create threat intelligence data
            threat_data = {
                "score": score,  # Severity score (0-10)
                "type": "ddos_attack" if is_attacker else "ddos_victim", 
                "confidence": 0.85,  # Confidence level (0-1)
                "source": self.name,  # Rule name as source
                "first_seen": time.time(),
                "details": {
                    # Detailed JSON information 
                    "detection_details": details_dict
                },
                # Extended columns for easy querying
                "protocol": "MULTIPLE",
                "destination_ip": details_dict.get("target_ip") if is_attacker else None,
                "detection_method": "connection_volume_analysis",
                "packet_count": details_dict.get("connection_count", 0)
            }
            
            # Update threat intelligence in x_ip_threat_intel
            return self.analysis_manager.update_threat_intel(ip_address, threat_data)
        except Exception as e:
            logging.error(f"Error adding threat intelligence data: {e}")
            return False
    
    def get_params(self):
        return {
            "connection_threshold": {
                "type": "int",
                "default": 100,
                "current": self.connection_threshold,
                "description": "Minimum connections to trigger alert"
            },
            "time_window": {
                "type": "int",
                "default": 300,
                "current": self.time_window,
                "description": "Time window in seconds to analyze"
            },
            "min_unique_sources": {
                "type": "int",
                "default": 10,
                "current": self.min_unique_sources,
                "description": "Minimum unique sources for DDoS pattern"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "connection_threshold":
            self.connection_threshold = int(value)
            return True
        elif param_name == "time_window":
            self.time_window = int(value)
            return True
        elif param_name == "min_unique_sources":
            self.min_unique_sources = int(value)
            return True
        return False