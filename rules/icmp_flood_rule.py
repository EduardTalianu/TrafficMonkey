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
    
    def analyze(self, db_cursor):
        alerts = []
        pending_alerts = []  # List for storing alerts to be queued after analysis
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
                
                # Add to pending alerts for queueing
                pending_alerts.append((src_ip, alert_msg, self.name))
                
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
                    alerts.append(f"  ICMP Type Distribution: {type_info}")
            
            # Queue all pending alerts AFTER all database operations are complete
            for ip, msg, rule_name in pending_alerts:
                try:
                    self.db_manager.queue_alert(ip, msg, rule_name)
                except Exception as e:
                    logging.error(f"Error queueing alert: {e}")
            
            return alerts
        except Exception as e:
            error_msg = f"Error in ICMP Flood rule: {str(e)}"
            logging.error(error_msg)
            # Try to queue the error alert
            try:
                self.db_manager.queue_alert("127.0.0.1", error_msg, self.name)
            except Exception as e:
                logging.error(f"Failed to queue error alert: {e}")
            return [error_msg]
    
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