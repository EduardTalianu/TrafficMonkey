# Rule class is injected by the RuleLoader
import time

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
        current_time = time.time()
        
        # Check if icmp_packets table exists, create if not
        db_cursor.execute("""
            CREATE TABLE IF NOT EXISTS icmp_packets (
                src_ip TEXT,
                dst_ip TEXT,
                icmp_type INTEGER,
                timestamp REAL
            )
        """)
        
        # Look for ICMP flood patterns
        db_cursor.execute("""
            SELECT src_ip, dst_ip, COUNT(*) as packet_count
            FROM icmp_packets
            WHERE timestamp > ?
            GROUP BY src_ip, dst_ip
            HAVING packet_count > ?
        """, (current_time - self.time_window, self.threshold))
        
        icmp_floods = db_cursor.fetchall()
        for src_ip, dst_ip, count in icmp_floods:
            # Prevent alert flooding by limiting alerts per source IP
            if src_ip in self.last_alert_time and (current_time - self.last_alert_time[src_ip]) < 300:  # 5 minutes
                continue
                
            alerts.append(f"Potential ICMP Flood Attack: {src_ip} sent {count} ICMP packets to {dst_ip} in {self.time_window} seconds")
            self.last_alert_time[src_ip] = current_time
            
            # Retrieve ICMP types distribution
            db_cursor.execute("""
                SELECT icmp_type, COUNT(*) as type_count
                FROM icmp_packets
                WHERE src_ip = ? AND dst_ip = ? AND timestamp > ?
                GROUP BY icmp_type
                ORDER BY type_count DESC
            """, (src_ip, dst_ip, current_time - self.time_window))
            
            icmp_types = db_cursor.fetchall()
            type_info = ", ".join([f"Type {t}: {c}" for t, c in icmp_types[:3]])  # Show top 3 types
            alerts.append(f"  ICMP Type Distribution: {type_info}")
        
        return alerts
    
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