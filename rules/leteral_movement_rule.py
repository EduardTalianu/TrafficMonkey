# Rule class is injected by the RuleLoader
import logging
import time
import ipaddress

class LateralMovementRule(Rule):
    """Rule that detects signs of lateral movement within internal networks"""
    def __init__(self):
        super().__init__(
            name="Lateral Movement Detection",
            description="Detects when a host connects to multiple internal systems, particularly using administrative protocols"
        )
        self.check_interval = 600  # Seconds between checks
        self.last_check_time = 0
        
        # Administrative/management protocols often used in lateral movement
        self.admin_ports = {
            22: "SSH",
            23: "Telnet",
            445: "SMB",
            135: "RPC",
            139: "NetBIOS",
            3389: "RDP",
            5985: "WinRM-HTTP",
            5986: "WinRM-HTTPS",
            1433: "MSSQL",
            3306: "MySQL",
            5432: "PostgreSQL"
        }
        
        # Thresholds
        self.min_target_hosts = 3  # Minimum hosts targeted to consider lateral movement
        self.connection_window = 600  # Time window in seconds (10 min)
        self.min_admin_protocols = 1  # Minimum admin protocols used
        
        # Detection state
        self.detected_movements = {}  # Track detected lateral movements
    
    def is_internal_ip(self, ip):
        """Check if an IP is internal/private"""
        try:
            # Remove port if present
            if ":" in ip:
                ip = ip.split(":")[0]
                
            # Check if this is a private address
            return ipaddress.ip_address(ip).is_private
        except:
            return False  # If we can't parse it, assume it's not internal
    
    def analyze(self, db_cursor):
        alerts = []
        current_time = time.time()
        
        # Only run periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Find hosts that have connected to multiple internal hosts
            db_cursor.execute("""
                SELECT src_ip, COUNT(DISTINCT dst_ip) as target_count
                FROM connections
                WHERE timestamp > datetime('now', ? || ' seconds')
                GROUP BY src_ip
                HAVING target_count >= ?
            """, (f"-{self.connection_window}", self.min_target_hosts))
            
            for src_ip, target_count in db_cursor.fetchall():
                # Get the targets
                db_cursor.execute("""
                    SELECT DISTINCT dst_ip
                    FROM connections
                    WHERE src_ip = ? AND timestamp > datetime('now', ? || ' seconds')
                """, (src_ip, f"-{self.connection_window}"))
                
                # Filter to only internal targets
                targets = [row[0] for row in db_cursor.fetchall()]
                internal_targets = [t for t in targets if self.is_internal_ip(t)]
                
                # Skip if not enough internal targets
                if len(internal_targets) < self.min_target_hosts:
                    continue
                
                # Check for administrative protocols used
                admin_protocol_count = 0
                admin_targets = {}
                
                # For each admin port, check if it was used
                for admin_port, protocol_name in self.admin_ports.items():
                    db_cursor.execute("""
                        SELECT DISTINCT dst_ip
                        FROM connections
                        WHERE src_ip = ? AND dst_port = ? AND timestamp > datetime('now', ? || ' seconds')
                    """, (src_ip, admin_port, f"-{self.connection_window}"))
                    
                    admin_targets[protocol_name] = [row[0] for row in db_cursor.fetchall()]
                    
                    if admin_targets[protocol_name]:
                        admin_protocol_count += 1
                
                # Skip if not enough admin protocols
                if admin_protocol_count < self.min_admin_protocols:
                    continue
                
                # Calculate total admin connections
                total_admin_connections = sum(len(targets) for targets in admin_targets.values())
                
                # Alert if this is a new detection
                alert_key = f"{src_ip}-lateral"
                
                if alert_key not in self.detected_movements:
                    self.detected_movements[alert_key] = current_time
                    
                    # Prepare targets information
                    protocols_used = []
                    for protocol, protocol_targets in admin_targets.items():
                        if protocol_targets:
                            targets_str = ", ".join(protocol_targets[:3])
                            if len(protocol_targets) > 3:
                                targets_str += f" and {len(protocol_targets) - 3} more"
                            protocols_used.append(f"{protocol} to {targets_str}")
                    
                    # Create main alert
                    alerts.append(f"Lateral movement detected: {src_ip} connected to {len(internal_targets)} internal hosts using {admin_protocol_count} administrative protocols")
                    
                    # Add details about protocols and targets
                    for protocol_info in protocols_used:
                        alerts.append(f"  - Used {protocol_info}")
            
            # Clean up old detections (after 12 hours)
            old_movements = [k for k, t in self.detected_movements.items() if current_time - t > 43200]
            for key in old_movements:
                self.detected_movements.pop(key, None)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Lateral Movement Detection rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def get_params(self):
        return {
            "check_interval": {
                "type": "int",
                "default": 600,
                "current": self.check_interval,
                "description": "Seconds between rule checks"
            },
            "min_target_hosts": {
                "type": "int",
                "default": 3,
                "current": self.min_target_hosts,
                "description": "Minimum internal hosts accessed to trigger alert"
            },
            "connection_window": {
                "type": "int",
                "default": 3600,
                "current": self.connection_window,
                "description": "Time window in seconds for analysis"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "check_interval":
            self.check_interval = int(value)
            return True
        elif param_name == "min_target_hosts":
            self.min_target_hosts = int(value)
            return True
        elif param_name == "connection_window":
            self.connection_window = int(value)
            return True
        return False