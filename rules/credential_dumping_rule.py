# Rule class is injected by the RuleLoader
import logging
import time
import re

class CredentialDumpingRule(Rule):
    """Rule that detects signs of credential dumping activities"""
    def __init__(self):
        super().__init__(
            name="Credential Dumping Detection",
            description="Detects activities associated with credential harvesting and password dumping"
        )
        self.check_interval = 300  # Seconds between checks
        self.last_check_time = 0
        
        # Known sensitive Windows system paths that contain credentials
        self.sensitive_windows_paths = [
            r"\\windows\\system32\\config\\sam",
            r"\\windows\\ntds\\ntds.dit",
            r"\\windows\\system32\\lsass.exe",
            r"\\windows\\repair\\sam",
            r"\\windows\\system32\\config\\system",
            r"\\windows\\system32\\config\\security"
        ]
        
        # Known sensitive Linux/Unix system paths
        self.sensitive_unix_paths = [
            "/etc/passwd",
            "/etc/shadow",
            "/etc/master.passwd",
            "/etc/security/passwd",
            "/etc/pam.d/",
            "/var/log/secure",
            "/var/log/auth.log"
        ]
        
        # Common credential dumping tools
        self.dumping_tools = [
            "mimikatz",
            "gsecdump",
            "wce",
            "pwdump",
            "procdump",
            "ntdsutil",
            "vssadmin",
            "reg.exe save",
            "reg save",
            "sekurlsa",
            "hashdump"
        ]
        
        # Ports commonly used in credential dumping
        self.suspicious_ports = [445, 137, 138, 389, 636, 88, 464]
        
        self.detected_dumps = {}  # Track previously detected activities
    
    def analyze_http_traffic(self, db_cursor):
        """Check HTTP traffic for credential dumping signatures"""
        alerts = []
        pending_alerts = []
        
        try:
            # First check if http_requests table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='http_requests'
            """)
            
            if not db_cursor.fetchone():
                return [], []  # Skip if table doesn't exist
            
            # Join http_requests with connections to get IPs
            db_cursor.execute("""
                SELECT c.src_ip, c.dst_ip, h.uri, h.host, h.user_agent
                FROM http_requests h
                JOIN connections c ON h.connection_key = c.connection_key
                WHERE h.timestamp > datetime('now', '-30 minutes')
            """)
            
            for src_ip, dst_ip, uri, host, user_agent in db_cursor.fetchall():
                # Skip if not enough data
                if not uri:
                    continue
                
                # Check for tool references in User-Agent
                if user_agent:
                    for tool in self.dumping_tools:
                        if tool.lower() in user_agent.lower():
                            alert_key = f"{src_ip}-{tool}-ua"
                            if alert_key not in self.detected_dumps:
                                self.detected_dumps[alert_key] = time.time()
                                alert_msg = f"Credential dumping tool signature in User-Agent: {src_ip} using {tool} to access {dst_ip}"
                                alerts.append(alert_msg)
                                pending_alerts.append((src_ip, alert_msg, self.name))
                
                # Check for sensitive path access in URI
                lower_uri = uri.lower().replace('/', '\\')
                for sensitive_path in self.sensitive_windows_paths:
                    if sensitive_path.lower() in lower_uri:
                        alert_key = f"{src_ip}-{sensitive_path}"
                        if alert_key not in self.detected_dumps:
                            self.detected_dumps[alert_key] = time.time()
                            alert_msg = f"HTTP access to sensitive Windows credential file: {src_ip} accessing {sensitive_path} on {dst_ip}"
                            alerts.append(alert_msg)
                            pending_alerts.append((src_ip, alert_msg, self.name))
                
                for sensitive_path in self.sensitive_unix_paths:
                    if sensitive_path.lower() in lower_uri.replace('\\', '/'):
                        alert_key = f"{src_ip}-{sensitive_path}"
                        if alert_key not in self.detected_dumps:
                            self.detected_dumps[alert_key] = time.time()
                            alert_msg = f"HTTP access to sensitive Unix credential file: {src_ip} accessing {sensitive_path} on {dst_ip}"
                            alerts.append(alert_msg)
                            pending_alerts.append((src_ip, alert_msg, self.name))
            
            return alerts, pending_alerts
        except Exception as e:
            logging.error(f"Error analyzing HTTP traffic for credential dumping: {e}")
            return [], []
    
    def analyze_smb_traffic(self, db_cursor):
        """Check for suspicious SMB traffic patterns"""
        alerts = []
        pending_alerts = []
        
        try:
            # Look for connections to SMB-related ports with significant data transfer
            ports_str = ','.join(str(p) for p in self.suspicious_ports)
            db_cursor.execute(f"""
                SELECT src_ip, dst_ip, dst_port, total_bytes
                FROM connections
                WHERE dst_port IN ({ports_str})
                AND total_bytes > 10000
                AND timestamp > datetime('now', '-30 minutes')
            """)
            
            for src_ip, dst_ip, dst_port, total_bytes in db_cursor.fetchall():
                # Create a unique key for this alert
                alert_key = f"{src_ip}-{dst_ip}-{dst_port}-smb"
                
                if alert_key not in self.detected_dumps:
                    self.detected_dumps[alert_key] = time.time()
                    
                    # Determine service based on port
                    service = "SMB"
                    if dst_port == 389 or dst_port == 636:
                        service = "LDAP"
                    elif dst_port == 88:
                        service = "Kerberos"
                    
                    alert_msg = f"Potential credential extraction: {src_ip} transferred {total_bytes/1024:.1f} KB from {dst_ip} via {service} (port {dst_port})"
                    alerts.append(alert_msg)
                    pending_alerts.append((src_ip, alert_msg, self.name))
            
            return alerts, pending_alerts
        except Exception as e:
            logging.error(f"Error analyzing SMB traffic for credential dumping: {e}")
            return [], []
    
    def analyze(self, db_cursor):
        all_alerts = []
        all_pending_alerts = []
        current_time = time.time()
        
        # Only run periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Run the specific analysis methods
            http_alerts, http_pending = self.analyze_http_traffic(db_cursor)
            smb_alerts, smb_pending = self.analyze_smb_traffic(db_cursor)
            
            all_alerts.extend(http_alerts)
            all_alerts.extend(smb_alerts)
            
            all_pending_alerts.extend(http_pending)
            all_pending_alerts.extend(smb_pending)
            
            # Clean up old detections (after 12 hours)
            old_detections = [k for k, t in self.detected_dumps.items() if current_time - t > 43200]
            for key in old_detections:
                self.detected_dumps.pop(key, None)
            
            # Queue all pending alerts
            for ip, msg, rule_name in all_pending_alerts:
                try:
                    self.db_manager.queue_alert(ip, msg, rule_name)
                except Exception as e:
                    logging.error(f"Error queueing alert: {e}")
            
            return all_alerts
            
        except Exception as e:
            error_msg = f"Error in Credential Dumping Detection rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def get_params(self):
        return {
            "check_interval": {
                "type": "int",
                "default": 300,
                "current": self.check_interval,
                "description": "Seconds between rule checks"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "check_interval":
            self.check_interval = int(value)
            return True
        return False