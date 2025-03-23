# This rule detects connections on high-numbered ports but excludes local machine connections
# Note: Rule class is injected into the namespace by the RuleLoader

class HighPortConnectionRule(Rule):
    def __init__(self):
        super().__init__(
            name="External High Port Detector",
            description="Detects connections to/from high port numbers from external machines (excludes local machine traffic)"
        )
        self.port_threshold = 1000  # Default threshold for high port numbers
        self.min_bytes = 50         # Minimum bytes to consider
        self.exclude_common = False  # Set to False to detect all high ports
        self.local_prefixes = ["127.", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", 
                             "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", 
                             "172.29.", "172.30.", "172.31."]  # Common local IP prefixes
        self.local_hostname = self._get_local_hostname()
        
    def _get_local_hostname(self):
        """Get local machine hostname to identify self-connections"""
        import socket
        try:
            return socket.gethostname()
        except:
            return "localhost"
    
    def is_local_ip(self, ip):
        """Check if an IP belongs to the local machine or private network"""
        # Remove port if present
        if ":" in ip:
            ip = ip.split(":")[0]
            
        # Check against common local prefixes
        for prefix in self.local_prefixes:
            if ip.startswith(prefix):
                return True
                
        # Check if it's the loopback address
        if ip.startswith("127."):
            return True
            
        # Check if it matches the hostname
        try:
            import socket
            host_ips = socket.gethostbyname_ex(self.local_hostname)[2]
            if ip in host_ips:
                return True
        except:
            pass
            
        return False
    
    def analyze(self, db_cursor):
        alerts = []
        
        try:
            # Check if port columns exist
            columns = [row[1] for row in db_cursor.execute("PRAGMA table_info(connections)").fetchall()]
            has_port_columns = "src_port" in columns and "dst_port" in columns
            
            if not has_port_columns:
                # Try to use connection_key parsing as fallback
                db_cursor.execute("""
                    SELECT connection_key, src_ip, dst_ip, total_bytes, packet_count
                    FROM connections
                    WHERE total_bytes > ?
                """, (self.min_bytes,))
                
                connections = db_cursor.fetchall()
                
                for connection_key, src_ip, dst_ip, total_bytes, packet_count in connections:
                    # Skip if either IP is local
                    if self.is_local_ip(src_ip) or self.is_local_ip(dst_ip):
                        continue
                        
                    # Try to extract ports from connection string
                    src_port = self._extract_port_from_str(src_ip)
                    dst_port = self._extract_port_from_str(dst_ip)
                    
                    # Alert on high destination ports
                    if dst_port and dst_port > self.port_threshold:
                        alerts.append(f"ALERT: External high destination port connection from {src_ip} to {dst_ip} (port {dst_port}, {total_bytes/1024:.2f} KB)")
                    
                    # Alert on high source ports
                    if src_port and src_port > self.port_threshold:
                        alerts.append(f"ALERT: External high source port connection from {src_ip} (port {src_port}) to {dst_ip} ({total_bytes/1024:.2f} KB)")
                
                return alerts
            
            # Use proper port columns when available
            # Query for connections with high ports (either source or destination)
            query = """
                SELECT src_ip, dst_ip, src_port, dst_port, total_bytes, packet_count 
                FROM connections
                WHERE (src_port > ? OR dst_port > ?) AND total_bytes > ?
            """
            
            db_cursor.execute(query, (self.port_threshold, self.port_threshold, self.min_bytes))
            
            high_port_connections = db_cursor.fetchall()
            
            for src_ip, dst_ip, src_port, dst_port, total_bytes, packet_count in high_port_connections:
                # Skip if either IP is local
                if self.is_local_ip(src_ip) or self.is_local_ip(dst_ip):
                    continue
                
                # Alert on high destination ports
                if dst_port > self.port_threshold:
                    alerts.append(f"ALERT: External high destination port connection from {src_ip}:{src_port} to {dst_ip}:{dst_port} ({total_bytes/1024:.2f} KB)")
                
                # Alert on high source ports
                if src_port > self.port_threshold:
                    alerts.append(f"ALERT: External high source port connection from {src_ip}:{src_port} to {dst_ip}:{dst_port} ({total_bytes/1024:.2f} KB)")
                    
            return alerts
                
        except Exception as e:
            return [f"ERROR in External High Port Detector: {str(e)}"]
    
    def _extract_port_from_str(self, ip_str):
        """Extract port number from IP string if present (format: ip:port)"""
        if isinstance(ip_str, str) and ':' in ip_str:
            try:
                port_part = ip_str.split(':')[-1]
                # Handle potential CIDR notation or other suffixes
                if '/' in port_part:
                    port_part = port_part.split('/')[0]
                return int(port_part)
            except (ValueError, IndexError):
                pass
        return None
    
    def get_params(self):
        return {
            "port_threshold": {
                "type": "int",
                "default": 1000,
                "current": self.port_threshold,
                "description": "Port number threshold (ports above this are considered high)"
            },
            "min_bytes": {
                "type": "int",
                "default": 50,
                "current": self.min_bytes,
                "description": "Minimum bytes to trigger detection (filters noise)"
            },
            "exclude_common": {
                "type": "bool",
                "default": False,
                "current": self.exclude_common,
                "description": "Exclude common high ports to reduce false positives"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "port_threshold":
            self.port_threshold = int(value)
            return True
        elif param_name == "min_bytes":
            self.min_bytes = int(value)
            return True
        elif param_name == "exclude_common":
            self.exclude_common = bool(value)
            return True
        return False