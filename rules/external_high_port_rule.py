# Updated HighPortConnectionRule
# Note: Rule class is injected into the namespace by the RuleLoader
import logging
import ipaddress

class HighPortConnectionRule(Rule):
    def __init__(self):
        super().__init__(
            name="External High Port Detector",
            description="Detects external connections to/from high port numbers (excludes local and multicast traffic)"
        )
        self.port_threshold = 10000  # Higher threshold to reduce overlap with ProtocolAnomalyRule
        self.min_bytes = 50         # Minimum bytes to consider
        self.exclude_common = True  # Exclude known high ports
        self.common_excluded_ports = {8080, 8443, 3389, 5900, 6667, 9000, 9001, 9090}  # Common legitimate high ports
        
        # Common ports that clients connect to (should ignore high source ports connecting to these)
        self.common_destination_ports = {80, 443, 8080, 8443, 53, 123}
        
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
    
    def is_multicast_ip(self, ip):
        """Check if an IP is a multicast or broadcast address"""
        # Remove port if present
        if ":" in ip:
            ip = ip.split(":")[0]
            
        try:
            # Check for multicast and broadcast patterns
            if ip.startswith("224.") or ip.startswith("239.") or ip.endswith(".255"):
                return True
                
            # More precise check using ipaddress module
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_multicast or ip_obj.is_broadcast
        except:
            return False  # If we can't parse it, assume it's not multicast
    
    def is_excluded_port(self, port):
        """Check if this port should be excluded"""
        if not self.exclude_common:
            return False
        return port in self.common_excluded_ports
    
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
                
                # Store results locally 
                connections = []
                for row in db_cursor.fetchall():
                    connections.append(row)
                
                for connection_key, src_ip, dst_ip, total_bytes, packet_count in connections:
                    # Skip if both IPs are local
                    if self.is_local_ip(src_ip) and self.is_local_ip(dst_ip):
                        continue
                        
                    # Skip multicast/broadcast traffic
                    if self.is_multicast_ip(dst_ip) or self.is_multicast_ip(src_ip):
                        continue
                        
                    # Try to extract ports from connection string
                    src_port = self._extract_port_from_str(src_ip)
                    dst_port = self._extract_port_from_str(dst_ip)
                    
                    # Skip excluded ports
                    if (dst_port and self.is_excluded_port(dst_port)) or (src_port and self.is_excluded_port(src_port)):
                        continue
                    
                    # Skip local high source ports going to common destinations (e.g., web browsing)
                    if self.is_local_ip(src_ip) and not self.is_local_ip(dst_ip) and dst_port in self.common_destination_ports:
                        continue

                    # Skip connection to high destination ports in the local network
                    if not self.is_local_ip(src_ip) and self.is_local_ip(dst_ip) and dst_port and dst_port > self.port_threshold:
                        continue
                    
                    # Alert on very high destination ports on external targets only
                    if dst_port and dst_port > self.port_threshold and not self.is_local_ip(dst_ip):
                        alerts.append(f"ALERT: External very high destination port connection from {src_ip} to {dst_ip} (port {dst_port}, {total_bytes/1024:.2f} KB)")
                    
                    # Alert on very high source ports from external sources only
                    elif src_port and src_port > self.port_threshold and not self.is_local_ip(src_ip):
                        alerts.append(f"ALERT: External very high source port connection from {src_ip} (port {src_port}) to {dst_ip} ({total_bytes/1024:.2f} KB)")
                
                return alerts
            
            # Use proper port columns when available
            # Query for connections with very high ports (either source or destination)
            query = """
                SELECT src_ip, dst_ip, src_port, dst_port, total_bytes, packet_count 
                FROM connections
                WHERE (src_port > ? OR dst_port > ?) AND total_bytes > ?
            """
            
            db_cursor.execute(query, (self.port_threshold, self.port_threshold, self.min_bytes))
            
            # Store results locally
            high_port_connections = []
            for row in db_cursor.fetchall():
                high_port_connections.append(row)
            
            for src_ip, dst_ip, src_port, dst_port, total_bytes, packet_count in high_port_connections:
                # Skip if both IPs are local
                if self.is_local_ip(src_ip) and self.is_local_ip(dst_ip):
                    continue
                
                # Skip multicast/broadcast traffic
                if self.is_multicast_ip(dst_ip) or self.is_multicast_ip(src_ip):
                    continue
                
                # Skip excluded ports
                if (dst_port and self.is_excluded_port(dst_port)) or (src_port and self.is_excluded_port(src_port)):
                    continue
                
                # Skip local high source ports going to common destinations (e.g., web browsing)
                if self.is_local_ip(src_ip) and not self.is_local_ip(dst_ip) and dst_port in self.common_destination_ports:
                    continue

                # Skip connection to high destination ports in the local network
                if not self.is_local_ip(src_ip) and self.is_local_ip(dst_ip) and dst_port > self.port_threshold:
                    continue
                
                # Alert on very high destination ports on external targets only
                if dst_port > self.port_threshold and not self.is_local_ip(dst_ip):
                    alerts.append(f"ALERT: External very high destination port connection from {src_ip}:{src_port} to {dst_ip}:{dst_port} ({total_bytes/1024:.2f} KB)")
                
                # Alert on very high source ports from external sources only
                elif src_port > self.port_threshold and not self.is_local_ip(src_ip):
                    alerts.append(f"ALERT: External very high source port connection from {src_ip}:{src_port} to {dst_ip}:{dst_port} ({total_bytes/1024:.2f} KB)")
                    
            return alerts
                
        except Exception as e:
            error_msg = f"ERROR in External High Port Detector: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
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
                "default": 10000,
                "current": self.port_threshold,
                "description": "Very high port number threshold (reduces overlap with ProtocolAnomalyRule)"
            },
            "min_bytes": {
                "type": "int",
                "default": 50,
                "current": self.min_bytes,
                "description": "Minimum bytes to trigger detection (filters noise)"
            },
            "exclude_common": {
                "type": "bool",
                "default": True,
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