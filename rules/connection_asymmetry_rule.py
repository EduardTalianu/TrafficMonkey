# Rule class is injected by the RuleLoader

class ConnectionAsymmetryRule(Rule):
    """Rule that detects unusual asymmetry in connection traffic volumes"""
    def __init__(self):
        super().__init__("Connection Asymmetry Detection", "Detects significant differences between inbound and outbound traffic volumes")
        self.asymmetry_ratio = 10.0  # Ratio of outbound to inbound traffic (or vice versa) to consider asymmetric
        self.min_bytes = 10000       # Minimum total bytes to consider
        self.exclude_common = True   # Exclude common services (web, streaming) that are naturally asymmetric
    
    def analyze(self, db_cursor):
        alerts = []
        
        try:
            # This rule requires tracking both directions of a connection
            # We need to analyze src/dst IP pairs regardless of the specific ports
            
            # Get all significant connections
            db_cursor.execute("""
                SELECT src_ip, dst_ip, SUM(total_bytes) as bytes
                FROM connections
                WHERE total_bytes > ?
                GROUP BY src_ip, dst_ip
            """, (self.min_bytes / 10,))  # Set a lower threshold for the query
            
            all_connections = db_cursor.fetchall()
            
            # Create a mapping of connections by IP pair (ignoring direction)
            connection_map = {}
            
            for src_ip, dst_ip, bytes_transferred in all_connections:
                # Create a normalized key regardless of direction (alphabetical order)
                ip_pair = tuple(sorted([src_ip, dst_ip]))
                
                if ip_pair not in connection_map:
                    connection_map[ip_pair] = {
                        src_ip: bytes_transferred,
                        dst_ip: 0
                    }
                else:
                    # Update the appropriate direction
                    if src_ip in connection_map[ip_pair]:
                        connection_map[ip_pair][src_ip] += bytes_transferred
                    else:
                        connection_map[ip_pair][dst_ip] += bytes_transferred
            
            # Check for asymmetric connections
            for ip_pair, direction_data in connection_map.items():
                # Extract the two IPs
                ip1, ip2 = ip_pair
                
                # Get bytes transferred in each direction
                bytes_ip1_to_ip2 = direction_data.get(ip1, 0)
                bytes_ip2_to_ip1 = direction_data.get(ip2, 0)
                
                # Check for common service ports if exclude_common is enabled
                if self.exclude_common:
                    # Skip if either IP is using common asymmetric services
                    db_cursor.execute("""
                        SELECT dst_port
                        FROM connections 
                        WHERE (src_ip = ? AND dst_ip = ?) OR (src_ip = ? AND dst_ip = ?)
                    """, (ip1, ip2, ip2, ip1))
                    
                    ports = [row[0] for row in db_cursor.fetchall() if row[0]]
                    
                    # Check for common service ports that are naturally asymmetric
                    common_asymmetric_ports = {80, 443, 8080, 8443, 25, 110, 143, 993, 995}
                    if any(port in common_asymmetric_ports for port in ports):
                        continue
                
                # Skip if total bytes are too low
                total_bytes = bytes_ip1_to_ip2 + bytes_ip2_to_ip1
                if total_bytes < self.min_bytes:
                    continue
                
                # Calculate asymmetry
                # Avoid division by zero
                if bytes_ip1_to_ip2 == 0:
                    bytes_ip1_to_ip2 = 1
                if bytes_ip2_to_ip1 == 0:
                    bytes_ip2_to_ip1 = 1
                    
                ratio_1_to_2 = bytes_ip1_to_ip2 / bytes_ip2_to_ip1
                ratio_2_to_1 = bytes_ip2_to_ip1 / bytes_ip1_to_ip2
                
                # Determine if there's a significant asymmetry
                if ratio_1_to_2 >= self.asymmetry_ratio:
                    alert_msg = (f"Traffic asymmetry detected: {ip1} sent {bytes_ip1_to_ip2/1024:.1f} KB to {ip2}, "
                                f"but received only {bytes_ip2_to_ip1/1024:.1f} KB (ratio: {ratio_1_to_2:.1f}x)")
                    alerts.append(alert_msg)
                    
                elif ratio_2_to_1 >= self.asymmetry_ratio:
                    alert_msg = (f"Traffic asymmetry detected: {ip2} sent {bytes_ip2_to_ip1/1024:.1f} KB to {ip1}, "
                                f"but received only {bytes_ip1_to_ip2/1024:.1f} KB (ratio: {ratio_2_to_1:.1f}x)")
                    alerts.append(alert_msg)
            
            return alerts
        except Exception as e:
            return [f"Error in Connection Asymmetry rule: {str(e)}"]
    
    def get_params(self):
        return {
            "asymmetry_ratio": {
                "type": "float",
                "default": 10.0,
                "current": self.asymmetry_ratio,
                "description": "Ratio threshold for traffic asymmetry"
            },
            "min_bytes": {
                "type": "int",
                "default": 10000,
                "current": self.min_bytes,
                "description": "Minimum bytes to analyze for asymmetry"
            },
            "exclude_common": {
                "type": "bool",
                "default": True,
                "current": self.exclude_common,
                "description": "Exclude naturally asymmetric services (web, email)"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "asymmetry_ratio":
            self.asymmetry_ratio = float(value)
            return True
        elif param_name == "min_bytes":
            self.min_bytes = int(value)
            return True
        elif param_name == "exclude_common":
            self.exclude_common = bool(value)
            return True
        return False