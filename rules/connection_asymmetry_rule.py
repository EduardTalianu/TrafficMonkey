# Rule class is injected by the RuleLoader
import logging

class ConnectionAsymmetryRule(Rule):
    """Rule that detects unusual asymmetry in connection traffic volumes"""
    def __init__(self):
        super().__init__("Connection Asymmetry Detection", "Detects significant differences between inbound and outbound traffic volumes")
        self.asymmetry_ratio = 100.0  # Ratio of outbound to inbound traffic (or vice versa) to consider asymmetric
        self.min_bytes = 10000       # Minimum total bytes to consider
        self.exclude_common = True   # Exclude common services (web, streaming) that are naturally asymmetric
        self.analysis_manager = None # Will be set when db_manager is set
    
    def analyze(self, db_cursor):
        # Ensure analysis_manager is linked
        if not self.analysis_manager and hasattr(self.db_manager, 'analysis_manager'):
            self.analysis_manager = self.db_manager.analysis_manager
        
        # Return early if analysis_manager is not available
        if not self.analysis_manager:
            logging.error(f"Cannot run {self.name} rule: analysis_manager not available")
            return [f"ERROR: {self.name} rule requires analysis_manager"]

        # Local list for returning alerts to UI immediately
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
            """, (self.min_bytes / 100,))  # Set a lower threshold for the query
            
            # Store results locally to avoid keeping the cursor active
            all_connections = []
            for row in db_cursor.fetchall():
                all_connections.append(row)
            
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
                
                # Skip null IPs (shouldn't happen, but just in case)
                if not ip1 or not ip2:
                    continue
                
                # Get bytes transferred in each direction
                bytes_ip1_to_ip2 = direction_data.get(ip1, 0)
                bytes_ip2_to_ip1 = direction_data.get(ip2, 0)
                
                # Check for common service ports if exclude_common is enabled
                if self.exclude_common:
                    # Get ports information for this IP pair
                    ports_result = []
                    try:
                        db_cursor.execute("""
                            SELECT dst_port
                            FROM connections 
                            WHERE (src_ip = ? AND dst_ip = ?) OR (src_ip = ? AND dst_ip = ?)
                        """, (ip1, ip2, ip2, ip1))
                        
                        ports_result = db_cursor.fetchall()
                    except Exception as e:
                        logging.error(f"Error fetching ports data: {e}")
                    
                    ports = [row[0] for row in ports_result if row[0]]
                    
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
                    # Add to immediate alerts list for UI
                    alerts.append(alert_msg)
                    
                    # Add alert to x_alerts table
                    self.add_alert(ip2, alert_msg)
                    
                    # Add threat intelligence data
                    self._add_threat_intel(ip1, ip2, {
                        "sent_bytes": bytes_ip1_to_ip2,
                        "received_bytes": bytes_ip2_to_ip1,
                        "ratio": ratio_1_to_2,
                        "type": "outbound_asymmetry"
                    })
                    
                elif ratio_2_to_1 >= self.asymmetry_ratio:
                    alert_msg = (f"Traffic asymmetry detected: {ip2} sent {bytes_ip2_to_ip1/1024:.1f} KB to {ip1}, "
                                f"but received only {bytes_ip1_to_ip2/1024:.1f} KB (ratio: {ratio_2_to_1:.1f}x)")
                    # Add to immediate alerts list for UI
                    alerts.append(alert_msg)
                    
                    # Add alert to x_alerts table
                    self.add_alert(ip1, alert_msg)
                    
                    # Add threat intelligence data
                    self._add_threat_intel(ip2, ip1, {
                        "sent_bytes": bytes_ip2_to_ip1,
                        "received_bytes": bytes_ip1_to_ip2,
                        "ratio": ratio_2_to_1,
                        "type": "outbound_asymmetry"
                    })
            
            return alerts
        except Exception as e:
            error_msg = f"Error in Connection Asymmetry rule: {str(e)}"
            logging.error(error_msg)
            # Try to add the error alert to x_alerts
            try:
                self.add_alert("127.0.0.1", error_msg)
            except:
                pass
            return [error_msg]
    
    def add_alert(self, ip_address, alert_message):
        """Add an alert to the x_alerts table"""
        if self.analysis_manager:
            return self.analysis_manager.add_alert(ip_address, alert_message, self.name)
        return False
    
    def _add_threat_intel(self, src_ip, dst_ip, details_dict):
        """Store threat intelligence data in x_ip_threat_intel"""
        try:
            # Create threat intelligence data
            threat_data = {
                "score": 5.0,  # Medium severity score (0-10)
                "type": "traffic_asymmetry", 
                "confidence": 0.7,  # Confidence level (0-1)
                "source": self.name,  # Rule name as source
                "first_seen": import_time.time(),
                "details": {
                    # Detailed JSON information 
                    "detection_details": details_dict
                },
                # Extended columns for easy querying
                "protocol": "TCP",
                "destination_ip": dst_ip,
                "bytes_transferred": details_dict.get("sent_bytes", 0),
                "detection_method": "traffic_asymmetry_analysis"
            }
            
            # Update threat intelligence in x_ip_threat_intel
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding threat intelligence data: {e}")
            return False
    
    def get_params(self):
        return {
            "asymmetry_ratio": {
                "type": "float",
                "default": 100.0,
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

# Add missing import
import time as import_time