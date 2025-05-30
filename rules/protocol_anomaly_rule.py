# Rule class is injected by the RuleLoader
import logging
import time

class ProtocolAnomalyRule(Rule):
    """Rule that detects unusual protocol usage on non-standard ports"""
    def __init__(self):
        super().__init__("Protocol Anomaly Detection", "Detects applications using unexpected protocols or ports")
        self.min_bytes = 15000  # Increased threshold to reduce false positives (15KB)
        self.ignore_outbound_high_ports = True  # Ignore client-side high ports for outbound connections
        self.known_services = {
            # Well-known service ports
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            465: "SMTPS",
            587: "Submission",
            993: "IMAPS",
            995: "POP3S",
            3389: "RDP"
        }
        self.suspicious_ports = {
            # Potentially suspicious service port combinations
            "HTTP": [22, 23, 25, 445, 3389],  # HTTP on SSH, Telnet, SMTP, SMB or RDP ports
            "SSH": [80, 443, 8080, 8443],     # SSH on HTTP ports
            "RDP": [80, 443, 8080]            # RDP on HTTP ports
        }
        # Common outbound ports that should not be flagged when local machine initiates connections
        self.common_outbound_ports = {80, 443, 8080, 8443, 53}
        
        # Store reference to analysis_manager (will be set later when analysis_manager is available)
        self.analysis_manager = None
    
    def detect_protocol(self, dst_port, total_bytes):
        """Attempt to determine protocol based on port and traffic pattern"""
        if dst_port in self.known_services:
            return self.known_services[dst_port]
        elif dst_port >= 8000 and dst_port <= 8999:
            return "HTTP/ALT"  # Common alternative HTTP ports
        elif dst_port >= 9000 and dst_port <= 9999:
            return "APPLICATION"  # Common application server ports
        elif dst_port > 49152 and dst_port <= 65535:
            return "EPHEMERAL"  # Dynamic/private ports
        else:
            return f"UNKNOWN:{dst_port}"
    
    def is_local_ip(self, ip):
        """Check if an IP belongs to a private network"""
        # Simple check for common private IP ranges
        return (ip.startswith("192.168.") or 
                ip.startswith("10.") or 
                ip.startswith("172.16.") or 
                ip.startswith("172.17.") or 
                ip.startswith("172.18.") or 
                ip.startswith("172.19.") or 
                ip.startswith("172.20.") or 
                ip.startswith("172.21.") or 
                ip.startswith("172.22.") or 
                ip.startswith("172.23.") or 
                ip.startswith("172.24.") or 
                ip.startswith("172.25.") or 
                ip.startswith("172.26.") or 
                ip.startswith("172.27.") or 
                ip.startswith("172.28.") or 
                ip.startswith("172.29.") or 
                ip.startswith("172.30.") or 
                ip.startswith("172.31."))
    
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
            # Check if port columns exist
            columns = [row[1] for row in db_cursor.execute("PRAGMA table_info(connections)").fetchall()]
            if "src_port" not in columns or "dst_port" not in columns:
                error_msg = "Protocol Anomaly rule requires port information to be captured"
                self.add_alert("127.0.0.1", error_msg)
                return [error_msg]
            
            # Look for significant connections
            db_cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port, total_bytes
                FROM connections
                WHERE total_bytes > ?
                ORDER BY timestamp DESC
                LIMIT 1000
            """, (self.min_bytes,))
            
            # Store results locally to avoid keeping the cursor active
            recent_connections = []
            for row in db_cursor.fetchall():
                recent_connections.append(row)
            
            # Track what we've already alerted on to avoid duplicates
            alerted_pairs = set()
            
            for src_ip, dst_ip, src_port, dst_port, total_bytes in recent_connections:
                # Skip if we can't determine both ports
                if not src_port or not dst_port:
                    continue
                
                # Detect direction of connection (outbound vs inbound)
                is_outbound = self.is_local_ip(src_ip) and not self.is_local_ip(dst_ip)
                is_inbound = not self.is_local_ip(src_ip) and self.is_local_ip(dst_ip)
                
                # Skip outbound connections to common services if ignore_outbound_high_ports is enabled
                if is_outbound and self.ignore_outbound_high_ports:
                    if dst_port in self.common_outbound_ports:
                        continue
                
                # Skip inbound connections to high client ports if ignore_outbound_high_ports is enabled
                if is_inbound and self.ignore_outbound_high_ports:
                    if dst_port > 1024 and src_port in self.common_outbound_ports:
                        continue
                
                # Detect the likely protocol based on destination port
                protocol = self.detect_protocol(dst_port, total_bytes)
                
                # Connection identifier
                conn_id = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
                
                # Skip if we've already alerted on this connection
                if conn_id in alerted_pairs:
                    continue
                
                # Check for suspicious port usage based on our rules
                alert_triggered = False
                
                # Case 1: Known protocol on unusual port
                base_protocol = protocol.split(':')[0] if ':' in protocol else protocol
                if base_protocol in self.suspicious_ports:
                    suspicious_list = self.suspicious_ports[base_protocol]
                    if dst_port in suspicious_list:
                        alert_msg = f"Protocol anomaly: Possible {base_protocol} traffic on suspicious port: {conn_id} ({total_bytes/1024:.2f} KB)"
                        # Add to immediate alerts list for UI
                        alerts.append(alert_msg)
                        
                        # Add to x_alerts table - use the destination IP as it's the suspicious service
                        self.add_alert(dst_ip, alert_msg)
                        
                        # Add threat intelligence to x_ip_threat_intel
                        self._add_protocol_anomaly_data(src_ip, dst_ip, base_protocol, dst_port, total_bytes, "unusual_port")
                        
                        alert_triggered = True
                
                # Case 2: Unusual high ports with significant data - but only for communication between non-local machines
                # or when a local machine is receiving data on unusual ports (potential backdoor)
                if not alert_triggered and dst_port > 1024 and dst_port not in self.known_services:
                    # Skip common outbound web traffic patterns (local machine -> internet)
                    if is_outbound and src_port > 1024 and dst_port in (80, 443, 8080, 8443):
                        continue
                        
                    # For inbound, only alert on uncommon destination ports (not ephemeral)
                    if is_inbound and dst_port > 49000:
                        continue
                        
                    # Alert on high data volumes on unusual ports
                    if base_protocol == "UNKNOWN" and total_bytes > self.min_bytes * 2:
                        alert_msg = f"Protocol anomaly: High data volume ({total_bytes/1024:.2f} KB) on unusual port: {conn_id}"
                        # Add to immediate alerts list for UI
                        alerts.append(alert_msg)
                        
                        # Add to x_alerts table
                        self.add_alert(dst_ip, alert_msg)
                        
                        # Add threat intelligence to x_ip_threat_intel
                        self._add_protocol_anomaly_data(src_ip, dst_ip, "UNKNOWN", dst_port, total_bytes, "high_volume")
                        
                        alert_triggered = True
                
                # Mark this connection as processed
                if alert_triggered:
                    alerted_pairs.add(conn_id)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Protocol Anomaly rule: {str(e)}"
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
    
    def _add_protocol_anomaly_data(self, src_ip, dst_ip, protocol, dst_port, total_bytes, anomaly_type):
        """Add protocol anomaly data to x_ip_threat_intel"""
        try:
            # Build threat intelligence data
            threat_data = {
                "score": 5.0,  # Medium score for protocol anomalies
                "type": "protocol_anomaly",
                "confidence": 0.7,
                "source": self.name,
                "first_seen": time.time(),
                "details": {
                    "protocol": protocol,
                    "port": dst_port,
                    "destination": dst_ip,
                    "bytes_transferred": total_bytes,
                    "anomaly_type": anomaly_type,
                    "detection_method": "port_protocol_analysis"
                },
                # Extended columns for better queryability
                "protocol": protocol,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "bytes_transferred": total_bytes,
                "detection_method": "port_protocol_analysis"
            }
            
            # Update threat intelligence in x_ip_threat_intel
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding protocol anomaly data: {e}")
            return False
    
    def get_params(self):
        return {
            "min_bytes": {
                "type": "int",
                "default": 15000,
                "current": self.min_bytes,
                "description": "Minimum bytes to consider a significant connection"
            },
            "ignore_outbound_high_ports": {
                "type": "bool",
                "default": True,
                "current": self.ignore_outbound_high_ports,
                "description": "Ignore client high ports for outbound connections (reduces false positives)"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "min_bytes":
            self.min_bytes = int(value)
            return True
        elif param_name == "ignore_outbound_high_ports":
            self.ignore_outbound_high_ports = bool(value)
            return True
        return False