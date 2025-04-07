# Updated ProtocolTunnelingRule
# Rule class is injected by the RuleLoader
import time
import math
import logging

class ProtocolTunnelingRule(Rule):
    """Rule that detects protocol tunneling (one protocol encapsulated in another, excluding DNS)"""
    def __init__(self):
        super().__init__("Protocol Tunneling Detection", "Detects when one protocol is being tunneled inside another (focusing on HTTP, ICMP and SSH tunneling)")
        self.check_interval = 600  # Seconds between rule checks
        self.min_http_content_length = 5000  # Minimum HTTP content length to analyze
        self.http_timing_variance_threshold = 0.3  # Threshold for HTTP timing variance
        self.unusual_user_agent_patterns = ["tun", "vpn", "shell", "proxy", "tunnel"]
        self.last_check_time = 0
        
        # Store reference to analysis_manager (will be set later when analysis_manager is available)
        self.analysis_manager = None
    
    def analyze_http_tunneling(self, db_cursor):
        """Analyze HTTP traffic for tunneling indicators"""
        alerts = []
        pending_alerts = []  # For writing to analysis_1.db
        
        try:
            # Check if http_requests table exists (not http_headers)
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='http_requests'
            """)
            
            if not db_cursor.fetchone():
                return []  # HTTP requests table doesn't exist, skip this check
            
            # Look for suspicious HTTP traffic that might indicate tunneling
            # Changed to use the correct table and fields
            db_cursor.execute("""
                SELECT r.connection_key, c.src_ip, c.dst_ip, c.dst_port, 
                    r.host, r.uri, r.user_agent, c.total_bytes
                FROM http_requests r
                JOIN connections c ON r.connection_key = c.connection_key
                WHERE c.total_bytes > ?
                AND c.timestamp > datetime('now', '-1 hour')
            """, (self.min_http_content_length,))
            
            # Store results locally
            http_connections = []
            for row in db_cursor.fetchall():
                http_connections.append(row)
            
            for conn_key, src_ip, dst_ip, dst_port, host, path, user_agent, total_bytes in http_connections:
                suspicious = False
                reasons = []
                
                # Check 1: Suspicious user
                agent = user_agent.lower() if user_agent else ""
                for pattern in self.unusual_user_agent_patterns:
                    if pattern.lower() in agent:
                        suspicious = True
                        reasons.append(f"suspicious user-agent containing '{pattern}'")
                        break
                
                # Check 2: Base64 encoded data in URLs
                if path and len(path) > 100:
                    # Simple check for Base64-like strings (long strings of alphanumeric + /+= characters)
                    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
                    path_chars = set(path)
                    
                    # If most characters are Base64 alphabet and path is long, it's suspicious
                    if len(path_chars.intersection(b64_chars)) / len(path_chars) > 0.9 and len(path) > 200:
                        suspicious = True
                        reasons.append("long Base64-like URL path")
                
                # Check 3: Non-standard port for HTTP
                if dst_port and dst_port not in (80, 443, 8080, 8443, 8000, 8008):
                    suspicious = True
                    reasons.append(f"unusual HTTP port ({dst_port})")
                
                # Alert if any checks triggered
                if suspicious:
                    alert_msg = f"Possible HTTP tunneling: {src_ip} to {dst_ip}:{dst_port} ({total_bytes/1024:.1f} KB) - {', '.join(reasons)}"
                    alerts.append(alert_msg)
                    # Add to pending alerts for writing to analysis_1.db
                    pending_alerts.append((src_ip, alert_msg, self.name))
                    
                    # Store threat intelligence in analysis_1.db
                    self.analysis_manager.queue_query(
                        lambda s=src_ip, d=dst_ip, p=dst_port, b=total_bytes, r=reasons: 
                        self._add_http_tunnel_intel(s, d, p, b, r)
                    )
            
            return alerts, pending_alerts
            
        except Exception as e:
            error_msg = f"Error in HTTP tunneling analysis: {str(e)}"
            logging.error(error_msg)
            return [error_msg], []
    
    def _add_http_tunnel_intel(self, src_ip, dst_ip, dst_port, bytes_transferred, reasons):
        """Add HTTP tunneling intelligence data to analysis_1.db"""
        try:
            # Build threat intelligence data
            threat_data = {
                "score": 6.5,  # Medium-high score for tunneling
                "type": "protocol_tunneling",
                "confidence": 0.7,
                "source": "Protocol_Tunneling_Rule",
                "first_seen": time.time(),
                "details": {
                    "protocol": "HTTP",
                    "destination": dst_ip,
                    "destination_port": dst_port,
                    "bytes_transferred": bytes_transferred,
                    "reasons": reasons,
                    "detection_method": "http_analysis"
                }
            }
            
            # Update threat intelligence in analysis_1.db
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding HTTP tunneling data: {e}")
            return False
        
    def analyze_icmp_tunneling(self, db_cursor):
        """Analyze ICMP traffic for tunneling indicators"""
        alerts = []
        pending_alerts = []  # For writing to analysis_1.db
        
        try:
            # Check if icmp_packets table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='icmp_packets'
            """)
            
            if not db_cursor.fetchone():
                return [], []  # ICMP table doesn't exist, skip this check
            
            # Look for unusual ICMP traffic
            db_cursor.execute("""
                SELECT src_ip, dst_ip, COUNT(*) as packet_count, AVG(timestamp) as avg_time
                FROM icmp_packets
                WHERE timestamp > ?
                GROUP BY src_ip, dst_ip
                HAVING packet_count > 20
            """, (time.time() - 3600,))  # Last hour
            
            # Store results locally
            icmp_connections = []
            for row in db_cursor.fetchall():
                icmp_connections.append(row)
            
            for src_ip, dst_ip, packet_count, avg_time in icmp_connections:
                # Check for regular timing patterns in ICMP
                db_cursor.execute("""
                    SELECT timestamp
                    FROM icmp_packets
                    WHERE src_ip = ? AND dst_ip = ? AND timestamp > ?
                    ORDER BY timestamp
                """, (src_ip, dst_ip, time.time() - 3600))
                
                timestamps = [row[0] for row in db_cursor.fetchall()]
                
                if len(timestamps) >= 10:
                    # Calculate intervals between packets
                    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                    
                    # Check for consistent intervals (indicating potential tunneling)
                    if len(intervals) >= 5:
                        avg_interval = sum(intervals) / len(intervals)
                        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
                        cv = (math.sqrt(variance) / avg_interval) if avg_interval > 0 else float('inf')
                        
                        # Low coefficient of variation indicates regular timing
                        if cv < 0.5 and avg_interval < 60:  # Less than 60 seconds between packets
                            alert_msg = f"Possible ICMP tunneling: {src_ip} sent {packet_count} ICMP packets to {dst_ip} with regular timing (variance: {cv:.2f})"
                            alerts.append(alert_msg)
                            # Add to pending alerts for writing to analysis_1.db
                            pending_alerts.append((src_ip, alert_msg, self.name))
                            
                            # Store threat intelligence in analysis_1.db
                            self.analysis_manager.queue_query(
                                lambda s=src_ip, d=dst_ip, p=packet_count, c=cv: 
                                self._add_icmp_tunnel_intel(s, d, p, c)
                            )
            
            return alerts, pending_alerts
            
        except Exception as e:
            error_msg = f"Error in ICMP tunneling analysis: {str(e)}"
            logging.error(error_msg)
            return [error_msg], []
    
    def _add_icmp_tunnel_intel(self, src_ip, dst_ip, packet_count, timing_variance):
        """Add ICMP tunneling intelligence data to analysis_1.db"""
        try:
            # Build threat intelligence data
            threat_data = {
                "score": 7.0,  # High score for ICMP tunneling (often malicious)
                "type": "protocol_tunneling",
                "confidence": 0.8,
                "source": "Protocol_Tunneling_Rule",
                "first_seen": time.time(),
                "details": {
                    "protocol": "ICMP",
                    "destination": dst_ip,
                    "packet_count": packet_count,
                    "timing_variance": timing_variance,
                    "detection_method": "icmp_timing_analysis"
                }
            }
            
            # Update threat intelligence in analysis_1.db
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding ICMP tunneling data: {e}")
            return False
    
    def analyze_ssh_tunneling(self, db_cursor):
        """Analyze SSH traffic for tunneling indicators"""
        alerts = []
        pending_alerts = []  # For writing to analysis_1.db
        
        try:
            # Look for SSH connections with unusual traffic patterns
            db_cursor.execute("""
                SELECT src_ip, dst_ip, total_bytes, packet_count
                FROM connections
                WHERE (dst_port = 22 OR src_port = 22)
                AND total_bytes > 100000  -- More than 100KB
                AND timestamp > datetime('now', '-1 hour')
            """)
            
            # Store results locally
            ssh_connections = []
            for row in db_cursor.fetchall():
                ssh_connections.append(row)
            
            for src_ip, dst_ip, total_bytes, packet_count in ssh_connections:
                # Calculate bytes per packet - high values can indicate bulk data transfer over SSH
                if packet_count > 10:
                    bytes_per_packet = total_bytes / packet_count
                    
                    # Very high bytes per packet can indicate tunneling (instead of interactive SSH)
                    if bytes_per_packet > 1000:  # More than 1KB per packet average
                        alert_msg = f"Possible SSH tunneling: {src_ip} to {dst_ip} with {total_bytes/1024:.1f} KB transferred ({bytes_per_packet:.1f} bytes/packet)"
                        alerts.append(alert_msg)
                        # Add to pending alerts for writing to analysis_1.db
                        pending_alerts.append((src_ip, alert_msg, self.name))
                        
                        # Store threat intelligence in analysis_1.db
                        self.analysis_manager.queue_query(
                            lambda s=src_ip, d=dst_ip, b=total_bytes, bp=bytes_per_packet: 
                            self._add_ssh_tunnel_intel(s, d, b, bp)
                        )
            
            return alerts, pending_alerts
            
        except Exception as e:
            error_msg = f"Error in SSH tunneling analysis: {str(e)}"
            logging.error(error_msg)
            return [error_msg], []
    
    def _add_ssh_tunnel_intel(self, src_ip, dst_ip, total_bytes, bytes_per_packet):
        """Add SSH tunneling intelligence data to analysis_1.db"""
        try:
            # Build threat intelligence data
            threat_data = {
                "score": 5.5,  # Medium score (SSH tunneling can be legitimate)
                "type": "protocol_tunneling",
                "confidence": 0.7,
                "source": "Protocol_Tunneling_Rule",
                "first_seen": time.time(),
                "details": {
                    "protocol": "SSH",
                    "destination": dst_ip,
                    "total_bytes": total_bytes,
                    "bytes_per_packet": bytes_per_packet,
                    "detection_method": "ssh_traffic_analysis"
                }
            }
            
            # Update threat intelligence in analysis_1.db
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding SSH tunneling data: {e}")
            return False
    
    def analyze(self, db_cursor):
        # Ensure analysis_manager is linked
        if not self.analysis_manager and hasattr(self.db_manager, 'analysis_manager'):
            self.analysis_manager = self.db_manager.analysis_manager
        
        # Return early if analysis_manager is not available
        if not self.analysis_manager:
            logging.error("Cannot run Protocol Tunneling rule: analysis_manager not available")
            return ["ERROR: Protocol Tunneling rule requires analysis_manager"]
            
        alerts = []
        current_time = time.time()
        
        # Only run this rule periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Run the different protocol tunneling detection methods (excluding DNS)
            http_alerts, http_pending = self.analyze_http_tunneling(db_cursor)
            icmp_alerts, icmp_pending = self.analyze_icmp_tunneling(db_cursor)
            ssh_alerts, ssh_pending = self.analyze_ssh_tunneling(db_cursor)
            
            # Combine all alerts
            alerts.extend(http_alerts)
            alerts.extend(icmp_alerts)
            alerts.extend(ssh_alerts)
            
            # Combine all pending alerts
            pending_alerts = []
            pending_alerts.extend(http_pending)
            pending_alerts.extend(icmp_pending)
            pending_alerts.extend(ssh_pending)
            
            # Write all pending alerts to analysis_1.db
            for ip, msg, rule_name in pending_alerts:
                try:
                    self.analysis_manager.add_alert(ip, msg, rule_name)
                except Exception as e:
                    logging.error(f"Error adding alert to analysis_1.db: {e}")
            
            return alerts
        except Exception as e:
            error_msg = f"Error in Protocol Tunneling rule: {str(e)}"
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
            "min_http_content_length": {
                "type": "int",
                "default": 5000,
                "current": self.min_http_content_length,
                "description": "Minimum HTTP content length for analysis"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "check_interval":
            self.check_interval = int(value)
            return True
        elif param_name == "min_http_content_length":
            self.min_http_content_length = int(value)
            return True
        return False