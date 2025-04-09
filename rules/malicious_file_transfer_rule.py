# Rule class is injected by the RuleLoader
import logging
import time
import re
import math
import base64

class MaliciousFileTransferRule(Rule):
    """Rule that detects file transfer through covert channels"""
    def __init__(self):
        super().__init__(
            name="Covert File Transfer Detection",
            description="Detects file transfers through DNS tunneling and other covert channels"
        )
        self.check_interval = 300  # Seconds between checks
        self.last_check_time = 0
        
        # DNS tunneling parameters
        self.dns_query_threshold = 50  # Minimum queries to analyze
        self.dns_subdomain_depth_threshold = 3  # Unusual subdomain depth
        self.dns_domain_length_threshold = 40  # Unusually long domain
        self.dns_entropy_threshold = 4.0  # High entropy indicates encoded data
        
        # HTTP tunneling parameters
        self.http_unusual_methods = ["PUT", "PATCH"]  # Methods often used for uploads
        self.http_suspicious_headers = ["x-up-", "file-", "attachment", "upload"]
        self.http_min_content_length = 10000  # Minimum content size to analyze
        
        # ICMP tunneling parameters
        self.icmp_payload_threshold = 100  # Bytes per packet for ICMP
        self.icmp_packet_threshold = 20  # Minimum packets to analyze
        
        # Store reference to analysis_manager (will be set later when analysis_manager is available)
        self.analysis_manager = None
        
        self.detected_transfers = {}  # Track detected transfers
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of string data"""
        if not data:
            return 0
            
        # Calculate entropy
        char_freq = {}
        for char in data:
            if char in char_freq:
                char_freq[char] += 1
            else:
                char_freq[char] = 1
        
        entropy = 0
        length = len(data)
        if length == 0:
            return 0
            
        for char, freq in char_freq.items():
            prob = freq / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def detect_dns_file_transfer(self, db_cursor):
        """Detect files being transferred via DNS tunneling"""
        alerts = []
        
        try:
            # Check if dns_queries table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='dns_queries'
            """)
            
            if not db_cursor.fetchone():
                return []  # Skip if table doesn't exist
            
            # Get IPs with high volumes of DNS queries
            db_cursor.execute("""
                SELECT src_ip, COUNT(*) as query_count
                FROM dns_queries
                WHERE timestamp > ?
                GROUP BY src_ip
                HAVING query_count >= ?
            """, (time.time() - 3600, self.dns_query_threshold))
            
            for src_ip, query_count in db_cursor.fetchall():
                # Get the actual queries
                db_cursor.execute("""
                    SELECT query_domain
                    FROM dns_queries
                    WHERE src_ip = ? AND timestamp > ?
                    ORDER BY timestamp
                """, (src_ip, time.time() - 3600))
                
                domains = [row[0] for row in db_cursor.fetchall() if row[0]]
                
                if not domains:
                    continue
                
                # Analyze domains for tunneling characteristics
                base64_encoded = 0
                hex_encoded = 0
                high_entropy = 0
                long_domains = 0
                deep_subdomains = 0
                
                for domain in domains:
                    # Check domain length
                    if len(domain) > self.dns_domain_length_threshold:
                        long_domains += 1
                    
                    # Check subdomain depth
                    subdomain_count = domain.count('.')
                    if subdomain_count > self.dns_subdomain_depth_threshold:
                        deep_subdomains += 1
                    
                    # Calculate entropy of subdomain part
                    parts = domain.split('.')
                    if len(parts) > 1:
                        subdomain = '.'.join(parts[:-2])  # Exclude TLD and domain
                        entropy = self.calculate_entropy(subdomain)
                        
                        if entropy > self.dns_entropy_threshold:
                            high_entropy += 1
                    
                    # Check for Base64 encoding patterns
                    subdomain = parts[0] if parts else ""
                    
                    if subdomain:
                        # Base64 check (character set and padding)
                        if re.match(r'^[A-Za-z0-9+/=]+$', subdomain) and len(subdomain) % 4 == 0:
                            try:
                                # Try to decode - if it works, likely Base64
                                base64.b64decode(subdomain + "===="[:4 - len(subdomain) % 4])
                                base64_encoded += 1
                            except:
                                pass
                        
                        # Hex encoding check
                        if re.match(r'^[0-9a-fA-F]+$', subdomain) and len(subdomain) % 2 == 0:
                            hex_encoded += 1
                
                # Calculate percentages
                long_pct = long_domains / len(domains) * 100
                deep_pct = deep_subdomains / len(domains) * 100
                entropy_pct = high_entropy / len(domains) * 100
                base64_pct = base64_encoded / len(domains) * 100
                hex_pct = hex_encoded / len(domains) * 100
                
                # Check for suspicious patterns
                if (long_pct > 60 or deep_pct > 60) and (entropy_pct > 50 or base64_pct > 40 or hex_pct > 40):
                    alert_key = f"{src_ip}-dns-transfer"
                    
                    if alert_key not in self.detected_transfers:
                        self.detected_transfers[alert_key] = time.time()
                        
                        encoding = "unknown"
                        if base64_pct > hex_pct:
                            encoding = "Base64"
                        elif hex_pct > 30:
                            encoding = "Hex"
                        
                        alert_msg = f"File transfer via DNS detected: {src_ip} sent {query_count} DNS queries with {encoding}-encoded data " + \
                                   f"(long: {long_pct:.1f}%, high entropy: {entropy_pct:.1f}%)"
                        
                        alerts.append(alert_msg)
                        
                        # Add alert to x_alerts table
                        self.add_alert(src_ip, alert_msg)
                        
                        # Store threat intelligence in x_ip_threat_intel
                        self._add_file_transfer_intel(src_ip, "DNS", {
                            "encoding": encoding,
                            "query_count": query_count,
                            "long_domains_pct": long_pct,
                            "entropy_pct": entropy_pct,
                            "base64_pct": base64_pct,
                            "hex_pct": hex_pct
                        })
            
            return alerts
        except Exception as e:
            logging.error(f"Error analyzing DNS for file transfers: {e}")
            return []
    
    def detect_http_file_transfer(self, db_cursor):
        """Detect unusual HTTP file transfers"""
        alerts = []
        
        try:
            # Check if http_requests table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='http_requests'
            """)
            
            if not db_cursor.fetchone():
                return []  # Skip if table doesn't exist
            
            # Look for suspicious HTTP requests using correct table and field names
            db_cursor.execute("""
                SELECT r.connection_key, c.src_ip, c.dst_ip, r.method, r.uri, r.host, 
                    r.request_size, r.content_type
                FROM http_requests r
                JOIN connections c ON r.connection_key = c.connection_key
                WHERE c.timestamp > datetime('now', '-30 minutes')
                AND (r.request_size > ? OR r.method IN ('PUT', 'PATCH'))
            """, (self.http_min_content_length,))
            
            for conn_key, src_ip, dst_ip, method, uri, host, content_length, content_type in db_cursor.fetchall():
                suspicion_level = 0
                reasons = []
                
                # Check for suspicious HTTP methods
                if method in self.http_unusual_methods:
                    suspicion_level += 2
                    reasons.append(f"unusual method ({method})")
                
                # Check content size
                if content_length and int(content_length) > self.http_min_content_length * 10:
                    suspicion_level += 2
                    reasons.append(f"large content ({int(content_length)/1024:.1f} KB)")
                
                # Check for suspicious content types
                if content_type:
                    if any(ext in content_type.lower() for ext in ['.zip', '.exe', '.rar', '.7z', 'binary', 'octet-stream']):
                        suspicion_level += 2
                        reasons.append(f"suspicious content-type ({content_type})")
                
                # Check for suspicious paths
                if uri:
                    if any(s in uri.lower() for s in ['upload', 'file', 'put', 'data']):
                        suspicion_level += 1
                        reasons.append("suspicious path")
                    
                    # Check if path contains encoded data
                    if len(uri) > 100:
                        entropy = self.calculate_entropy(uri)
                        if entropy > 4.0:
                            suspicion_level += 2
                            reasons.append(f"high entropy path (entropy: {entropy:.2f})")
                
                # Check for non-standard destination port
                db_cursor.execute("""
                    SELECT dst_port FROM connections WHERE connection_key = ?
                """, (conn_key,))
                
                result = db_cursor.fetchone()
                if result and result[0] and result[0] not in (80, 443, 8080, 8443):
                    suspicion_level += 1
                    reasons.append(f"unusual port ({result[0]})")
                
                # Alert if suspicious enough
                if suspicion_level >= 3:
                    alert_key = f"{src_ip}-{dst_ip}-http-transfer"
                    
                    if alert_key not in self.detected_transfers:
                        self.detected_transfers[alert_key] = time.time()
                        alert_msg = f"Suspicious HTTP file transfer: {src_ip} to {dst_ip} - {', '.join(reasons)}"
                        alerts.append(alert_msg)
                        
                        # Add alert to x_alerts table
                        self.add_alert(src_ip, alert_msg)
                        
                        # Store threat intelligence in x_ip_threat_intel
                        self._add_file_transfer_intel(src_ip, "HTTP", {
                            "destination": dst_ip,
                            "method": method,
                            "content_type": content_type,
                            "suspicion_level": suspicion_level,
                            "reasons": reasons,
                            "connection_key": conn_key
                        })
            
            return alerts
        except Exception as e:
            logging.error(f"Error analyzing HTTP for file transfers: {e}")
            return []
    
    def detect_icmp_file_transfer(self, db_cursor):
        """Detect files being transferred via ICMP tunneling"""
        alerts = []
        
        try:
            # Check if icmp_packets table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='icmp_packets'
            """)
            
            if not db_cursor.fetchone():
                return []  # Skip if table doesn't exist
            
            # Find ICMP traffic with many packets
            db_cursor.execute("""
                SELECT src_ip, dst_ip, COUNT(*) as packet_count
                FROM icmp_packets
                WHERE timestamp > ?
                GROUP BY src_ip, dst_ip
                HAVING packet_count >= ?
            """, (time.time() - 1800, self.icmp_packet_threshold))
            
            for src_ip, dst_ip, packet_count in db_cursor.fetchall():
                alert_key = f"{src_ip}-{dst_ip}-icmp-transfer"
                
                if alert_key not in self.detected_transfers:
                    self.detected_transfers[alert_key] = time.time()
                    alert_msg = f"Potential ICMP tunneling: {src_ip} sent {packet_count} ICMP packets to {dst_ip} in the last 30 minutes"
                    alerts.append(alert_msg)
                    
                    # Add alert to x_alerts table
                    self.add_alert(src_ip, alert_msg)
                    
                    # Store threat intelligence in x_ip_threat_intel
                    self._add_file_transfer_intel(src_ip, "ICMP", {
                        "destination": dst_ip,
                        "packet_count": packet_count,
                        "timeframe": "30 minutes"
                    })
            
            return alerts
        except Exception as e:
            logging.error(f"Error analyzing ICMP for file transfers: {e}")
            return []
    
    def _add_file_transfer_intel(self, ip_address, protocol, details):
        """Add file transfer intelligence data to x_ip_threat_intel with extended columns"""
        if not self.analysis_manager:
            return False
            
        try:
            # Create threat intelligence data
            threat_data = {
                "score": 7.5,  # High score for covert file transfers
                "type": "covert_file_transfer",
                "confidence": 0.75,
                "source": "MaliciousFileTransferRule",
                "first_seen": time.time(),
                "details": {
                    "protocol": protocol,
                    "detection_type": "covert_file_transfer",
                    **details  # Include all the protocol-specific details
                },
                # Extended columns
                "protocol": protocol,
                "destination_ip": details.get("destination"),
                "bytes_transferred": details.get("content_length") or details.get("total_bytes"),
                "detection_method": f"{protocol.lower()}_file_transfer_detection",
                "encoding_type": details.get("encoding"),
                "packet_count": details.get("packet_count") or details.get("query_count")
            }
            
            # Update threat intelligence in x_ip_threat_intel
            return self.analysis_manager.update_threat_intel(ip_address, threat_data)
        except Exception as e:
            logging.error(f"Error adding file transfer intelligence data: {e}")
            return False
    
    def analyze(self, db_cursor):
        # Ensure analysis_manager is linked
        if not self.analysis_manager and hasattr(self.db_manager, 'analysis_manager'):
            self.analysis_manager = self.db_manager.analysis_manager
        
        # Return early if analysis_manager is not available
        if not self.analysis_manager:
            logging.error("Cannot run Malicious File Transfer rule: analysis_manager not available")
            return ["ERROR: Malicious File Transfer rule requires analysis_manager"]
        
        alerts = []
        current_time = time.time()
        
        # Only run periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Run different file transfer detection methods
            dns_alerts = self.detect_dns_file_transfer(db_cursor)
            http_alerts = self.detect_http_file_transfer(db_cursor)
            icmp_alerts = self.detect_icmp_file_transfer(db_cursor)
            
            alerts.extend(dns_alerts)
            alerts.extend(http_alerts)
            alerts.extend(icmp_alerts)
            
            # Clean up old detections (after 6 hours)
            old_detections = [k for k, t in self.detected_transfers.items() if current_time - t > 21600]
            for key in old_detections:
                self.detected_transfers.pop(key, None)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Covert File Transfer Detection rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def get_params(self):
        return {
            "check_interval": {
                "type": "int",
                "default": 300,
                "current": self.check_interval,
                "description": "Seconds between rule checks"
            },
            "dns_query_threshold": {
                "type": "int",
                "default": 50,
                "current": self.dns_query_threshold,
                "description": "Minimum DNS queries to analyze for tunneling"
            },
            "http_min_content_length": {
                "type": "int",
                "default": 10000,
                "current": self.http_min_content_length,
                "description": "Minimum content size for HTTP analysis"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "check_interval":
            self.check_interval = int(value)
            return True
        elif param_name == "dns_query_threshold":
            self.dns_query_threshold = int(value)
            return True
        elif param_name == "http_min_content_length":
            self.http_min_content_length = int(value)
            return True
        return False
        
    def add_alert(self, ip_address, alert_message):
        """Add an alert to the x_alerts table"""
        if self.analysis_manager:
            return self.analysis_manager.add_alert(ip_address, alert_message, self.name)
        return False
    
    