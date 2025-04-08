# http_analysis.py - Analyzes HTTP traffic for suspicious activity
import time
import logging
import json
import re

logger = logging.getLogger('http_analysis')

class HTTPAnalyzer(AnalysisBase):
    """Analyzes HTTP traffic for suspicious patterns and potential attacks"""
    
    def __init__(self):
        super().__init__(
            name="HTTP Traffic Analysis",
            description="Analyzes HTTP requests and responses for suspicious patterns"
        )
        # Suspicious patterns in URLs
        self.suspicious_url_patterns = [
            r'(?i)(?:\.\.\/|\.\.\\)',               # Directory traversal
            r'(?i)(?:\/etc\/passwd|c:\\windows)',    # Common file access attempts
            r'(?i)(?:\'|\%27).+(?:\'|\%27)',        # SQL injection
            r'(?i)(?:<script>|<\/script>)',         # XSS
            r'(?i)(?:eval\(|\balert\()',            # JavaScript injection
            r'(?i)(?:exec\(|system\(|passthru\()',  # PHP command injection
            r'(?i)(?:cmd\.exe|\/bin\/bash)',        # Command execution
            r'(?i)(?:\bor\b|\band\b).*?(?:--|#)',   # SQL injection keywords
            r'(?i)(?:base64_decode|eval\(base64_)', # Encoded attacks
            r'(?i)(?:select.+from)',                # SQL SELECT statements
        ]
        
        # Suspicious user agent patterns
        self.suspicious_user_agents = [
            r'(?i)(?:sqlmap|nikto|nessus|nmap)',    # Common scanning tools
            r'(?i)(?:python-requests|curl|wget)',   # Non-browser clients 
            r'(?i)(?:zgrab|gobuster|dirsearch)',    # More scanning tools
            r'(?i)(?:metasploit|burp|hydra)'        # Pentesting tools
        ]
        
        # Suspicious IP address patterns
        self.ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        
        self.last_report_time = 0
        self.report_interval = 1800  # 30 minutes
    
    def initialize(self):
        # Create or update required tables
        cursor = self.analysis_manager.get_cursor()
        try:
            # HTTP analysis results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS http_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_key TEXT,
                    host TEXT,
                    uri TEXT,
                    method TEXT,
                    suspicious_score REAL DEFAULT 0,
                    user_agent TEXT,
                    reason TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    request_count INTEGER DEFAULT 1
                )
            """)
            
            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_analysis_host ON http_analysis(host)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_analysis_score ON http_analysis(suspicious_score DESC)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("HTTP analysis tables initialized")
        except Exception as e:
            logger.error(f"Error initializing HTTP analysis tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process an HTTP packet for analysis"""
        # Get the layers
        layers = packet_data.get("layers", {})
        if not layers:
            return False
        
        # Check if this is an HTTP packet
        if not self.analysis_manager._has_http_data(layers):
            return False
        
        try:
            # Extract HTTP data
            src_ip = self.analysis_manager._get_layer_value(layers, "ip_src") or self.analysis_manager._get_layer_value(layers, "ipv6_src")
            dst_ip = self.analysis_manager._get_layer_value(layers, "ip_dst") or self.analysis_manager._get_layer_value(layers, "ipv6_dst")
            
            if not src_ip or not dst_ip:
                return False
                
            src_port, dst_port = self.analysis_manager._extract_ports(layers)
            
            # Create connection key
            if src_port and dst_port:
                connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            else:
                connection_key = f"{src_ip}->{dst_ip}"
            
            # Extract HTTP fields for request analysis
            method = self.analysis_manager._get_layer_value(layers, "http_request_method")
            uri = self.analysis_manager._get_layer_value(layers, "http_request_uri")
            host = self.analysis_manager._get_layer_value(layers, "http_host")
            user_agent = self.analysis_manager._get_layer_value(layers, "http_user_agent")
            
            # Check if we have a request to analyze
            if method and uri:
                # Calculate suspicion score
                suspicious_score = 0
                reasons = []
                
                # Check for suspicious URL patterns
                for pattern in self.suspicious_url_patterns:
                    if re.search(pattern, uri):
                        suspicious_score += 3
                        reasons.append(f"Suspicious pattern in URL: {pattern}")
                
                # Check for suspicious user agent
                if user_agent:
                    for pattern in self.suspicious_user_agents:
                        if re.search(pattern, user_agent):
                            suspicious_score += 2
                            reasons.append(f"Suspicious user agent: {user_agent}")
                
                # Check for IP addresses in host header (unusual)
                if host and re.search(self.ip_pattern, host):
                    suspicious_score += 1
                    reasons.append("Using IP address instead of hostname")
                
                # Check for unusual HTTP methods
                if method not in ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"]:
                    suspicious_score += 2
                    reasons.append(f"Unusual HTTP method: {method}")
                
                # Store analysis results if suspicious
                if suspicious_score > 0:
                    current_time = time.time()
                    cursor = self.analysis_manager.get_cursor()
                    
                    try:
                        # Check if we've seen this host/URI combination before
                        cursor.execute("""
                            SELECT id, suspicious_score, first_seen, request_count, reason
                            FROM http_analysis
                            WHERE host = ? AND uri = ? AND method = ?
                        """, (host or dst_ip, uri, method))
                        
                        result = cursor.fetchone()
                        
                        # Combine reasons into a string
                        reason_text = ", ".join(reasons)
                        
                        if result:
                            # Update existing record
                            record_id, old_score, first_seen, request_count, old_reasons = result
                            # Use the higher score
                            final_score = max(suspicious_score, old_score)
                            
                            # Combine reasons if they're different
                            if old_reasons and reason_text and old_reasons != reason_text:
                                combined_reasons = f"{old_reasons}; {reason_text}"
                            else:
                                combined_reasons = reason_text or old_reasons
                                
                            cursor.execute("""
                                UPDATE http_analysis
                                SET last_seen = ?,
                                    request_count = request_count + 1,
                                    suspicious_score = ?,
                                    user_agent = ?,
                                    reason = ?
                                WHERE id = ?
                            """, (current_time, final_score, user_agent or "", combined_reasons, record_id))
                        else:
                            # Insert new record
                            cursor.execute("""
                                INSERT INTO http_analysis
                                (connection_key, host, uri, method, suspicious_score, user_agent, reason, first_seen, last_seen)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                connection_key,
                                host or dst_ip,
                                uri,
                                method,
                                suspicious_score,
                                user_agent or "",
                                reason_text,
                                current_time,
                                current_time
                            ))
                        
                        # Create alerts for highly suspicious requests
                        if suspicious_score >= 5:
                            alert_message = f"Suspicious HTTP request to {host or dst_ip}{uri} - {reason_text}"
                            self.analysis_manager.add_alert(src_ip, alert_message, "HTTP_Request_Analyzer")
                        
                        self.analysis_manager.analysis1_conn.commit()
                    finally:
                        cursor.close()
            
            # Also check for HTTP response status codes
            status_code_raw = self.analysis_manager._get_layer_value(layers, "http_response_code")
            if status_code_raw:
                try:
                    status_code = int(status_code_raw)
                    
                    # Analyze interesting status codes (400s and 500s)
                    if status_code >= 400:
                        # Store in the database for trending/analysis
                        # But only alert on server errors or excessive client errors
                        if status_code >= 500:
                            cursor = self.analysis_manager.get_cursor()
                            try:
                                # Check if we've alerted about this recently
                                one_hour_ago = time.time() - 3600
                                cursor.execute("""
                                    SELECT COUNT(*) FROM alerts
                                    WHERE ip_address = ? AND alert_message LIKE ? AND timestamp > ?
                                """, (src_ip, f"%HTTP {status_code}%", one_hour_ago))
                                
                                if cursor.fetchone()[0] == 0:
                                    # Create a new alert
                                    alert_message = f"HTTP server error: {status_code} response from {dst_ip} to {src_ip}"
                                    self.analysis_manager.add_alert(src_ip, alert_message, "HTTP_Response_Analyzer")
                            finally:
                                cursor.close()
                except (ValueError, TypeError):
                    pass
            
            return True
        except Exception as e:
            logger.error(f"Error analyzing HTTP packet: {e}")
            return False
    
    def run_periodic_analysis(self):
        """Run periodic analysis on HTTP traffic"""
        current_time = time.time()
        if current_time - self.last_report_time < self.report_interval:
            return False  # Not time for a report yet
        
        self.last_report_time = current_time
        
        try:
            cursor = self.analysis_manager.get_cursor()
            
            # Get top suspicious HTTP requests
            cursor.execute("""
                SELECT host, uri, method, suspicious_score, reason, request_count
                FROM http_analysis 
                WHERE suspicious_score > 3
                AND last_seen > ?
                ORDER BY suspicious_score DESC, request_count DESC
                LIMIT 20
            """, (current_time - 86400,))  # From the last 24 hours
            
            suspicious_requests = cursor.fetchall()
            cursor.close()
            
            if suspicious_requests:
                logger.info(f"HTTP Analysis Report: Found {len(suspicious_requests)} suspicious requests")
                for req in suspicious_requests:
                    host, uri, method, score, reason, count = req
                    logger.info(f"  - {method} {host}{uri}: score={score}, requests={count}, reason={reason}")
            
            return True
        except Exception as e:
            logger.error(f"Error in HTTP periodic analysis: {e}")
            return False