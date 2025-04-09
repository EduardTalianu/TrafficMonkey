# Rule class is injected by the RuleLoader
import logging
import os
import json
import time
import re

class CommandControlDetectionRule(Rule):
    """Rule that detects traffic matching known command and control patterns"""
    def __init__(self):
        super().__init__(
            name="Command & Control Detection",
            description="Detects traffic matching known C2 communication patterns using timing, sizes, and destinations"
        )
        self.check_interval = 600  # Seconds between checks
        self.last_check_time = 0
        self.c2_domains_file = self._get_c2_file_path()
        self.c2_domains = []  # Known C2 domains
        self.c2_ips = []      # Known C2 IPs
        self.c2_patterns = {  # Patterns of known C2 frameworks
            "empire": {
                "interval": [1.0, 5.0],  # Beaconing interval range
                "jitter": 0.2,          # Timing jitter percentage
                "sizes": [200, 400]     # Typical packet size range
            },
            "cobaltstrike": {
                "interval": [30.0, 120.0],  
                "jitter": 0.3,
                "sizes": [400, 800]
            },
            "metasploit": {
                "interval": [5.0, 20.0],
                "jitter": 0.1,
                "sizes": [300, 600]
            }
        }
        self.detected_c2 = {}  # Track detected C2 channels
        
        # Store reference to analysis_manager (will be set later when analysis_manager is available)
        self.analysis_manager = None
        
        # Load known C2 indicators
        self.load_c2_indicators()
    
    def _get_c2_file_path(self):
        """Determine path for C2 indicators file"""
        try:
            # Try to locate the db directory
            if hasattr(self, 'db_manager') and hasattr(self.db_manager, 'app_root'):
                app_root = self.db_manager.app_root
                c2_file = os.path.join(app_root, "db", "c2_indicators.json")
            else:
                current_dir = os.getcwd()
                if os.path.exists(os.path.join(current_dir, "db")):
                    c2_file = os.path.join(current_dir, "db", "c2_indicators.json")
                elif os.path.exists(os.path.join(current_dir, "..", "db")):
                    c2_file = os.path.join(current_dir, "..", "db", "c2_indicators.json")
                else:
                    c2_file = "c2_indicators.json"
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(c2_file), exist_ok=True)
            return c2_file
        except Exception as e:
            logging.error(f"Error determining C2 indicators file path: {e}")
            return "c2_indicators.json"
    
    def load_c2_indicators(self):
        """Load C2 indicators from file or create defaults"""
        try:
            if os.path.exists(self.c2_domains_file):
                with open(self.c2_domains_file, 'r') as f:
                    data = json.load(f)
                    self.c2_domains = data.get('domains', [])
                    self.c2_ips = data.get('ips', [])
                    patterns = data.get('patterns', {})
                    
                    # Update patterns if they exist in the file
                    if patterns:
                        self.c2_patterns.update(patterns)
                        
                logging.info(f"Loaded {len(self.c2_domains)} C2 domains and {len(self.c2_ips)} C2 IPs")
            else:
                # Create default C2 indicators file
                self._create_default_c2_indicators()
        except Exception as e:
            logging.error(f"Error loading C2 indicators: {e}")
            self._create_default_c2_indicators()
    
    def _create_default_c2_indicators(self):
        """Create default C2 indicators"""
        # Example data - in a real implementation, you would use actual threat intelligence
        default_data = {
            "domains": [
                "evil-c2.example.com",
                "command.bad-domain.com",
                "exfil.malware-server.net"
            ],
            "ips": [
                "203.0.113.100",
                "198.51.100.200",
                "192.0.2.50"
            ],
            "patterns": self.c2_patterns  # Use the built-in patterns
        }
        
        self.c2_domains = default_data['domains']
        self.c2_ips = default_data['ips']
        
        try:
            with open(self.c2_domains_file, 'w') as f:
                json.dump(default_data, f, indent=2)
            logging.info(f"Created default C2 indicators file at {self.c2_domains_file}")
        except Exception as e:
            logging.error(f"Error creating default C2 indicators file: {e}")
    
    def match_domain_pattern(self, domain):
        """Check if a domain matches known C2 patterns or blocklists"""
        # Direct match
        if domain in self.c2_domains:
            return True
            
        # Check for domain pattern matches
        for c2_domain in self.c2_domains:
            # Convert domain patterns to regex
            pattern = c2_domain.replace('.', '\\.').replace('*', '.*')
            if re.match(f"^{pattern}$", domain):
                return True
                
        return False
    
    def analyze_timing_pattern(self, intervals, sizes, c2_type):
        """Check if a connection's timing and size patterns match known C2 behavior"""
        if not intervals or not sizes:
            return False, ""
            
        c2_config = self.c2_patterns.get(c2_type)
        if not c2_config:
            return False, ""
            
        # Check for consistent interval with expected jitter
        avg_interval = sum(intervals) / len(intervals)
        expected_interval_min = c2_config['interval'][0]
        expected_interval_max = c2_config['interval'][1]
        
        if not (expected_interval_min <= avg_interval <= expected_interval_max):
            return False, f"interval outside range ({avg_interval:.1f}s)"
            
        # Calculate jitter (normalized standard deviation)
        if len(intervals) >= 3:
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            jitter = (variance ** 0.5) / avg_interval if avg_interval > 0 else float('inf')
            
            if jitter > c2_config['jitter'] * 2:  # Allow double the expected jitter
                return False, f"jitter too high ({jitter:.2f})"
        
        # Check packet sizes
        avg_size = sum(sizes) / len(sizes)
        size_min = c2_config['sizes'][0]
        size_max = c2_config['sizes'][1]
        
        if not (size_min * 0.5 <= avg_size <= size_max * 1.5):  # Allow more flexibility in sizes
            return False, f"size outside range ({avg_size:.1f} bytes)"
            
        return True, f"matches {c2_type} pattern (interval: {avg_interval:.1f}s, jitter: {jitter:.2f})"
    
    def analyze(self, db_cursor):
        # Ensure analysis_manager is linked
        if not self.analysis_manager and hasattr(self.db_manager, 'analysis_manager'):
            self.analysis_manager = self.db_manager.analysis_manager
        
        # Return early if analysis_manager is not available (this shouldn't happen with new architecture)
        if not self.analysis_manager:
            logging.error("Cannot run Command & Control Detection rule: analysis_manager not available")
            return ["ERROR: Command & Control Detection rule requires analysis_manager"]
            
        alerts = []
        current_time = time.time()
        
        # Only run periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # 1. Check for connections to known C2 domains/IPs
            # First check DNS queries for known domains
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='dns_queries'
            """)
            
            if db_cursor.fetchone():
                db_cursor.execute("""
                    SELECT src_ip, query_domain
                    FROM dns_queries
                    WHERE timestamp > ?
                    GROUP BY src_ip, query_domain
                """, (current_time - 86400,))  # Last 24 hours
                
                for src_ip, domain in db_cursor.fetchall():
                    if domain and self.match_domain_pattern(domain):
                        c2_key = f"{src_ip}->{domain}"
                        
                        if c2_key not in self.detected_c2:
                            self.detected_c2[c2_key] = current_time
                            alert_msg = f"Potential C2: {src_ip} queried known C2 domain: {domain}"
                            alerts.append(alert_msg)
                            
                            # Add alert using the new method
                            self.add_alert(src_ip, alert_msg)
            
            # Check for connections to known C2 IPs
            for c2_ip in self.c2_ips:
                db_cursor.execute("""
                    SELECT src_ip, dst_ip, COUNT(*) as conn_count
                    FROM connections
                    WHERE dst_ip = ?
                    AND timestamp > datetime('now', '-1 day')
                    GROUP BY src_ip
                """, (c2_ip,))
                
                for src_ip, dst_ip, count in db_cursor.fetchall():
                    c2_key = f"{src_ip}->{dst_ip}"
                    
                    if c2_key not in self.detected_c2:
                        self.detected_c2[c2_key] = current_time
                        alert_msg = f"Potential C2: {src_ip} connected to known C2 server: {dst_ip} ({count} connections)"
                        alerts.append(alert_msg)
                        
                        # Add alert using the new method
                        self.add_alert(src_ip, alert_msg)
            
            # 2. Check for beaconing patterns matching known C2 frameworks
            db_cursor.execute("""
                SELECT src_ip, dst_ip, dst_port, COUNT(*) as conn_count
                FROM connections
                WHERE timestamp > datetime('now', '-6 hours')
                GROUP BY src_ip, dst_ip, dst_port
                HAVING conn_count >= 5
            """)
            
            for src_ip, dst_ip, dst_port, count in db_cursor.fetchall():
                # Skip if already detected as C2
                c2_key = f"{src_ip}->{dst_ip}"
                if c2_key in self.detected_c2:
                    continue
                
                # Get connection timestamps and sizes
                db_cursor.execute("""
                    SELECT timestamp, total_bytes
                    FROM connections
                    WHERE src_ip = ? AND dst_ip = ? AND dst_port = ?
                    AND timestamp > datetime('now', '-6 hours')
                    ORDER BY timestamp
                """, (src_ip, dst_ip, dst_port))
                
                conn_data = db_cursor.fetchall()
                
                if len(conn_data) >= 5:
                    # Convert timestamps to epoch
                    timestamps = []
                    sizes = []
                    
                    for ts, size in conn_data:
                        # Handle string timestamps
                        if isinstance(ts, str):
                            try:
                                import datetime
                                dt = datetime.datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
                                timestamps.append(dt.timestamp())
                            except:
                                continue
                        else:
                            timestamps.append(float(ts))
                        
                        sizes.append(size)
                    
                    # Calculate intervals
                    intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
                    
                    # Check against each C2 framework pattern
                    for c2_type in self.c2_patterns:
                        is_match, reason = self.analyze_timing_pattern(intervals, sizes, c2_type)
                        
                        if is_match:
                            self.detected_c2[c2_key] = current_time
                            alert_msg = f"Potential {c2_type} C2 channel: {src_ip} to {dst_ip}:{dst_port} - {reason}"
                            alerts.append(alert_msg)
                            
                            # Add alert using the new method
                            self.add_alert(src_ip, alert_msg)
                            
                            # Add threat intelligence to analysis_1.db
                            self._add_threat_intel(src_ip, dst_ip, dst_port, c2_type)
                            break
            
            # Clean up old detections (after 12 hours)
            old_c2 = [k for k, t in self.detected_c2.items() if current_time - t > 43200]
            for key in old_c2:
                self.detected_c2.pop(key, None)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Command & Control Detection rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def add_alert(self, ip_address, alert_message):
        """Add an alert to the x_alerts table"""
        if self.analysis_manager:
            return self.analysis_manager.add_alert(ip_address, alert_message, self.name)
        return False
    
    def _add_threat_intel(self, src_ip, dst_ip, dst_port, c2_type):
        """Add threat intelligence data to analysis_1.db for C2 detections"""
        try:
            # Build threat intelligence data for the IP
            threat_data = {
                "score": 8.0,  # High score for C2 traffic
                "type": "command_and_control",
                "confidence": 0.75,
                "source": "C2_Detection_Rule",
                "first_seen": time.time(),
                "details": {
                    "c2_type": c2_type,
                    "c2_server": dst_ip,
                    "c2_port": dst_port,
                    "detection_method": "behavior_analysis"
                },
                # Extended columns for easy querying
                "protocol": "TCP",
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "detection_method": "behavior_analysis"
            }
            
            # Update threat intelligence in analysis_1.db
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            
            # Also add data about the destination if it's not in our known list
            if dst_ip not in self.c2_ips:
                server_threat_data = {
                    "score": 9.0,  # Higher score for C2 server
                    "type": "command_and_control_server",
                    "confidence": 0.75,
                    "source": "C2_Detection_Rule",
                    "first_seen": time.time(),
                    "details": {
                        "c2_type": c2_type,
                        "c2_client": src_ip,
                        "c2_port": dst_port,
                        "detection_method": "behavior_analysis"
                    },
                    # Extended columns for easy querying
                    "protocol": "TCP",
                    "destination_port": dst_port,
                    "detection_method": "behavior_analysis"
                }
                self.analysis_manager.update_threat_intel(dst_ip, server_threat_data)
                
                # Consider adding this IP to our known list for future fast matching
                self.c2_ips.append(dst_ip)
                
            return True
        except Exception as e:
            logging.error(f"Error adding C2 threat intelligence: {e}")
            return False
    
    def get_params(self):
        return {
            "check_interval": {
                "type": "int",
                "default": 600,
                "current": self.check_interval,
                "description": "Seconds between rule checks"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "check_interval":
            self.check_interval = int(value)
            return True
        return False