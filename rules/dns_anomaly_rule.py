# Enhanced DNSAnomalyRule
# Rule class is injected by the RuleLoader
import re
import math
import logging
import statistics
import time

class DNSAnomalyRule(Rule):
    """Rule that detects unusual DNS activity and DNS tunneling"""
    def __init__(self):
        super().__init__("Enhanced DNS Anomaly Detection", "Detects unusual DNS activity including tunneling, DGA domains, and DNS floods")
        # Length and entropy parameters
        self.length_threshold = 50  # Maximum domain name length
        self.entropy_threshold = 4.0  # Shannon entropy threshold for DGA detection
        
        # Query rate parameters
        self.query_rate_threshold = 100  # Queries per minute threshold
        
        # Tunneling detection parameters
        self.min_requests = 10  # Minimum number of requests to trigger analysis
        self.domain_variance_threshold = 0.7  # Threshold for domain name variance
        
        # Operational parameters
        self.check_interval = 600  # Seconds between rule checks
        self.last_check_time = 0
        
        # Store reference to analysis_manager (will be set later when analysis_manager is available)
        self.analysis_manager = None
        
        self.configurable_params = {
            "length_threshold": {
                "description": "Maximum domain name length before flagging",
                "type": "int",
                "default": 50,
                "current": self.length_threshold
            },
            "entropy_threshold": {
                "description": "Shannon entropy threshold for detecting algorithm-generated domains",
                "type": "float",
                "default": 4.0,
                "current": self.entropy_threshold
            },
            "query_rate_threshold": {
                "description": "Maximum DNS queries per minute before flagging",
                "type": "int",
                "default": 100,
                "current": self.query_rate_threshold
            },
            "min_requests": {
                "description": "Minimum DNS queries needed for tunneling analysis",
                "type": "int",
                "default": 10,
                "current": self.min_requests
            },
            "check_interval": {
                "description": "Seconds between full DNS analysis",
                "type": "int",
                "default": 600,
                "current": self.check_interval
            }
        }
    
    def calculate_entropy(self, domain):
        """Calculate Shannon entropy of a domain name"""
        # Remove common TLDs to focus on the domain part
        domain = re.sub(r'\.(com|net|org|io|edu|gov|mil|info|biz)$', '', domain.lower())
        
        # Calculate entropy
        char_freq = {}
        for char in domain:
            if char in char_freq:
                char_freq[char] += 1
            else:
                char_freq[char] = 1
        
        entropy = 0
        length = len(domain)
        if length == 0:
            return 0
            
        for char, freq in char_freq.items():
            prob = freq / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def analyze(self, db_cursor):
        # Ensure analysis_manager is linked
        if not self.analysis_manager and hasattr(self.db_manager, 'analysis_manager'):
            self.analysis_manager = self.db_manager.analysis_manager
        
        # Return early if analysis_manager is not available (this shouldn't happen with new architecture)
        if not self.analysis_manager:
            logging.error("Cannot run DNS Anomaly rule: analysis_manager not available")
            return ["ERROR: DNS Anomaly rule requires analysis_manager"]
            
        alerts = []
        current_time = time.time()
        
        # Always check for basic DNS anomalies
        try:
            # Check if dns_queries table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='dns_queries'
            """)
            
            if not db_cursor.fetchone():
                return ["DNS Anomaly rule requires dns_queries table which doesn't exist"]
            
            # Check for unusually long domain names (potential DNS tunneling)
            db_cursor.execute("""
                SELECT src_ip, query_domain, COUNT(*) as query_count
                FROM dns_queries
                GROUP BY src_ip, query_domain
                HAVING LENGTH(query_domain) > ?
            """, (self.length_threshold,))
            
            # Store results locally
            long_domains = []
            for row in db_cursor.fetchall():
                long_domains.append(row)
            
            for src_ip, domain, count in long_domains:
                alert_msg = f"Potential DNS Tunneling: {src_ip} queried unusually long domain: {domain}"
                alerts.append(alert_msg)
                
                # Add alert using the new method
                self.add_alert(src_ip, alert_msg)
                
                # Add threat intel data
                self._add_dns_tunneling_data(src_ip, domain, count, "long_domain")
            
            # Check for high entropy domain names (potential DGA)
            db_cursor.execute("""
                SELECT DISTINCT src_ip, query_domain
                FROM dns_queries
            """)
            
            # Store results locally
            domains = []
            for row in db_cursor.fetchall():
                domains.append(row)
            
            for src_ip, domain in domains:
                if not domain:
                    continue
                    
                entropy = self.calculate_entropy(domain)
                if entropy > self.entropy_threshold:
                    alert_msg = f"Potential DGA Domain: {src_ip} queried high-entropy domain: {domain} (entropy: {entropy:.2f})"
                    alerts.append(alert_msg)
                    
                    # Add alert using the new method
                    self.add_alert(src_ip, alert_msg)
                    
                    # Add threat intel data
                    self._add_dga_domain_data(src_ip, domain, entropy)
            
            # Check for high query rates (potential DNS flood)
            db_cursor.execute("""
                SELECT src_ip, COUNT(*) as query_count
                FROM dns_queries
                WHERE timestamp > strftime('%s', 'now') - 60
                GROUP BY src_ip
                HAVING query_count > ?
            """, (self.query_rate_threshold,))
            
            # Store results locally
            high_rates = []
            for row in db_cursor.fetchall():
                high_rates.append(row)
            
            for src_ip, count in high_rates:
                alert_msg = f"Potential DNS Flood: {src_ip} made {count} DNS queries in the last minute"
                alerts.append(alert_msg)
                
                # Add alert using the new method
                self.add_alert(src_ip, alert_msg)
                
                # Add threat intel data
                self._add_dns_flood_data(src_ip, count)
            
            # Perform more detailed DNS tunneling analysis less frequently
            if current_time - self.last_check_time >= self.check_interval:
                self.last_check_time = current_time
                
                # Get DNS queries for tunneling analysis
                db_cursor.execute("""
                    SELECT src_ip, query_domain, COUNT(*) as query_count
                    FROM dns_queries
                    WHERE timestamp > ?
                    GROUP BY src_ip, query_domain
                    ORDER BY query_count DESC
                """, (time.time() - 3600,))  # Look at last hour
                
                # Store results locally
                dns_queries = []
                for row in db_cursor.fetchall():
                    dns_queries.append(row)
                
                # Analyze each source IP separately
                src_ip_stats = {}
                
                for src_ip, domain, count in dns_queries:
                    # Skip if domain is None
                    if not domain:
                        continue
                        
                    # Initialize stats for this source IP
                    if src_ip not in src_ip_stats:
                        src_ip_stats[src_ip] = {
                            'domains': [],
                            'lengths': [],
                            'entropies': [],
                            'subdomains': [],
                            'total_queries': 0
                        }
                    
                    # Calculate statistics
                    domain_length = len(domain)
                    entropy = self.calculate_entropy(domain)
                    
                    # Count subdomain levels
                    subdomain_count = domain.count('.')
                    
                    # Store for aggregate analysis
                    src_ip_stats[src_ip]['domains'].append(domain)
                    src_ip_stats[src_ip]['lengths'].append(domain_length)
                    src_ip_stats[src_ip]['entropies'].append(entropy)
                    src_ip_stats[src_ip]['subdomains'].append(subdomain_count)
                    src_ip_stats[src_ip]['total_queries'] += count
                
                # Analyze aggregate statistics for each source IP
                for src_ip, stats in src_ip_stats.items():
                    # Skip if not enough queries
                    if stats['total_queries'] < self.min_requests:
                        continue
                        
                    # Get average and variance of domain components
                    if len(stats['lengths']) > 1:
                        avg_length = statistics.mean(stats['lengths'])
                        avg_entropy = statistics.mean(stats['entropies'])
                        
                        # Calculate variance as a normalized measure 
                        try:
                            length_variance = statistics.stdev(stats['lengths']) / avg_length if avg_length > 0 else 0
                        except statistics.StatisticsError:
                            length_variance = 0
                        
                        # Check for anomalous patterns indicating tunneling
                        # 1. Consistently long domains
                        # 2. High entropy domains
                        # 3. Low variance in domain structure (fixed encoding pattern)
                        if (avg_length > self.length_threshold * 0.7 and 
                            avg_entropy > self.entropy_threshold * 0.8 and 
                            length_variance < self.domain_variance_threshold):
                                
                            alert_msg = f"Sustained DNS tunneling activity: {src_ip} made {stats['total_queries']} queries with average length {avg_length:.1f}, entropy {avg_entropy:.2f}, and low length variance ({length_variance:.3f})"
                            alerts.append(alert_msg)
                            
                            # Add alert using the new method
                            self.add_alert(src_ip, alert_msg)
                            
                            # Add example domains
                            example_domains = stats['domains'][:3] if len(stats['domains']) > 3 else stats['domains']
                            example_msg = f"  Example domains: {', '.join(example_domains)}"
                            if len(stats['domains']) > 3:
                                example_msg += "..."
                            alerts.append(example_msg)
                            
                            # Add as a supplementary alert
                            self.add_alert(src_ip, example_msg)
                            
                            # Add detailed threat intel
                            self._add_sustained_dns_tunneling_data(
                                src_ip, 
                                stats['domains'], 
                                stats['total_queries'], 
                                avg_length,
                                avg_entropy,
                                length_variance
                            )
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Enhanced DNS Anomaly rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def add_alert(self, ip_address, alert_message):
        """Add an alert to the x_alerts table"""
        if self.analysis_manager:
            return self.analysis_manager.add_alert(ip_address, alert_message, self.name)
        return False
    
    def _add_dns_tunneling_data(self, src_ip, domain, query_count, detection_type):
        """Add DNS tunneling data to x_ip_threat_intel"""
        try:
            # Build threat intelligence data
            threat_data = {
                "score": 7.0,  # High score for DNS tunneling
                "type": "dns_tunneling",
                "confidence": 0.7,
                "source": "DNS_Anomaly_Rule",
                "first_seen": time.time(),
                "details": {
                    "domain": domain,
                    "query_count": query_count,
                    "domain_length": len(domain),
                    "entropy": self.calculate_entropy(domain),
                    "detection_type": detection_type,
                    "detection_method": "dns_analysis"
                },
                # Extended columns for easy querying
                "protocol": "DNS",
                "encoding_type": "domain_name",
                "detection_method": "dns_tunneling_analysis",
                "bytes_transferred": len(domain) * query_count,
                "packet_count": query_count
            }
            
            # Update threat intelligence in analysis_1.db
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding DNS tunneling data: {e}")
            return False
    
    def _add_dga_domain_data(self, src_ip, domain, entropy):
        """Add DGA domain data to x_ip_threat_intel"""
        try:
            # Build threat intelligence data
            threat_data = {
                "score": 6.0,  # Medium-high score for DGA
                "type": "dga_domain",
                "confidence": 0.6,
                "source": "DNS_Anomaly_Rule",
                "first_seen": time.time(),
                "details": {
                    "domain": domain,
                    "entropy": entropy,
                    "domain_length": len(domain),
                    "detection_method": "entropy_analysis"
                },
                # Extended columns for easy querying
                "protocol": "DNS",
                "detection_method": "dga_detection",
                "encoding_type": "algorithmic_generation"
            }
            
            # Update threat intelligence in analysis_1.db
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding DGA domain data: {e}")
            return False
    
    def _add_dns_flood_data(self, src_ip, query_count):
        """Add DNS flood data to x_ip_threat_intel"""
        try:
            # Build threat intelligence data
            threat_data = {
                "score": 5.0,  # Medium score for DNS flood
                "type": "dns_flood",
                "confidence": 0.8,
                "source": "DNS_Anomaly_Rule",
                "first_seen": time.time(),
                "details": {
                    "query_count": query_count,
                    "time_window_seconds": 60,
                    "queries_per_second": query_count / 60,
                    "detection_method": "query_rate_analysis"
                },
                # Extended columns for easy querying
                "protocol": "DNS",
                "detection_method": "traffic_rate_analysis",
                "packet_count": query_count
            }
            
            # Update threat intelligence in analysis_1.db
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding DNS flood data: {e}")
            return False
    
    def _add_sustained_dns_tunneling_data(self, src_ip, domains, query_count, avg_length, avg_entropy, length_variance):
        """Add sustained DNS tunneling data to x_ip_threat_intel"""
        try:
            # Calculate total bytes transferred (approximate)
            total_bytes = sum(len(d) for d in domains)
            
            # Build threat intelligence data
            threat_data = {
                "score": 8.0,  # Very high score for sustained tunneling
                "type": "dns_tunneling",
                "confidence": 0.9,
                "source": "DNS_Anomaly_Rule",
                "first_seen": time.time(),
                "details": {
                    "example_domains": domains[:5] if len(domains) > 5 else domains,
                    "query_count": query_count,
                    "average_domain_length": avg_length,
                    "average_entropy": avg_entropy,
                    "length_variance": length_variance,
                    "detection_method": "pattern_analysis",
                    "unique_domains": len(domains)
                },
                # Extended columns for easy querying
                "protocol": "DNS",
                "detection_method": "pattern_analysis",
                "encoding_type": "domain_name",
                "bytes_transferred": total_bytes,
                "packet_count": query_count,
                "timing_variance": length_variance
            }
            
            # Update threat intelligence in analysis_1.db
            self.analysis_manager.update_threat_intel(src_ip, threat_data)
            return True
        except Exception as e:
            logging.error(f"Error adding sustained DNS tunneling data: {e}")
            return False
    
    def update_param(self, param_name, value):
        """Update a configurable parameter"""
        if param_name in self.configurable_params:
            if param_name == "length_threshold":
                self.length_threshold = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
            elif param_name == "entropy_threshold":
                self.entropy_threshold = float(value)
                self.configurable_params[param_name]["current"] = float(value)
                return True
            elif param_name == "query_rate_threshold":
                self.query_rate_threshold = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
            elif param_name == "min_requests":
                self.min_requests = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
            elif param_name == "check_interval":
                self.check_interval = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
        return False
    
    def get_params(self):
        """Get configurable parameters"""
        return self.configurable_params