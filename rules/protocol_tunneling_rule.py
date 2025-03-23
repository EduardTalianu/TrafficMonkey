# Rule class is injected by the RuleLoader
import statistics
import time
import math

class ProtocolTunnelingRule(Rule):
    """Rule that detects protocol tunneling (one protocol encapsulated in another)"""
    def __init__(self):
        super().__init__("Protocol Tunneling Detection", "Detects when one protocol is being tunneled inside another (like DNS tunneling)")
        self.dns_domain_length_threshold = 40  # Maximum domain name length before flagging
        self.dns_entropy_threshold = 4.0  # Shannon entropy threshold for DNS tunneling
        self.check_interval = 600  # Seconds between rule checks (10 minutes)
        self.min_requests = 10  # Minimum number of requests to trigger analysis
        self.last_check_time = 0
    
    def calculate_entropy(self, domain):
        """Calculate Shannon entropy of a domain name"""
        if not domain:
            return 0
            
        # Remove common TLDs and subdomains for better detection
        domain = domain.lower()
        common_tlds = [".com", ".net", ".org", ".io", ".edu", ".gov", ".mil", ".info", ".biz"]
        for tld in common_tlds:
            if domain.endswith(tld):
                domain = domain[:-len(tld)]
                break
                
        # Calculate entropy
        char_freq = {}
        for char in domain:
            if char in char_freq:
                char_freq[char] += 1
            else:
                char_freq[char] = 1
        
        entropy = 0
        length = len(domain)
        if length < 1:
            return 0
            
        for char, freq in char_freq.items():
            prob = freq / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def analyze_dns_tunneling(self, db_cursor):
        """Analyze DNS queries for tunneling indicators"""
        alerts = []
        
        try:
            # Check if dns_queries table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='dns_queries'
            """)
            
            if not db_cursor.fetchone():
                return []  # DNS table doesn't exist, skip this check
            
            # Get DNS queries for analysis
            db_cursor.execute("""
                SELECT src_ip, query_domain, COUNT(*) as query_count
                FROM dns_queries
                WHERE timestamp > ?
                GROUP BY src_ip, query_domain
                ORDER BY query_count DESC
            """, (time.time() - 3600,))  # Look at last hour
            
            dns_queries = db_cursor.fetchall()
            
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
                        'total_queries': 0
                    }
                
                # Calculate statistics
                domain_length = len(domain)
                entropy = self.calculate_entropy(domain)
                
                # Store for aggregate analysis
                src_ip_stats[src_ip]['domains'].append(domain)
                src_ip_stats[src_ip]['lengths'].append(domain_length)
                src_ip_stats[src_ip]['entropies'].append(entropy)
                src_ip_stats[src_ip]['total_queries'] += count
                
                # Check individual domains for immediate red flags
                if domain_length > self.dns_domain_length_threshold and entropy > self.dns_entropy_threshold:
                    alerts.append(f"Potential DNS tunneling: {src_ip} queried long, high-entropy domain: {domain} (length: {domain_length}, entropy: {entropy:.2f})")
            
            # Analyze aggregate statistics for each source IP
            for src_ip, stats in src_ip_stats.items():
                # Skip if not enough queries
                if stats['total_queries'] < self.min_requests:
                    continue
                    
                # Get average domain length and entropy
                avg_length = statistics.mean(stats['lengths']) if stats['lengths'] else 0
                avg_entropy = statistics.mean(stats['entropies']) if stats['entropies'] else 0
                
                # Check for anomalous patterns
                if avg_length > self.dns_domain_length_threshold * 0.7 and avg_entropy > self.dns_entropy_threshold * 0.8:
                    alerts.append(f"Sustained DNS tunneling activity: {src_ip} made {stats['total_queries']} queries with average length {avg_length:.1f} and entropy {avg_entropy:.2f}")
                    
                    # Add example domains
                    if len(stats['domains']) <= 3:
                        alerts.append(f"  Example domains: {', '.join(stats['domains'])}")
                    else:
                        alerts.append(f"  Example domains: {', '.join(stats['domains'][:3])}...")
            
            return alerts
        except Exception as e:
            return [f"Error in DNS tunneling analysis: {str(e)}"]
    
    def analyze_http_tunneling(self, db_cursor):
        """Analyze HTTP traffic for tunneling indicators"""
        alerts = []
        
        try:
            # Check if http_headers table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='http_headers'
            """)
            
            if not db_cursor.fetchone():
                return []  # HTTP headers table doesn't exist, skip this check
            
            # Look for suspicious HTTP traffic that might indicate tunneling
            db_cursor.execute("""
                SELECT h.connection_key, c.src_ip, c.dst_ip, c.dst_port, h.host, h.path, c.total_bytes
                FROM http_headers h
                JOIN connections c ON h.connection_key = c.connection_key
                WHERE c.total_bytes > 10000
                AND c.timestamp > datetime('now', '-1 hour')
            """)
            
            http_connections = db_cursor.fetchall()
            
            for conn_key, src_ip, dst_ip, dst_port, host, path, total_bytes in http_connections:
                # Look for Base64 encoded data in URLs
                if path and len(path) > 100:
                    # Simple check for Base64-like strings (long strings of alphanumeric + /+= characters)
                    b64_chars = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
                    path_chars = set(path)
                    
                    # If most characters are Base64 alphabet and path is long, it's suspicious
                    if len(path_chars.intersection(b64_chars)) / len(path_chars) > 0.9 and len(path) > 200:
                        alerts.append(f"Possible HTTP tunneling: {src_ip} to {dst_ip}:{dst_port} with long Base64-like URL path ({len(path)} chars)")
            
            return alerts
        except Exception as e:
            return [f"Error in HTTP tunneling analysis: {str(e)}"]
    
    def analyze(self, db_cursor):
        alerts = []
        current_time = time.time()
        
        # Only run this rule periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Run the different protocol tunneling detection methods
            dns_alerts = self.analyze_dns_tunneling(db_cursor)
            http_alerts = self.analyze_http_tunneling(db_cursor)
            
            alerts.extend(dns_alerts)
            alerts.extend(http_alerts)
            
            return alerts
        except Exception as e:
            return [f"Error in Protocol Tunneling rule: {str(e)}"]
    
    def get_params(self):
        return {
            "dns_domain_length_threshold": {
                "type": "int",
                "default": 40,
                "current": self.dns_domain_length_threshold,
                "description": "Maximum domain name length before flagging"
            },
            "dns_entropy_threshold": {
                "type": "float",
                "default": 4.0,
                "current": self.dns_entropy_threshold,
                "description": "Shannon entropy threshold for DNS tunneling"
            },
            "check_interval": {
                "type": "int",
                "default": 600,
                "current": self.check_interval,
                "description": "Seconds between rule checks"
            },
            "min_requests": {
                "type": "int",
                "default": 10,
                "current": self.min_requests,
                "description": "Minimum requests needed for statistical analysis"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "dns_domain_length_threshold":
            self.dns_domain_length_threshold = int(value)
            return True
        elif param_name == "dns_entropy_threshold":
            self.dns_entropy_threshold = float(value)
            return True
        elif param_name == "check_interval":
            self.check_interval = int(value)
            return True
        elif param_name == "min_requests":
            self.min_requests = int(value)
            return True
        return False