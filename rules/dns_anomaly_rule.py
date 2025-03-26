# Rule class is injected by the RuleLoader
import re
import math
import logging

class DNSAnomalyRule(Rule):
    """Rule that detects unusual DNS activity"""
    def __init__(self):
        super().__init__("DNS Anomaly Rule", "Detects unusual DNS activity like tunneling or DGA domains")
        self.length_threshold = 50  # Maximum domain name length
        self.entropy_threshold = 4.0  # Shannon entropy threshold for DGA detection
        self.query_rate_threshold = 100  # Queries per minute threshold
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
        for char, freq in char_freq.items():
            prob = freq / length
            entropy -= prob * math.log2(prob)
        
        return entropy
    
    def analyze(self, db_cursor):
        alerts = []
        
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
                alerts.append(f"Potential DNS Tunneling: {src_ip} queried unusually long domain: {domain}")
            
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
                entropy = self.calculate_entropy(domain)
                if entropy > self.entropy_threshold:
                    alerts.append(f"Potential DGA Domain: {src_ip} queried high-entropy domain: {domain} (entropy: {entropy:.2f})")
            
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
                alerts.append(f"Potential DNS Flood: {src_ip} made {count} DNS queries in the last minute")
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in DNS Anomaly rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
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
        return False
    
    def get_params(self):
        """Get configurable parameters"""
        return self.configurable_params