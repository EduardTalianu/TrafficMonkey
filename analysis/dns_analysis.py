# dns_analysis.py - Analyzes DNS traffic patterns
import time
import math
import logging

logger = logging.getLogger('dns_analysis')

class DNSAnalyzer(AnalysisBase):
    """Analyzes DNS queries for potential C&C, DGA, and other suspicious patterns"""
    
    def __init__(self):
        super().__init__(
            name="DNS Traffic Analysis",
            description="Analyzes DNS query patterns for suspicious activity"
        )
        self.entropy_threshold = 4.0
        self.consonant_threshold = 5
        self.last_report_time = 0
        self.report_interval = 3600  # Generate report once per hour
    
    def initialize(self):
        # Create or update required tables
        cursor = self.analysis_manager.get_cursor()
        try:
            # DNS analysis results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT UNIQUE,
                    entropy REAL,
                    max_consonant_seq INTEGER,
                    query_count INTEGER,
                    first_seen REAL,
                    last_seen REAL,
                    score REAL,
                    classification TEXT
                )
            """)
            
            # Create index
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_analysis_domain ON dns_analysis(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_analysis_score ON dns_analysis(score DESC)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("DNS analysis tables initialized")
        except Exception as e:
            logger.error(f"Error initializing DNS analysis tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process a DNS packet for analysis"""
        # Get the layers
        layers = packet_data.get("layers", {})
        if not layers:
            return False
            
        # Check if this is a DNS packet
        if not self.analysis_manager._has_dns_data(layers):
            return False
        
        try:
            # Extract query data
            src_ip = self.analysis_manager._get_layer_value(layers, "ip_src") or self.analysis_manager._get_layer_value(layers, "ipv6_src")
            query_name = self.analysis_manager._get_layer_value(layers, "dns_qry_name")
            query_type = self.analysis_manager._get_layer_value(layers, "dns_qry_type") or "unknown"
            
            if not query_name or not src_ip:
                return False
                
            # Calculate entropy and max consonant sequence
            entropy = self._calculate_entropy(query_name)
            max_consonant_seq = self._max_consonant_sequence(query_name)
            
            # Determine suspicion score - higher is more suspicious
            score = 0
            classification = "benign"
            
            # Entropy-based scoring
            if entropy > self.entropy_threshold:
                score += (entropy - self.entropy_threshold) * 2
                
            # Consonant sequence scoring
            if max_consonant_seq > self.consonant_threshold:
                score += (max_consonant_seq - self.consonant_threshold) * 1.5
                
            # Length-based scoring (very long domains are suspicious)
            if len(query_name) > 25:
                score += (len(query_name) - 25) * 0.1
                
            # Classify based on score
            if score > 10:
                classification = "highly_suspicious"
            elif score > 5:
                classification = "suspicious"
            elif score > 2:
                classification = "unusual"
                
            # Store analysis results
            current_time = time.time()
            cursor = self.analysis_manager.get_cursor()
            
            try:
                # Check if domain exists
                cursor.execute("SELECT query_count, first_seen FROM dns_analysis WHERE domain = ?", (query_name,))
                result = cursor.fetchone()
                
                if result:
                    # Update existing domain record
                    query_count, first_seen = result
                    cursor.execute("""
                        UPDATE dns_analysis
                        SET query_count = query_count + 1,
                            entropy = ?,
                            max_consonant_seq = ?,
                            last_seen = ?,
                            score = ?,
                            classification = ?
                        WHERE domain = ?
                    """, (entropy, max_consonant_seq, current_time, score, classification, query_name))
                else:
                    # Insert new domain record
                    cursor.execute("""
                        INSERT INTO dns_analysis
                        (domain, entropy, max_consonant_seq, query_count, first_seen, last_seen, score, classification)
                        VALUES (?, ?, ?, 1, ?, ?, ?, ?)
                    """, (query_name, entropy, max_consonant_seq, current_time, current_time, score, classification))
                
                self.analysis_manager.analysis1_conn.commit()
                
                # Generate alert for suspicious domains
                if classification in ("suspicious", "highly_suspicious"):
                    alert_message = f"Suspicious DNS query to {query_name} (score: {score:.2f}, entropy: {entropy:.2f})"
                    self.analysis_manager.add_alert(src_ip, alert_message, "DNS_Analysis")
                
            finally:
                cursor.close()
            
            return True
        except Exception as e:
            logger.error(f"Error analyzing DNS packet: {e}")
            return False
    
    def run_periodic_analysis(self):
        """Run periodic analysis on DNS data"""
        current_time = time.time()
        if current_time - self.last_report_time < self.report_interval:
            return False  # Not time for a report yet
        
        self.last_report_time = current_time
        
        try:
            cursor = self.analysis_manager.get_cursor()
            
            # Find domains with high suspicion scores
            cursor.execute("""
                SELECT domain, score, query_count, first_seen, last_seen 
                FROM dns_analysis 
                WHERE classification IN ('suspicious', 'highly_suspicious')
                AND last_seen > ?
                ORDER BY score DESC
                LIMIT 50
            """, (current_time - 86400,))  # Look at suspicious domains in the last 24 hours
            
            suspicious_domains = cursor.fetchall()
            cursor.close()
            
            logger.info(f"DNS Analysis Report: Found {len(suspicious_domains)} suspicious domains")
            
            # We could generate a more comprehensive report here
            # or store the results for a dashboard
            
            return True
        except Exception as e:
            logger.error(f"Error in DNS periodic analysis: {e}")
            return False
    
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        # Count character frequencies
        char_count = {}
        for char in text.lower():
            if char in char_count:
                char_count[char] += 1
            else:
                char_count[char] = 1
        
        length = len(text)
        
        # Calculate entropy
        entropy = 0
        for count in char_count.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _max_consonant_sequence(self, text):
        """Find the longest sequence of consonants in text"""
        if not text:
            return 0
        
        consonants = "bcdfghjklmnpqrstvwxyz"
        text = text.lower()
        
        max_seq = 0
        current_seq = 0
        
        for char in text:
            if char in consonants:
                current_seq += 1
                max_seq = max(max_seq, current_seq)
            else:
                current_seq = 0
        
        return max_seq