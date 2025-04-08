# dns_analysis.py - Analyzes DNS traffic patterns with enhanced analytics
import time
import math
import logging
import json
from collections import Counter

logger = logging.getLogger('dns_analysis')

class DNSAnalyzer(AnalysisBase):
    """Analyzes DNS queries for potential C&C, DGA, and other suspicious patterns with advanced analytics"""
    
    def __init__(self):
        super().__init__(
            name="DNS Traffic Analysis",
            description="Analyzes DNS query patterns for suspicious activity and domain reputation"
        )
        # Detection thresholds
        self.entropy_threshold = 4.0
        self.consonant_threshold = 5
        
        # Analysis intervals
        self.last_report_time = 0
        self.report_interval = 3600  # Generate report once per hour
        
        # Domain TLD categorization
        self.common_tlds = set(['com', 'net', 'org', 'edu', 'gov', 'info', 'io', 'co', 'me', 'biz'])
        self.rare_tlds = set(['top', 'xyz', 'club', 'online', 'site', 'live', 'click', 'tech', 'space', 'link'])
        
        # Historical data tracking
        self.domain_trends = {}  # Tracking domain query frequency over time
        self.historical_interval = 86400  # 24 hours for trend analysis
    
    def initialize(self):
        # Create or update required tables with enhanced schema
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
                    classification TEXT,
                    tld TEXT,
                    domain_length INTEGER,
                    digit_ratio REAL,
                    has_repetitive_patterns BOOLEAN,
                    randomness_score REAL,
                    trend_factor REAL DEFAULT 0,
                    is_dga_candidate BOOLEAN DEFAULT 0,
                    domain_age_days INTEGER DEFAULT 0,
                    parent_domain TEXT
                )
            """)
            
            # Domain popularity tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_domain_popularity (
                    domain TEXT PRIMARY KEY,
                    hourly_counts TEXT,  -- JSON array of hourly query counts
                    daily_counts TEXT,   -- JSON array of daily query counts
                    unique_clients INTEGER,
                    last_updated REAL
                )
            """)
            
            # DNS Query pattern analysis
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_client_patterns (
                    client_ip TEXT PRIMARY KEY,
                    domains_queried INTEGER,
                    query_interval_avg REAL,
                    query_interval_std REAL,
                    query_patterns TEXT,  -- JSON of query patterns
                    periodic_score REAL DEFAULT 0,
                    last_updated REAL
                )
            """)
            
            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_analysis_domain ON dns_analysis(domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_analysis_score ON dns_analysis(score DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_analysis_classification ON dns_analysis(classification)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_analysis_tld ON dns_analysis(tld)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_analysis_dga ON dns_analysis(is_dga_candidate)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_popularity_domain ON dns_domain_popularity(domain)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_client_patterns_periodic ON dns_client_patterns(periodic_score DESC)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("DNS analysis tables initialized with enhanced schema")
        except Exception as e:
            logger.error(f"Error initializing DNS analysis tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process a DNS packet for analysis with enhanced metrics"""
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
            
            # Process and analyze the DNS query
            self._analyze_dns_query(src_ip, query_name, query_type)
            
            # Update client query patterns (for C2 beaconing detection)
            self._update_client_patterns(src_ip, query_name)
            
            return True
        except Exception as e:
            logger.error(f"Error analyzing DNS packet: {e}")
            return False
    
    def _analyze_dns_query(self, src_ip, query_name, query_type):
        """Enhanced analysis of DNS query with multiple metrics"""
        query_name = query_name.lower()  # Normalize to lowercase
        
        # Extract metadata
        domain_length = len(query_name)
        tld = self._extract_tld(query_name)
        parent_domain = self._extract_parent_domain(query_name)
        
        # Calculate linguistic metrics
        entropy = self._calculate_entropy(query_name)
        max_consonant_seq = self._max_consonant_sequence(query_name)
        digit_ratio = self._calculate_digit_ratio(query_name)
        has_repetition = self._has_repetitive_patterns(query_name)
        
        # Calculate randomness score
        randomness_score = self._calculate_randomness_score(query_name, entropy, digit_ratio)
        
        # Determine suspicion score - higher is more suspicious
        score = 0
        
        # Entropy-based scoring
        if entropy > self.entropy_threshold:
            score += (entropy - self.entropy_threshold) * 2
            
        # Consonant sequence scoring
        if max_consonant_seq > self.consonant_threshold:
            score += (max_consonant_seq - self.consonant_threshold) * 1.5
            
        # Length-based scoring (very long domains are suspicious)
        if domain_length > 25:
            score += (domain_length - 25) * 0.1
        
        # TLD scoring
        if tld in self.rare_tlds:
            score += 2
        
        # Digit ratio scoring
        if digit_ratio > 0.3:  # More than 30% digits is unusual
            score += digit_ratio * 5
        
        # Repetitive pattern detection
        if has_repetition:
            score += 2
        
        # Randomness scoring
        score += randomness_score * 1.5
        
        # Is this a potential DGA domain?
        is_dga_candidate = (score > 8 and entropy > 3.8 and (digit_ratio > 0.2 or max_consonant_seq > 4))
        
        # Classify based on score
        classification = "benign"
        if score > 12:
            classification = "highly_suspicious"
        elif score > 8:
            classification = "suspicious"
        elif score > 4:
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
                        classification = ?,
                        tld = ?,
                        domain_length = ?,
                        digit_ratio = ?,
                        has_repetitive_patterns = ?,
                        randomness_score = ?,
                        is_dga_candidate = ?
                    WHERE domain = ?
                """, (
                    entropy, max_consonant_seq, current_time, score, classification,
                    tld, domain_length, digit_ratio, has_repetition, randomness_score,
                    is_dga_candidate, query_name
                ))
            else:
                # Insert new domain record
                cursor.execute("""
                    INSERT INTO dns_analysis
                    (domain, entropy, max_consonant_seq, query_count, first_seen, last_seen, 
                     score, classification, tld, domain_length, digit_ratio, 
                     has_repetitive_patterns, randomness_score, is_dga_candidate, parent_domain)
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    query_name, entropy, max_consonant_seq, current_time, current_time, 
                    score, classification, tld, domain_length, digit_ratio,
                    has_repetition, randomness_score, is_dga_candidate, parent_domain
                ))
            
            # Update domain popularity statistics
            self._update_domain_popularity(cursor, query_name, src_ip, current_time)
            
            self.analysis_manager.analysis1_conn.commit()
            
        finally:
            cursor.close()
    
    def _update_domain_popularity(self, cursor, domain, client_ip, timestamp):
        """Track domain popularity over time for trend analysis"""
        current_hour = int(timestamp / 3600) * 3600  # Round to nearest hour
        
        # Check if domain exists in popularity tracking
        cursor.execute("SELECT hourly_counts, daily_counts, unique_clients FROM dns_domain_popularity WHERE domain = ?", (domain,))
        result = cursor.fetchone()
        
        if result:
            hourly_counts_json, daily_counts_json, unique_clients = result
            
            # Parse JSON data
            try:
                hourly_counts = json.loads(hourly_counts_json) if hourly_counts_json else {}
                daily_counts = json.loads(daily_counts_json) if daily_counts_json else {}
            except json.JSONDecodeError:
                hourly_counts = {}
                daily_counts = {}
            
            # Update hourly counts
            hour_key = str(current_hour)
            if hour_key in hourly_counts:
                hourly_counts[hour_key] += 1
            else:
                hourly_counts[hour_key] = 1
            
            # Update daily counts
            current_day = int(timestamp / 86400) * 86400
            day_key = str(current_day)
            if day_key in daily_counts:
                daily_counts[day_key] += 1
            else:
                daily_counts[day_key] = 1
            
            # Limit storage to last 7 days
            cutoff_time = timestamp - (7 * 86400)
            hourly_counts = {k: v for k, v in hourly_counts.items() if float(k) >= cutoff_time}
            daily_counts = {k: v for k, v in daily_counts.items() if float(k) >= cutoff_time}
            
            # Track unique clients (as a simple counter for now)
            cursor.execute("""
                SELECT COUNT(*) FROM (
                    SELECT DISTINCT src_ip FROM dns_queries 
                    WHERE query_domain = ? LIMIT 1000
                )
            """, (domain,))
            unique_clients = cursor.fetchone()[0] or 1
            
            # Update popularity record
            cursor.execute("""
                UPDATE dns_domain_popularity
                SET hourly_counts = ?,
                    daily_counts = ?,
                    unique_clients = ?,
                    last_updated = ?
                WHERE domain = ?
            """, (
                json.dumps(hourly_counts),
                json.dumps(daily_counts),
                unique_clients,
                timestamp,
                domain
            ))
        else:
            # Create new popularity record
            hourly_counts = {str(current_hour): 1}
            daily_counts = {str(int(timestamp / 86400) * 86400): 1}
            
            cursor.execute("""
                INSERT INTO dns_domain_popularity
                (domain, hourly_counts, daily_counts, unique_clients, last_updated)
                VALUES (?, ?, ?, 1, ?)
            """, (
                domain,
                json.dumps(hourly_counts),
                json.dumps(daily_counts),
                timestamp
            ))
    
    def _update_client_patterns(self, client_ip, query_domain):
        """Analyze client query patterns for potential C2 beaconing behavior"""
        current_time = time.time()
        cursor = self.analysis_manager.get_cursor()
        
        try:
            # Get recent queries from this client
            cursor.execute("""
                SELECT query_domain, timestamp 
                FROM dns_queries 
                WHERE src_ip = ? 
                ORDER BY timestamp DESC 
                LIMIT 50
            """, (client_ip,))
            
            queries = cursor.fetchall()
            
            if len(queries) < 5:  # Need at least 5 queries for meaningful analysis
                return
            
            # Count domains and calculate query intervals
            domains = [q[0] for q in queries]
            timestamps = [q[1] for q in queries]
            
            domain_counter = Counter(domains)
            domains_queried = len(domain_counter)
            
            # Calculate interval stats
            intervals = []
            for i in range(1, len(timestamps)):
                intervals.append(timestamps[i-1] - timestamps[i])
            
            if intervals:
                avg_interval = sum(intervals) / len(intervals)
                
                # Calculate standard deviation
                if len(intervals) > 1:
                    variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
                    std_dev = math.sqrt(variance)
                else:
                    std_dev = 0
                
                # Look for repetitive patterns in domain queries
                patterns = self._detect_query_patterns(domains)
                
                # Calculate periodicity score - lower std_dev relative to avg means more periodic
                if avg_interval > 0:
                    cv = std_dev / avg_interval  # Coefficient of variation
                    periodic_score = max(0, min(10, 10 * (1 - min(cv, 1))))
                else:
                    periodic_score = 0
                
                # Store client pattern data
                cursor.execute("""
                    INSERT OR REPLACE INTO dns_client_patterns
                    (client_ip, domains_queried, query_interval_avg, query_interval_std, 
                     query_patterns, periodic_score, last_updated)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    client_ip, 
                    domains_queried,
                    avg_interval, 
                    std_dev,
                    json.dumps(patterns), 
                    periodic_score,
                    current_time
                ))
                
                self.analysis_manager.analysis1_conn.commit()
        finally:
            cursor.close()
    
    def _detect_query_patterns(self, domains):
        """Detect patterns in domain query sequences"""
        patterns = {}
        
        # Look for repeating sequences of domains
        for length in range(2, min(6, len(domains) // 2 + 1)):
            for start in range(len(domains) - length * 2 + 1):
                potential_pattern = tuple(domains[start:start+length])
                next_sequence = tuple(domains[start+length:start+length*2])
                
                if potential_pattern == next_sequence:
                    pattern_str = "->".join(potential_pattern)
                    if pattern_str in patterns:
                        patterns[pattern_str] += 1
                    else:
                        patterns[pattern_str] = 1
        
        return patterns
    
    def run_periodic_analysis(self):
        """Run periodic analysis on DNS data for trend detection and advanced analytics"""
        current_time = time.time()
        if current_time - self.last_report_time < self.report_interval:
            return False  # Not time for a report yet
        
        self.last_report_time = current_time
        
        try:
            cursor = self.analysis_manager.get_cursor()
            
            # Calculate domain trends
            self._calculate_domain_trends(cursor, current_time)
            
            # Analyze client query patterns
            self._analyze_client_beaconing(cursor)
            
            # Find related domains (similar patterns)
            self._identify_related_domains(cursor)
            
            cursor.close()
            logger.info("Completed DNS periodic analysis with trend detection")
            
            return True
        except Exception as e:
            logger.error(f"Error in DNS periodic analysis: {e}")
            return False
    
    def _calculate_domain_trends(self, cursor, current_time):
        """Calculate domain query trends over time for anomaly detection"""
        try:
            # Get domains with popularity data
            cursor.execute("SELECT domain, hourly_counts, daily_counts FROM dns_domain_popularity")
            domains = cursor.fetchall()
            
            for domain, hourly_counts_json, daily_counts_json in domains:
                try:
                    hourly_counts = json.loads(hourly_counts_json) if hourly_counts_json else {}
                    daily_counts = json.loads(daily_counts_json) if daily_counts_json else {}
                    
                    if not hourly_counts or not daily_counts:
                        continue
                    
                    # Calculate hourly trend
                    hours = sorted([int(h) for h in hourly_counts.keys()])
                    if len(hours) < 2:
                        continue
                        
                    # Get hourly query counts from newest to oldest
                    recent_counts = [hourly_counts[str(h)] for h in sorted(hours, reverse=True)[:24]]
                    
                    if len(recent_counts) < 6:  # Need at least 6 hours of data
                        continue
                    
                    # Calculate trend factor - ratio of recent activity to historical
                    recent_avg = sum(recent_counts[:3]) / 3  # Last 3 hours
                    historical_avg = sum(recent_counts[3:]) / len(recent_counts[3:])  # Previous hours
                    
                    if historical_avg > 0:
                        trend_factor = recent_avg / historical_avg
                    else:
                        trend_factor = 1.0 if recent_avg == 0 else 2.0
                    
                    # Detect sudden appearance or disappearance
                    sudden_appearance = trend_factor > 3 and historical_avg < 1
                    sudden_disappearance = trend_factor < 0.3 and historical_avg > 1
                    
                    # Update trend factor in dns_analysis
                    cursor.execute("""
                        UPDATE dns_analysis
                        SET trend_factor = ?
                        WHERE domain = ?
                    """, (trend_factor, domain))
                    
                except (json.JSONDecodeError, KeyError, ZeroDivisionError) as e:
                    logger.warning(f"Error analyzing trends for domain {domain}: {e}")
                    continue
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info(f"Updated domain trends for {len(domains)} domains")
            
        except Exception as e:
            logger.error(f"Error calculating domain trends: {e}")
    
    def _analyze_client_beaconing(self, cursor):
        """Analyze client query patterns for potential C2 beaconing behavior"""
        try:
            # Find clients with high periodic scores
            cursor.execute("""
                SELECT client_ip, domains_queried, query_interval_avg, 
                       query_interval_std, periodic_score
                FROM dns_client_patterns
                WHERE periodic_score > 7
                ORDER BY periodic_score DESC
                LIMIT 20
            """)
            
            high_periodic_clients = cursor.fetchall()
            
            for client_ip, domains_queried, interval_avg, interval_std, score in high_periodic_clients:
                logger.info(f"Client {client_ip} shows potential beaconing behavior: periodic_score={score:.1f}, interval={interval_avg:.1f}s ±{interval_std:.1f}s, domains={domains_queried}")
                
                # For each highly periodic client, find their top domains
                cursor.execute("""
                    SELECT query_domain, COUNT(*) as query_count
                    FROM dns_queries
                    WHERE src_ip = ?
                    GROUP BY query_domain
                    ORDER BY query_count DESC
                    LIMIT 5
                """, (client_ip,))
                
                top_domains = cursor.fetchall()
                domain_list = ", ".join([f"{domain} ({count})" for domain, count in top_domains])
                logger.info(f"Client {client_ip} top queried domains: {domain_list}")
            
        except Exception as e:
            logger.error(f"Error analyzing client beaconing behavior: {e}")
    
    def _identify_related_domains(self, cursor):
        """Find potentially related domains based on naming patterns"""
        try:
            # Find DGA candidate domains
            cursor.execute("""
                SELECT domain, entropy, score
                FROM dns_analysis
                WHERE is_dga_candidate = 1
                AND last_seen > ?
                ORDER BY score DESC
                LIMIT 100
            """, (time.time() - 86400,))  # Last 24 hours
            
            dga_candidates = cursor.fetchall()
            
            # Group domains by pattern similarities
            domain_groups = {}
            
            for domain, entropy, score in dga_candidates:
                # Extract domain parts excluding common TLDs
                parts = domain.split('.')
                base_domain = parts[0]
                
                # Calculate character frequency distribution
                char_dist = {}
                for c in base_domain:
                    if c in char_dist:
                        char_dist[c] += 1
                    else:
                        char_dist[c] = 1
                
                # Calculate length and digit patterns
                length = len(base_domain)
                digit_count = sum(1 for c in base_domain if c.isdigit())
                
                # Create a signature for this domain pattern
                signature = f"{length}:{digit_count}:{entropy:.1f}"
                
                if signature in domain_groups:
                    domain_groups[signature].append(domain)
                else:
                    domain_groups[signature] = [domain]
            
            # Log groups of similar domains
            for signature, domains in domain_groups.items():
                if len(domains) >= 3:  # Only report groups with at least 3 domains
                    logger.info(f"Found related DGA-like domains (signature: {signature}): {', '.join(domains[:5])}" + (f" and {len(domains)-5} more" if len(domains) > 5 else ""))
            
        except Exception as e:
            logger.error(f"Error identifying related domains: {e}")
    
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
    
    def _calculate_digit_ratio(self, text):
        """Calculate the ratio of digits in the text"""
        if not text:
            return 0
            
        digit_count = sum(c.isdigit() for c in text)
        return digit_count / len(text)
    
    def _has_repetitive_patterns(self, text):
        """Check for repetitive patterns in the text"""
        # Remove common separators
        clean_text = ''.join(c for c in text if c not in ['.', '-', '_'])
        
        # Check for repeated character sequences
        for length in range(2, min(5, len(clean_text) // 2)):
            for i in range(len(clean_text) - length * 2 + 1):
                if clean_text[i:i+length] == clean_text[i+length:i+length*2]:
                    return True
        
        return False
    
    def _calculate_randomness_score(self, domain, entropy, digit_ratio):
        """Calculate a randomness score based on various factors"""
        # Remove TLD for analysis
        parts = domain.split('.')
        if len(parts) > 1:
            base_domain = parts[0]
        else:
            base_domain = domain
        
        # Check for alternating patterns (e.g., a1b2c3)
        alternating_pattern = 0
        for i in range(len(base_domain) - 1):
            if (base_domain[i].isalpha() and base_domain[i+1].isdigit()) or \
               (base_domain[i].isdigit() and base_domain[i+1].isalpha()):
                alternating_pattern += 1
        
        alternating_ratio = alternating_pattern / (len(base_domain) - 1) if len(base_domain) > 1 else 0
        
        # Calculate character distribution evenness
        char_counts = {}
        for c in base_domain.lower():
            char_counts[c] = char_counts.get(c, 0) + 1
        
        if char_counts:
            avg_count = len(base_domain) / len(char_counts)
            count_variance = sum((count - avg_count) ** 2 for count in char_counts.values()) / len(char_counts)
            distribution_score = min(1.0, count_variance / (avg_count ** 2))
        else:
            distribution_score = 0
        
        # Combine factors into a randomness score (0-10)
        randomness_score = (
            (entropy / 5) * 4 +       # Entropy factor (normalized to ~0-4)
            alternating_ratio * 3 +   # Alternating pattern factor (0-3)
            digit_ratio * 2 +         # Digit ratio factor (0-2)
            distribution_score * 1     # Distribution evenness factor (0-1)
        )
        
        return min(10, randomness_score)
    
    def _extract_tld(self, domain):
        """Extract the TLD from a domain name"""
        parts = domain.split('.')
        if len(parts) > 1:
            return parts[-1].lower()
        return ""
    
    def _extract_parent_domain(self, domain):
        """Extract the parent domain (domain + TLD without subdomains)"""
        parts = domain.split('.')
        if len(parts) > 2:
            return '.'.join(parts[-2:])
        return domain