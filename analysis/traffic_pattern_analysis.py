# traffic_pattern_analysis.py - Analyzes traffic patterns for anomalies
import time
import logging
import json
import math
import statistics
from collections import defaultdict

logger = logging.getLogger('traffic_pattern_analysis')

class TrafficPatternAnalyzer(AnalysisBase):
    """Analyzes traffic patterns to detect anomalies and periodic behavior"""
    
    def __init__(self):
        super().__init__(
            name="Traffic Pattern Analysis",
            description="Analyzes traffic patterns for anomalies and beaconing"
        )
        self.connections = defaultdict(list)  # Store packet sizes for each connection
        self.max_samples = 100  # Maximum number of packet sizes to keep per connection
        self.last_analysis_time = 0
        self.analysis_interval = 60  # seconds
    
    def initialize(self):
        # Create or update required tables
        cursor = self.analysis_manager.get_cursor()
        try:
            # This table should already exist, but ensure it's properly set up
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS traffic_patterns (
                    connection_key TEXT PRIMARY KEY,
                    avg_packet_size REAL,
                    std_dev_packet_size REAL,
                    packet_size_distribution TEXT,
                    periodic_score REAL DEFAULT 0,
                    burst_score REAL DEFAULT 0,
                    direction_ratio REAL,
                    session_count INTEGER DEFAULT 1,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    classification TEXT
                )
            """)
            
            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_periodic ON traffic_patterns(periodic_score DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_burst ON traffic_patterns(burst_score DESC)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("Traffic pattern tables initialized")
        except Exception as e:
            logger.error(f"Error initializing traffic pattern tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process a packet for traffic pattern analysis"""
        # Get the layers
        layers = packet_data.get("layers", {})
        if not layers:
            return False
        
        try:
            # Extract basic packet info
            src_ip = self.analysis_manager._get_layer_value(layers, "ip_src") or self.analysis_manager._get_layer_value(layers, "ipv6_src")
            dst_ip = self.analysis_manager._get_layer_value(layers, "ip_dst") or self.analysis_manager._get_layer_value(layers, "ipv6_dst")
            
            if not src_ip or not dst_ip:
                return False
                
            # Extract ports if available
            src_port, dst_port = self.analysis_manager._extract_ports(layers)
            
            # Create connection key
            if src_port and dst_port:
                connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            else:
                connection_key = f"{src_ip}->{dst_ip}"
            
            # Get packet size
            packet_size = self.analysis_manager._extract_length(layers)
            if packet_size <= 0:
                return False
                
            # Store packet size for this connection (limited to max_samples)
            self.connections[connection_key].append((packet_size, time.time()))
            if len(self.connections[connection_key]) > self.max_samples:
                self.connections[connection_key].pop(0)  # Remove oldest
                
            # Update traffic patterns in the database
            self._update_traffic_patterns(connection_key, packet_size)
            
            # Periodically analyze for beaconing behavior
            current_time = time.time()
            if current_time - self.last_analysis_time >= self.analysis_interval:
                self.last_analysis_time = current_time
                self._analyze_traffic_patterns()
            
            return True
        except Exception as e:
            logger.error(f"Error analyzing packet for traffic patterns: {e}")
            return False
    
    def _update_traffic_patterns(self, connection_key, packet_size):
        """Update traffic pattern information for behavioral analysis"""
        try:
            cursor = self.analysis_manager.get_cursor()
            
            # Check if we already have a record for this connection
            cursor.execute("""
                SELECT avg_packet_size, session_count, packet_size_distribution
                FROM traffic_patterns
                WHERE connection_key = ?
            """, (connection_key,))
            
            result = cursor.fetchone()
            
            if result:
                # Update existing pattern
                avg_size, session_count, size_dist_json = result
                
                # Calculate new average
                new_avg = ((avg_size * session_count) + packet_size) / (session_count + 1)
                
                # Update distribution (if it exists)
                size_dist = {}
                if size_dist_json:
                    try:
                        size_dist = json.loads(size_dist_json)
                    except (json.JSONDecodeError, TypeError):
                        size_dist = {}
                
                # Update packet size distribution
                size_key = str(packet_size - (packet_size % 100))  # Group by 100-byte ranges
                size_dist[size_key] = size_dist.get(size_key, 0) + 1
                
                cursor.execute("""
                    UPDATE traffic_patterns
                    SET avg_packet_size = ?,
                        packet_size_distribution = ?,
                        session_count = session_count + 1,
                        last_seen = CURRENT_TIMESTAMP
                    WHERE connection_key = ?
                """, (new_avg, json.dumps(size_dist), connection_key))
            else:
                # Create new pattern with initial distribution
                size_dist = {str(packet_size - (packet_size % 100)): 1}
                
                cursor.execute("""
                    INSERT INTO traffic_patterns
                    (connection_key, avg_packet_size, packet_size_distribution, session_count, first_seen, last_seen)
                    VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                """, (connection_key, packet_size, json.dumps(size_dist)))
            
            self.analysis_manager.analysis1_conn.commit()
            cursor.close()
            
            return True
        except Exception as e:
            logger.error(f"Error updating traffic patterns: {e}")
            return False
    
    def _analyze_traffic_patterns(self):
        """Analyze stored connection data for patterns"""
        try:
            # Calculate standard deviation and look for beaconing behavior
            for connection_key, packets in list(self.connections.items()):
                if len(packets) < 5:  # Need at least 5 packets for meaningful analysis
                    continue
                
                # Extract sizes and timestamps
                sizes = [p[0] for p in packets]
                timestamps = [p[1] for p in packets]
                
                # Calculate statistics
                try:
                    avg_size = sum(sizes) / len(sizes)
                    std_dev = statistics.stdev(sizes) if len(sizes) > 1 else 0
                    
                    # Look for periodic behavior in timestamps
                    time_diffs = []
                    for i in range(1, len(timestamps)):
                        time_diffs.append(timestamps[i] - timestamps[i-1])
                    
                    # Calculate time difference statistics
                    if time_diffs:
                        avg_time_diff = sum(time_diffs) / len(time_diffs)
                        if len(time_diffs) > 1:
                            time_diff_std = statistics.stdev(time_diffs)
                            
                            # Calculate coefficient of variation (lower means more regular)
                            # Periodic beaconing will have low CV
                            cv = time_diff_std / avg_time_diff if avg_time_diff > 0 else float('inf')
                            
                            # Calculate a periodic score (higher means more likely periodic)
                            # Scale it to 0-10 range
                            periodic_score = 10 * (1 - min(cv, 1)) if cv < 1 else 0
                            
                            # Only update the database if we have meaningful values
                            if periodic_score > 2:  # Only care about somewhat periodic behavior
                                cursor = self.analysis_manager.get_cursor()
                                try:
                                    # Update the periodic score
                                    cursor.execute("""
                                        UPDATE traffic_patterns
                                        SET periodic_score = ?,
                                            std_dev_packet_size = ?,
                                            classification = CASE WHEN ? > 7 THEN 'potential_beacon' ELSE classification END
                                        WHERE connection_key = ?
                                    """, (periodic_score, std_dev, periodic_score, connection_key))
                                    
                                    # Generate an alert for highly periodic traffic
                                    if periodic_score > 7:
                                        # Extract src_ip and dst_ip from connection key
                                        parts = connection_key.split('->')
                                        if len(parts) == 2:
                                            src_part = parts[0].split(':')[0] if ':' in parts[0] else parts[0]
                                            dst_part = parts[1].split(':')[0] if ':' in parts[1] else parts[1]
                                            
                                            # Check if we already alerted about this connection
                                            cursor.execute("""
                                                SELECT COUNT(*) FROM alerts
                                                WHERE ip_address = ? AND alert_message LIKE ? AND timestamp > ?
                                            """, (src_part, f"%potential beaconing to {dst_part}%", time.time() - 3600))
                                            
                                            if cursor.fetchone()[0] == 0:
                                                # Create a new alert
                                                alert_message = (f"Potential beaconing behavior detected from {src_part} to {dst_part}: "
                                                                f"periodic traffic every {avg_time_diff:.2f} seconds (score: {periodic_score:.1f}/10)")
                                                
                                                self.analysis_manager.add_alert(src_part, alert_message, "Traffic_Pattern_Analyzer")
                                    
                                    self.analysis_manager.analysis1_conn.commit()
                                finally:
                                    cursor.close()
                                    
                except (statistics.StatisticsError, ZeroDivisionError):
                    # Not enough data or other statistical error
                    pass
                    
            return True
        except Exception as e:
            logger.error(f"Error analyzing traffic patterns: {e}")
            return False
    
    def run_periodic_analysis(self):
        """Run periodic analysis on traffic patterns"""
        try:
            cursor = self.analysis_manager.get_cursor()
            
            # Find high-scoring connections for beaconing
            cursor.execute("""
                SELECT connection_key, periodic_score, avg_packet_size, session_count
                FROM traffic_patterns
                WHERE periodic_score > 7
                AND last_seen > ?
                ORDER BY periodic_score DESC
                LIMIT 10
            """, (time.time() - 86400,))  # Look at connections from the last 24 hours
            
            beaconing_connections = cursor.fetchall()
            
            if beaconing_connections:
                logger.info(f"Found {len(beaconing_connections)} potential beaconing connections:")
                for conn in beaconing_connections:
                    conn_key, score, avg_size, count = conn
                    logger.info(f"  - {conn_key}: score={score:.1f}, avg_size={avg_size:.1f} bytes, packets={count}")
            
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error in traffic pattern periodic analysis: {e}")
            return False
            
    def cleanup(self):
        """Clean up resources"""
        self.connections.clear()