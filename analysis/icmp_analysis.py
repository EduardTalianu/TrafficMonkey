# icmp_analysis.py - Enhanced ICMP traffic analysis
import time
import logging
import json
import math
from collections import defaultdict, Counter

logger = logging.getLogger('icmp_analysis')

class ICMPAnalyzer(AnalysisBase):
    """Advanced ICMP traffic analyzer for detecting floods, tunneling, and sweep patterns"""
    
    def __init__(self):
        super().__init__(
            name="ICMP Traffic Analysis",
            description="Advanced detection of ICMP floods, tunneling, and network mapping"
        )
        # Detection thresholds
        self.flood_threshold = 10      # packets in 10 seconds for flood detection
        self.flood_time_window = 10    # seconds for flood detection window
        self.tunnel_size_threshold = 1000  # bytes for potential tunneling
        self.sweep_threshold = 5       # hosts pinged in 30 seconds for ping sweep
        self.sweep_time_window = 30    # seconds for ping sweep detection
        self.timing_variation_threshold = 0.1  # coefficient of variation threshold for timed pings
        
        # Data structures for tracking ICMP activity
        self.ping_cache = defaultdict(list)  # {src_ip: [(dst_ip, timestamp)]}
        self.icmp_size_cache = defaultdict(list)  # {src_ip -> dst_ip: [packet_sizes]}
        self.icmp_timing_cache = defaultdict(list)  # {src_ip: [ping_intervals]}
        self.sequence_cache = defaultdict(list)  # {src_ip: [icmp_seq_numbers]}
        
        # Cache for tracking potential ICMP tunnels
        self.potential_tunnels = {}  # {src_ip -> dst_ip: {"count": 0, "large_packets": 0, "sizes": [], "first_seen": timestamp}}
        
        # Clean interval
        self.clean_interval = 300  # 5 minutes
        self.last_clean_time = time.time()
    
    def initialize(self):
        # Create or update required tables
        cursor = self.analysis_manager.get_cursor()
        try:
            # ICMP flood events table with enhanced schema
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS x_icmp_flood_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    packet_count INTEGER,
                    average_size REAL,
                    size_variation REAL,
                    start_time REAL,
                    end_time REAL,
                    event_type TEXT,
                    reported BOOLEAN DEFAULT 0,
                    timing_pattern TEXT,
                    sequence_pattern TEXT,
                    burst_pattern TEXT,
                    tunnel_probability REAL DEFAULT 0,
                    likely_tool TEXT,
                    interval_avg REAL,
                    interval_std REAL
                )
            """)
            
            # ICMP ping sweep events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS x_icmp_sweep_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    target_count INTEGER,
                    scanned_subnets TEXT,
                    start_time REAL,
                    end_time REAL,
                    sweep_pattern TEXT,
                    likely_tool TEXT,
                    timing_score REAL,
                    reported BOOLEAN DEFAULT 0,
                    response_rate REAL DEFAULT 0,
                    sequence_behavior TEXT
                )
            """)
            
            # ICMP behavior patterns table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS x_icmp_behavior_patterns (
                    src_ip TEXT PRIMARY KEY,
                    first_seen REAL,
                    last_seen REAL,
                    total_packets INTEGER DEFAULT 0,
                    avg_packet_size REAL DEFAULT 0,
                    usual_targets TEXT,
                    usual_icmp_types TEXT,
                    timing_pattern REAL DEFAULT 0,
                    sequence_pattern TEXT,
                    behavior_profile TEXT,
                    behavioral_score REAL DEFAULT 0,
                    flags TEXT
                )
            """)
            
            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_icmp_flood_src ON x_icmp_flood_events(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_icmp_flood_dst ON x_icmp_flood_events(dst_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_icmp_flood_time ON x_icmp_flood_events(start_time)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_icmp_flood_type ON x_icmp_flood_events(event_type)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_icmp_sweep_src ON x_icmp_sweep_events(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_icmp_sweep_time ON x_icmp_sweep_events(start_time)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_icmp_behavior_seen ON x_icmp_behavior_patterns(last_seen)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_icmp_behavior_score ON x_icmp_behavior_patterns(behavioral_score)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("ICMP analysis tables initialized with enhanced schema")
        except Exception as e:
            logger.error(f"Error initializing ICMP analysis tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process an ICMP packet for advanced analysis"""
        # Get the layers
        layers = packet_data.get("layers", {})
        if not layers:
            return False
        
        # Check if this is an ICMP packet
        if "icmp_type" not in layers:
            return False
        
        try:
            # Extract ICMP data
            src_ip = self.analysis_manager._get_layer_value(layers, "ip_src") or self.analysis_manager._get_layer_value(layers, "ipv6_src")
            dst_ip = self.analysis_manager._get_layer_value(layers, "ip_dst") or self.analysis_manager._get_layer_value(layers, "ipv6_dst")
            icmp_type_raw = self.analysis_manager._get_layer_value(layers, "icmp_type")
            icmp_code_raw = self.analysis_manager._get_layer_value(layers, "icmp_code")
            icmp_seq_raw = self.analysis_manager._get_layer_value(layers, "icmp_seq")
            icmp_id_raw = self.analysis_manager._get_layer_value(layers, "icmp_identifier")
            
            if not src_ip or not dst_ip:
                return False
                
            # Parse ICMP data
            icmp_type = 0
            icmp_code = 0
            icmp_seq = None
            icmp_id = None
            
            if icmp_type_raw is not None:
                try:
                    icmp_type = int(icmp_type_raw)
                except (ValueError, TypeError):
                    pass
                    
            if icmp_code_raw is not None:
                try:
                    icmp_code = int(icmp_code_raw)
                except (ValueError, TypeError):
                    pass
            
            if icmp_seq_raw is not None:
                try:
                    icmp_seq = int(icmp_seq_raw)
                    # Track sequence numbers for pattern detection
                    self.sequence_cache[src_ip].append(icmp_seq)
                    # Keep cache manageable
                    if len(self.sequence_cache[src_ip]) > 100:
                        self.sequence_cache[src_ip] = self.sequence_cache[src_ip][-100:]
                except (ValueError, TypeError):
                    pass
            
            if icmp_id_raw is not None:
                try:
                    icmp_id = int(icmp_id_raw)
                except (ValueError, TypeError):
                    pass
            
            # Get packet size for tunnel detection
            packet_size = self.analysis_manager._extract_length(layers)
            
            # Get timestamp
            current_time = time.time()
            
            # Update packet size cache
            key = f"{src_ip}->{dst_ip}"
            self.icmp_size_cache[key].append(packet_size)
            # Keep size cache manageable
            if len(self.icmp_size_cache[key]) > 100:
                self.icmp_size_cache[key] = self.icmp_size_cache[key][-100:]
            
            # Update ping cache for sweep detection
            if icmp_type == 8:  # Echo Request (ping)
                # Store ping data with destination
                self.ping_cache[src_ip].append((dst_ip, current_time))
                # Keep ping cache manageable
                if len(self.ping_cache[src_ip]) > 100:
                    self.ping_cache[src_ip] = self.ping_cache[src_ip][-100:]
                
                # Calculate ping timing intervals
                if len(self.ping_cache[src_ip]) > 1:
                    prev_time = self.ping_cache[src_ip][-2][1]
                    interval = current_time - prev_time
                    if 0 < interval < 60:  # Ignore outliers
                        self.icmp_timing_cache[src_ip].append(interval)
                        # Keep timing cache manageable
                        if len(self.icmp_timing_cache[src_ip]) > 50:
                            self.icmp_timing_cache[src_ip] = self.icmp_timing_cache[src_ip][-50:]
            
            # Update tunnel detection data
            if packet_size > self.tunnel_size_threshold:
                if key not in self.potential_tunnels:
                    self.potential_tunnels[key] = {
                        "count": 1,
                        "large_packets": 1,
                        "sizes": [packet_size],
                        "first_seen": current_time,
                        "last_seen": current_time
                    }
                else:
                    self.potential_tunnels[key]["count"] += 1
                    self.potential_tunnels[key]["large_packets"] += 1
                    self.potential_tunnels[key]["sizes"].append(packet_size)
                    self.potential_tunnels[key]["last_seen"] = current_time
                    # Keep size history manageable
                    if len(self.potential_tunnels[key]["sizes"]) > 50:
                        self.potential_tunnels[key]["sizes"] = self.potential_tunnels[key]["sizes"][-50:]
            else:
                # Still track normal packets for the pair
                if key in self.potential_tunnels:
                    self.potential_tunnels[key]["count"] += 1
                    self.potential_tunnels[key]["last_seen"] = current_time
            
            # Run detection for ICMP floods
            self._detect_icmp_flood(src_ip, dst_ip, packet_size, current_time)
            
            # Run detection for ping sweeps
            self._detect_ping_sweep(src_ip, current_time)
            
            # Run detection for tunneling
            self._detect_icmp_tunneling(src_ip, dst_ip, packet_size, current_time)
            
            # Update behavior profile
            self._update_behavior_profile(src_ip, dst_ip, icmp_type, icmp_code, packet_size, current_time)
            
            # Clean up old data periodically
            if current_time - self.last_clean_time > self.clean_interval:
                self._clean_old_entries(current_time)
                self.last_clean_time = current_time
            
            return True
        except Exception as e:
            logger.error(f"Error analyzing ICMP packet: {e}")
            return False
    
    def _detect_icmp_flood(self, src_ip, dst_ip, packet_size, current_time):
        """Enhanced ICMP flood detection with pattern recognition"""
        key = f"{src_ip}->{dst_ip}"
        
        # Get recent packets for this src-dst pair
        cursor = self.analysis_manager.get_cursor()
        
        try:
            # Count recent packets between this src/dst pair
            cutoff_time = current_time - self.flood_time_window
            cursor.execute("""
                SELECT COUNT(*) FROM icmp_packets
                WHERE src_ip = ? AND dst_ip = ? AND timestamp > ?
            """, (src_ip, dst_ip, cutoff_time))
            
            recent_packet_count = cursor.fetchone()[0]
            
            # Check for ICMP flood
            if recent_packet_count >= self.flood_threshold:
                # Look for existing ongoing flood event
                cursor.execute("""
                    SELECT id, packet_count, start_time FROM x_icmp_flood_events
                    WHERE src_ip = ? AND dst_ip = ? AND end_time > ? AND reported = 0
                    ORDER BY end_time DESC LIMIT 1
                """, (src_ip, dst_ip, current_time - 60))  # Look for events in the last minute
                
                flood_event = cursor.fetchone()
                
                if flood_event:
                    # Update existing flood event
                    event_id, packet_count, start_time = flood_event
                    
                    # Get packet sizes for variance calculation
                    sizes = self.icmp_size_cache.get(key, [])
                    avg_size = sum(sizes) / len(sizes) if sizes else packet_size
                    size_variance = sum((s - avg_size) ** 2 for s in sizes) / len(sizes) if len(sizes) > 1 else 0
                    size_variation = math.sqrt(size_variance)
                    
                    # Get timing pattern
                    timing_pattern = self._analyze_timing_pattern(src_ip)
                    
                    # Get sequence pattern
                    sequence_pattern = self._analyze_sequence_pattern(src_ip)
                    
                    # Identify burst pattern
                    burst_pattern = self._identify_burst_pattern(src_ip, dst_ip)
                    
                    # Calculate tunnel probability
                    tunnel_probability = self._calculate_tunnel_probability(key)
                    
                    # Get interval statistics
                    intervals = self.icmp_timing_cache.get(src_ip, [])
                    interval_avg = sum(intervals) / len(intervals) if intervals else 0
                    interval_std = math.sqrt(sum((i - interval_avg) ** 2 for i in intervals) / len(intervals)) if len(intervals) > 1 else 0
                    
                    # Determine likely tool
                    likely_tool = self._determine_icmp_tool(timing_pattern, sequence_pattern, burst_pattern, avg_size)
                    
                    # Update the event
                    cursor.execute("""
                        UPDATE x_icmp_flood_events
                        SET packet_count = packet_count + 1,
                            average_size = ?,
                            size_variation = ?,
                            end_time = ?,
                            timing_pattern = ?,
                            sequence_pattern = ?,
                            burst_pattern = ?,
                            tunnel_probability = ?,
                            likely_tool = ?,
                            interval_avg = ?,
                            interval_std = ?
                        WHERE id = ?
                    """, (
                        avg_size, 
                        size_variation,
                        current_time,
                        timing_pattern,
                        sequence_pattern,
                        burst_pattern,
                        tunnel_probability,
                        likely_tool,
                        interval_avg,
                        interval_std,
                        event_id
                    ))
                else:
                    # Determine event type
                    event_type = "flood"
                    if packet_size > self.tunnel_size_threshold:
                        event_type = "potential_tunnel"
                    
                    # Get available size data
                    sizes = self.icmp_size_cache.get(key, [])
                    avg_size = sum(sizes) / len(sizes) if sizes else packet_size
                    size_variance = sum((s - avg_size) ** 2 for s in sizes) / len(sizes) if len(sizes) > 1 else 0
                    size_variation = math.sqrt(size_variance)
                    
                    # Get timing pattern
                    timing_pattern = self._analyze_timing_pattern(src_ip)
                    
                    # Get sequence pattern
                    sequence_pattern = self._analyze_sequence_pattern(src_ip)
                    
                    # Identify burst pattern
                    burst_pattern = self._identify_burst_pattern(src_ip, dst_ip)
                    
                    # Calculate tunnel probability
                    tunnel_probability = self._calculate_tunnel_probability(key)
                    
                    # Get interval statistics
                    intervals = self.icmp_timing_cache.get(src_ip, [])
                    interval_avg = sum(intervals) / len(intervals) if intervals else 0
                    interval_std = math.sqrt(sum((i - interval_avg) ** 2 for i in intervals) / len(intervals)) if len(intervals) > 1 else 0
                    
                    # Determine likely tool
                    likely_tool = self._determine_icmp_tool(timing_pattern, sequence_pattern, burst_pattern, avg_size)
                    
                    # Create new flood event with enhanced metadata
                    cursor.execute("""
                        INSERT INTO x_icmp_flood_events
                        (src_ip, dst_ip, packet_count, average_size, size_variation, start_time, end_time, 
                         event_type, timing_pattern, sequence_pattern, burst_pattern, tunnel_probability,
                         likely_tool, interval_avg, interval_std)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        src_ip, 
                        dst_ip, 
                        recent_packet_count,
                        avg_size,
                        size_variation,
                        current_time - self.flood_time_window,
                        current_time,
                        event_type,
                        timing_pattern,
                        sequence_pattern,
                        burst_pattern,
                        tunnel_probability,
                        likely_tool,
                        interval_avg,
                        interval_std
                    ))
            
            self.analysis_manager.analysis1_conn.commit()
        finally:
            cursor.close()
    
    def _detect_ping_sweep(self, src_ip, current_time):
        """Enhanced ping sweep detection with pattern analysis"""
        # Look for ping sweep - multiple destinations in a short time
        if src_ip not in self.ping_cache:
            return
            
        # Get recent pings from this source
        sweep_cutoff = current_time - self.sweep_time_window
        recent_pings = [(dst, ts) for dst, ts in self.ping_cache[src_ip] if ts > sweep_cutoff]
        
        # Count unique destinations
        unique_destinations = set(dst for dst, _ in recent_pings)
        
        if len(unique_destinations) >= self.sweep_threshold:
            # Check if these destinations are in the same subnet
            subnet_groups = self._group_by_subnet(unique_destinations)
            
            # Determine sweep pattern
            if len(subnet_groups) == 1:
                # Single subnet sweep
                subnet, ips = list(subnet_groups.items())[0]
                
                # Check if sequential
                is_sequential = self._is_sequential_sweep(ips)
                
                if is_sequential:
                    sweep_pattern = f"Sequential sweep of subnet {subnet}"
                else:
                    sweep_pattern = f"Random sweep of subnet {subnet}"
            else:
                # Multi-subnet sweep
                sweep_pattern = f"Multi-subnet sweep ({len(subnet_groups)} subnets)"
            
            # Calculate timing score (how regular are the pings)
            timing_score = self._calculate_timing_regularity(src_ip)
            
            # Analyze sequence number behavior
            sequence_behavior = self._analyze_sequence_pattern(src_ip)
            
            # Determine likely tool
            likely_tool = "Unknown"
            if timing_score > 0.8:
                likely_tool = "Automated scanner"
                if "Sequential" in sweep_pattern:
                    likely_tool = "NMAP ping sweep" if len(unique_destinations) < 30 else "Automated sweep tool"
            elif "Sequential" in sweep_pattern:
                likely_tool = "NMAP" if len(unique_destinations) < 50 else "Fast scanner"
            
            # Calculate response rate
            response_rate = self._calculate_ping_response_rate(src_ip)
            
            # Serialize subnet data for storage
            subnets_list = [f"{subnet}:{len(ips)}" for subnet, ips in subnet_groups.items()]
            subnets_json = json.dumps(subnets_list)
            
            # Record sweep event
            cursor = self.analysis_manager.get_cursor()
            
            try:
                # Check for recent similar sweep to avoid duplicates
                cursor.execute("""
                    SELECT id FROM x_icmp_sweep_events
                    WHERE src_ip = ? AND end_time > ?
                    ORDER BY end_time DESC LIMIT 1
                """, (src_ip, current_time - 300))  # Look for events in the last 5 minutes
                
                existing_sweep = cursor.fetchone()
                
                if not existing_sweep:
                    # Create new sweep event
                    cursor.execute("""
                        INSERT INTO x_icmp_sweep_events
                        (src_ip, target_count, scanned_subnets, start_time, end_time, 
                         sweep_pattern, likely_tool, timing_score, response_rate, sequence_behavior)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        src_ip,
                        len(unique_destinations),
                        subnets_json,
                        sweep_cutoff,
                        current_time,
                        sweep_pattern,
                        likely_tool,
                        timing_score,
                        response_rate,
                        sequence_behavior
                    ))
                    
                    logger.info(f"Recorded ping sweep from {src_ip}: {len(unique_destinations)} targets, pattern: {sweep_pattern}")
                
                self.analysis_manager.analysis1_conn.commit()
            finally:
                cursor.close()
    
    def _detect_icmp_tunneling(self, src_ip, dst_ip, packet_size, current_time):
        """Enhanced ICMP tunneling detection with pattern analysis"""
        key = f"{src_ip}->{dst_ip}"
        
        # Continue only if we've been tracking this pair
        if key not in self.potential_tunnels:
            return
            
        tunnel_data = self.potential_tunnels[key]
        tunnel_duration = current_time - tunnel_data["first_seen"]
        
        # Only analyze pairs with sufficient history
        if tunnel_data["count"] < 10 or tunnel_duration < 60:
            return
        
        # Calculate tunneling metrics
        large_packet_ratio = tunnel_data["large_packets"] / tunnel_data["count"]
        size_consistency = self._calculate_size_consistency(tunnel_data["sizes"])
        tunnel_probability = large_packet_ratio * size_consistency
        
        # High probability of tunneling if:
        # 1. Significant portion of packets are large
        # 2. Packet sizes show some consistency
        # 3. Traffic has been sustained for some time
        if tunnel_probability > 0.7 and large_packet_ratio > 0.5 and tunnel_duration > 120:
            # Don't create duplicate events too frequently
            cursor = self.analysis_manager.get_cursor()
            
            try:
                # Check for recent tunnel alert to avoid duplicates
                cursor.execute("""
                    SELECT id FROM x_icmp_flood_events
                    WHERE src_ip = ? AND dst_ip = ? AND event_type = 'confirmed_tunnel' AND end_time > ?
                    ORDER BY end_time DESC LIMIT 1
                """, (src_ip, dst_ip, current_time - 600))  # Last 10 minutes
                
                existing_event = cursor.fetchone()
                
                if not existing_event:
                    # Get timing and sequence patterns
                    timing_pattern = self._analyze_timing_pattern(src_ip)
                    sequence_pattern = self._analyze_sequence_pattern(src_ip)
                    
                    # Get interval statistics
                    intervals = self.icmp_timing_cache.get(src_ip, [])
                    interval_avg = sum(intervals) / len(intervals) if intervals else 0
                    interval_std = math.sqrt(sum((i - interval_avg) ** 2 for i in intervals) / len(intervals)) if len(intervals) > 1 else 0
                    
                    # Calculate size statistics
                    sizes = tunnel_data["sizes"]
                    avg_size = sum(sizes) / len(sizes) if sizes else packet_size
                    size_variance = sum((s - avg_size) ** 2 for s in sizes) / len(sizes) if len(sizes) > 1 else 0
                    size_variation = math.sqrt(size_variance)
                    
                    # Record confirmed tunnel event
                    cursor.execute("""
                        INSERT INTO x_icmp_flood_events
                        (src_ip, dst_ip, packet_count, average_size, size_variation, start_time, end_time, 
                         event_type, timing_pattern, sequence_pattern, burst_pattern, tunnel_probability,
                         likely_tool, interval_avg, interval_std)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        src_ip, 
                        dst_ip, 
                        tunnel_data["count"],
                        avg_size,
                        size_variation,
                        tunnel_data["first_seen"],
                        current_time,
                        "confirmed_tunnel",
                        timing_pattern,
                        sequence_pattern,
                        "sustained",  # Tunnels typically use sustained traffic
                        tunnel_probability,
                        "ICMP Tunnel",  # Likely a tunneling tool
                        interval_avg,
                        interval_std
                    ))
                    
                    logger.info(f"Detected ICMP tunneling from {src_ip} to {dst_ip}: {tunnel_data['count']} packets, {avg_size:.1f} avg size, probability {tunnel_probability:.2f}")
                
                self.analysis_manager.analysis1_conn.commit()
            finally:
                cursor.close()
    
    def _update_behavior_profile(self, src_ip, dst_ip, icmp_type, icmp_code, packet_size, current_time):
        """Update ICMP behavioral profile for the source IP"""
        cursor = self.analysis_manager.get_cursor()
        
        try:
            # Check if profile exists
            cursor.execute("""
                SELECT total_packets, avg_packet_size, usual_targets, usual_icmp_types, timing_pattern
                FROM x_icmp_behavior_patterns
                WHERE src_ip = ?
            """, (src_ip,))
            
            result = cursor.fetchone()
            
            if result:
                # Update existing profile
                total_packets, avg_packet_size, usual_targets_json, usual_types_json, timing_pattern = result
                
                # Parse JSON data
                usual_targets = json.loads(usual_targets_json) if usual_targets_json else {}
                usual_types = json.loads(usual_types_json) if usual_types_json else {}
                
                # Update packet count and average size
                new_total = total_packets + 1
                new_avg_size = ((avg_packet_size * total_packets) + packet_size) / new_total
                
                # Update targets
                usual_targets[dst_ip] = usual_targets.get(dst_ip, 0) + 1
                
                # Update ICMP types
                type_key = f"{icmp_type}:{icmp_code}"
                usual_types[type_key] = usual_types.get(type_key, 0) + 1
                
                # Calculate timing score
                new_timing_pattern = self._calculate_timing_regularity(src_ip)
                
                # Get sequence pattern
                sequence_pattern = self._analyze_sequence_pattern(src_ip)
                
                # Determine behavior profile
                behavior_profile = self._determine_behavior_profile(
                    usual_targets, usual_types, new_timing_pattern, sequence_pattern
                )
                
                # Calculate behavioral score
                behavioral_score = self._calculate_behavioral_score(
                    new_timing_pattern, sequence_pattern, usual_targets, usual_types
                )
                
                # Determine flags
                flags = self._determine_behavior_flags(
                    behavioral_score, new_timing_pattern, usual_types, usual_targets
                )
                
                # Update profile
                cursor.execute("""
                    UPDATE x_icmp_behavior_patterns
                    SET last_seen = ?,
                        total_packets = ?,
                        avg_packet_size = ?,
                        usual_targets = ?,
                        usual_icmp_types = ?,
                        timing_pattern = ?,
                        sequence_pattern = ?,
                        behavior_profile = ?,
                        behavioral_score = ?,
                        flags = ?
                    WHERE src_ip = ?
                """, (
                    current_time,
                    new_total,
                    new_avg_size,
                    json.dumps(usual_targets),
                    json.dumps(usual_types),
                    new_timing_pattern,
                    sequence_pattern,
                    behavior_profile,
                    behavioral_score,
                    flags,
                    src_ip
                ))
            else:
                # Create new profile
                usual_targets = {dst_ip: 1}
                usual_types = {f"{icmp_type}:{icmp_code}": 1}
                
                # Default timing score for new profiles
                timing_pattern = 0
                
                # Get sequence pattern (will likely be minimal)
                sequence_pattern = self._analyze_sequence_pattern(src_ip)
                
                # Initial behavior profile (will be refined over time)
                behavior_profile = "new"
                
                # Initial behavioral score (minimal data)
                behavioral_score = 0
                
                # Initial flags
                flags = "new_host"
                
                cursor.execute("""
                    INSERT INTO x_icmp_behavior_patterns
                    (src_ip, first_seen, last_seen, total_packets, avg_packet_size, usual_targets,
                     usual_icmp_types, timing_pattern, sequence_pattern, behavior_profile, behavioral_score, flags)
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    src_ip,
                    current_time,
                    current_time,
                    packet_size,
                    json.dumps(usual_targets),
                    json.dumps(usual_types),
                    timing_pattern,
                    sequence_pattern,
                    behavior_profile,
                    behavioral_score,
                    flags
                ))
            
            self.analysis_manager.analysis1_conn.commit()
        finally:
            cursor.close()
    
    def _clean_old_entries(self, current_time):
        """Remove old entries from caches"""
        # Clean ping cache
        for src_ip in list(self.ping_cache.keys()):
            self.ping_cache[src_ip] = [(dst, ts) for dst, ts in self.ping_cache[src_ip] 
                                      if ts > current_time - 600]  # Keep 10 minutes
            if not self.ping_cache[src_ip]:
                del self.ping_cache[src_ip]
        
        # Clean size cache
        for key in list(self.icmp_size_cache.keys()):
            if not self.icmp_size_cache[key]:
                del self.icmp_size_cache[key]
        
        # Clean timing cache
        for src_ip in list(self.icmp_timing_cache.keys()):
            if not self.icmp_timing_cache[src_ip]:
                del self.icmp_timing_cache[src_ip]
        
        # Clean sequence cache
        for src_ip in list(self.sequence_cache.keys()):
            if not self.sequence_cache[src_ip]:
                del self.sequence_cache[src_ip]
        
        # Clean tunnel cache
        for key in list(self.potential_tunnels.keys()):
            if current_time - self.potential_tunnels[key]["last_seen"] > 1800:  # 30 minutes
                del self.potential_tunnels[key]
    
    def _analyze_timing_pattern(self, src_ip):
        """Analyze ICMP timing pattern regularity"""
        intervals = self.icmp_timing_cache.get(src_ip, [])
        
        if len(intervals) < 3:
            return "Unknown"
            
        # Calculate statistics
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        
        # Coefficient of variation (lower means more regular timing)
        cv = std_dev / avg_interval if avg_interval > 0 else float('inf')
        
        if cv < 0.1:
            return f"Very regular ({avg_interval:.2f}s intervals)"
        elif cv < 0.3:
            return f"Somewhat regular ({avg_interval:.2f}s intervals)"
        elif cv < 0.7:
            return f"Variable ({avg_interval:.2f}s intervals)"
        else:
            return "Irregular timing"
    
    def _analyze_sequence_pattern(self, src_ip):
        """Analyze ICMP sequence number patterns"""
        sequence_numbers = self.sequence_cache.get(src_ip, [])
        
        if len(sequence_numbers) < 3:
            return "Unknown"
            
        # Check for sequential pattern
        is_sequential = True
        for i in range(1, len(sequence_numbers)):
            if sequence_numbers[i] != sequence_numbers[i-1] + 1:
                is_sequential = False
                break
        
        if is_sequential:
            return "Sequential"
            
        # Check for constant pattern
        if len(set(sequence_numbers)) == 1:
            return "Constant"
            
        # Check for incrementing pattern but with gaps
        if sorted(sequence_numbers) == sequence_numbers and len(set(sequence_numbers)) > len(sequence_numbers) / 2:
            return "Incrementing with gaps"
            
        # Check for cycling pattern
        unique_values = set(sequence_numbers)
        if len(unique_values) < len(sequence_numbers) / 2:
            return f"Cycling ({len(unique_values)} unique values)"
            
        return "Random"
    
    def _identify_burst_pattern(self, src_ip, dst_ip):
        """Identify ICMP traffic burst patterns"""
        key = f"{src_ip}->{dst_ip}"
        
        # Get packet timestamps
        cursor = self.analysis_manager.get_cursor()
        try:
            cursor.execute("""
                SELECT timestamp FROM icmp_packets
                WHERE src_ip = ? AND dst_ip = ?
                ORDER BY timestamp DESC
                LIMIT 100
            """, (src_ip, dst_ip))
            
            timestamps = [row[0] for row in cursor.fetchall()]
            
            if len(timestamps) < 5:
                return "Insufficient data"
                
            # Sort timestamps in ascending order
            timestamps.sort()
            
            # Calculate inter-arrival times
            intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
            
            # Look for bursts (clusters of activity)
            burst_threshold = 1.0  # 1 second threshold
            bursts = []
            current_burst = [timestamps[0]]
            
            for i in range(1, len(timestamps)):
                if timestamps[i] - timestamps[i-1] < burst_threshold:
                    current_burst.append(timestamps[i])
                else:
                    if len(current_burst) > 1:
                        bursts.append(current_burst)
                    current_burst = [timestamps[i]]
            
            if len(current_burst) > 1:
                bursts.append(current_burst)
            
            # Analyze burst pattern
            if not bursts:
                return "No bursts detected"
                
            if len(bursts) == 1 and len(bursts[0]) > 5:
                return "Sustained traffic"
                
            if len(bursts) > 3:
                # Calculate average burst size and inter-burst interval
                avg_burst_size = sum(len(b) for b in bursts) / len(bursts)
                
                # Calculate intervals between bursts
                burst_intervals = []
                for i in range(1, len(bursts)):
                    burst_intervals.append(bursts[i][0] - bursts[i-1][-1])
                
                if burst_intervals:
                    avg_burst_interval = sum(burst_intervals) / len(burst_intervals)
                    cv = math.sqrt(sum((i - avg_burst_interval) ** 2 for i in burst_intervals) / len(burst_intervals)) / avg_burst_interval if avg_burst_interval > 0 else float('inf')
                    
                    if cv < 0.3:
                        return f"Regular bursts ({avg_burst_size:.1f} packets every {avg_burst_interval:.1f}s)"
                    else:
                        return f"Irregular bursts (avg {avg_burst_size:.1f} packets)"
            
            return f"Mixed pattern ({len(bursts)} bursts)"
            
        finally:
            cursor.close()
    
    def _calculate_tunnel_probability(self, key):
        """Calculate probability that ICMP traffic is being used for tunneling"""
        if key not in self.potential_tunnels:
            return 0
            
        tunnel_data = self.potential_tunnels[key]
        
        # Factors influencing tunnel probability:
        # 1. Proportion of large packets
        large_ratio = tunnel_data["large_packets"] / max(1, tunnel_data["count"])
        
        # 2. Consistency of packet sizes (tunneled data often has certain size patterns)
        size_consistency = self._calculate_size_consistency(tunnel_data["sizes"])
        
        # 3. Sustained traffic duration
        duration = tunnel_data["last_seen"] - tunnel_data["first_seen"]
        duration_factor = min(1.0, duration / 600)  # Normalize to max of 1.0 (10 minutes)
        
        # Calculate combined probability
        probability = (large_ratio * 0.6) + (size_consistency * 0.3) + (duration_factor * 0.1)
        
        return probability
    
    def _calculate_size_consistency(self, sizes):
        """Calculate consistency of packet sizes (higher value = more consistent)"""
        if not sizes or len(sizes) < 3:
            return 0
            
        # Calculate size distribution
        size_counts = Counter(sizes)
        
        # Calculate entropy of size distribution
        total = len(sizes)
        entropy = 0
        
        for count in size_counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        
        # Max entropy is log2(unique sizes)
        max_entropy = math.log2(len(size_counts))
        
        # Normalize entropy (0 = completely random, 1 = completely consistent)
        if max_entropy > 0:
            consistency = 1 - (entropy / max_entropy)
        else:
            consistency = 1  # Only one size, perfectly consistent
            
        return consistency
    
    def _determine_icmp_tool(self, timing_pattern, sequence_pattern, burst_pattern, avg_size):
        """Determine likely ICMP tool based on behavioral patterns"""
        # Default to unknown
        tool = "Unknown"
        
        # Use timing pattern as key indicator
        if "Very regular" in timing_pattern:
            if sequence_pattern == "Sequential":
                tool = "ping (standard)"
            elif sequence_pattern == "Incrementing with gaps":
                tool = "fping"
            elif "Regular bursts" in burst_pattern:
                tool = "hping3"
            elif avg_size > 1000:
                tool = "ICMP tunneling tool"
        elif "Somewhat regular" in timing_pattern:
            if sequence_pattern == "Sequential":
                tool = "ping (manual)"
            elif "Cycling" in sequence_pattern:
                tool = "Nmap ping scan"
        elif "Sustained traffic" in burst_pattern and avg_size > 800:
            tool = "ICMP tunnel"
        
        return tool
    
    def _group_by_subnet(self, ip_addresses):
        """Group IP addresses by subnet (/24)"""
        subnet_groups = defaultdict(list)
        
        for ip in ip_addresses:
            try:
                # Get /24 subnet
                subnet = '.'.join(ip.split('.')[:3]) + '.0/24'
                subnet_groups[subnet].append(ip)
            except:
                continue
                
        return subnet_groups
    
    def _is_sequential_sweep(self, ip_addresses):
        """Determine if IP addresses were scanned sequentially"""
        if not ip_addresses or len(ip_addresses) < 3:
            return False
            
        # Extract last octets and sort
        octets = []
        for ip in ip_addresses:
            try:
                last_octet = int(ip.split('.')[-1])
                octets.append(last_octet)
            except:
                continue
        
        if not octets:
            return False
            
        octets.sort()
        
        # Check for sequential scanning
        sequential_count = 0
        for i in range(1, len(octets)):
            if octets[i] == octets[i-1] + 1:
                sequential_count += 1
        
        # Return true if at least 80% of IPs were scanned sequentially
        return sequential_count >= (len(octets) - 1) * 0.8
    
    def _calculate_timing_regularity(self, src_ip):
        """Calculate timing regularity score (0-1)"""
        intervals = self.icmp_timing_cache.get(src_ip, [])
        
        if len(intervals) < 3:
            return 0
            
        # Calculate statistics
        avg_interval = sum(intervals) / len(intervals)
        variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
        std_dev = math.sqrt(variance)
        
        # Coefficient of variation (lower means more regular timing)
        cv = std_dev / avg_interval if avg_interval > 0 else float('inf')
        
        # Convert CV to regularity score (0-1)
        regularity = max(0, min(1, 1 - (cv / 2)))
        
        return regularity
    
    def _calculate_ping_response_rate(self, src_ip):
        """Calculate ping response rate for a source"""
        # This would require tracking echoes and replies
        # For this simplified implementation, we return a default value
        return 0.5  # Default placeholder value
    
    def _determine_behavior_profile(self, targets, types, timing_pattern, sequence_pattern):
        """Determine ICMP behavior profile based on patterns"""
        # Count total ICMP packets
        total_packets = sum(targets.values())
        
        # Check if mostly single target or multi-target
        max_target_count = max(targets.values()) if targets else 0
        target_ratio = max_target_count / total_packets if total_packets > 0 else 0
        
        # Check ICMP types
        echo_request_count = types.get("8:0", 0)  # Echo request
        echo_reply_count = types.get("0:0", 0)    # Echo reply
        
        request_ratio = echo_request_count / total_packets if total_packets > 0 else 0
        reply_ratio = echo_reply_count / total_packets if total_packets > 0 else 0
        
        # Determine profile
        if target_ratio > 0.8 and request_ratio > 0.8:
            return "Regular ping"
        elif target_ratio > 0.8 and reply_ratio > 0.8:
            return "Echo responder"
        elif target_ratio < 0.2 and request_ratio > 0.8:
            return "Network scanner"
        elif timing_pattern > 0.8 and request_ratio > 0.5:
            return "Automated ping"
        elif timing_pattern < 0.3 and len(targets) > 10:
            return "Manual scanning"
        elif len(types) > 3:
            return "ICMP toolkit"
        
        return "General ICMP"
    
    def _calculate_behavioral_score(self, timing_pattern, sequence_pattern, targets, types):
        """Calculate behavioral abnormality score (0-10)"""
        # Start with neutral score
        score = 5
        
        # Adjust based on timing regularity (very regular timing is more unusual)
        if timing_pattern > 0.8:
            score += 2
        elif timing_pattern > 0.5:
            score += 1
        
        # Adjust based on sequence pattern
        if sequence_pattern == "Sequential":
            score -= 1  # Common for standard tools
        elif sequence_pattern == "Random":
            score += 1  # More unusual
        elif "Cycling" in sequence_pattern:
            score += 1  # Unusual pattern
        
        # Adjust based on target diversity
        if len(targets) > 10:
            score += min(3, len(targets) / 10)  # Scanning many targets is unusual
        
        # Adjust based on ICMP type diversity
        if len(types) > 2:
            score += len(types) - 2  # Multiple ICMP types is unusual
        
        # Cap the score
        return max(0, min(10, score))
    
    def _determine_behavior_flags(self, behavioral_score, timing_pattern, types, targets):
        """Determine behavior flags for the source"""
        flags = []
        
        # Flag based on behavioral score
        if behavioral_score > 8:
            flags.append("highly_unusual")
        elif behavioral_score > 6:
            flags.append("unusual")
        
        # Flag based on timing pattern
        if timing_pattern > 0.9:
            flags.append("automated")
        
        # Flag based on ICMP types
        if len(types) > 3:
            flags.append("icmp_toolkit")
        
        # Flag based on targets
        if len(targets) > 20:
            flags.append("scanner")
        elif len(targets) == 1:
            flags.append("focused")
        
        return ",".join(flags) if flags else "normal"
    
    def run_periodic_analysis(self):
        """Run periodic analysis on ICMP data"""
        try:
            cursor = self.analysis_manager.get_cursor()
            current_time = time.time()
            
            # Find unreported ICMP events
            cursor.execute("""
                SELECT id, src_ip, dst_ip, packet_count, start_time, end_time, event_type,
                      average_size, timing_pattern, likely_tool
                FROM x_icmp_flood_events
                WHERE reported = 0 AND end_time < ?
                ORDER BY packet_count DESC
                LIMIT 20
            """, (current_time - 60,))  # Only report events that ended at least a minute ago
            
            events = cursor.fetchall()
            
            for event in events:
                event_id, src_ip, dst_ip, packet_count, start_time, end_time, event_type, avg_size, timing_pattern, likely_tool = event
                
                # Mark as reported
                cursor.execute("UPDATE x_icmp_flood_events SET reported = 1 WHERE id = ?", (event_id,))
                
                # Log summary of the event
                duration = end_time - start_time
                packet_rate = packet_count / duration if duration > 0 else 0
                
                logger.info(f"ICMP {event_type} summary: {src_ip} -> {dst_ip}, {packet_count} packets over {duration:.1f}s ({packet_rate:.1f} packets/s)")
                if timing_pattern:
                    logger.info(f"  Pattern: {timing_pattern}, Tool: {likely_tool}")
            
            # Also report on ping sweeps
            cursor.execute("""
                SELECT id, src_ip, target_count, sweep_pattern, likely_tool, timing_score, sequence_behavior
                FROM x_icmp_sweep_events
                WHERE reported = 0 AND end_time < ?
                ORDER BY target_count DESC
                LIMIT 10
            """, (current_time - 60,))
            
            sweep_events = cursor.fetchall()
            
            for event in sweep_events:
                event_id, src_ip, target_count, sweep_pattern, likely_tool, timing_score, sequence_behavior = event
                
                # Mark as reported
                cursor.execute("UPDATE x_icmp_sweep_events SET reported = 1 WHERE id = ?", (event_id,))
                
                # Log summary of the sweep
                logger.info(f"ICMP sweep summary: {src_ip} scanned {target_count} targets, pattern: {sweep_pattern}")
                logger.info(f"  Tool: {likely_tool}, Timing regularity: {timing_score:.2f}, Sequence: {sequence_behavior}")
            
            # Analyze behavior patterns
            cursor.execute("""
                SELECT src_ip, behavior_profile, behavioral_score, flags, total_packets
                FROM x_icmp_behavior_patterns
                WHERE behavioral_score > 7 AND last_seen > ?
                ORDER BY behavioral_score DESC
                LIMIT 10
            """, (current_time - 86400,))  # Last 24 hours
            
            behaviors = cursor.fetchall()
            
            if behaviors:
                logger.info("Notable ICMP behavior patterns:")
                for src_ip, profile, score, flags, packets in behaviors:
                    logger.info(f"  {src_ip}: {profile}, score={score:.1f}, flags={flags}, packets={packets}")
            
            self.analysis_manager.analysis1_conn.commit()
            cursor.close()
            
            return bool(events) or bool(sweep_events)  # Return True if we processed any events
        except Exception as e:
            logger.error(f"Error in ICMP periodic analysis: {e}")
            return False