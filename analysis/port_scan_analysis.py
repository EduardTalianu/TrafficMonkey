# port_scan_analysis.py - Enhanced port scanning detection and analysis
import time
import logging
from collections import defaultdict, Counter
import json
import math

logger = logging.getLogger('port_scan_analysis')

class PortScanAnalyzer(AnalysisBase):
    """Advanced port scan detector with behavioral profiling and fingerprinting"""
    
    def __init__(self):
        super().__init__(
            name="Port Scan Detector",
            description="Advanced port scanning and network reconnaissance detection"
        )
        # Scan detection thresholds
        self.scan_thresholds = {
            'horizontal': 15,   # Number of different ports to same host
            'vertical': 20,     # Number of different hosts on same port
            'block': 50,        # Number of connections to detect a block scan
            'stealth': 5,       # Number of ports on non-responsive targets
            'rate': 10,         # Connections per second to consider a fast scan
            'timing': 0.05      # ICMP difference threshold for timing pattern detection
        }
        
        self.time_window = 60  # Seconds for scan detection window
        
        # Enhanced data structures for scan detection with advanced metrics
        self.scan_cache = {
            'src_to_dst_ports': defaultdict(set),     # {src_ip -> dst_ip: {ports}}
            'src_to_dst_ips': defaultdict(set),       # {src_ip -> port: {dst_ips}}
            'connection_times': defaultdict(list),    # {src_ip: [timestamps]}
            'last_detection_time': defaultdict(float), # {src_ip_type: last_detection_time}
            'scan_patterns': defaultdict(dict),       # {src_ip: {pattern_data}}
            'port_sequence': defaultdict(list),       # {src_ip: [scanned_ports_sequence]}
            'response_stats': defaultdict(lambda: {'attempts': 0, 'responses': 0}) # {src_ip: {response_statistics}}
        }
        
        # Common port groups for fingerprinting scan targets
        self.port_groups = {
            'web': {80, 443, 8080, 8443, 3000, 8000, 8888},
            'email': {25, 110, 143, 465, 587, 993, 995},
            'file_sharing': {20, 21, 22, 139, 445, 2049},
            'databases': {1433, 1521, 3306, 5432, 6379, 9042, 27017},
            'remote_access': {22, 23, 3389, 5900, 5901},
            'network_services': {53, 67, 68, 123, 161, 389, 636},
            'voip': {5060, 5061, 16384, 16394},
            'industrial': {102, 502, 1089, 1091, 2222, 4000, 44818},
            'iot': {1883, 5683, 8883, 8886, 32768}
        }
        
        # Common scan tools port sequences for fingerprinting scan tools
        self.known_scan_patterns = {
            'nmap_default': [21, 22, 23, 25, 80, 139, 443, 445, 3389],
            'nmap_common': [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080],
            'zmap_common': [21, 22, 23, 25, 80, 443, 8080, 8443],
            'masscan_common': [22, 23, 80, 443, 445, 3389, 8080, 8443]
        }
    
    def initialize(self):
        # Create or update required tables with enhanced schema
        cursor = self.analysis_manager.get_cursor()
        try:
            # Port scan events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS x_port_scan_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    scan_type TEXT,
                    target_count INTEGER,
                    port_count INTEGER,
                    start_time REAL,
                    end_time REAL,
                    rate REAL,
                    alert_generated BOOLEAN DEFAULT 0,
                    ports_scanned TEXT,
                    port_sequence TEXT,
                    response_rate REAL DEFAULT 0,
                    scan_pattern TEXT,
                    likely_tool TEXT,
                    scan_sophistication INTEGER DEFAULT 1,
                    stealth_score REAL DEFAULT 0,
                    target_categories TEXT
                )
            """)
            
            # Scanner profile table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS x_port_scanner_profiles (
                    scanner_ip TEXT PRIMARY KEY,
                    first_seen REAL,
                    last_seen REAL,
                    total_scans INTEGER DEFAULT 1,
                    preferred_scan_types TEXT,
                    usual_ports TEXT,
                    usual_targets TEXT,
                    port_sequence_patterns TEXT,
                    timing_patterns TEXT,
                    noise_level REAL DEFAULT 0,
                    sophistication_level REAL DEFAULT 0,
                    scan_count_history TEXT,
                    average_rate REAL DEFAULT 0,
                    source_reputation TEXT
                )
            """)
            
            # Target vulnerability tracking
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS x_port_scan_targets (
                    target_ip TEXT PRIMARY KEY,
                    first_scanned REAL,
                    last_scanned REAL,
                    scan_count INTEGER DEFAULT 1,
                    scanner_count INTEGER DEFAULT 1,
                    ports_probed TEXT,
                    open_ports TEXT,
                    closed_ports TEXT,
                    service_fingerprints TEXT,
                    likely_os TEXT,
                    vulnerability_score REAL DEFAULT 0,
                    exposure_profile TEXT
                )
            """)
            
            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_portscan_src ON x_port_scan_events(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_portscan_time ON x_port_scan_events(start_time)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_portscan_type ON x_port_scan_events(scan_type)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_portscan_sophistication ON x_port_scan_events(scan_sophistication DESC)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scanner_profiles_seen ON x_port_scanner_profiles(last_seen DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scanner_profiles_total ON x_port_scanner_profiles(total_scans DESC)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_targets_count ON x_port_scan_targets(scan_count DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scan_targets_vuln ON x_port_scan_targets(vulnerability_score DESC)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("Port scan analysis tables initialized with enhanced schema")
        except Exception as e:
            logger.error(f"Error initializing port scan analysis tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process a packet for enhanced port scan detection"""
        # Get the layers
        layers = packet_data.get("layers", {})
        if not layers:
            return False
        
        try:
            # Extract IP addresses and ports
            src_ip = self.analysis_manager._get_layer_value(layers, "ip_src") or self.analysis_manager._get_layer_value(layers, "ipv6_src")
            dst_ip = self.analysis_manager._get_layer_value(layers, "ip_dst") or self.analysis_manager._get_layer_value(layers, "ipv6_dst")
            
            if not src_ip or not dst_ip:
                return False
                
            src_port, dst_port = self.analysis_manager._extract_ports(layers)
            
            if not dst_port:
                return False  # Need destination port for port scan detection
            
            # Process TCP flags for stealth scan detection
            tcp_flags = self.analysis_manager._get_layer_value(layers, "tcp_flags")
            tcp_flags_str = self.analysis_manager._get_layer_value(layers, "tcp_flags_str")
            
            is_syn_scan = False
            is_fin_scan = False
            is_xmas_scan = False
            is_null_scan = False
            is_ack_scan = False
            is_response = False
            
            if tcp_flags is not None:
                try:
                    flags = int(tcp_flags, 16) if isinstance(tcp_flags, str) else int(tcp_flags)
                    is_syn_scan = (flags & 0x02) and not (flags & 0x10)  # SYN but not ACK
                    is_fin_scan = (flags & 0x01) and not (flags & 0x02) and not (flags & 0x10)  # FIN but not SYN/ACK
                    is_xmas_scan = (flags & 0x01) and (flags & 0x04) and (flags & 0x20) and not (flags & 0x10)  # FIN+PSH+URG but not ACK
                    is_null_scan = flags == 0  # No flags set
                    is_ack_scan = (flags & 0x10) and not (flags & 0x02)  # ACK but not SYN
                    is_response = (flags & 0x10) and (flags & 0x04)  # ACK+RST or ACK+SYN
                except (ValueError, TypeError):
                    pass
            elif tcp_flags_str:
                is_syn_scan = 'SYN' in tcp_flags_str and 'ACK' not in tcp_flags_str
                is_fin_scan = 'FIN' in tcp_flags_str and 'SYN' not in tcp_flags_str and 'ACK' not in tcp_flags_str
                is_xmas_scan = 'FIN' in tcp_flags_str and 'PSH' in tcp_flags_str and 'URG' in tcp_flags_str
                is_null_scan = tcp_flags_str == '·······'  # Common null flags representation
                is_ack_scan = 'ACK' in tcp_flags_str and 'SYN' not in tcp_flags_str
                is_response = 'ACK' in tcp_flags_str and ('RST' in tcp_flags_str or 'SYN' in tcp_flags_str)
            
            # Get packet size and timestamp
            current_time = time.time()
            
            # Track scanning attempts and responses for response rate calculation
            if is_response and src_ip in self.scan_cache['response_stats']:
                self.scan_cache['response_stats'][dst_ip]['responses'] += 1
            elif (is_syn_scan or is_fin_scan or is_xmas_scan or is_null_scan or is_ack_scan):
                self.scan_cache['response_stats'][src_ip]['attempts'] += 1
            
            # Update scan detection data structures
            
            # 1. Track src->dst:port combinations for horizontal scan detection
            key = f"{src_ip}->{dst_ip}"
            if dst_port not in self.scan_cache['src_to_dst_ports'][key]:
                self.scan_cache['src_to_dst_ports'][key].add(dst_port)
                
                # 1a. Track port sequence for scan pattern detection
                self.scan_cache['port_sequence'][src_ip].append(dst_port)
                # Limit sequence length to avoid memory issues
                if len(self.scan_cache['port_sequence'][src_ip]) > 100:
                    self.scan_cache['port_sequence'][src_ip] = self.scan_cache['port_sequence'][src_ip][-100:]
            
            # 2. Track src->port:dst combinations for vertical scan detection
            key = f"{src_ip}->{dst_port}"
            if dst_ip not in self.scan_cache['src_to_dst_ips'][key]:
                self.scan_cache['src_to_dst_ips'][key].add(dst_ip)
            
            # 3. Track connection timestamps for rate detection
            self.scan_cache['connection_times'][src_ip].append(current_time)
            
            # Cleanup old timestamps
            self.scan_cache['connection_times'][src_ip] = [t for t in self.scan_cache['connection_times'][src_ip] 
                                                          if t > current_time - self.time_window]
            
            # 4. Track scan pattern information
            if src_ip not in self.scan_cache['scan_patterns']:
                self.scan_cache['scan_patterns'][src_ip] = {
                    'stealth_scans': 0,
                    'total_scans': 0,
                    'intervals': [],
                    'scan_types': Counter(),
                    'port_groups': defaultdict(int)
                }
            
            # Update scan pattern data
            self.scan_cache['scan_patterns'][src_ip]['total_scans'] += 1
            
            if is_syn_scan:
                self.scan_cache['scan_patterns'][src_ip]['scan_types']['syn'] += 1
            elif is_fin_scan:
                self.scan_cache['scan_patterns'][src_ip]['scan_types']['fin'] += 1
                self.scan_cache['scan_patterns'][src_ip]['stealth_scans'] += 1
            elif is_xmas_scan:
                self.scan_cache['scan_patterns'][src_ip]['scan_types']['xmas'] += 1
                self.scan_cache['scan_patterns'][src_ip]['stealth_scans'] += 1
            elif is_null_scan:
                self.scan_cache['scan_patterns'][src_ip]['scan_types']['null'] += 1
                self.scan_cache['scan_patterns'][src_ip]['stealth_scans'] += 1
            elif is_ack_scan:
                self.scan_cache['scan_patterns'][src_ip]['scan_types']['ack'] += 1
                self.scan_cache['scan_patterns'][src_ip]['stealth_scans'] += 1
            
            # Track timing intervals for scan pattern detection
            if len(self.scan_cache['connection_times'][src_ip]) > 1:
                intervals = []
                for i in range(1, len(self.scan_cache['connection_times'][src_ip])):
                    interval = self.scan_cache['connection_times'][src_ip][i] - self.scan_cache['connection_times'][src_ip][i-1]
                    if interval > 0:
                        intervals.append(interval)
                        
                # Keep recent intervals
                if intervals:
                    self.scan_cache['scan_patterns'][src_ip]['intervals'].extend(intervals)
                    if len(self.scan_cache['scan_patterns'][src_ip]['intervals']) > 20:
                        self.scan_cache['scan_patterns'][src_ip]['intervals'] = self.scan_cache['scan_patterns'][src_ip]['intervals'][-20:]
            
            # Categorize ports into functional groups
            for group, ports in self.port_groups.items():
                if dst_port in ports:
                    self.scan_cache['scan_patterns'][src_ip]['port_groups'][group] += 1
            
            # Run detection for various scan types
            self._detect_and_record_scans(src_ip, dst_ip, dst_port, current_time)
            
            # Process each packet for target vulnerability profiling
            self._update_target_profile(dst_ip, dst_port, is_response, current_time)
            
            return True
        except Exception as e:
            logger.error(f"Error in port scan detection: {e}")
            return False
    
    def _detect_and_record_scans(self, src_ip, dst_ip, dst_port, current_time):
        """Enhanced scan detection with multiple scan types, patterns, and tools identification"""
        # Detect horizontal scan (many ports on one host)
        self._detect_horizontal_scan(src_ip, dst_ip, current_time)
        
        # Detect vertical scan (one port on many hosts)
        self._detect_vertical_scan(src_ip, dst_port, current_time)
        
        # Detect block scan (many hosts, many ports)
        self._detect_block_scan(src_ip, current_time)
        
        # Detect fast scanning based on connection rate
        self._detect_fast_scan(src_ip, current_time)
        
        # Detect stealth scanning based on scan techniques
        self._detect_stealth_scan(src_ip, current_time)
        
        # Detect timing pattern-based scanning
        self._detect_timing_pattern(src_ip, current_time)
    
    def _detect_horizontal_scan(self, src_ip, dst_ip, current_time):
        """Detect horizontal port scan (many ports on one host) with enhanced fingerprinting"""
        key = f"{src_ip}->{dst_ip}"
        if key in self.scan_cache['src_to_dst_ports']:
            port_count = len(self.scan_cache['src_to_dst_ports'][key])
            
            if port_count >= self.scan_thresholds['horizontal']:
                # Check cooldown timer to avoid duplicate detections
                if current_time - self.scan_cache['last_detection_time'].get(f"h_{src_ip}_{dst_ip}", 0) > 300:
                    # Get list of scanned ports for analysis
                    scanned_ports = list(self.scan_cache['src_to_dst_ports'][key])
                    
                    # Get port sequence if available
                    port_sequence = self.scan_cache['port_sequence'].get(src_ip, [])
                    
                    # Calculate stealth score
                    stealth_score = 0
                    if src_ip in self.scan_cache['scan_patterns']:
                        stealth_score = self.scan_cache['scan_patterns'][src_ip]['stealth_scans'] / max(1, self.scan_cache['scan_patterns'][src_ip]['total_scans'])
                    
                    # Identify scan pattern and likely tool
                    scan_pattern, likely_tool = self._identify_scan_pattern(scanned_ports, port_sequence)
                    
                    # Calculate sophistication level (1-10)
                    sophistication = self._calculate_scan_sophistication(stealth_score, scan_pattern, port_count)
                    
                    # Calculate response rate
                    response_rate = 0
                    if src_ip in self.scan_cache['response_stats']:
                        attempts = self.scan_cache['response_stats'][src_ip]['attempts']
                        responses = self.scan_cache['response_stats'][src_ip]['responses']
                        if attempts > 0:
                            response_rate = responses / attempts
                    
                    # Identify target categories
                    target_categories = self._identify_target_categories(scanned_ports)
                    
                    # Record with enhanced metadata
                    self._record_scan_event(
                        src_ip, 'horizontal', 1, port_count, current_time,
                        scanned_ports=scanned_ports,
                        port_sequence=port_sequence,
                        response_rate=response_rate,
                        scan_pattern=scan_pattern,
                        likely_tool=likely_tool,
                        sophistication=sophistication,
                        stealth_score=stealth_score,
                        target_categories=target_categories
                    )
                    
                    # Update cooldown timer
                    self.scan_cache['last_detection_time'][f"h_{src_ip}_{dst_ip}"] = current_time
                    
                    # Clear cache for this specific scan
                    del self.scan_cache['src_to_dst_ports'][key]
    
    def _detect_vertical_scan(self, src_ip, dst_port, current_time):
        """Detect vertical port scan (one port on many hosts) with enhanced fingerprinting"""
        key = f"{src_ip}->{dst_port}"
        if key in self.scan_cache['src_to_dst_ips']:
            target_count = len(self.scan_cache['src_to_dst_ips'][key])
            
            if target_count >= self.scan_thresholds['vertical']:
                # Check cooldown timer
                if current_time - self.scan_cache['last_detection_time'].get(f"v_{src_ip}_{dst_port}", 0) > 300:
                    # Get list of targets for analysis
                    target_ips = list(self.scan_cache['src_to_dst_ips'][key])
                    
                    # Calculate stealth score
                    stealth_score = 0
                    if src_ip in self.scan_cache['scan_patterns']:
                        stealth_score = self.scan_cache['scan_patterns'][src_ip]['stealth_scans'] / max(1, self.scan_cache['scan_patterns'][src_ip]['total_scans'])
                    
                    # For vertical scans, identify subnet patterns
                    scan_pattern = self._identify_subnet_pattern(target_ips)
                    
                    # Calculate sophistication level (1-10)
                    sophistication = self._calculate_scan_sophistication(stealth_score, scan_pattern, 0, target_count)
                    
                    # Calculate response rate
                    response_rate = 0
                    if src_ip in self.scan_cache['response_stats']:
                        attempts = self.scan_cache['response_stats'][src_ip]['attempts']
                        responses = self.scan_cache['response_stats'][src_ip]['responses']
                        if attempts > 0:
                            response_rate = responses / attempts
                    
                    # Identify service being targeted
                    target_categories = {}
                    for group, ports in self.port_groups.items():
                        if dst_port in ports:
                            target_categories = {group: 1.0}
                            break
                    
                    # Record with enhanced metadata
                    self._record_scan_event(
                        src_ip, 'vertical', target_count, 1, current_time,
                        scanned_ports=[dst_port],
                        response_rate=response_rate,
                        scan_pattern=scan_pattern,
                        likely_tool=self._guess_tool_by_port(dst_port),
                        sophistication=sophistication,
                        stealth_score=stealth_score,
                        target_categories=target_categories
                    )
                    
                    # Update cooldown timer
                    self.scan_cache['last_detection_time'][f"v_{src_ip}_{dst_port}"] = current_time
                    
                    # Clear cache for this specific scan
                    del self.scan_cache['src_to_dst_ips'][key]
    
    def _detect_block_scan(self, src_ip, current_time):
        """Detect block scan (many hosts, many ports) with enhanced fingerprinting"""
        # Count unique destination IPs across all port scans
        dst_ips = set()
        for key in self.scan_cache['src_to_dst_ports']:
            if key.startswith(f"{src_ip}->"):
                dst_ip = key.split('->')[1]
                dst_ips.add(dst_ip)
        
        # If scanning multiple hosts with multiple ports, it's a block scan
        if len(dst_ips) >= 5:  # At least 5 different targets
            # Count total unique ports across all destinations
            total_ports = set()
            for key in self.scan_cache['src_to_dst_ports']:
                if key.startswith(f"{src_ip}->"):
                    total_ports.update(self.scan_cache['src_to_dst_ports'][key])
            
            if len(total_ports) >= self.scan_thresholds['block'] and len(dst_ips) >= 5:
                # Check cooldown timer
                if current_time - self.scan_cache['last_detection_time'].get(f"b_{src_ip}", 0) > 300:
                    # Get combined port sequence
                    port_sequence = self.scan_cache['port_sequence'].get(src_ip, [])
                    
                    # Get list of scanned ports
                    scanned_ports = list(total_ports)
                    
                    # Identify scan pattern and likely tool
                    scan_pattern, likely_tool = self._identify_scan_pattern(scanned_ports, port_sequence)
                    
                    # Calculate stealth score
                    stealth_score = 0
                    if src_ip in self.scan_cache['scan_patterns']:
                        stealth_score = self.scan_cache['scan_patterns'][src_ip]['stealth_scans'] / max(1, self.scan_cache['scan_patterns'][src_ip]['total_scans'])
                    
                    # Calculate sophistication level (1-10)
                    sophistication = self._calculate_scan_sophistication(
                        stealth_score, scan_pattern, len(total_ports), len(dst_ips)
                    )
                    
                    # Calculate response rate
                    response_rate = 0
                    if src_ip in self.scan_cache['response_stats']:
                        attempts = self.scan_cache['response_stats'][src_ip]['attempts']
                        responses = self.scan_cache['response_stats'][src_ip]['responses']
                        if attempts > 0:
                            response_rate = responses / attempts
                    
                    # Identify target categories
                    target_categories = self._identify_target_categories(scanned_ports)
                    
                    # Record with enhanced metadata
                    self._record_scan_event(
                        src_ip, 'block', len(dst_ips), len(total_ports), current_time,
                        scanned_ports=scanned_ports,
                        port_sequence=port_sequence,
                        response_rate=response_rate,
                        scan_pattern=scan_pattern,
                        likely_tool=likely_tool,
                        sophistication=sophistication,
                        stealth_score=stealth_score,
                        target_categories=target_categories
                    )
                    
                    # Update cooldown timer
                    self.scan_cache['last_detection_time'][f"b_{src_ip}"] = current_time
                    
                    # Clear all caches for this source
                    for key in list(self.scan_cache['src_to_dst_ports'].keys()):
                        if key.startswith(f"{src_ip}->"):
                            del self.scan_cache['src_to_dst_ports'][key]
                    
                    for key in list(self.scan_cache['src_to_dst_ips'].keys()):
                        if key.startswith(f"{src_ip}->"):
                            del self.scan_cache['src_to_dst_ips'][key]
    
    def _detect_fast_scan(self, src_ip, current_time):
        """Detect fast scanning based on connection rate with enhanced fingerprinting"""
        if src_ip in self.scan_cache['connection_times']:
            # Get connections in the time window
            recent_connections = [t for t in self.scan_cache['connection_times'][src_ip] 
                                 if t > current_time - self.time_window]
            
            if len(recent_connections) >= self.scan_thresholds['rate']:
                # Calculate rate (connections per second)
                if recent_connections:
                    time_span = max(1, current_time - min(recent_connections))  # At least 1 second
                    rate = len(recent_connections) / time_span
                    
                    if rate >= self.scan_thresholds['rate']:
                        # Check cooldown timer
                        if current_time - self.scan_cache['last_detection_time'].get(f"f_{src_ip}", 0) > 300:
                            # Count unique destinations and ports
                            dst_ips = set()
                            dst_ports = set()
                            
                            for key in self.scan_cache['src_to_dst_ports']:
                                if key.startswith(f"{src_ip}->"):
                                    dst_ip = key.split('->')[1]
                                    dst_ips.add(dst_ip)
                                    dst_ports.update(self.scan_cache['src_to_dst_ports'][key])
                            
                            # Get combined port sequence
                            port_sequence = self.scan_cache['port_sequence'].get(src_ip, [])
                            
                            # Identify scan pattern and likely tool
                            scan_pattern, likely_tool = self._identify_scan_pattern(list(dst_ports), port_sequence)
                            
                            # Adjust tool guess based on scan rate
                            if rate > 100:  # Very fast
                                likely_candidates = ["masscan", "zmap"]
                                for candidate in likely_candidates:
                                    if candidate in likely_tool.lower():
                                        likely_tool = candidate.upper()
                                        break
                                if "zmap" not in likely_tool.lower() and "masscan" not in likely_tool.lower():
                                    likely_tool = f"Fast scanner ({likely_tool})"
                            
                            # Calculate stealth score (fast scans are typically less stealthy)
                            stealth_score = 0
                            if src_ip in self.scan_cache['scan_patterns']:
                                raw_stealth = self.scan_cache['scan_patterns'][src_ip]['stealth_scans'] / max(1, self.scan_cache['scan_patterns'][src_ip]['total_scans'])
                                # Fast scans reduce stealth score
                                stealth_score = raw_stealth * max(0.1, 1.0 - (rate / 100))
                            
                            # Calculate sophistication (fast scans can be sophisticated in different ways)
                            sophistication = self._calculate_scan_sophistication(
                                stealth_score, scan_pattern, len(dst_ports), len(dst_ips)
                            )
                            # Adjust for speed
                            if rate > 50:
                                sophistication = min(10, sophistication + 2)  # Speed requires sophistication
                            
                            # Calculate response rate
                            response_rate = 0
                            if src_ip in self.scan_cache['response_stats']:
                                attempts = self.scan_cache['response_stats'][src_ip]['attempts']
                                responses = self.scan_cache['response_stats'][src_ip]['responses']
                                if attempts > 0:
                                    response_rate = responses / attempts
                            
                            # Identify target categories
                            target_categories = self._identify_target_categories(list(dst_ports))
                            
                            # Record with enhanced metadata
                            self._record_scan_event(
                                src_ip, 'fast', len(dst_ips), len(dst_ports), current_time, rate,
                                scanned_ports=list(dst_ports),
                                port_sequence=port_sequence,
                                response_rate=response_rate,
                                scan_pattern=scan_pattern,
                                likely_tool=likely_tool,
                                sophistication=sophistication,
                                stealth_score=stealth_score,
                                target_categories=target_categories
                            )
                            
                            # Update cooldown timer
                            self.scan_cache['last_detection_time'][f"f_{src_ip}"] = current_time
    
    def _detect_stealth_scan(self, src_ip, current_time):
        """Detect stealth scanning techniques"""
        if src_ip in self.scan_cache['scan_patterns']:
            pattern_data = self.scan_cache['scan_patterns'][src_ip]
            stealth_scans = pattern_data['stealth_scans']
            total_scans = pattern_data['total_scans']
            
            # Require a minimum number of scans to detect a pattern
            if total_scans < 10:
                return
            
            # Stealth scan detection requires a significant portion of stealth techniques
            stealth_ratio = stealth_scans / total_scans if total_scans > 0 else 0
            
            if stealth_ratio > 0.6 and stealth_scans >= self.scan_thresholds['stealth']:
                # Check cooldown timer
                if current_time - self.scan_cache['last_detection_time'].get(f"s_{src_ip}", 0) > 300:
                    # Categorize stealth scan type based on most common technique
                    scan_types = pattern_data['scan_types']
                    most_common_type = scan_types.most_common(1)[0][0] if scan_types else "unknown"
                    
                    # Count targets and ports
                    dst_ips = set()
                    dst_ports = set()
                    
                    for key in self.scan_cache['src_to_dst_ports']:
                        if key.startswith(f"{src_ip}->"):
                            dst_ip = key.split('->')[1]
                            dst_ips.add(dst_ip)
                            dst_ports.update(self.scan_cache['src_to_dst_ports'][key])
                    
                    # Get port sequence for fingerprinting
                    port_sequence = self.scan_cache['port_sequence'].get(src_ip, [])
                    
                    # Identify scan pattern
                    scan_pattern, likely_tool = self._identify_scan_pattern(list(dst_ports), port_sequence)
                    
                    # For stealth scans, adjust likely tool
                    if "nmap" in likely_tool.lower():
                        likely_tool = "NMAP (stealth mode)"
                    else:
                        likely_tool = f"{likely_tool} (stealth mode)"
                    
                    # Calculate sophistication (stealth scans are generally more sophisticated)
                    sophistication = self._calculate_scan_sophistication(
                        stealth_ratio, scan_pattern, len(dst_ports), len(dst_ips)
                    )
                    # Stealth increases sophistication
                    sophistication = min(10, sophistication + 2)
                    
                    # Calculate response rate
                    response_rate = 0
                    if src_ip in self.scan_cache['response_stats']:
                        attempts = self.scan_cache['response_stats'][src_ip]['attempts']
                        responses = self.scan_cache['response_stats'][src_ip]['responses']
                        if attempts > 0:
                            response_rate = responses / attempts
                    
                    # Identify target categories
                    target_categories = self._identify_target_categories(list(dst_ports))
                    
                    # Record stealth scan event with enhanced metadata
                    stealth_scan_type = f"stealth_{most_common_type}"
                    self._record_scan_event(
                        src_ip, stealth_scan_type, len(dst_ips), len(dst_ports), current_time,
                        scanned_ports=list(dst_ports),
                        port_sequence=port_sequence,
                        response_rate=response_rate,
                        scan_pattern=scan_pattern,
                        likely_tool=likely_tool,
                        sophistication=sophistication,
                        stealth_score=stealth_ratio,
                        target_categories=target_categories
                    )
                    
                    # Update cooldown timer
                    self.scan_cache['last_detection_time'][f"s_{src_ip}"] = current_time
    
    def _detect_timing_pattern(self, src_ip, current_time):
        """Detect timing-based scan patterns (evenly spaced, slow deliberate scans)"""
        if src_ip in self.scan_cache['scan_patterns']:
            intervals = self.scan_cache['scan_patterns'][src_ip]['intervals']
            
            # Need enough intervals to detect a pattern
            if len(intervals) < 5:
                return
            
            # Calculate variance in intervals
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((i - avg_interval) ** 2 for i in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            
            # Coefficient of variation measures consistency (lower is more consistent)
            cv = std_dev / avg_interval if avg_interval > 0 else float('inf')
            
            # Look for very consistent timing - indicates automated tool with timing controls
            if cv < self.scan_thresholds['timing'] and avg_interval > 1.0:
                # Ensure we don't detect the same timing pattern too frequently
                if current_time - self.scan_cache['last_detection_time'].get(f"t_{src_ip}", 0) > 600:
                    # This is likely a deliberate low-and-slow scan with carefully timed probes
                    # Count targets and ports
                    dst_ips = set()
                    dst_ports = set()
                    
                    for key in self.scan_cache['src_to_dst_ports']:
                        if key.startswith(f"{src_ip}->"):
                            dst_ip = key.split('->')[1]
                            dst_ips.add(dst_ip)
                            dst_ports.update(self.scan_cache['src_to_dst_ports'][key])
                    
                    # Get port sequence
                    port_sequence = self.scan_cache['port_sequence'].get(src_ip, [])
                    
                    # For timing pattern scans, the pattern is the timing itself
                    scan_pattern = f"Timed pattern: {avg_interval:.2f}s intervals (±{std_dev:.2f}s)"
                    
                    # Determine likely tool (timed scans often use specific tools)
                    likely_tool = "NMAP (timing controlled)"
                    if avg_interval > 10:
                        likely_tool = "Custom scanner (low and slow)"
                    
                    # Calculate sophistication (timed scans are highly sophisticated)
                    sophistication = 8  # Base score for timing control
                    sophistication += min(2, 2 * (1 - cv))  # Higher consistency = higher sophistication
                    sophistication = min(10, sophistication)
                    
                    # Get stealth score
                    stealth_score = 0
                    if src_ip in self.scan_cache['scan_patterns']:
                        raw_stealth = self.scan_cache['scan_patterns'][src_ip]['stealth_scans'] / max(1, self.scan_cache['scan_patterns'][src_ip]['total_scans'])
                        # Timed scans are inherently stealthy
                        stealth_score = max(raw_stealth, 0.5)
                    
                    # Calculate response rate
                    response_rate = 0
                    if src_ip in self.scan_cache['response_stats']:
                        attempts = self.scan_cache['response_stats'][src_ip]['attempts']
                        responses = self.scan_cache['response_stats'][src_ip]['responses']
                        if attempts > 0:
                            response_rate = responses / attempts
                    
                    # Identify target categories
                    target_categories = self._identify_target_categories(list(dst_ports))
                    
                    # Record timed scan event
                    self._record_scan_event(
                        src_ip, 'timed', len(dst_ips), len(dst_ports), current_time,
                        scanned_ports=list(dst_ports),
                        port_sequence=port_sequence,
                        response_rate=response_rate,
                        scan_pattern=scan_pattern,
                        likely_tool=likely_tool,
                        sophistication=sophistication,
                        stealth_score=stealth_score,
                        target_categories=target_categories
                    )
                    
                    # Update cooldown timer
                    self.scan_cache['last_detection_time'][f"t_{src_ip}"] = current_time
    
    def _identify_scan_pattern(self, scanned_ports, port_sequence):
        """Identify port scan pattern and potential scanning tool"""
        if not scanned_ports:
            return "Unknown", "Unknown"
        
        # Sort ports for better pattern detection
        scanned_ports.sort()
        
        # Check for sequential port patterns
        sequential_ranges = []
        current_range = [scanned_ports[0]]
        
        for i in range(1, len(scanned_ports)):
            if scanned_ports[i] == scanned_ports[i-1] + 1:
                current_range.append(scanned_ports[i])
            else:
                if len(current_range) > 1:
                    sequential_ranges.append(current_range)
                current_range = [scanned_ports[i]]
        
        if len(current_range) > 1:
            sequential_ranges.append(current_range)
        
        # Calculate percentage of ports that fall within sequential ranges
        ports_in_ranges = sum(len(r) for r in sequential_ranges)
        sequential_pct = ports_in_ranges / len(scanned_ports) if scanned_ports else 0
        
        # Analyze port distribution
        common_ports = set([21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080])
        common_found = [p for p in scanned_ports if p in common_ports]
        common_pct = len(common_found) / len(scanned_ports) if scanned_ports else 0
        
        # Check for patterns in port sequence ordering
        tool_matches = {}
        if port_sequence:
            for tool, pattern in self.known_scan_patterns.items():
                # Look for subsequence matches
                matches = 0
                for i in range(len(port_sequence) - len(pattern) + 1):
                    if port_sequence[i:i+len(pattern)] == pattern:
                        matches += 1
                
                if matches > 0:
                    tool_matches[tool] = matches
        
        # Determine pattern description
        pattern_description = "Unknown"
        
        if sequential_pct > 0.9:
            # Almost all ports are in sequential ranges
            pattern_description = "Sequential scan"
            for r in sequential_ranges:
                if len(r) > 5:  # Only mention significant ranges
                    pattern_description += f" [{r[0]}-{r[-1]}]"
        elif common_pct > 0.8:
            # Mostly common/well-known ports
            pattern_description = "Common ports scan"
        elif len(scanned_ports) > 100:
            pattern_description = "Comprehensive scan"
        else:
            # Mixed/targeted pattern
            service_categories = []
            for group, ports in self.port_groups.items():
                group_ports = [p for p in scanned_ports if p in ports]
                if group_ports and len(group_ports) / len(ports) > 0.3:  # At least 30% of the group's ports
                    service_categories.append(group)
            
            if service_categories:
                pattern_description = f"Targeted scan ({', '.join(service_categories)})"
            else:
                pattern_description = "Mixed scan pattern"
        
        # Determine likely tool
        likely_tool = "Unknown"
        
        if tool_matches:
            # Use the tool with the most matches
            best_match = max(tool_matches.items(), key=lambda x: x[1])
            if best_match[1] > 0:
                if best_match[0] == 'nmap_default':
                    likely_tool = "NMAP (default)"
                elif best_match[0] == 'nmap_common':
                    likely_tool = "NMAP (common)"
                elif best_match[0] == 'zmap_common':
                    likely_tool = "ZMAP"
                elif best_match[0] == 'masscan_common':
                    likely_tool = "MASSCAN"
        elif sequential_pct > 0.9:
            likely_tool = "NMAP (sequential)"
        elif common_pct > 0.8:
            likely_tool = "NMAP (service detection)"
        
        return pattern_description, likely_tool
    
    def _identify_subnet_pattern(self, target_ips):
        """Identify subnet scanning pattern"""
        if not target_ips:
            return "Unknown"
            
        # Try to detect subnet-based scanning by looking at IP patterns
        subnet_groups = defaultdict(list)
        
        for ip in target_ips:
            try:
                # Get /24 subnet
                subnet = '.'.join(ip.split('.')[:3])
                subnet_groups[subnet].append(ip)
            except:
                continue
        
        # If most IPs fall within one or few subnets, it's a subnet scan
        if subnet_groups:
            largest_subnet = max(subnet_groups.items(), key=lambda x: len(x[1]))
            subnet, ips = largest_subnet
            
            if len(ips) / len(target_ips) > 0.8:
                # Check if IPs are sequential within subnet
                last_octets = [int(ip.split('.')[-1]) for ip in ips]
                last_octets.sort()
                
                sequential_count = 0
                for i in range(1, len(last_octets)):
                    if last_octets[i] == last_octets[i-1] + 1:
                        sequential_count += 1
                
                sequential_pct = sequential_count / (len(last_octets) - 1) if len(last_octets) > 1 else 0
                
                if sequential_pct > 0.7:
                    return f"Sequential subnet scan ({subnet}.0/24)"
                else:
                    return f"Subnet scan ({subnet}.0/24)"
            else:
                # Multiple subnets are being scanned
                subnet_count = len(subnet_groups)
                if subnet_count > 1:
                    return f"Multi-subnet scan ({subnet_count} subnets)"
        
        return "Distributed scan"
    
    def _guess_tool_by_port(self, port):
        """Make an educated guess about the tool based on specific port"""
        if port == 80:
            return "Web scanner (possibly Nikto, Dirb, etc.)"
        elif port == 443:
            return "SSL/TLS scanner (possibly SSLyze, Qualys)"
        elif port == 22:
            return "SSH scanner (possibly Hydra, custom)"
        elif port == 3389:
            return "RDP scanner"
        elif port == 445 or port == 139:
            return "SMB scanner (possibly Enum4linux)"
        elif port == 5060:
            return "VoIP scanner (SIPVicious)"
        else:
            return "Unknown"
    
    def _calculate_scan_sophistication(self, stealth_score, scan_pattern, port_count=0, target_count=0):
        """Calculate scan sophistication score (1-10)"""
        sophistication = 5  # Start with neutral score
        
        # Adjust based on stealth techniques
        sophistication += stealth_score * 3  # Up to +3 points for stealth
        
        # Adjust based on scan pattern complexity
        if "Sequential" in scan_pattern:
            sophistication -= 1  # Simple sequential scans are less sophisticated
        elif "Targeted" in scan_pattern:
            sophistication += 2  # Targeted scans show knowledge
        elif "Comprehensive" in scan_pattern:
            sophistication += 1  # Comprehensive scans show thoroughness
        elif "Timed pattern" in scan_pattern:
            sophistication += 3  # Timed patterns are sophisticated
        
        # Adjust based on scale
        if port_count > 100 and target_count > 100:
            sophistication += 1  # Large scale scans require more sophistication
        
        # Cap the score
        return max(1, min(10, sophistication))
    
    def _identify_target_categories(self, scanned_ports):
        """Identify target service categories based on ports"""
        categories = defaultdict(int)
        total_categorized = 0
        
        for port in scanned_ports:
            for group, ports in self.port_groups.items():
                if port in ports:
                    categories[group] += 1
                    total_categorized += 1
                    break
        
        # Convert to percentage distribution
        result = {}
        if total_categorized > 0:
            for category, count in categories.items():
                result[category] = count / total_categorized
        
        return result
    
    def _update_target_profile(self, target_ip, port, is_response, current_time):
        """Update profile information about scan targets"""
        cursor = self.analysis_manager.get_cursor()
        
        try:
            # Check if target exists
            cursor.execute("SELECT ports_probed, open_ports FROM x_port_scan_targets WHERE target_ip = ?", (target_ip,))
            result = cursor.fetchone()
            
            if result:
                # Update existing target
                ports_probed_json, open_ports_json = result
                
                # Parse JSON data
                ports_probed = json.loads(ports_probed_json) if ports_probed_json else {}
                open_ports = json.loads(open_ports_json) if open_ports_json else []
                
                # Update probed ports
                port_str = str(port)
                if port_str in ports_probed:
                    ports_probed[port_str] += 1
                else:
                    ports_probed[port_str] = 1
                
                # Update open ports if this is a response packet
                if is_response and port_str not in open_ports:
                    open_ports.append(port_str)
                
                # Calculate vulnerability score based on open ports
                vulnerability_score = self._calculate_target_vulnerability(open_ports, ports_probed)
                
                # Determine exposure profile
                exposure_profile = self._determine_exposure_profile(open_ports)
                
                # Update scanner count
                cursor.execute("""
                    SELECT COUNT(DISTINCT src_ip) FROM x_port_scan_events
                    WHERE id IN (SELECT id FROM x_port_scan_events WHERE ports_scanned LIKE ?)
                """, (f'%{port}%',))
                
                scanner_count = cursor.fetchone()[0] or 1
                
                cursor.execute("""
                    UPDATE x_port_scan_targets
                    SET last_scanned = ?,
                        scan_count = scan_count + 1,
                        scanner_count = ?,
                        ports_probed = ?,
                        open_ports = ?,
                        vulnerability_score = ?,
                        exposure_profile = ?
                    WHERE target_ip = ?
                """, (
                    current_time,
                    scanner_count,
                    json.dumps(ports_probed),
                    json.dumps(open_ports),
                    vulnerability_score,
                    exposure_profile,
                    target_ip
                ))
            else:
                # Create new target profile
                ports_probed = {str(port): 1}
                open_ports = [str(port)] if is_response else []
                
                vulnerability_score = self._calculate_target_vulnerability(open_ports, ports_probed)
                exposure_profile = self._determine_exposure_profile(open_ports)
                
                cursor.execute("""
                    INSERT INTO x_port_scan_targets
                    (target_ip, first_scanned, last_scanned, ports_probed, open_ports,
                     vulnerability_score, exposure_profile)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    target_ip,
                    current_time,
                    current_time,
                    json.dumps(ports_probed),
                    json.dumps(open_ports),
                    vulnerability_score,
                    exposure_profile
                ))
            
            self.analysis_manager.analysis1_conn.commit()
        except Exception as e:
            logger.error(f"Error updating target profile for {target_ip}: {e}")
        finally:
            cursor.close()
    
    def _calculate_target_vulnerability(self, open_ports, probed_ports):
        """Calculate vulnerability score based on open ports and patterns"""
        if not open_ports:
            return 0
            
        # Base score starts at 1 for any open ports
        score = 1
        
        # Convert to integers for comparison
        open_port_numbers = [int(p) for p in open_ports]
        
        # Check for high-risk open ports
        high_risk_ports = {21, 22, 23, 3389, 445, 135, 139, 1433, 3306, 5432}
        for port in high_risk_ports:
            if port in open_port_numbers:
                score += 1
        
        # Check for unusual port combinations
        if 80 in open_port_numbers and 443 in open_port_numbers:
            score += 0.5  # Web server
        if 21 in open_port_numbers and 22 in open_port_numbers:
            score += 0.5  # FTP + SSH is common for file access
        
        # Check exposure breadth
        exposure_categories = set()
        for port in open_port_numbers:
            for category, ports in self.port_groups.items():
                if port in ports:
                    exposure_categories.add(category)
                    break
        
        # More diverse exposure = higher risk
        score += len(exposure_categories) * 0.5
        
        # Cap the score at 10
        return min(10, score)
    
    def _determine_exposure_profile(self, open_ports):
        """Determine exposure profile based on open ports"""
        if not open_ports:
            return "minimal"
            
        # Convert to integers
        open_port_numbers = [int(p) for p in open_ports]
        
        # Count ports by category
        category_counts = defaultdict(int)
        for port in open_port_numbers:
            for category, ports in self.port_groups.items():
                if port in ports:
                    category_counts[category] += 1
                    break
        
        # Determine primary exposure
        if not category_counts:
            return "unknown"
            
        primary_category = max(category_counts.items(), key=lambda x: x[1])[0]
        
        if primary_category == "web":
            return "web_server"
        elif primary_category == "database":
            return "database_server"
        elif primary_category == "remote_access":
            return "remote_access_server"
        elif primary_category == "file_sharing":
            return "file_server"
        elif primary_category == "email":
            return "mail_server"
        elif primary_category == "industrial":
            return "industrial_system"
        elif primary_category == "iot":
            return "iot_device"
        else:
            return f"{primary_category}_server"
    
    def _record_scan_event(self, src_ip, scan_type, target_count, port_count, current_time, 
                          rate=0, scanned_ports=None, port_sequence=None, response_rate=0,
                          scan_pattern="Unknown", likely_tool="Unknown", sophistication=5,
                          stealth_score=0, target_categories=None):
        """Record a scan event in the database with enhanced metadata"""
        try:
            cursor = self.analysis_manager.get_cursor()
            
            # Convert ports to JSON
            # Convert ports to JSON
            ports_json = json.dumps(scanned_ports) if scanned_ports else "[]"
            
            # Convert sequence to JSON
            sequence_json = json.dumps(port_sequence) if port_sequence else "[]"
            
            # Convert target categories to JSON
            categories_json = json.dumps(target_categories) if target_categories else "{}"
            
            cursor.execute("""
                INSERT INTO x_port_scan_events
                (src_ip, scan_type, target_count, port_count, start_time, end_time, rate,
                ports_scanned, port_sequence, response_rate, scan_pattern, likely_tool,
                scan_sophistication, stealth_score, target_categories)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                src_ip,
                scan_type,
                target_count,
                port_count,
                current_time - self.time_window,
                current_time,
                rate,
                ports_json,
                sequence_json,
                response_rate,
                scan_pattern,
                likely_tool,
                sophistication,
                stealth_score,
                categories_json
            ))
            
            # Update scanner profile
            self._update_scanner_profile(
                cursor, src_ip, scan_type, target_count, port_count,
                rate, scanned_ports, scan_pattern, likely_tool, 
                sophistication, stealth_score, current_time
            )
            
            self.analysis_manager.analysis1_conn.commit()
            
            logger.info(f"Recorded {scan_type} scan from {src_ip}: {target_count} targets, {port_count} ports, tool: {likely_tool}, sophistication: {sophistication}/10")
            
            cursor.close()
        except Exception as e:
            logger.error(f"Error recording scan event: {e}")
    
    def _update_scanner_profile(self, cursor, src_ip, scan_type, target_count, port_count,
                              rate, scanned_ports, scan_pattern, likely_tool, 
                              sophistication, stealth_score, current_time):
        """Update scanner profile with behavioral analysis"""
        try:
            # Check if scanner exists
            cursor.execute("""
                SELECT preferred_scan_types, usual_ports, sophistication_level, 
                       noise_level, scan_count_history, average_rate
                FROM x_port_scanner_profiles
                WHERE scanner_ip = ?
            """, (src_ip,))
            
            result = cursor.fetchone()
            
            if result:
                # Update existing scanner profile
                scan_types_json, usual_ports_json, sophistication_level, noise_level, scan_history_json, avg_rate = result
                
                # Parse JSON data
                scan_types = json.loads(scan_types_json) if scan_types_json else {}
                usual_ports = json.loads(usual_ports_json) if usual_ports_json else []
                scan_history = json.loads(scan_history_json) if scan_history_json else []
                
                # Update scan types frequency
                if scan_type in scan_types:
                    scan_types[scan_type] += 1
                else:
                    scan_types[scan_type] = 1
                
                # Update usual ports
                if scanned_ports:
                    for port in scanned_ports:
                        if port not in usual_ports:
                            usual_ports.append(port)
                
                # Limit usual ports to avoid excessive growth
                if len(usual_ports) > 100:
                    usual_ports = usual_ports[-100:]
                
                # Update scan history (timestamp and target count)
                scan_history.append([int(current_time), target_count])
                
                # Keep only recent history (last 7 days)
                cutoff_time = current_time - (86400 * 7)
                scan_history = [entry for entry in scan_history if entry[0] > cutoff_time]
                
                # Update sophistication level (running average)
                sophistication_level = (sophistication_level * 0.7) + (sophistication * 0.3)
                
                # Calculate noise level
                if target_count > 100 or port_count > 100 or (rate and rate > 50):
                    noise_level = min(10, noise_level + 0.5)
                else:
                    noise_level = max(0, noise_level - 0.2)
                
                # Update average scan rate
                if rate > 0:
                    if avg_rate > 0:
                        avg_rate = (avg_rate * 0.7) + (rate * 0.3)
                    else:
                        avg_rate = rate
                
                # Determine source reputation based on behavior
                source_reputation = self._determine_scanner_reputation(
                    scan_types, sophistication_level, noise_level, stealth_score, 
                    likely_tool, scan_history
                )
                
                cursor.execute("""
                    UPDATE x_port_scanner_profiles
                    SET last_seen = ?,
                        total_scans = total_scans + 1,
                        preferred_scan_types = ?,
                        usual_ports = ?,
                        scan_pattern = ?,
                        sophistication_level = ?,
                        noise_level = ?,
                        scan_count_history = ?,
                        average_rate = ?,
                        source_reputation = ?
                    WHERE scanner_ip = ?
                """, (
                    current_time,
                    json.dumps(scan_types),
                    json.dumps(usual_ports),
                    scan_pattern,
                    sophistication_level,
                    noise_level,
                    json.dumps(scan_history),
                    avg_rate,
                    source_reputation,
                    src_ip
                ))
            else:
                # Create new scanner profile
                scan_types = {scan_type: 1}
                usual_ports = scanned_ports if scanned_ports else []
                scan_history = [[int(current_time), target_count]]
                
                # Determine initial reputation
                source_reputation = self._determine_scanner_reputation(
                    scan_types, sophistication, 0, stealth_score, 
                    likely_tool, scan_history
                )
                
                cursor.execute("""
                    INSERT INTO x_port_scanner_profiles
                    (scanner_ip, first_seen, last_seen, total_scans, preferred_scan_types,
                     usual_ports, port_sequence_patterns, sophistication_level, noise_level,
                     scan_count_history, average_rate, source_reputation)
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    src_ip,
                    current_time,
                    current_time,
                    json.dumps(scan_types),
                    json.dumps(usual_ports),
                    scan_pattern,
                    sophistication,
                    0,  # Initial noise level
                    json.dumps(scan_history),
                    rate,
                    source_reputation
                ))
        except Exception as e:
            logger.error(f"Error updating scanner profile for {src_ip}: {e}")
    
    def _determine_scanner_reputation(self, scan_types, sophistication, noise_level, 
                                     stealth_score, likely_tool, scan_history):
        """Determine scanner reputation based on behavior patterns"""
        # Default reputation
        reputation = "unknown"
        
        # Count total scans
        total_scans = sum(scan_types.values())
        
        # Check if this is likely a security tool
        security_tool_keywords = ["nmap", "masscan", "zmap", "scanner"]
        is_security_tool = any(keyword in likely_tool.lower() for keyword in security_tool_keywords)
        
        # Determine scan frequency and volume
        high_volume = False
        frequent_scanning = False
        
        if len(scan_history) > 5:
            # Calculate scan frequency
            timestamps = [entry[0] for entry in scan_history]
            timestamps.sort()
            
            if len(timestamps) > 1:
                time_span = timestamps[-1] - timestamps[0]
                scan_frequency = len(timestamps) / (time_span / 86400)  # Scans per day
                
                if scan_frequency > 10:
                    frequent_scanning = True
            
            # Calculate scan volume
            total_targets = sum(entry[1] for entry in scan_history)
            if total_targets > 1000:
                high_volume = True
        
        # Determine reputation category
        if is_security_tool and sophistication > 7 and stealth_score > 0.7:
            reputation = "professional_security"
        elif is_security_tool and sophistication > 5:
            reputation = "security_tool_user"
        elif high_volume and frequent_scanning and noise_level > 7:
            reputation = "aggressive_scanner"
        elif sophistication > 8 and stealth_score > 0.8:
            reputation = "advanced_threat_actor"
        elif noise_level < 3 and sophistication > 6:
            reputation = "stealthy_reconnaissance"
        elif noise_level > 8:
            reputation = "noisy_scanner"
        elif total_scans < 3:
            reputation = "new_scanner"
        
        return reputation
    
    def run_periodic_analysis(self):
        """Run periodic analysis on port scan data"""
        try:
            # Clean up old data
            current_time = time.time()
            cutoff_time = current_time - self.time_window
            
            # Remove old timestamps
            for src_ip in list(self.scan_cache['connection_times'].keys()):
                self.scan_cache['connection_times'][src_ip] = [t for t in self.scan_cache['connection_times'][src_ip] 
                                                              if t > cutoff_time]
                if not self.scan_cache['connection_times'][src_ip]:
                    del self.scan_cache['connection_times'][src_ip]
            
            # Analyze scanning trends
            self._analyze_scanning_trends()
            
            # Analyze target vulnerability patterns
            self._analyze_target_vulnerabilities()
            
            # Analyze scanner behaviors and correlate scanners
            self._analyze_scanner_behaviors()
            
            return True
        except Exception as e:
            logger.error(f"Error in port scan periodic analysis: {e}")
            return False
    
    def _analyze_scanning_trends(self):
        """Analyze port scanning trends and patterns"""
        try:
            cursor = self.analysis_manager.get_cursor()
            current_time = time.time()
            
            # Look at scans in the last 24 hours
            one_day_ago = current_time - 86400
            
            # Get scan counts by type
            cursor.execute("""
                SELECT scan_type, COUNT(*) 
                FROM x_port_scan_events 
                WHERE start_time > ?
                GROUP BY scan_type
            """, (one_day_ago,))
            
            scan_stats = cursor.fetchall()
            
            if scan_stats:
                stats_msg = "Port scan statistics for last 24 hours: "
                stats_parts = []
                for scan_type, count in scan_stats:
                    stats_parts.append(f"{scan_type}: {count}")
                
                logger.info(stats_msg + ", ".join(stats_parts))
            
            # Get most sophisticated scanners
            cursor.execute("""
                SELECT scanner_ip, sophistication_level, source_reputation, total_scans
                FROM x_port_scanner_profiles
                WHERE last_seen > ?
                ORDER BY sophistication_level DESC
                LIMIT 5
            """, (one_day_ago,))
            
            sophisticated_scanners = cursor.fetchall()
            
            if sophisticated_scanners:
                logger.info("Most sophisticated scanners in the last 24 hours:")
                for ip, sophistication, reputation, scans in sophisticated_scanners:
                    logger.info(f"  {ip}: sophistication={sophistication:.1f}/10, reputation={reputation}, scans={scans}")
            
            cursor.close()
        except Exception as e:
            logger.error(f"Error analyzing scanning trends: {e}")
    
    def _analyze_target_vulnerabilities(self):
        """Analyze target vulnerability patterns"""
        try:
            cursor = self.analysis_manager.get_cursor()
            current_time = time.time()
            
            # Look at vulnerable targets in the last 24 hours
            one_day_ago = current_time - 86400
            
            # Get most vulnerable targets
            cursor.execute("""
                SELECT target_ip, vulnerability_score, exposure_profile, scan_count, scanner_count
                FROM x_port_scan_targets
                WHERE last_scanned > ? AND vulnerability_score > 5
                ORDER BY vulnerability_score DESC
                LIMIT 10
            """, (one_day_ago,))
            
            vulnerable_targets = cursor.fetchall()
            
            if vulnerable_targets:
                logger.info("Most vulnerable targets in the last 24 hours:")
                for ip, score, profile, scans, scanners in vulnerable_targets:
                    logger.info(f"  {ip}: vulnerability={score:.1f}/10, profile={profile}, scans={scans}, unique scanners={scanners}")
            
            cursor.close()
        except Exception as e:
            logger.error(f"Error analyzing target vulnerabilities: {e}")
    
    def _analyze_scanner_behaviors(self):
        """Analyze scanner behaviors and correlate scanners"""
        try:
            cursor = self.analysis_manager.get_cursor()
            current_time = time.time()
            
            # Look at scanner behaviors in the last 24 hours
            one_day_ago = current_time - 86400
            
            # Get scanner profiles
            cursor.execute("""
                SELECT scanner_ip, preferred_scan_types, usual_ports, source_reputation
                FROM x_port_scanner_profiles
                WHERE last_seen > ?
                ORDER BY total_scans DESC
                LIMIT 20
            """, (one_day_ago,))
            
            scanner_profiles = cursor.fetchall()
            
            if not scanner_profiles:
                return
            
            # Group scanners by similar behavior
            scanner_groups = defaultdict(list)
            
            for ip, scan_types_json, usual_ports_json, reputation in scanner_profiles:
                scan_types = json.loads(scan_types_json) if scan_types_json else {}
                usual_ports = json.loads(usual_ports_json) if usual_ports_json else []
                
                # Create a fingerprint of scanner behavior
                fingerprint = f"{reputation}:{sorted(scan_types.keys())}:{sorted(usual_ports[:20])}"
                scanner_groups[fingerprint].append(ip)
            
            # Report on scanner groups
            for fingerprint, scanners in scanner_groups.items():
                if len(scanners) > 1:
                    logger.info(f"Found {len(scanners)} scanners with similar behavior pattern:")
                    logger.info(f"  IPs: {', '.join(scanners[:5])}" + (f" and {len(scanners)-5} more" if len(scanners) > 5 else ""))
                    
                    # Extract behavior pattern from fingerprint
                    pattern_parts = fingerprint.split(':')
                    if len(pattern_parts) >= 3:
                        reputation = pattern_parts[0]
                        logger.info(f"  Reputation: {reputation}")
            
            cursor.close()
        except Exception as e:
            logger.error(f"Error analyzing scanner behaviors: {e}")
    
    def cleanup(self):
        """Clean up resources"""
        for cache in self.scan_cache.values():
            if isinstance(cache, dict):
                cache.clear()