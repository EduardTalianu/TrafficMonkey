# port_scan_analysis.py - Detects various types of port scanning activity
import time
import logging
from collections import defaultdict

logger = logging.getLogger('port_scan_analysis')

class PortScanAnalyzer(AnalysisBase):
    """Detects various types of port scanning activity"""
    
    def __init__(self):
        super().__init__(
            name="Port Scan Detector",
            description="Detects port scanning and network reconnaissance"
        )
        self.scan_thresholds = {
            'horizontal': 15,   # Number of different ports to same host
            'vertical': 20,     # Number of different hosts on same port
            'block': 50,        # Number of connections to detect a block scan
            'rate': 10          # Connections per second to consider a fast scan
        }
        
        self.time_window = 60  # Seconds for scan detection window
        self.scan_cache = {
            'src_to_dst_ports': defaultdict(set),     # {src_ip -> dst_ip: {ports}}
            'src_to_dst_ips': defaultdict(set),       # {src_ip -> port: {dst_ips}}
            'connection_times': defaultdict(list),    # {src_ip: [timestamps]}
            'last_alert_time': defaultdict(float)     # {src_ip: last_alert_time}
        }
        
        self.alert_cooldown = 300  # 5 minutes between alerts for same source
    
    def initialize(self):
        # Create or update required tables
        cursor = self.analysis_manager.get_cursor()
        try:
            # Port scan events table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS port_scan_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    scan_type TEXT,
                    target_count INTEGER,
                    port_count INTEGER,
                    start_time REAL,
                    end_time REAL,
                    rate REAL,
                    alert_generated BOOLEAN DEFAULT 1
                )
            """)
            
            # Create index
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_portscan_src ON port_scan_events(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_portscan_time ON port_scan_events(start_time)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("Port scan analysis tables initialized")
        except Exception as e:
            logger.error(f"Error initializing port scan analysis tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process a packet for port scan detection"""
        # Get the layers
        layers = packet_data.get("layers", {})
        if not layers:
            return False
        
        try:
            # We need IP addresses and at least one port
            src_ip = self.analysis_manager._get_layer_value(layers, "ip_src") or self.analysis_manager._get_layer_value(layers, "ipv6_src")
            dst_ip = self.analysis_manager._get_layer_value(layers, "ip_dst") or self.analysis_manager._get_layer_value(layers, "ipv6_dst")
            
            src_port, dst_port = self.analysis_manager._extract_ports(layers)
            
            if not src_ip or not dst_ip or not dst_port:
                return False  # Need these fields for port scan detection
            
            current_time = time.time()
            
            # Update scan detection data structures
            
            # 1. Track src->dst:port combinations for horizontal scan detection
            key = f"{src_ip}->{dst_ip}"
            self.scan_cache['src_to_dst_ports'][key].add(dst_port)
            
            # 2. Track src->port:dst combinations for vertical scan detection
            key = f"{src_ip}->{dst_port}"
            self.scan_cache['src_to_dst_ips'][key].add(dst_ip)
            
            # 3. Track connection timestamps for rate detection
            self.scan_cache['connection_times'][src_ip].append(current_time)
            
            # Cleanup old timestamps
            self.scan_cache['connection_times'][src_ip] = [t for t in self.scan_cache['connection_times'][src_ip] 
                                                          if t > current_time - self.time_window]
            
            # Run scan detection
            self._detect_horizontal_scan(src_ip, dst_ip, current_time)
            self._detect_vertical_scan(src_ip, dst_port, current_time)
            self._detect_block_scan(src_ip, current_time)
            self._detect_fast_scan(src_ip, current_time)
            
            return True
        except Exception as e:
            logger.error(f"Error in port scan detection: {e}")
            return False
    
    def _detect_horizontal_scan(self, src_ip, dst_ip, current_time):
        """Detect horizontal port scan (many ports on one host)"""
        key = f"{src_ip}->{dst_ip}"
        if key in self.scan_cache['src_to_dst_ports']:
            port_count = len(self.scan_cache['src_to_dst_ports'][key])
            
            # Check if we've reached the threshold
            if port_count >= self.scan_thresholds['horizontal']:
                # Check cooldown
                if current_time - self.scan_cache['last_alert_time'].get(src_ip, 0) > self.alert_cooldown:
                    # Record the scan
                    self._record_scan_event(src_ip, 'horizontal', 1, port_count, current_time)
                    
                    # Generate alert
                    alert_message = f"Horizontal port scan detected from {src_ip} to {dst_ip}: {port_count} ports scanned"
                    self.analysis_manager.add_alert(src_ip, alert_message, "Port_Scan_Detector")
                    
                    # Update cooldown
                    self.scan_cache['last_alert_time'][src_ip] = current_time
                    
                    # Clear the cache for this scan
                    del self.scan_cache['src_to_dst_ports'][key]
    
    def _detect_vertical_scan(self, src_ip, dst_port, current_time):
        """Detect vertical port scan (one port on many hosts)"""
        key = f"{src_ip}->{dst_port}"
        if key in self.scan_cache['src_to_dst_ips']:
            target_count = len(self.scan_cache['src_to_dst_ips'][key])
            
            # Check if we've reached the threshold
            if target_count >= self.scan_thresholds['vertical']:
                # Check cooldown
                if current_time - self.scan_cache['last_alert_time'].get(src_ip, 0) > self.alert_cooldown:
                    # Record the scan
                    self._record_scan_event(src_ip, 'vertical', target_count, 1, current_time)
                    
                    # Generate alert
                    alert_message = f"Vertical port scan detected from {src_ip} to port {dst_port}: {target_count} hosts scanned"
                    self.analysis_manager.add_alert(src_ip, alert_message, "Port_Scan_Detector")
                    
                    # Update cooldown
                    self.scan_cache['last_alert_time'][src_ip] = current_time
                    
                    # Clear the cache for this scan
                    del self.scan_cache['src_to_dst_ips'][key]
    
    def _detect_block_scan(self, src_ip, current_time):
        """Detect block scan (many hosts, many ports)"""
        # Count unique destination IPs across all port scans
        dst_ips = set()
        for key in self.scan_cache['src_to_dst_ports']:
            if key.startswith(f"{src_ip}->"):
                dst_ip = key.split('->')[1]
                dst_ips.add(dst_ip)
        
        # If scanning multiple hosts with multiple ports, it's a block scan
        if len(dst_ips) >= 5:  # Arbitrary threshold for multiple hosts
            # Count total unique ports across all destinations
            total_ports = set()
            for key in self.scan_cache['src_to_dst_ports']:
                if key.startswith(f"{src_ip}->"):
                    total_ports.update(self.scan_cache['src_to_dst_ports'][key])
            
            if len(total_ports) >= self.scan_thresholds['block'] and len(dst_ips) >= 5:
                # Check cooldown
                if current_time - self.scan_cache['last_alert_time'].get(src_ip, 0) > self.alert_cooldown:
                    # Record the scan
                    self._record_scan_event(src_ip, 'block', len(dst_ips), len(total_ports), current_time)
                    
                    # Generate alert
                    alert_message = f"Block scan detected from {src_ip}: {len(dst_ips)} hosts and {len(total_ports)} ports scanned"
                    self.analysis_manager.add_alert(src_ip, alert_message, "Port_Scan_Detector")
                    
                    # Update cooldown
                    self.scan_cache['last_alert_time'][src_ip] = current_time
                    
                    # Clear all caches for this source
                    for key in list(self.scan_cache['src_to_dst_ports'].keys()):
                        if key.startswith(f"{src_ip}->"):
                            del self.scan_cache['src_to_dst_ports'][key]
                    
                    for key in list(self.scan_cache['src_to_dst_ips'].keys()):
                        if key.startswith(f"{src_ip}->"):
                            del self.scan_cache['src_to_dst_ips'][key]
    
    def _detect_fast_scan(self, src_ip, current_time):
        """Detect fast scanning based on connection rate"""
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
                        # Check cooldown
                        if current_time - self.scan_cache['last_alert_time'].get(src_ip, 0) > self.alert_cooldown:
                            # Count unique destinations
                            dst_ips = set()
                            dst_ports = set()
                            
                            for key in self.scan_cache['src_to_dst_ports']:
                                if key.startswith(f"{src_ip}->"):
                                    dst_ip = key.split('->')[1]
                                    dst_ips.add(dst_ip)
                                    dst_ports.update(self.scan_cache['src_to_dst_ports'][key])
                            
                            # Record the scan
                            self._record_scan_event(src_ip, 'fast', len(dst_ips), len(dst_ports), current_time, rate)
                            
                            # Generate alert
                            alert_message = f"Fast scan detected from {src_ip}: {rate:.1f} connections/second to {len(dst_ips)} hosts"
                            self.analysis_manager.add_alert(src_ip, alert_message, "Port_Scan_Detector")
                            
                            # Update cooldown
                            self.scan_cache['last_alert_time'][src_ip] = current_time
    
    def _record_scan_event(self, src_ip, scan_type, target_count, port_count, current_time, rate=0):
        """Record a scan event in the database"""
        try:
            cursor = self.analysis_manager.get_cursor()
            cursor.execute("""
                INSERT INTO port_scan_events
                (src_ip, scan_type, target_count, port_count, start_time, end_time, rate)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                src_ip,
                scan_type,
                target_count,
                port_count,
                current_time - self.time_window,
                current_time,
                rate
            ))
            
            self.analysis_manager.analysis1_conn.commit()
            cursor.close()
            
            logger.info(f"Recorded {scan_type} scan from {src_ip}: {target_count} targets, {port_count} ports")
        except Exception as e:
            logger.error(f"Error recording scan event: {e}")
    
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
            
            # Get statistics on recent scans
            cursor = self.analysis_manager.get_cursor()
            
            # Get recent scan counts by type
            cursor.execute("""
                SELECT scan_type, COUNT(*) 
                FROM port_scan_events 
                WHERE start_time > ?
                GROUP BY scan_type
            """, (current_time - 86400,))  # Last 24 hours
            
            scan_stats = cursor.fetchall()
            
            if scan_stats:
                stats_msg = "Port scan statistics for last 24 hours: "
                stats_parts = []
                for scan_type, count in scan_stats:
                    stats_parts.append(f"{scan_type}: {count}")
                
                logger.info(stats_msg + ", ".join(stats_parts))
            
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error in port scan periodic analysis: {e}")
            return False
            
    def cleanup(self):
        """Clean up resources"""
        for cache in self.scan_cache.values():
            if isinstance(cache, dict):
                cache.clear()