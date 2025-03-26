# Rule class is injected by the RuleLoader
import logging
import statistics
import time
from collections import defaultdict

class InteractiveSessionRule(Rule):
    """Rule that detects interactive terminal sessions based on traffic patterns"""
    def __init__(self):
        super().__init__(
            name="Interactive Session Detection",
            description="Detects likely interactive command line sessions by analyzing traffic timing and size patterns"
        )
        self.check_interval = 300  # Seconds between checks (5 minutes)
        self.last_check_time = 0
        self.session_ports = [22, 23, 3389, 5900, 5901]  # SSH, Telnet, RDP, VNC
        self.min_packets = 10  # Minimum packets to analyze
        self.max_bytes_per_packet = 1000  # Maximum bytes per packet for interactive traffic
        self.keyboard_interval_min = 0.2  # Minimum interval for keystrokes (seconds)
        self.keyboard_interval_max = 10  # Maximum interval for keystrokes (seconds)
        self.traffic_asymmetry_threshold = 5.0  # Asymmetry ratio for command input vs output
        self.detected_sessions = {}  # Track detected sessions
    
    def is_interactive_traffic_pattern(self, packet_sizes, packet_times):
        """Analyze if traffic pattern resembles human typing and command responses"""
        if len(packet_sizes) < self.min_packets:
            return False, "insufficient packets"
            
        # Calculate intervals between packets
        intervals = [packet_times[i+1] - packet_times[i] for i in range(len(packet_times)-1)]
        
        # Skip if all packets arrived at once (bulk transfer)
        if all(i < 0.01 for i in intervals):
            return False, "bulk transfer"
            
        # Check for mixed short and long intervals (human typing pattern)
        intervals_in_range = [i for i in intervals if self.keyboard_interval_min <= i <= self.keyboard_interval_max]
        if len(intervals_in_range) < len(intervals) * 0.5:
            return False, "irregular timing"
            
        # Check for small packets (typical for keystrokes/commands)
        small_packets = [size for size in packet_sizes if size <= self.max_bytes_per_packet]
        if len(small_packets) < len(packet_sizes) * 0.5:
            return False, "packets too large"
            
        # Check for variance in packet sizes (commands vs responses)
        if len(packet_sizes) > 5:
            try:
                size_variance = statistics.variance(packet_sizes)
                if size_variance < 100:  # Very little variance means not interactive
                    return False, "low packet size variance"
            except statistics.StatisticsError:
                pass
        
        return True, "interactive pattern detected"
    
    def analyze(self, db_cursor):
        alerts = []
        current_time = time.time()
        
        # Only run this rule periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # This rule works best with a dedicated packet capture table, but we'll use the connections
            # table as a fallback with timing approximation
            
            # First, check for connections to known interactive session ports
            session_ports_str = ','.join(str(p) for p in self.session_ports)
            db_cursor.execute(f"""
                SELECT src_ip, dst_ip, dst_port, connection_key
                FROM connections
                WHERE dst_port IN ({session_ports_str})
                AND timestamp > datetime('now', '-30 minutes')
                GROUP BY src_ip, dst_ip, dst_port
            """)
            
            connections = []
            for row in db_cursor.fetchall():
                connections.append(row)
                
            for src_ip, dst_ip, dst_port, connection_key in connections:
                session_id = f"{src_ip}->{dst_ip}:{dst_port}"
                
                # Skip if we've already detected this session
                if session_id in self.detected_sessions:
                    continue
                    
                # Try to get packet data if available
                packet_data_available = False
                
                try:
                    # Check if there's a packet_data table - this is for advanced implementations
                    # that might capture individual packets
                    db_cursor.execute("""
                        SELECT name FROM sqlite_master 
                        WHERE type='table' AND name='packet_data'
                    """)
                    
                    if db_cursor.fetchone():
                        packet_data_available = True
                except:
                    pass
                    
                # If we have packet-level data, analyze it
                if packet_data_available:
                    db_cursor.execute("""
                        SELECT timestamp, packet_size, direction
                        FROM packet_data
                        WHERE connection_key = ?
                        ORDER BY timestamp
                    """, (connection_key,))
                    
                    packets = db_cursor.fetchall()
                    
                    if len(packets) >= self.min_packets:
                        packet_times = [p[0] for p in packets]
                        packet_sizes = [p[1] for p in packets]
                        directions = [p[2] for p in packets]
                        
                        interactive, reason = self.is_interactive_traffic_pattern(packet_sizes, packet_times)
                        
                        if interactive:
                            # Calculate traffic asymmetry (interactive sessions typically have small inputs, large outputs)
                            inbound = sum(packet_sizes[i] for i, d in enumerate(directions) if d == 'in')
                            outbound = sum(packet_sizes[i] for i, d in enumerate(directions) if d == 'out')
                            
                            # Prevent division by zero
                            inbound = max(inbound, 1)
                            outbound = max(outbound, 1)
                            
                            ratio = max(inbound / outbound, outbound / inbound)
                            
                            self.detected_sessions[session_id] = current_time
                            alerts.append(f"Interactive session detected: {src_ip} to {dst_ip}:{dst_port} ({packet_times[-1] - packet_times[0]:.1f} sec duration, traffic ratio: {ratio:.1f}x)")
                
                # Fallback method using just connection data
                else:
                    # For this fallback, we'll use multiple small connections to the same destination
                    # as an indicator of interactive behavior
                    db_cursor.execute("""
                        SELECT total_bytes, packet_count, timestamp
                        FROM connections
                        WHERE src_ip = ? AND dst_ip = ? AND dst_port = ?
                        AND timestamp > datetime('now', '-30 minutes')
                        ORDER BY timestamp
                    """, (src_ip, dst_ip, dst_port))
                    
                    transactions = db_cursor.fetchall()
                    
                    if len(transactions) >= 5:  # Need several transactions to detect pattern
                        # Look for small packet sizes
                        bytes_per_packet = [t[0]/max(t[1], 1) for t in transactions]
                        times = [t[2] for t in transactions]
                        
                        # Check if most transactions have small packets
                        small_packet_txns = [bpp for bpp in bytes_per_packet if bpp <= self.max_bytes_per_packet]
                        
                        if len(small_packet_txns) >= len(bytes_per_packet) * 0.7:
                            # Convert timestamps to epoch time
                            epoch_times = []
                            for t in times:
                                if isinstance(t, str):
                                    # Try to convert string timestamp to float
                                    try:
                                        import datetime
                                        dt = datetime.datetime.strptime(t, '%Y-%m-%d %H:%M:%S')
                                        epoch_times.append(dt.timestamp())
                                    except:
                                        epoch_times.append(0)
                                else:
                                    epoch_times.append(float(t))
                            
                            # Calculate intervals
                            if len(epoch_times) > 1:
                                intervals = [epoch_times[i+1] - epoch_times[i] for i in range(len(epoch_times)-1)]
                                
                                # Check for human-like typing intervals
                                human_intervals = [i for i in intervals if self.keyboard_interval_min <= i <= self.keyboard_interval_max]
                                
                                if len(human_intervals) >= len(intervals) * 0.5:
                                    self.detected_sessions[session_id] = current_time
                                    alerts.append(f"Likely interactive session: {src_ip} to {dst_ip}:{dst_port} ({len(transactions)} transactions with human-like timing)")
                
            # Clean up old detected sessions (after 4 hours)
            old_sessions = [s for s, t in self.detected_sessions.items() if current_time - t > 14400]
            for session in old_sessions:
                self.detected_sessions.pop(session, None)
                
            return alerts
                
        except Exception as e:
            error_msg = f"Error in Interactive Session Detection rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def get_params(self):
        return {
            "check_interval": {
                "type": "int",
                "default": 300,
                "current": self.check_interval,
                "description": "Seconds between rule checks"
            },
            "max_bytes_per_packet": {
                "type": "int",
                "default": 1000,
                "current": self.max_bytes_per_packet,
                "description": "Maximum bytes per packet for interactive traffic"
            },
            "keyboard_interval_max": {
                "type": "float",
                "default": 10.0,
                "current": self.keyboard_interval_max,
                "description": "Maximum seconds between interactive inputs"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "check_interval":
            self.check_interval = int(value)
            return True
        elif param_name == "max_bytes_per_packet":
            self.max_bytes_per_packet = int(value)
            return True
        elif param_name == "keyboard_interval_max":
            self.keyboard_interval_max = float(value)
            return True
        return False