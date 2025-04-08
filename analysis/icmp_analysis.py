# icmp_analysis.py - Analyzes ICMP traffic for suspicious activity
import time
import logging

logger = logging.getLogger('icmp_analysis')

class ICMPAnalyzer(AnalysisBase):
    """Analyzes ICMP traffic for potential flooding and tunneling activity"""
    
    def __init__(self):
        super().__init__(
            name="ICMP Traffic Analysis",
            description="Detects ICMP floods and potential ICMP tunneling"
        )
        self.flood_threshold = 10  # packets in 10 seconds
        self.flood_time_window = 10  # seconds
        self.tunnel_size_threshold = 1000  # bytes for potential tunneling
    
    def initialize(self):
        # Create or update required tables
        cursor = self.analysis_manager.get_cursor()
        try:
            # ICMP analysis results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS icmp_flood_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    packet_count INTEGER,
                    start_time REAL,
                    end_time REAL,
                    event_type TEXT,
                    reported BOOLEAN DEFAULT 0
                )
            """)
            
            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_icmp_flood_src ON icmp_flood_events(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_icmp_flood_time ON icmp_flood_events(start_time)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("ICMP analysis tables initialized")
        except Exception as e:
            logger.error(f"Error initializing ICMP analysis tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process an ICMP packet for analysis"""
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
            
            if not src_ip or not dst_ip:
                return False
                
            # Parse ICMP type
            icmp_type = 0
            if icmp_type_raw is not None:
                try:
                    icmp_type = int(icmp_type_raw)
                except (ValueError, TypeError):
                    pass
            
            # Get packet size
            packet_size = self.analysis_manager._extract_length(layers)
            
            # Check for ICMP floods (a lot of packets in a short time)
            current_time = time.time()
            cursor = self.analysis_manager.get_cursor()
            
            try:
                # Count recent packets between this src/dst pair
                cursor.execute("""
                    SELECT COUNT(*) FROM icmp_packets
                    WHERE src_ip = ? AND dst_ip = ? AND timestamp > ?
                """, (src_ip, dst_ip, current_time - self.flood_time_window))
                
                recent_packet_count = cursor.fetchone()[0]
                
                # Check for ICMP flood
                if recent_packet_count >= self.flood_threshold:
                    # Look for existing ongoing flood event
                    cursor.execute("""
                        SELECT id, packet_count, start_time FROM icmp_flood_events
                        WHERE src_ip = ? AND dst_ip = ? AND end_time > ?
                        ORDER BY end_time DESC LIMIT 1
                    """, (src_ip, dst_ip, current_time - 60))  # Look for events in the last minute
                    
                    flood_event = cursor.fetchone()
                    
                    if flood_event:
                        # Update existing flood event
                        event_id, packet_count, start_time = flood_event
                        cursor.execute("""
                            UPDATE icmp_flood_events
                            SET packet_count = packet_count + 1,
                                end_time = ?
                            WHERE id = ?
                        """, (current_time, event_id))
                    else:
                        # Create new flood event
                        event_type = "flood"
                        if packet_size > self.tunnel_size_threshold:
                            event_type = "potential_tunnel"
                            
                        cursor.execute("""
                            INSERT INTO icmp_flood_events
                            (src_ip, dst_ip, packet_count, start_time, end_time, event_type)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """, (src_ip, dst_ip, recent_packet_count, current_time - self.flood_time_window, current_time, event_type))
                        
                        # Generate alert for new flood
                        alert_message = f"ICMP flood detected from {src_ip} to {dst_ip}: {recent_packet_count} packets in {self.flood_time_window} seconds"
                        self.analysis_manager.add_alert(src_ip, alert_message, "ICMP_Flood_Detector")
                
                # Check for potential ICMP tunneling (large packet size)
                if packet_size > self.tunnel_size_threshold:
                    # Look for existing tunneling alert to avoid duplicates
                    cursor.execute("""
                        SELECT COUNT(*) FROM alerts
                        WHERE ip_address = ? AND alert_message LIKE ? AND timestamp > ?
                    """, (src_ip, f"%ICMP tunneling from {src_ip} to {dst_ip}%", current_time - 3600))
                    
                    if cursor.fetchone()[0] == 0:
                        # No recent alert, create a new one
                        alert_message = f"Potential ICMP tunneling from {src_ip} to {dst_ip}: unusual packet size ({packet_size} bytes)"
                        self.analysis_manager.add_alert(src_ip, alert_message, "ICMP_Tunnel_Detector")
                
                self.analysis_manager.analysis1_conn.commit()
            finally:
                cursor.close()
            
            return True
        except Exception as e:
            logger.error(f"Error analyzing ICMP packet: {e}")
            return False
    
    def run_periodic_analysis(self):
        """Run periodic analysis on ICMP data"""
        try:
            cursor = self.analysis_manager.get_cursor()
            current_time = time.time()
            
            # Find unreported flood events
            cursor.execute("""
                SELECT id, src_ip, dst_ip, packet_count, start_time, end_time, event_type
                FROM icmp_flood_events
                WHERE reported = 0 AND end_time < ?
                ORDER BY packet_count DESC
                LIMIT 20
            """, (current_time - 60,))  # Only report events that ended at least a minute ago
            
            events = cursor.fetchall()
            
            for event in events:
                event_id, src_ip, dst_ip, packet_count, start_time, end_time, event_type = event
                
                # Mark as reported
                cursor.execute("UPDATE icmp_flood_events SET reported = 1 WHERE id = ?", (event_id,))
                
                # Log summary of the event
                duration = end_time - start_time
                packet_rate = packet_count / duration if duration > 0 else 0
                
                logger.info(f"ICMP {event_type} summary: {src_ip} -> {dst_ip}, {packet_count} packets over {duration:.1f}s ({packet_rate:.1f} packets/s)")
            
            self.analysis_manager.analysis1_conn.commit()
            cursor.close()
            
            return bool(events)  # Return True if we processed any events
        except Exception as e:
            logger.error(f"Error in ICMP periodic analysis: {e}")
            return False