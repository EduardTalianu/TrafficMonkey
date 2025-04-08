# arp_analysis.py - Analyzes ARP traffic for suspicious activity
import time
import logging
from collections import defaultdict

logger = logging.getLogger('arp_analysis')

class ARPAnalyzer(AnalysisBase):
    """Analyzes ARP traffic for potential ARP spoofing and poisoning attacks"""
    
    def __init__(self):
        super().__init__(
            name="ARP Traffic Analysis",
            description="Detects ARP spoofing and poisoning attacks"
        )
        self.arp_cache = defaultdict(dict)  # {ip_address: {mac_address: timestamp}}
        self.ip_mac_mappings = {}  # {ip_address: mac_address}
        self.clean_interval = 3600  # 1 hour
        self.last_clean_time = time.time()
    
    def initialize(self):
        # Create or update required tables
        cursor = self.analysis_manager.get_cursor()
        try:
            # ARP analysis results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS arp_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    mac_address TEXT,
                    original_mac TEXT,
                    detection_time REAL,
                    alert_generated BOOLEAN DEFAULT 0,
                    resolved BOOLEAN DEFAULT 0,
                    notes TEXT
                )
            """)
            
            # Create index
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_analysis_ip ON arp_analysis(ip_address)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("ARP analysis tables initialized")
        except Exception as e:
            logger.error(f"Error initializing ARP analysis tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process an ARP packet for analysis"""
        # Get the layers
        layers = packet_data.get("layers", {})
        if not layers:
            return False
        
        # Check if this is an ARP packet
        if not ("arp_src_proto_ipv4" in layers or "arp_dst_proto_ipv4" in layers):
            return False
        
        try:
            # Define current_time at the beginning of the method
            current_time = time.time()
            
            # Extract ARP data
            src_ip = self.analysis_manager._get_layer_value(layers, "arp_src_proto_ipv4")
            dst_ip = self.analysis_manager._get_layer_value(layers, "arp_dst_proto_ipv4")
            
            # Extract MAC addresses if available
            src_mac = self.analysis_manager._get_layer_value(layers, "arp_src_hw_mac")
            dst_mac = self.analysis_manager._get_layer_value(layers, "arp_dst_hw_mac")
            
            # Extract ARP operation (1=request, 2=reply)
            operation_raw = self.analysis_manager._get_layer_value(layers, "arp_opcode")
            operation = 0
            if operation_raw:
                try:
                    operation = int(operation_raw)
                except (ValueError, TypeError):
                    pass
            
            # Focus on ARP replies (operation=2) for spoofing detection
            if operation == 2 and src_ip and src_mac:
                # Update our ARP cache
                if src_ip not in self.arp_cache:
                    # First time seeing this IP
                    self.arp_cache[src_ip][src_mac] = current_time
                    self.ip_mac_mappings[src_ip] = src_mac
                else:
                    # We've seen this IP before
                    if src_mac not in self.arp_cache[src_ip]:
                        # New MAC for this IP - potential spoofing
                        self.arp_cache[src_ip][src_mac] = current_time
                        
                        # Check if this is a change from established mapping
                        if src_ip in self.ip_mac_mappings and self.ip_mac_mappings[src_ip] != src_mac:
                            # Detect a potential ARP spoofing attack
                            original_mac = self.ip_mac_mappings[src_ip]
                            cursor = self.analysis_manager.get_cursor()
                            
                            try:
                                # Check if we've already recorded this spoofing attempt
                                cursor.execute("""
                                    SELECT id FROM arp_analysis
                                    WHERE ip_address = ? AND mac_address = ? AND resolved = 0
                                """, (src_ip, src_mac))
                                
                                if not cursor.fetchone():
                                    # Record the spoofing attempt
                                    cursor.execute("""
                                        INSERT INTO arp_analysis
                                        (ip_address, mac_address, original_mac, detection_time, notes)
                                        VALUES (?, ?, ?, ?, ?)
                                    """, (
                                        src_ip,
                                        src_mac,
                                        original_mac,
                                        current_time,
                                        f"Potential ARP spoofing: IP {src_ip} changed from MAC {original_mac} to {src_mac}"
                                    ))
                                    
                                    # Generate an alert
                                    alert_message = f"Potential ARP spoofing detected: IP {src_ip} changed from MAC {original_mac} to {src_mac}"
                                    self.analysis_manager.add_alert(src_ip, alert_message, "ARP_Spoofing_Detector")
                                    
                                    # Mark alert as generated
                                    cursor.execute("""
                                        UPDATE arp_analysis
                                        SET alert_generated = 1
                                        WHERE ip_address = ? AND mac_address = ? AND resolved = 0
                                    """, (src_ip, src_mac))
                                    
                                    self.analysis_manager.analysis1_conn.commit()
                                    
                                    logger.warning(alert_message)
                            finally:
                                cursor.close()
                    else:
                        # Update timestamp for existing MAC
                        self.arp_cache[src_ip][src_mac] = current_time
            
            # Clean up old entries periodically
            if current_time - self.last_clean_time > self.clean_interval:
                self._clean_old_entries()
                self.last_clean_time = current_time
            
            return True
        except Exception as e:
            logger.error(f"Error analyzing ARP packet: {e}")
            return False
    
    def _clean_old_entries(self):
        """Remove old entries from the ARP cache"""
        current_time = time.time()
        expiration_time = current_time - self.clean_interval
        
        # Clean up expired entries
        for ip in list(self.arp_cache.keys()):
            for mac in list(self.arp_cache[ip].keys()):
                if self.arp_cache[ip][mac] < expiration_time:
                    del self.arp_cache[ip][mac]
            
            # If no more MAC entries for this IP, remove the IP entry
            if not self.arp_cache[ip]:
                del self.arp_cache[ip]
                if ip in self.ip_mac_mappings:
                    del self.ip_mac_mappings[ip]
    
    def run_periodic_analysis(self):
        """Run periodic analysis on ARP data"""
        try:
            cursor = self.analysis_manager.get_cursor()
            
            # Check for unresolved ARP spoofing incidents
            cursor.execute("""
                SELECT ip_address, mac_address, original_mac, detection_time
                FROM arp_analysis
                WHERE resolved = 0
                ORDER BY detection_time DESC
            """)
            
            unresolved_incidents = cursor.fetchall()
            
            if unresolved_incidents:
                logger.info(f"Found {len(unresolved_incidents)} unresolved ARP spoofing incidents:")
                for incident in unresolved_incidents:
                    ip, mac, original_mac, detection_time = incident
                    logger.info(f"  - IP: {ip}, Changed: {original_mac} -> {mac}, Detected: {time.ctime(detection_time)}")
            
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error in ARP periodic analysis: {e}")
            return False
    
    def cleanup(self):
        """Clean up resources"""
        self.arp_cache.clear()
        self.ip_mac_mappings.clear()