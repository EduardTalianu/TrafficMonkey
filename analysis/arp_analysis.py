# arp_analysis.py - Enhanced ARP traffic analysis for spoofing detection
import time
import logging
from collections import defaultdict
import json
import math

logger = logging.getLogger('arp_analysis')

class ARPAnalyzer(AnalysisBase):
    """Advanced ARP traffic analyzer with enhanced spoofing and poisoning detection"""
    
    def __init__(self):
        super().__init__(
            name="ARP Traffic Analysis",
            description="Advanced detection of ARP spoofing, poisoning, and network mapping"
        )
        # Enhanced data structures for ARP analysis
        self.arp_cache = defaultdict(dict)  # {ip_address: {mac_address: timestamp}}
        self.ip_mac_mappings = {}  # {ip_address: mac_address}
        self.mac_ip_mappings = defaultdict(set)  # {mac_address: {ip_addresses}}
        self.arp_request_patterns = defaultdict(list)  # {src_ip: [(target_ip, timestamp)]}
        self.mac_vendor_cache = {}  # {mac_prefix: vendor}
        
        # Historical MAC changes to track frequency
        self.mac_change_history = defaultdict(list)  # {ip_address: [(old_mac, new_mac, timestamp)]}
        
        # Gateway monitoring (special focus on default gateway)
        self.gateway_macs = {}  # {gateway_ip: mac_address}
        
        # Maintenance intervals
        self.clean_interval = 3600  # 1 hour
        self.last_clean_time = time.time()
    
    def initialize(self):
        # Create or update required tables
        cursor = self.analysis_manager.get_cursor()
        try:
            # ARP analysis results table with enhanced schema
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS arp_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    mac_address TEXT,
                    original_mac TEXT,
                    detection_time REAL,
                    resolved BOOLEAN DEFAULT 0,
                    notes TEXT,
                    confidence_score REAL DEFAULT 0,
                    change_frequency INTEGER DEFAULT 1,
                    is_gateway BOOLEAN DEFAULT 0,
                    vendor_mismatch BOOLEAN DEFAULT 0,
                    active BOOLEAN DEFAULT 1,
                    attack_type TEXT,
                    affected_hosts TEXT
                )
            """)
            
            # ARP host tracking table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS arp_host_tracking (
                    ip_address TEXT PRIMARY KEY,
                    primary_mac TEXT,
                    all_observed_macs TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    stability_score REAL DEFAULT 1.0,
                    request_count INTEGER DEFAULT 0,
                    response_count INTEGER DEFAULT 0,
                    is_gateway BOOLEAN DEFAULT 0,
                    vendor TEXT,
                    host_type TEXT,
                    known_spoofed BOOLEAN DEFAULT 0
                )
            """)
            
            # ARP activities and behavioral patterns
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS arp_behavior_patterns (
                    mac_address TEXT PRIMARY KEY,
                    first_seen REAL,
                    last_seen REAL,
                    request_pattern TEXT,
                    ip_count INTEGER DEFAULT 1,
                    associated_ips TEXT,
                    gratuitous_count INTEGER DEFAULT 0,
                    behavioral_score REAL DEFAULT 0,
                    vendor TEXT,
                    mac_oui TEXT,
                    behavior_type TEXT,
                    is_anomalous BOOLEAN DEFAULT 0
                )
            """)
            
            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_analysis_ip ON arp_analysis(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_analysis_mac ON arp_analysis(mac_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_analysis_time ON arp_analysis(detection_time)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_analysis_active ON arp_analysis(active)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_host_ip ON arp_host_tracking(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_host_mac ON arp_host_tracking(primary_mac)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_host_gateway ON arp_host_tracking(is_gateway)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_behavior_mac ON arp_behavior_patterns(mac_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_behavior_score ON arp_behavior_patterns(behavioral_score)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_behavior_anomaly ON arp_behavior_patterns(is_anomalous)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("ARP analysis tables initialized with enhanced schema")
        except Exception as e:
            logger.error(f"Error initializing ARP analysis tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process an ARP packet for advanced analysis"""
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
            
            # Process based on ARP operation type
            if operation == 1:  # ARP Request
                self._process_arp_request(src_ip, dst_ip, src_mac, dst_mac, current_time)
            elif operation == 2:  # ARP Reply
                self._process_arp_reply(src_ip, dst_ip, src_mac, dst_mac, current_time)
            
            # Check for ARP spoofing indicators
            if src_ip and src_mac:
                self._check_for_spoofing(src_ip, src_mac, operation, current_time)
            
            # Update MAC-vendor cache if needed
            if src_mac and src_mac not in self.mac_vendor_cache:
                self._update_mac_vendor(src_mac)
            
            # Update behavior patterns
            if src_mac:
                self._update_behavior_pattern(src_mac, src_ip, dst_ip, operation, current_time)
            
            # Clean up old entries periodically
            if current_time - self.last_clean_time > self.clean_interval:
                self._clean_old_entries(current_time)
                self.last_clean_time = current_time
            
            return True
        except Exception as e:
            logger.error(f"Error analyzing ARP packet: {e}")
            return False
    
    def _process_arp_request(self, src_ip, dst_ip, src_mac, dst_mac, current_time):
        """Process ARP request for reconnaissance and mapping detection"""
        if not src_ip or not src_mac:
            return
            
        # Track ARP request pattern for this source
        if dst_ip:
            self.arp_request_patterns[src_ip].append((dst_ip, current_time))
            # Keep cache manageable
            if len(self.arp_request_patterns[src_ip]) > 100:
                self.arp_request_patterns[src_ip] = self.arp_request_patterns[src_ip][-100:]
        
        # Update host tracking
        self._update_host_tracking(src_ip, src_mac, "request", current_time)
        
        # Check for ARP scan (many requests in short time)
        self._check_for_arp_scan(src_ip, current_time)
    
    def _process_arp_reply(self, src_ip, dst_ip, src_mac, dst_mac, current_time):
        """Process ARP reply for spoofing and poisoning detection"""
        if not src_ip or not src_mac:
            return
            
        # Update our ARP cache with this mapping
        if src_ip not in self.arp_cache:
            # First time seeing this IP
            self.arp_cache[src_ip][src_mac] = current_time
            self.ip_mac_mappings[src_ip] = src_mac
            self.mac_ip_mappings[src_mac].add(src_ip)
        else:
            # We've seen this IP before
            if src_mac not in self.arp_cache[src_ip]:
                # New MAC for this IP - potential spoofing
                previous_mac = self.ip_mac_mappings.get(src_ip)
                self.arp_cache[src_ip][src_mac] = current_time
                
                # Record this MAC change
                if previous_mac:
                    self.mac_change_history[src_ip].append((previous_mac, src_mac, current_time))
                    
                    # Update IP->MAC mapping
                    self.ip_mac_mappings[src_ip] = src_mac
                    
                    # Update MAC->IP mapping
                    self.mac_ip_mappings[src_mac].add(src_ip)
            else:
                # Update timestamp for existing MAC
                self.arp_cache[src_ip][src_mac] = current_time
        
        # Check if this is a gateway IP (heuristic)
        is_gateway = False
        if "1" in src_ip.split('.')[-1] or dst_ip and "1" in dst_ip.split('.')[-1]:
            is_gateway = True
            if src_ip not in self.gateway_macs:
                self.gateway_macs[src_ip] = src_mac
        
        # Update host tracking
        self._update_host_tracking(src_ip, src_mac, "reply", current_time, is_gateway)
        
        # Check for gratuitous ARP (src_ip = dst_ip)
        if src_ip == dst_ip:
            self._process_gratuitous_arp(src_ip, src_mac, current_time)
    
    def _check_for_spoofing(self, ip, mac, operation, current_time):
        """Check for potential ARP spoofing activity"""
        # Only check if we have a previous mapping
        if ip in self.ip_mac_mappings and self.ip_mac_mappings[ip] != mac:
            # Detect a potential ARP spoofing attack
            original_mac = self.ip_mac_mappings[ip]
            
            # Get change frequency for this IP
            change_frequency = len(self.mac_change_history.get(ip, []))
            
            # Calculate confidence score
            confidence = self._calculate_spoofing_confidence(ip, mac, original_mac, change_frequency, operation)
            
            # Identify attack type
            attack_type = self._identify_arp_attack_type(ip, mac, operation, change_frequency)
            
            # Get affected hosts
            affected_hosts = self._identify_affected_hosts(ip, mac)
            
            # Check for vendor mismatch
            vendor_mismatch = self._check_vendor_mismatch(original_mac, mac)
            
            # Is this a gateway?
            is_gateway = ip in self.gateway_macs
            
            # Only record if confidence is significant
            if confidence > 0.3:
                cursor = self.analysis_manager.get_cursor()
                
                try:
                    # Check if we've already recorded this spoofing attempt
                    cursor.execute("""
                        SELECT id, confidence_score FROM arp_analysis
                        WHERE ip_address = ? AND mac_address = ? AND original_mac = ? AND resolved = 0
                    """, (ip, mac, original_mac))
                    
                    result = cursor.fetchone()
                    
                    if result:
                        # Update existing record
                        record_id, old_confidence = result
                        # Use the higher confidence score
                        new_confidence = max(confidence, old_confidence)
                        
                        cursor.execute("""
                            UPDATE arp_analysis
                            SET confidence_score = ?,
                                change_frequency = ?,
                                is_gateway = ?,
                                vendor_mismatch = ?,
                                attack_type = ?,
                                affected_hosts = ?
                            WHERE id = ?
                        """, (
                            new_confidence,
                            change_frequency,
                            1 if is_gateway else 0,
                            1 if vendor_mismatch else 0,
                            attack_type,
                            json.dumps(affected_hosts),
                            record_id
                        ))
                    else:
                        # Record the spoofing attempt
                        notes = f"Potential ARP spoofing: IP {ip} changed from MAC {original_mac} to {mac}"
                        
                        cursor.execute("""
                            INSERT INTO arp_analysis
                            (ip_address, mac_address, original_mac, detection_time, notes, 
                             confidence_score, change_frequency, is_gateway, vendor_mismatch,
                             attack_type, affected_hosts)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            ip,
                            mac,
                            original_mac,
                            current_time,
                            notes,
                            confidence,
                            change_frequency,
                            1 if is_gateway else 0,
                            1 if vendor_mismatch else 0,
                            attack_type,
                            json.dumps(affected_hosts)
                        ))
                    
                    self.analysis_manager.analysis1_conn.commit()
                    
                    logger.info(f"Recorded potential ARP spoofing: IP {ip} MAC changed from {original_mac} to {mac}, confidence: {confidence:.2f}")
                finally:
                    cursor.close()
    
    def _update_host_tracking(self, ip, mac, operation_type, current_time, is_gateway=False):
        """Update host tracking information"""
        cursor = self.analysis_manager.get_cursor()
        
        try:
            # Check if host exists
            cursor.execute("""
                SELECT primary_mac, all_observed_macs, request_count, response_count, stability_score
                FROM arp_host_tracking
                WHERE ip_address = ?
            """, (ip,))
            
            result = cursor.fetchone()
            
            if result:
                # Update existing host
                primary_mac, all_macs_json, request_count, response_count, stability_score = result
                
                # Parse JSON data
                all_observed_macs = json.loads(all_macs_json) if all_macs_json else []
                
                # Add new MAC if not already seen
                if mac not in all_observed_macs:
                    all_observed_macs.append(mac)
                
                # Update counts
                if operation_type == "request":
                    request_count += 1
                else:
                    response_count += 1
                
                # Calculate stability score
                if primary_mac != mac:
                    # Decreasing stability due to MAC change
                    stability_score = max(0.1, stability_score - 0.2)
                else:
                    # Increasing stability for consistent MAC
                    stability_score = min(1.0, stability_score + 0.05)
                
                # Determine host type
                host_type = self._determine_host_type(request_count, response_count, is_gateway)
                
                # Get vendor information
                vendor = self.mac_vendor_cache.get(mac[:8], "Unknown")
                
                # Check if this is a known spoofed IP
                cursor.execute("""
                    SELECT COUNT(*) FROM arp_analysis
                    WHERE ip_address = ? AND confidence_score > 0.7 AND resolved = 0
                """, (ip,))
                
                known_spoofed = cursor.fetchone()[0] > 0
                
                cursor.execute("""
                    UPDATE arp_host_tracking
                    SET primary_mac = ?,
                        all_observed_macs = ?,
                        last_seen = ?,
                        stability_score = ?,
                        request_count = ?,
                        response_count = ?,
                        is_gateway = ?,
                        vendor = ?,
                        host_type = ?,
                        known_spoofed = ?
                    WHERE ip_address = ?
                """, (
                    mac,  # Always update to latest MAC
                    json.dumps(all_observed_macs),
                    current_time,
                    stability_score,
                    request_count,
                    response_count,
                    1 if is_gateway else 0,
                    vendor,
                    host_type,
                    1 if known_spoofed else 0,
                    ip
                ))
            else:
                # Create new host entry
                host_type = self._determine_host_type(
                    1 if operation_type == "request" else 0,
                    1 if operation_type == "reply" else 0,
                    is_gateway
                )
                
                vendor = self.mac_vendor_cache.get(mac[:8], "Unknown")
                
                cursor.execute("""
                    INSERT INTO arp_host_tracking
                    (ip_address, primary_mac, all_observed_macs, first_seen, last_seen,
                     request_count, response_count, is_gateway, vendor, host_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip,
                    mac,
                    json.dumps([mac]),
                    current_time,
                    current_time,
                    1 if operation_type == "request" else 0,
                    1 if operation_type == "reply" else 0,
                    1 if is_gateway else 0,
                    vendor,
                    host_type
                ))
            
            self.analysis_manager.analysis1_conn.commit()
        finally:
            cursor.close()
    
    def _update_behavior_pattern(self, mac, src_ip, dst_ip, operation, current_time):
        """Update behavior pattern for this MAC address"""
        cursor = self.analysis_manager.get_cursor()
        
        try:
            # Check if behavior pattern exists
            cursor.execute("""
                SELECT associated_ips, request_pattern, gratuitous_count, behavioral_score
                FROM arp_behavior_patterns
                WHERE mac_address = ?
            """, (mac,))
            
            result = cursor.fetchone()
            
            # Get associated IPs for this MAC
            associated_ips = list(self.mac_ip_mappings.get(mac, {src_ip}))
            
            # Get OUI (first 3 bytes of MAC)
            mac_oui = mac[:8] if len(mac) >= 8 else mac
            
            # Get vendor info
            vendor = self.mac_vendor_cache.get(mac_oui, "Unknown")
            
            # Determine if this is a gratuitous ARP
            is_gratuitous = (operation == 2 and src_ip == dst_ip)
            
            if result:
                # Update existing pattern
                ips_json, request_pattern, gratuitous_count, behavioral_score = result
                
                # Update IP list
                existing_ips = json.loads(ips_json) if ips_json else []
                for ip in associated_ips:
                    if ip not in existing_ips:
                        existing_ips.append(ip)
                
                # Update gratuitous count
                if is_gratuitous:
                    gratuitous_count += 1
                
                # Update request pattern description
                if operation == 1:  # Only update for requests
                    request_pattern = self._analyze_request_pattern(mac)
                
                # Calculate behavioral score
                behavioral_score = self._calculate_behavioral_score(
                    mac, len(existing_ips), gratuitous_count, request_pattern
                )
                
                # Determine behavior type
                behavior_type = self._determine_behavior_type(
                    len(existing_ips), gratuitous_count, behavioral_score
                )
                
                # Determine if behavior is anomalous
                is_anomalous = behavioral_score > 7
                
                cursor.execute("""
                    UPDATE arp_behavior_patterns
                    SET last_seen = ?,
                        associated_ips = ?,
                        ip_count = ?,
                        request_pattern = ?,
                        gratuitous_count = ?,
                        behavioral_score = ?,
                        vendor = ?,
                        mac_oui = ?,
                        behavior_type = ?,
                        is_anomalous = ?
                    WHERE mac_address = ?
                """, (
                    current_time,
                    json.dumps(existing_ips),
                    len(existing_ips),
                    request_pattern,
                    gratuitous_count,
                    behavioral_score,
                    vendor,
                    mac_oui,
                    behavior_type,
                    1 if is_anomalous else 0,
                    mac
                ))
            else:
                # Create new behavior pattern
                request_pattern = "New host"
                behavioral_score = 1 if len(associated_ips) > 1 else 0
                behavior_type = "normal"
                
                if is_gratuitous:
                    gratuitous_count = 1
                    behavioral_score += 1
                    behavior_type = "announcing"
                else:
                    gratuitous_count = 0
                
                cursor.execute("""
                    INSERT INTO arp_behavior_patterns
                    (mac_address, first_seen, last_seen, associated_ips, ip_count,
                     request_pattern, gratuitous_count, behavioral_score, vendor,
                     mac_oui, behavior_type, is_anomalous)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                """, (
                    mac,
                    current_time,
                    current_time,
                    json.dumps(associated_ips),
                    len(associated_ips),
                    request_pattern,
                    gratuitous_count,
                    behavioral_score,
                    vendor,
                    mac_oui,
                    behavior_type
                ))
            
            self.analysis_manager.analysis1_conn.commit()
        finally:
            cursor.close()
    
    def _process_gratuitous_arp(self, ip, mac, current_time):
        """Process gratuitous ARP (announcement)"""
        # Gratuitous ARPs are normal for announcements but can be used in attacks
        # Check frequency of announcements
        announcements = sum(1 for _, m, _ in self.mac_change_history.get(ip, []) if m == mac)
        
        # Frequent gratuitous ARPs may indicate an attack
        if announcements > 5:
            logger.info(f"Frequent gratuitous ARPs from {ip} ({mac}): {announcements} announcements")
    
    def _check_for_arp_scan(self, src_ip, current_time):
        """Check for ARP scanning activity"""
        if src_ip not in self.arp_request_patterns:
            return
            
        # Get recent requests
        recent_requests = [(dst, ts) for dst, ts in self.arp_request_patterns[src_ip]
                          if ts > current_time - 60]  # last 60 seconds
        
        # Count unique targets
        unique_targets = set(dst for dst, _ in recent_requests)
        
        # Detect ARP scan (many targets in a short time)
        if len(unique_targets) > 10:
            # Check for subnet scanning pattern
            subnet_groups = self._group_by_subnet(unique_targets)
            
            if len(subnet_groups) == 1:
                # Single subnet scan
                subnet = list(subnet_groups.keys())[0]
                scan_type = f"ARP scan of subnet {subnet}"
            else:
                # Multi-subnet scan
                scan_type = f"ARP scan of multiple subnets ({len(subnet_groups)})"
            
            logger.info(f"Detected {scan_type} from {src_ip}: {len(unique_targets)} targets in 60 seconds")
    
    def _clean_old_entries(self, current_time):
        """Remove old entries from caches"""
        # Clean ARP cache
        for ip in list(self.arp_cache.keys()):
            for mac in list(self.arp_cache[ip].keys()):
                if current_time - self.arp_cache[ip][mac] > 86400:  # 24 hours
                    del self.arp_cache[ip][mac]
            if not self.arp_cache[ip]:
                del self.arp_cache[ip]
                if ip in self.ip_mac_mappings:
                    del self.ip_mac_mappings[ip]
        
        # Clean MAC IP mappings
        for mac in list(self.mac_ip_mappings.keys()):
            if not self.mac_ip_mappings[mac]:
                del self.mac_ip_mappings[mac]
        
        # Clean ARP request patterns
        for src_ip in list(self.arp_request_patterns.keys()):
            self.arp_request_patterns[src_ip] = [
                (dst, ts) for dst, ts in self.arp_request_patterns[src_ip]
                if ts > current_time - 3600  # Keep 1 hour
            ]
            if not self.arp_request_patterns[src_ip]:
                del self.arp_request_patterns[src_ip]
        
        # Clean MAC change history (keep 7 days)
        for ip in list(self.mac_change_history.keys()):
            self.mac_change_history[ip] = [
                (old_mac, new_mac, ts) for old_mac, new_mac, ts in self.mac_change_history[ip]
                if ts > current_time - 604800  # 7 days
            ]
            if not self.mac_change_history[ip]:
                del self.mac_change_history[ip]
    
    def _calculate_spoofing_confidence(self, ip, new_mac, original_mac, change_frequency, operation):
        """Calculate confidence score for spoofing detection"""
        # Start with base confidence
        confidence = 0.5
        
        # Adjust based on factors
        
        # 1. Change frequency - frequent changes are suspicious
        if change_frequency > 10:
            confidence += 0.3
        elif change_frequency > 5:
            confidence += 0.2
        elif change_frequency > 2:
            confidence += 0.1
        
        # 2. Gateway status - targeting gateways is common
        if ip in self.gateway_macs:
            confidence += 0.2
        
        # 3. Gratuitous ARP - often used in attacks
        if operation == 2:
            confidence += 0.1
        
        # 4. Vendor mismatch
        if self._check_vendor_mismatch(original_mac, new_mac):
            confidence += 0.2
        
        # Cap confidence at 1.0
        return min(1.0, confidence)
    
    def _identify_arp_attack_type(self, ip, mac, operation, change_frequency):
        """Identify the type of ARP attack"""
        if ip in self.gateway_macs:
            return "Gateway spoofing"
        elif operation == 2 and change_frequency > 5:
            return "ARP poisoning"
        elif len(self.mac_ip_mappings.get(mac, set())) > 3:
            return "Host impersonation"
        else:
            return "MAC spoofing"
    
    def _identify_affected_hosts(self, spoofed_ip, spoofing_mac):
        """Identify hosts potentially affected by this spoofing"""
        # For gateway spoofing, all hosts communicating with the gateway are affected
        if spoofed_ip in self.gateway_macs:
            cursor = self.analysis_manager.get_cursor()
            try:
                cursor.execute("""
                    SELECT DISTINCT src_ip
                    FROM connections
                    WHERE dst_ip = ?
                    LIMIT 50
                """, (spoofed_ip,))
                
                affected = [row[0] for row in cursor.fetchall()]
                return affected
            finally:
                cursor.close()
        
        # For other kinds of spoofing, typically the spoofed IP is the target
        return [spoofed_ip]
    
    def _check_vendor_mismatch(self, mac1, mac2):
        """Check if two MACs have different vendors"""
        if not mac1 or not mac2 or len(mac1) < 8 or len(mac2) < 8:
            return False
            
        # Get OUIs (first 3 bytes)
        oui1 = mac1[:8]
        oui2 = mac2[:8]
        
        # Different OUIs indicate different manufacturers
        return oui1 != oui2
    
    def _update_mac_vendor(self, mac):
        """Update MAC vendor information (simplified)"""
        # This would normally involve a lookup service or database
        # For this implementation, we'll just store the OUI
        oui = mac[:8] if len(mac) >= 8 else mac
        
        if oui not in self.mac_vendor_cache:
            self.mac_vendor_cache[oui] = f"Vendor-{oui}"
    
    def _analyze_request_pattern(self, mac):
        """Analyze ARP request pattern for this MAC"""
        # This would be more complex in a real implementation
        # looking at request frequency, distribution, etc.
        ips = self.mac_ip_mappings.get(mac, set())
        
        if len(ips) > 5:
            return "Network scanner"
        elif len(ips) > 1:
            return "Multi-IP host"
        else:
            return "Normal host"
    
    def _determine_host_type(self, request_count, response_count, is_gateway):
        """Determine the type of host based on ARP behavior"""
        if is_gateway:
            return "gateway"
        elif request_count > response_count * 10:
            return "scanner"
        elif response_count > request_count * 10:
            return "server"
        elif request_count > 100 and response_count > 100:
            return "active_host"
        else:
            return "normal_host"
    
    def _calculate_behavioral_score(self, mac, ip_count, gratuitous_count, request_pattern):
        """Calculate behavioral abnormality score (0-10)"""
        # Start with neutral score
        score = 3
        
        # Adjust based on multiple IPs
        if ip_count > 10:
            score += 4
        elif ip_count > 5:
            score += 3
        elif ip_count > 2:
            score += 2
        elif ip_count > 1:
            score += 1
        
        # Adjust based on gratuitous ARP frequency
        if gratuitous_count > 20:
            score += 3
        elif gratuitous_count > 10:
            score += 2
        elif gratuitous_count > 5:
            score += 1
        
        # Adjust based on request pattern
        if request_pattern == "Network scanner":
            score += 2
        
        # Cap score at 10
        return min(10, score)
    
    def _determine_behavior_type(self, ip_count, gratuitous_count, behavioral_score):
        """Determine behavior type based on pattern analysis"""
        if behavioral_score > 8:
            return "highly_suspicious"
        elif behavioral_score > 6:
            return "suspicious"
        elif ip_count > 5:
            return "multi_identity"
        elif gratuitous_count > 10:
            return "aggressive_announcer"
        elif behavioral_score > 4:
            return "unusual"
        else:
            return "normal"
    
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
    
    def run_periodic_analysis(self):
        """Run periodic analysis on ARP data"""
        try:
            current_time = time.time()
            cursor = self.analysis_manager.get_cursor()
            
            # Find unresolved spoofing incidents
            cursor.execute("""
                SELECT id, ip_address, mac_address, original_mac, confidence_score, 
                       attack_type, is_gateway, detection_time
                FROM arp_analysis
                WHERE resolved = 0 AND active = 1
                ORDER BY confidence_score DESC, detection_time DESC
                LIMIT 20
            """)
            
            incidents = cursor.fetchall()
            
            if incidents:
                logger.info(f"Found {len(incidents)} active ARP spoofing incidents:")
                for incident in incidents:
                    id, ip, mac, original_mac, confidence, attack_type, is_gateway, detection_time = incident
                    gateway_status = "gateway" if is_gateway else "host"
                    age = (current_time - detection_time) / 60  # minutes
                    
                    logger.info(f"  {attack_type}: {ip} ({gateway_status}) MAC changed from {original_mac} to {mac}, "
                               f"confidence: {confidence:.2f}, age: {age:.1f} minutes")
                    
                    # Check if this incident is still active (MAC still present)
                    if ip in self.arp_cache and mac in self.arp_cache[ip]:
                        # Still active, update last seen time
                        cursor.execute("""
                            UPDATE arp_analysis
                            SET active = 1
                            WHERE id = ?
                        """, (id,))
                    else:
                        # No longer active, mark as inactive
                        if current_time - detection_time > 1800:  # 30 minutes without seeing the MAC
                            cursor.execute("""
                                UPDATE arp_analysis
                                SET active = 0
                                WHERE id = ?
                            """, (id,))
                            logger.info(f"  Marked incident for {ip} as inactive (not seen in 30+ minutes)")
            
            # Find hosts with unusual behavioral patterns
            cursor.execute("""
                SELECT mac_address, behavior_type, behavioral_score, ip_count, gratuitous_count
                FROM arp_behavior_patterns
                WHERE behavioral_score > 6 AND last_seen > ?
                ORDER BY behavioral_score DESC
                LIMIT 10
            """, (current_time - 3600,))  # Last hour
            
            unusual_behaviors = cursor.fetchall()
            
            if unusual_behaviors:
                logger.info(f"Found {len(unusual_behaviors)} hosts with unusual ARP behavior:")
                for mac, behavior, score, ip_count, gratuitous in unusual_behaviors:
                    logger.info(f"  {mac}: {behavior}, score: {score:.1f}, IPs: {ip_count}, "
                              f"gratuitous ARPs: {gratuitous}")
            
            # Update long-term statistics
            self._update_network_statistics(cursor, current_time)
            
            self.analysis_manager.analysis1_conn.commit()
            cursor.close()
            
            return bool(incidents) or bool(unusual_behaviors)
        except Exception as e:
            logger.error(f"Error in ARP periodic analysis: {e}")
            return False
    
    def _update_network_statistics(self, cursor, current_time):
        """Update long-term network statistics for baseline and trend analysis"""
        try:
            # Count stable vs. unstable hosts
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_hosts,
                    SUM(CASE WHEN stability_score > 0.8 THEN 1 ELSE 0 END) as stable_hosts,
                    SUM(CASE WHEN stability_score < 0.5 THEN 1 ELSE 0 END) as unstable_hosts
                FROM arp_host_tracking
                WHERE last_seen > ?
            """, (current_time - 86400,))  # Last 24 hours
            
            total, stable, unstable = cursor.fetchone()
            
            if total:
                stable_pct = (stable / total) * 100 if total > 0 else 0
                unstable_pct = (unstable / total) * 100 if total > 0 else 0
                
                logger.info(f"Network stability: {stable_pct:.1f}% stable hosts, {unstable_pct:.1f}% unstable hosts")
            
            # Count suspicious behavior trends
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_hosts,
                    SUM(CASE WHEN behavioral_score > 8 THEN 1 ELSE 0 END) as highly_suspicious,
                    SUM(CASE WHEN behavioral_score > 6 AND behavioral_score <= 8 THEN 1 ELSE 0 END) as suspicious,
                    SUM(CASE WHEN behavioral_score > 4 AND behavioral_score <= 6 THEN 1 ELSE 0 END) as unusual
                FROM arp_behavior_patterns
                WHERE last_seen > ?
            """, (current_time - 86400,))  # Last 24 hours
            
            result = cursor.fetchone()
            if result:
                total, highly_suspicious, suspicious, unusual = result
                
                if total > 0:
                    logger.info(f"Behavior statistics: "
                               f"{highly_suspicious} highly suspicious, "
                               f"{suspicious} suspicious, "
                               f"{unusual} unusual out of {total} hosts")
        except Exception as e:
            logger.error(f"Error updating network statistics: {e}")
    
    def cleanup(self):
        """Clean up resources"""
        self.arp_cache.clear()
        self.ip_mac_mappings.clear()
        self.mac_ip_mappings.clear()
        self.arp_request_patterns.clear()
        self.mac_change_history.clear()
        self.gateway_macs.clear()