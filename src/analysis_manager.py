# analysis_manager.py
import sqlite3
import os
import time
import threading
import logging
import queue
import json
import math
import statistics
from collections import defaultdict, Counter

# Configure logging
logger = logging.getLogger('analysis_manager')

class AnalysisManager:
    """Manages advanced analytics processing and storage"""
    
    def __init__(self, app_root, db_manager=None):
        self.app_root = app_root
        self.db_dir = os.path.join(app_root, "db")
        os.makedirs(self.db_dir, exist_ok=True)
        
        # Reference to primary database manager (for access to analysis.db)
        self.db_manager = db_manager
        
        # Set up analysis_1 database
        self.analysis1_db_path = os.path.join(self.db_dir, "analysis_1.db")
        self.analysis1_conn = sqlite3.connect(self.analysis1_db_path, check_same_thread=False)
        
        # Configure database
        self._setup_analysis1_db()
        
        # Set up synchronization
        self.sync_lock = threading.Lock()
        self.last_sync_time = time.time()
        self.sync_interval = 20  # seconds between syncs
        
        # Set up query queue for background processing
        self.query_queue = queue.Queue()
        self.queue_running = True
        self.queue_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.queue_thread.start()
        
        # Start periodic analysis thread
        self.analysis_interval = 300  # Run analysis every 5 minutes
        self.last_analysis_time = 0   # Force first analysis soon after startup
        self.analysis_thread = threading.Thread(target=self._periodic_analysis, daemon=True)
        self.analysis_thread.start()
        
        # Start sync thread if we have a db_manager reference
        if db_manager:
            self.sync_thread = threading.Thread(target=self._sync_thread, daemon=True)
            self.sync_thread.start()
            
        logger.info("Analysis manager initialized with analysis_1.db")
    
    def _setup_analysis1_db(self):
        """Set up analysis_1 database tables"""
        cursor = self.analysis1_conn.cursor()
        try:
            # Configure for performance
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA cache_size=10000")
            
            # IP geolocation table (existing)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_geolocation (
                    ip_address TEXT PRIMARY KEY,
                    country TEXT,
                    region TEXT,
                    city TEXT,
                    latitude REAL,
                    longitude REAL,
                    asn TEXT,
                    asn_name TEXT,
                    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Threat intelligence data (existing)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ip_threat_intel (
                    ip_address TEXT PRIMARY KEY,
                    threat_score REAL DEFAULT 0,
                    threat_type TEXT,
                    confidence REAL DEFAULT 0,
                    source TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    details TEXT
                )
            """)
            
            # Traffic patterns table (existing)
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
            
            # DNS queries table (new)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dns_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT NOT NULL,
                    query_domain TEXT NOT NULL,
                    query_type TEXT,
                    timestamp REAL NOT NULL
                )
            """)
            
            # HTTP requests table (new)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS http_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_key TEXT NOT NULL,
                    method TEXT,
                    host TEXT,
                    uri TEXT,
                    user_agent TEXT,
                    timestamp REAL NOT NULL
                )
            """)
            
            # HTTP responses table (new)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS http_responses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER,
                    status_code INTEGER,
                    timestamp REAL NOT NULL,
                    FOREIGN KEY(request_id) REFERENCES http_requests(id)
                )
            """)
            
            # TLS connections table (new)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tls_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_key TEXT NOT NULL,
                    tls_version TEXT,
                    cipher_suite TEXT,
                    server_name TEXT,
                    timestamp REAL NOT NULL
                )
            """)
            
            # ICMP packets table (new)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS icmp_packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    icmp_type INTEGER,
                    timestamp REAL NOT NULL
                )
            """)
            
            # ARP data table (new)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS arp_data (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    operation INTEGER,
                    timestamp REAL NOT NULL
                )
            """)
            
            # Create alerts table (existing)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    alert_message TEXT,
                    rule_name TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ip_address, alert_message)
                )
            """)
            
            # Create indices for the new tables
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_geolocation_country ON ip_geolocation(country)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_threat_score ON ip_threat_intel(threat_score DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ip ON alerts(ip_address)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_rule ON alerts(rule_name)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_queries_domain ON dns_queries(query_domain)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_queries_src ON dns_queries(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_dns_queries_time ON dns_queries(timestamp)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_requests_conn ON http_requests(connection_key)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_requests_host ON http_requests(host)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_responses_req ON http_responses(request_id)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_connections_conn ON tls_connections(connection_key)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_connections_server ON tls_connections(server_name)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_icmp_packets_src_dst ON icmp_packets(src_ip, dst_ip)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_arp_data_src_dst ON arp_data(src_ip, dst_ip)")
            
            self.analysis1_conn.commit()
            logger.info("Analysis_1 database tables initialized")
        finally:
            cursor.close()
    
    def _sync_thread(self):
        """Thread that periodically synchronizes with analysis.db"""
        logger.info("Analysis sync thread started")
        while self.queue_running:
            try:
                current_time = time.time()
                if current_time - self.last_sync_time >= self.sync_interval:
                    self.sync_from_analysis_db()
                
                # Sleep for a short time before checking again
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in sync thread: {e}")
    
    def _process_queue(self):
        """Process database query queue in a separate thread"""
        logger.info("Analysis query processing thread started")
        while self.queue_running:
            try:
                # Get next query from queue
                query_func, args, kwargs, callback = self.query_queue.get(timeout=0.5)
                
                # Execute the query
                try:
                    result = query_func(*args, **kwargs)
                    
                    # Execute callback with result if provided
                    if callback:
                        callback(result)
                except Exception as e:
                    logger.error(f"Error executing queued query: {e}")
                
                # Mark task as done
                self.query_queue.task_done()
                
            except queue.Empty:
                # No queries in queue, just continue
                pass
            except Exception as e:
                logger.error(f"Error in analysis queue processor: {e}")
    
    
    def queue_query(self, query_func, callback=None, *args, **kwargs):
        """Add a query to the processing queue"""
        self.query_queue.put((query_func, args, kwargs, callback))
        logger.debug("Analysis query added to processing queue")
    
    def sync_from_analysis_db(self):
        """Synchronize data from analysis.db to analysis_1.db with support for all relevant tables"""
        if not self.db_manager:
            logger.warning("Cannot sync without db_manager reference")
            return 0
            
        try:
            with self.sync_lock:
                current_time = time.time()
                logger.info("Starting synchronization from analysis.db")
                sync_count = 0
                
                # Extended list of tables to synchronize
                tables = [
                    'alerts',
                    'dns_queries', 
                    'http_requests', 
                    'http_responses', 
                    'tls_connections', 
                    'icmp_packets', 
                    'arp_data',
                    'connections'  # Include base connections table
                ]
                
                # Use dedicated connections for sync
                analysis_conn = self.db_manager.analysis_conn
                analysis1_conn = self.analysis1_conn
                
                # Begin transaction for better performance
                analysis1_conn.execute("BEGIN TRANSACTION")
                
                for table in tables:
                    try:
                        # Check if table exists in source database
                        analysis_cursor = analysis_conn.cursor()
                        analysis_cursor.execute(
                            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                            (table,)
                        )
                        
                        if analysis_cursor.fetchone() is None:
                            logger.info(f"Table {table} not found in analysis.db, skipping")
                            analysis_cursor.close()
                            continue
                        
                        # Check if table exists in destination database
                        analysis1_cursor = analysis1_conn.cursor()
                        analysis1_cursor.execute(
                            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                            (table,)
                        )
                        
                        if analysis1_cursor.fetchone() is None:
                            # Create table in destination if it doesn't exist
                            logger.info(f"Table {table} not found in analysis_1.db, creating it")
                            
                            # Get schema from source
                            analysis_cursor.execute(
                                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                                (table,)
                            )
                            create_table_sql = analysis_cursor.fetchone()
                            
                            if create_table_sql and create_table_sql[0]:
                                analysis1_cursor.execute(create_table_sql[0])
                                logger.info(f"Created table {table} in analysis_1.db")
                        
                        # Get sync identifier column (prefer 'id' or 'timestamp')
                        sync_column = 'id'  # Default
                        
                        # Check if 'id' column exists
                        analysis_cursor.execute(f"PRAGMA table_info({table})")
                        columns = analysis_cursor.fetchall()
                        column_names = [col[1] for col in columns]  # Column name is at index 1
                        
                        if 'id' not in column_names and 'timestamp' in column_names:
                            sync_column = 'timestamp'
                        
                        # Get last synced value
                        if sync_column == 'id':
                            analysis1_cursor.execute(f"SELECT MAX({sync_column}) FROM {table}")
                            last_value = analysis1_cursor.fetchone()[0] or 0
                            
                            # Get new records from analysis.db
                            analysis_cursor.execute(f"SELECT * FROM {table} WHERE {sync_column} > ?", (last_value,))
                        else:  # timestamp-based sync
                            analysis1_cursor.execute(f"SELECT MAX({sync_column}) FROM {table}")
                            last_timestamp = analysis1_cursor.fetchone()[0] or 0
                            
                            # Get new records from analysis.db
                            analysis_cursor.execute(f"SELECT * FROM {table} WHERE {sync_column} > ?", (last_timestamp,))
                        
                        # Get column names from source database
                        columns = [desc[0] for desc in analysis_cursor.description]
                        
                        # Process rows
                        rows = analysis_cursor.fetchall()
                        if rows:
                            # Prepare SQL for insertion
                            columns_str = ', '.join(columns)
                            placeholders = ', '.join(['?' for _ in columns])
                            
                            # Insert rows into destination
                            for row in rows:
                                try:
                                    analysis1_cursor.execute(
                                        f"INSERT OR IGNORE INTO {table} ({columns_str}) VALUES ({placeholders})",
                                        row
                                    )
                                    sync_count += 1
                                except Exception as e:
                                    logger.error(f"Error inserting row into {table}: {e}")
                            
                            logger.info(f"Synchronized {len(rows)} records from {table}")
                        
                        # Close cursors
                        analysis_cursor.close()
                        analysis1_cursor.close()
                        
                    except Exception as e:
                        logger.error(f"Error syncing table {table}: {e}")
                
                # Commit the transaction
                analysis1_conn.commit()
                
                self.last_sync_time = current_time
                logger.info(f"Synchronized {sync_count} records from analysis.db")
                return sync_count
                    
        except Exception as e:
            # Make sure to rollback if there's an error
            try:
                analysis1_conn.rollback()
            except:
                pass
            logger.error(f"Synchronization error: {e}")
            import traceback
            traceback.print_exc()
            return 0
    
    def receive_packet_data(self, packet_data):
        """
        Method to be called from traffic_capture.py to integrate with analysis
        This can be called directly after a packet is processed in traffic_capture.py
        """
        try:
            # Queue processing to avoid blocking the capture thread
            self.queue_query(self.process_packet, None, packet_data)
            return True
        except Exception as e:
            logger.error(f"Error queueing packet for analysis: {e}")
            return False
    
    def get_cursor(self):
        """Get a cursor for the analysis_1 database"""
        return self.analysis1_conn.cursor()
    
    def store_ip_geolocation(self, ip_address, geo_data):
        """Store IP geolocation data"""
        try:
            cursor = self.analysis1_conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO ip_geolocation
                (ip_address, country, region, city, latitude, longitude, asn, asn_name, last_updated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                ip_address,
                geo_data.get('country'),
                geo_data.get('region'),
                geo_data.get('city'),
                geo_data.get('latitude'),
                geo_data.get('longitude'),
                geo_data.get('asn'),
                geo_data.get('asn_name')
            ))
            self.analysis1_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error storing IP geolocation: {e}")
            return False
    
    def get_ip_geolocation(self, ip_address):
        """Get geolocation data for an IP address"""
        try:
            cursor = self.analysis1_conn.cursor()
            cursor.execute("""
                SELECT country, region, city, latitude, longitude, asn, asn_name
                FROM ip_geolocation
                WHERE ip_address = ?
            """, (ip_address,))
            result = cursor.fetchone()
            cursor.close()
            
            if result:
                return {
                    'country': result[0],
                    'region': result[1],
                    'city': result[2],
                    'latitude': result[3],
                    'longitude': result[4],
                    'asn': result[5],
                    'asn_name': result[6]
                }
            return None
        except Exception as e:
            logger.error(f"Error getting IP geolocation: {e}")
            return None
    
    def add_alert(self, ip_address, alert_message, rule_name):
        """Add an alert to analysis_1.db"""
        try:
            cursor = self.analysis1_conn.cursor()
            cursor.execute("""
                INSERT OR IGNORE INTO alerts (ip_address, alert_message, rule_name)
                VALUES (?, ?, ?)
            """, (ip_address, alert_message, rule_name))
            self.analysis1_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error adding alert: {e}")
            return False
    
    def update_threat_intel(self, ip_address, threat_data):
        """Update threat intelligence data for an IP"""
        try:
            cursor = self.analysis1_conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO ip_threat_intel
                (ip_address, threat_score, threat_type, confidence, source, first_seen, last_seen, details)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?)
            """, (
                ip_address,
                threat_data.get('score', 0),
                threat_data.get('type'),
                threat_data.get('confidence', 0),
                threat_data.get('source'),
                threat_data.get('first_seen') or time.time(),
                json.dumps(threat_data.get('details', {}))
            ))
            self.analysis1_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error updating threat intel: {e}")
            return False
    
    def process_packet(self, packet_data):
        """Process a packet for analysis (similar to process_packet_ek in traffic_capture)"""
        try:
            # Get the layers
            layers = packet_data.get("layers", {})
            if not layers:
                return False
            
            # Extract IP addresses (supporting both IPv4 and IPv6)
            src_ip = self._get_layer_value(layers, "ip_src") or self._get_layer_value(layers, "ipv6_src")
            dst_ip = self._get_layer_value(layers, "ip_dst") or self._get_layer_value(layers, "ipv6_dst")
            
            # Extract port and length information
            src_port, dst_port = self._extract_ports(layers)
            length = self._extract_length(layers)
            
            # Basic data validation for IP-based packets
            if not src_ip or not dst_ip:
                # This might be an ARP packet, try processing it
                if "arp_src_proto_ipv4" in layers or "arp_dst_proto_ipv4" in layers:
                    self._process_arp_packet(layers)
                    return True
                return False
            
            # Create a connection key
            if src_port is not None and dst_port is not None:
                connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            else:
                connection_key = f"{src_ip}->{dst_ip}"
            
            # Process specific protocol data if present
            if self._has_dns_data(layers):
                self._process_dns_packet(layers, src_ip, dst_ip)
            
            if self._has_http_data(layers):
                self._process_http_packet(layers, src_ip, dst_ip, src_port, dst_port)
            
            if self._has_tls_data(layers):
                self._process_tls_packet(layers, src_ip, dst_ip, src_port, dst_port)
            
            if "icmp_type" in layers:
                self._process_icmp_packet(layers, src_ip, dst_ip)
            
            # Update traffic patterns
            self._update_traffic_patterns(connection_key, length)
            
            return True
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _get_layer_value(self, layers, field_name):
        """Get a value from the layers object, handling array format"""
        if field_name in layers:
            value = layers[field_name]
            if isinstance(value, list) and value:
                return value[0]
        return None
    
    def _extract_ports(self, layers):
        """Extract source and destination ports from packet layers"""
        src_port = None
        dst_port = None
        
        # Try TCP ports first
        tcp_src = self._get_layer_value(layers, "tcp_srcport")
        if tcp_src:
            try:
                src_port = int(tcp_src)
            except (ValueError, TypeError):
                pass
        
        tcp_dst = self._get_layer_value(layers, "tcp_dstport")
        if tcp_dst:
            try:
                dst_port = int(tcp_dst)
            except (ValueError, TypeError):
                pass
        
        # If not found, try UDP ports
        if src_port is None:
            udp_src = self._get_layer_value(layers, "udp_srcport")
            if udp_src:
                try:
                    src_port = int(udp_src)
                except (ValueError, TypeError):
                    pass
        
        if dst_port is None:
            udp_dst = self._get_layer_value(layers, "udp_dstport")
            if udp_dst:
                try:
                    dst_port = int(udp_dst)
                except (ValueError, TypeError):
                    pass
        
        return src_port, dst_port
    
    def _extract_length(self, layers):
        """Extract frame length from packet layers"""
        length = 0
        frame_len = self._get_layer_value(layers, "frame_len")
        if frame_len:
            try:
                length = int(frame_len)
            except (ValueError, TypeError):
                pass
        return length
    
    def _has_dns_data(self, layers):
        """Check if layers contain DNS query data"""
        return "dns_qry_name" in layers
    
    def _has_http_data(self, layers):
        """Check if layers contain HTTP data"""
        return any(key in layers for key in ["http_host", "http_request_method", "http_request_uri", "http_response_code"])
    
    def _has_tls_data(self, layers):
        """Check if layers contain TLS data"""
        return any(key in layers for key in ["tls_handshake_type", "tls_handshake_version"])
    
    def _process_dns_packet(self, layers, src_ip, dst_ip):
        """Process DNS packet data"""
        try:
            # Extract query name
            query_name = self._get_layer_value(layers, "dns_qry_name")
            if not query_name:
                return False
            
            # Extract query type
            query_type = self._get_layer_value(layers, "dns_qry_type") or "unknown"
            
            # Store in database
            cursor = self.get_cursor()
            current_time = time.time()
            
            cursor.execute("""
                INSERT INTO dns_queries
                (src_ip, query_domain, query_type, timestamp)
                VALUES (?, ?, ?, ?)
            """, (src_ip, query_name, query_type, current_time))
            
            self.analysis1_conn.commit()
            cursor.close()
            
            return True
        except Exception as e:
            logger.error(f"Error processing DNS packet: {e}")
            return False
    
        
    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text"""
        if not text:
            return 0
        
        # Count character frequencies
        char_count = Counter(text.lower())
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
    
    def _process_http_packet(self, layers, src_ip, dst_ip, src_port, dst_port):
        """Process HTTP packet data"""
        try:
            # Create connection key
            connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            
            # Extract HTTP fields
            method = self._get_layer_value(layers, "http_request_method")
            uri = self._get_layer_value(layers, "http_request_uri")
            host = self._get_layer_value(layers, "http_host")
            user_agent = self._get_layer_value(layers, "http_user_agent")
            status_code_raw = self._get_layer_value(layers, "http_response_code")
            
            cursor = self.get_cursor()
            current_time = time.time()
            request_id = None
            
            # Store HTTP request if present
            if method or uri or host:
                # Set defaults for missing fields
                method = method or "GET"
                host = host or dst_ip
                uri = uri or "/"
                
                cursor.execute("""
                    INSERT INTO http_requests
                    (connection_key, method, host, uri, user_agent, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (connection_key, method, host, uri, user_agent or "", current_time))
                
                request_id = cursor.lastrowid
            
            # Store HTTP response if present
            if status_code_raw:
                try:
                    status_code = int(status_code_raw)
                    
                    # If we don't have a request ID from above, try to find the corresponding request
                    if not request_id:
                        cursor.execute("""
                            SELECT id FROM http_requests 
                            WHERE connection_key = ? 
                            ORDER BY timestamp DESC LIMIT 1
                        """, (connection_key,))
                        
                        result = cursor.fetchone()
                        if result:
                            request_id = result[0]
                    
                    if request_id:
                        # Store response
                        cursor.execute("""
                            INSERT INTO http_responses
                            (request_id, status_code, timestamp)
                            VALUES (?, ?, ?)
                        """, (request_id, status_code, current_time))
                except (ValueError, TypeError):
                    pass
            
            self.analysis1_conn.commit()
            cursor.close()
            
            return True
        except Exception as e:
            logger.error(f"Error processing HTTP packet: {e}")
            return False
    
    def _process_tls_packet(self, layers, src_ip, dst_ip, src_port, dst_port):
        """Process TLS/SSL packet data"""
        try:
            # Create connection key
            connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            
            # Extract TLS fields
            tls_version = self._get_layer_value(layers, "tls_handshake_version")
            cipher_suite = self._get_layer_value(layers, "tls_handshake_ciphersuite")
            server_name = self._get_layer_value(layers, "tls_handshake_extensions_server_name")
            
            # Set defaults
            if not tls_version:
                if dst_port == 443:
                    tls_version = "TLSv1.2 (assumed)"
                else:
                    tls_version = "Unknown"
            
            if not cipher_suite:
                cipher_suite = "Unknown"
            
            if not server_name:
                server_name = dst_ip
            
            # Store in database
            cursor = self.get_cursor()
            current_time = time.time()
            
            cursor.execute("""
                INSERT INTO tls_connections
                (connection_key, tls_version, cipher_suite, server_name, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (connection_key, tls_version, cipher_suite, server_name, current_time))
            
            self.analysis1_conn.commit()
            cursor.close()
            
            return True
        except Exception as e:
            logger.error(f"Error processing TLS packet: {e}")
            return False
    
    def _process_icmp_packet(self, layers, src_ip, dst_ip):
        """Process ICMP packet data and check for ICMP floods"""
        try:
            # Extract ICMP type
            icmp_type_raw = self._get_layer_value(layers, "icmp_type")
            icmp_type = 0
            
            if icmp_type_raw is not None:
                try:
                    icmp_type = int(icmp_type_raw)
                except (ValueError, TypeError):
                    icmp_type = 0
            
            # Store in database
            cursor = self.get_cursor()
            current_time = time.time()
            
            cursor.execute("""
                INSERT INTO icmp_packets
                (src_ip, dst_ip, icmp_type, timestamp)
                VALUES (?, ?, ?, ?)
            """, (src_ip, dst_ip, icmp_type, current_time))
            
            # Check for ICMP floods
            cursor.execute("""
                SELECT COUNT(*) FROM icmp_packets
                WHERE src_ip = ? AND dst_ip = ? AND timestamp > ?
            """, (src_ip, dst_ip, current_time - 10))  # Last 10 seconds
            
            count = cursor.fetchone()[0]
            if count > 10:
                # Log a potential ICMP flood
                logger.warning(f"Potential ICMP flood detected from {src_ip} to {dst_ip}: {count} packets in 10 seconds")
                
                # Add an alert
                self.add_alert(src_ip, f"ICMP flood to {dst_ip}: {count} packets in 10 seconds", "ICMP_Flood_Detector")
            
            self.analysis1_conn.commit()
            cursor.close()
            
            return True
        except Exception as e:
            logger.error(f"Error processing ICMP packet: {e}")
            return False
    
    def _process_arp_packet(self, layers):
        """Process ARP packet data"""
        try:
            # Extract ARP source and destination IPs
            arp_src_ip = self._get_layer_value(layers, "arp_src_proto_ipv4")
            arp_dst_ip = self._get_layer_value(layers, "arp_dst_proto_ipv4")
            
            # Extract ARP operation (1=request, 2=reply)
            operation_raw = self._get_layer_value(layers, "arp_opcode")
            operation = 0
            
            if operation_raw:
                try:
                    operation = int(operation_raw)
                except (ValueError, TypeError):
                    operation = 0
            
            # Store in database
            if arp_src_ip or arp_dst_ip:
                cursor = self.get_cursor()
                current_time = time.time()
                
                cursor.execute("""
                    INSERT INTO arp_data
                    (src_ip, dst_ip, operation, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (arp_src_ip or "Unknown", arp_dst_ip or "Unknown", operation, current_time))
                
                self.analysis1_conn.commit()
                cursor.close()
                
                return True
            
            return False
        except Exception as e:
            logger.error(f"Error processing ARP packet: {e}")
            return False
    
    def _update_traffic_patterns(self, connection_key, packet_size):
        """Update traffic pattern information for behavioral analysis"""
        try:
            cursor = self.get_cursor()
            
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
            
            self.analysis1_conn.commit()
            cursor.close()
            
            return True
        except Exception as e:
            logger.error(f"Error updating traffic patterns: {e}")
            return False
    
        
    def process_packet_batch(self, packet_batch):
        """Process a batch of packets for analysis"""
        processed_count = 0
        for packet_data in packet_batch:
            if self.process_packet(packet_data):
                processed_count += 1
        
        logger.info(f"Processed {processed_count} packets in analysis batch")
        return processed_count
    
    
    def close(self):
        """Close connections and stop threads"""
        self.queue_running = False
        if hasattr(self, 'queue_thread') and self.queue_thread:
            self.queue_thread.join(timeout=2)
        if hasattr(self, 'sync_thread') and self.sync_thread:
            self.sync_thread.join(timeout=2)
        if hasattr(self, 'analysis_thread') and self.analysis_thread:
            self.analysis_thread.join(timeout=2)
        if self.analysis1_conn:
            self.analysis1_conn.close()
        logger.info("Analysis manager closed")


    def resolve_domain_names(self):
        """Resolve IP addresses to domain names for TLS connections"""
        import socket
        
        try:
            cursor = self.get_cursor()
            
            # Get all TLS connections with server names that look like IP addresses
            cursor.execute("""
                SELECT id, server_name, connection_key
                FROM tls_connections
                WHERE server_name LIKE '%\\.%\\.%\\.%' 
                OR server_name IS NULL
                LIMIT 100
            """)
            
            rows = cursor.fetchall()
            updates = 0
            
            for row in rows:
                tls_id, server_name, connection_key = row
                
                # Extract destination IP from connection key
                try:
                    dst_ip = connection_key.split('->')[1].split(':')[0]
                except IndexError:
                    continue
                    
                # Skip if we already have a non-IP server name
                if server_name and not self._is_ip_address(server_name):
                    continue
                    
                # Try reverse DNS lookup
                try:
                    hostname, _, _ = socket.gethostbyaddr(dst_ip)
                    if hostname and hostname != dst_ip and not self._is_ip_address(hostname):
                        # Update the server name in the database
                        cursor.execute("""
                            UPDATE tls_connections
                            SET server_name = ?
                            WHERE id = ?
                        """, (hostname, tls_id))
                        
                        updates += 1
                        logger.info(f"Resolved {dst_ip} to {hostname}")
                except (socket.herror, socket.gaierror):
                    # If reverse lookup fails, that's okay
                    pass
                    
            if updates > 0:
                logger.info(f"Resolved {updates} domain names for TLS connections")
                self.analysis1_conn.commit()
            
            cursor.close()
            return updates
            
        except Exception as e:
            logger.error(f"Error in resolve_domain_names: {e}")
            return 0
            
    def _is_ip_address(self, value):
        """Check if a string is an IP address"""
        if not value:
            return False
            
        # Simple IPv4 check
        parts = value.split('.')
        if len(parts) != 4:
            return False
            
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
   
    def aggregate_connection_statistics(self):
        """
        Aggregate connection statistics and store in analysis_1.db
        """
        try:
            cursor = self.get_cursor()
            
            # Create statistics table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS connection_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    total_connections INTEGER,
                    active_connections INTEGER,
                    total_bytes REAL,
                    unique_src_ips INTEGER,
                    unique_dst_ips INTEGER,
                    rdp_connections INTEGER,
                    http_connections INTEGER,
                    https_connections INTEGER,
                    dns_queries INTEGER
                )
            """)
            
            # Get connection statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_connections,
                    COUNT(CASE WHEN timestamp > ? THEN 1 END) as active_connections,
                    SUM(total_bytes) as total_bytes,
                    COUNT(DISTINCT src_ip) as unique_src_ips,
                    COUNT(DISTINCT dst_ip) as unique_dst_ips,
                    SUM(CASE WHEN is_rdp_client = 1 THEN 1 ELSE 0 END) as rdp_connections
                FROM connections
            """, (time.time() - 3600,))  # Active means activity in the last hour
            
            conn_stats = cursor.fetchone()
            
            # Get protocol-specific statistics
            cursor.execute("SELECT COUNT(*) FROM http_requests")
            http_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM tls_connections")
            tls_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM dns_queries")
            dns_count = cursor.fetchone()[0]
            
            # Store aggregated statistics
            current_time = time.time()
            cursor.execute("""
                INSERT INTO connection_statistics
                (timestamp, total_connections, active_connections, total_bytes, 
                unique_src_ips, unique_dst_ips, rdp_connections, 
                http_connections, https_connections, dns_queries)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                current_time,
                conn_stats[0] or 0,
                conn_stats[1] or 0,
                conn_stats[2] or 0,
                conn_stats[3] or 0,
                conn_stats[4] or 0,
                conn_stats[5] or 0,
                http_count,
                tls_count,
                dns_count
            ))
            
            self.analysis1_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error aggregating connection statistics: {e}")
            return False 

    
    
    def _periodic_analysis(self):
        """Thread that periodically runs analysis tasks"""
        logger.info("Periodic analysis thread started")
        while self.queue_running:
            try:
                current_time = time.time()
                if current_time - self.last_analysis_time >= self.analysis_interval:
                    # Only keep the methods that weren't deleted
                    self.queue_query(self.resolve_domain_names)
                    self.queue_query(self.aggregate_connection_statistics)
                    
                    self.last_analysis_time = current_time
                    logger.info("Scheduled periodic analysis tasks")
                
                # Sleep for a short time before checking again
                time.sleep(30)
            except Exception as e:
                logger.error(f"Error in periodic analysis thread: {e}")

