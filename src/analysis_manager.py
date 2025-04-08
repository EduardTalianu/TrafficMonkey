# analysis_manager.py
import sqlite3
import os
import time
import threading
import logging
import queue
import json
import importlib
import sys
from collections import defaultdict, Counter

# Configure logging
logger = logging.getLogger('analysis_manager')

class AnalysisBase:
    """Base class for all analysis plugins"""
    
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.enabled = True
        self.analysis_manager = None  # Will be set by AnalysisLoader
    
    def initialize(self):
        """Initialize any resources needed by the analysis"""
        pass
    
    def process_packet(self, packet_data):
        """Process a single packet"""
        return False
    
    def run_periodic_analysis(self):
        """Run analysis that doesn't depend on individual packets"""
        return False
    
    def cleanup(self):
        """Clean up any resources used by the analysis"""
        pass

class AnalysisManager:
    """Manages advanced analytics processing and storage with plugin support"""
    
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
        
        # Analysis plugins
        self.analysis_plugins = []
        self.analysis_plugins_dir = os.path.join(app_root, "analysis")
        os.makedirs(self.analysis_plugins_dir, exist_ok=True)
        
        # Load analysis plugins
        self.load_analysis_plugins()
        
        # Start periodic analysis thread
        self.analysis_interval = 300  # Run analysis every 5 minutes
        self.last_analysis_time = 0   # Force first analysis soon after startup
        self.analysis_thread = threading.Thread(target=self._periodic_analysis, daemon=True)
        self.analysis_thread.start()
        
        # Start sync thread if we have a db_manager reference
        if db_manager:
            self.sync_thread = threading.Thread(target=self._sync_thread, daemon=True)
            self.sync_thread.start()
            
        logger.info(f"Analysis manager initialized with {len(self.analysis_plugins)} plugins")
    
    def load_analysis_plugins(self):
        """Load analysis plugins from the analysis directory"""
        # Check if analysis directory exists
        if not os.path.exists(self.analysis_plugins_dir):
            os.makedirs(self.analysis_plugins_dir, exist_ok=True)
            logger.warning(f"Analysis plugins directory created at {self.analysis_plugins_dir}")
            return
        
        # Add the analysis directory to Python path
        if self.analysis_plugins_dir not in sys.path:
            sys.path.append(self.analysis_plugins_dir)
        
        # Load analysis plugin files
        for filename in os.listdir(self.analysis_plugins_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]  # Remove .py extension
                module_path = os.path.join(self.analysis_plugins_dir, filename)
                
                try:
                    # Create a custom namespace for the module
                    analysis_namespace = {
                        'AnalysisBase': AnalysisBase,
                        'time': time,
                        'logging': logging,
                        'logger': logger,
                        'json': json,
                        'os': os,
                        'Counter': Counter,
                        'defaultdict': defaultdict,
                        'sqlite3': sqlite3,
                    }
                    
                    # Load the module content with proper encoding handling
                    try:
                        # Try UTF-8 encoding first (recommended)
                        with open(module_path, 'r', encoding='utf-8') as f:
                            module_code = f.read()
                    except UnicodeDecodeError:
                        # Fall back to latin-1 which can read any byte values
                        with open(module_path, 'r', encoding='latin-1') as f:
                            module_code = f.read()
                            logger.warning(f"File {filename} had to be read with latin-1 encoding. Consider saving it as UTF-8.")
                    
                    # Execute the module code in the custom namespace
                    exec(module_code, analysis_namespace)
                    
                    # Find analysis classes in the namespace (subclasses of AnalysisBase)
                    for name, obj in analysis_namespace.items():
                        if (isinstance(obj, type) and 
                            issubclass(obj, AnalysisBase) and 
                            obj != AnalysisBase and 
                            hasattr(obj, '__init__')):
                            
                            # Create an instance of the analysis plugin
                            analysis_instance = obj()
                            
                            # Inject analysis manager reference
                            analysis_instance.analysis_manager = self
                            
                            # Initialize the plugin
                            analysis_instance.initialize()
                            
                            self.analysis_plugins.append(analysis_instance)
                            logger.info(f"Loaded analysis plugin: {analysis_instance.name} from {filename}")
                            print(f"Loaded analysis plugin: {analysis_instance.name} from {filename}")
                
                except Exception as e:
                    logger.error(f"Error loading analysis plugin {module_name}: {e}")
                    import traceback
                    traceback.print_exc()
        
        # Sort analysis plugins alphabetically by name for consistent ordering
        self.analysis_plugins.sort(key=lambda x: x.name)
        
        # Log summary of loaded plugins
        logger.info(f"Loaded {len(self.analysis_plugins)} analysis plugins")
        
        # If no plugins were loaded, show a warning
        if not self.analysis_plugins:
            logger.warning("No analysis plugins were loaded! Advanced analysis will be disabled.")
    
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
                    response_domain TEXT,  
                    response_type TEXT,   
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
                    referer TEXT,
                    user_agent TEXT,
                    version TEXT,
                    timestamp REAL NOT NULL
                )
            """)
            
            # HTTP responses table (new)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS http_responses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id INTEGER,
                    status_code INTEGER,
                    server TEXT,
                    timestamp REAL NOT NULL,
                    content_type TEXT,
                    content_length INTEGER,
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
                    ja3_fingerprint TEXT,
                    ja3s_fingerprint TEXT,
                    certificate_issuer TEXT,
                    certificate_subject TEXT,
                    certificate_validity_start TEXT,
                    certificate_validity_end TEXT,
                    certificate_serial   TEXT,
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
                    src_mac TEXT,  
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
            
            # Connection statistics table (new)
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
            
            # Create indices for the tables
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
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_conn_stats_time ON connection_statistics(timestamp)")
            
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
    
    def process_packet(self, packet_data):
        """Process a packet by passing it to all enabled analysis plugins"""
        success = False
        for plugin in self.analysis_plugins:
            if plugin.enabled:
                try:
                    if plugin.process_packet(packet_data):
                        success = True
                except Exception as e:
                    logger.error(f"Error in analysis plugin {plugin.name}: {e}")
        return success
    
    def get_cursor(self):
        """Get a cursor for the analysis_1 database"""
        return self.analysis1_conn.cursor()
    
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
    
    def _periodic_analysis(self):
        """Thread that periodically runs analysis tasks for all plugins"""
        logger.info("Periodic analysis thread started")
        while self.queue_running:
            try:
                current_time = time.time()
                if current_time - self.last_analysis_time >= self.analysis_interval:
                    # Run periodic analysis for each enabled plugin
                    for plugin in self.analysis_plugins:
                        if plugin.enabled:
                            try:
                                self.queue_query(plugin.run_periodic_analysis)
                            except Exception as e:
                                logger.error(f"Error queueing periodic analysis for {plugin.name}: {e}")
                    
                    self.last_analysis_time = current_time
                    logger.info("Scheduled periodic analysis tasks")
                
                # Sleep for a short time before checking again
                time.sleep(30)
            except Exception as e:
                logger.error(f"Error in periodic analysis thread: {e}")
    
    def close(self):
        """Close connections and stop threads"""
        self.queue_running = False
        
        # Call cleanup method for each plugin
        for plugin in self.analysis_plugins:
            try:
                plugin.cleanup()
            except Exception as e:
                logger.error(f"Error cleaning up plugin {plugin.name}: {e}")
        
        if hasattr(self, 'queue_thread') and self.queue_thread:
            self.queue_thread.join(timeout=2)
        if hasattr(self, 'sync_thread') and self.sync_thread:
            self.sync_thread.join(timeout=2)
        if hasattr(self, 'analysis_thread') and self.analysis_thread:
            self.analysis_thread.join(timeout=2)
        if self.analysis1_conn:
            self.analysis1_conn.close()
        logger.info("Analysis manager closed")

    # Helper methods that can be used by plugins
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
        
    def update_threat_intel(self, ip_address, threat_data):
        """Update threat intelligence data for an IP (compatibility method)"""
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
            logger.info(f"Updated threat intel for {ip_address} (compatibility method)")
            return True
        except Exception as e:
            logger.error(f"Error updating threat intel: {e}")
            return False
        
    def store_ip_geolocation(self, ip_address, geo_data):
        """Store IP geolocation data in the analysis_1.db"""
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
            logger.info(f"Stored geolocation data for {ip_address}")
            return True
        except Exception as e:
            logger.error(f"Error storing geolocation data: {e}")
            return False