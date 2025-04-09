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
import capture_fields  # Import the centralized schema

# Configure logging
logger = logging.getLogger('analysis_manager')

# Define extended table definitions specific to analysis_1.db
EXTENDED_TABLE_DEFINITIONS = {
    # Tables moved from capture.db to analysis_1.db
    "x_alerts": [
        {"name": "id", "type": "INTEGER PRIMARY KEY AUTOINCREMENT", "required": True},
        {"name": "ip_address", "type": "TEXT", "required": True},
        {"name": "alert_message", "type": "TEXT", "required": True},
        {"name": "rule_name", "type": "TEXT", "required": True},
        {"name": "timestamp", "type": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP", "required": True}
    ],
    "x_port_scans": [
        {"name": "src_ip", "type": "TEXT", "required": True},
        {"name": "dst_ip", "type": "TEXT", "required": True},
        {"name": "dst_port", "type": "INTEGER", "required": True},
        {"name": "timestamp", "type": "REAL", "required": True}
    ],
    "x_app_protocols": [
        {"name": "connection_key", "type": "TEXT PRIMARY KEY", "required": True},
        {"name": "app_protocol", "type": "TEXT", "required": True},
        {"name": "protocol_details", "type": "TEXT", "required": False},
        {"name": "detection_method", "type": "TEXT", "required": False},
        {"name": "timestamp", "type": "REAL", "required": True}
    ],
    # Original analytics tables
    "x_ip_geolocation": [
        {"name": "ip_address", "type": "TEXT PRIMARY KEY", "required": True},
        {"name": "country", "type": "TEXT", "required": False},
        {"name": "region", "type": "TEXT", "required": False},
        {"name": "city", "type": "TEXT", "required": False},
        {"name": "latitude", "type": "REAL", "required": False},
        {"name": "longitude", "type": "REAL", "required": False},
        {"name": "asn", "type": "TEXT", "required": False},
        {"name": "asn_name", "type": "TEXT", "required": False},
        {"name": "last_updated", "type": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP", "required": True}
    ],
    "x_ip_threat_intel": [
        {"name": "ip_address", "type": "TEXT PRIMARY KEY", "required": True},
        {"name": "threat_score", "type": "REAL DEFAULT 0", "required": False},
        {"name": "threat_type", "type": "TEXT", "required": False},
        {"name": "confidence", "type": "REAL DEFAULT 0", "required": False},
        {"name": "source", "type": "TEXT", "required": False},
        {"name": "first_seen", "type": "TIMESTAMP", "required": False},
        {"name": "last_seen", "type": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP", "required": True},
        {"name": "details", "type": "TEXT", "required": False}
    ],
    "x_traffic_patterns": [
        {"name": "connection_key", "type": "TEXT PRIMARY KEY", "required": True},
        {"name": "avg_packet_size", "type": "REAL", "required": False},
        {"name": "std_dev_packet_size", "type": "REAL", "required": False},
        {"name": "packet_size_distribution", "type": "TEXT", "required": False},
        {"name": "periodic_score", "type": "REAL DEFAULT 0", "required": False},
        {"name": "burst_score", "type": "REAL DEFAULT 0", "required": False},
        {"name": "direction_ratio", "type": "REAL", "required": False},
        {"name": "session_count", "type": "INTEGER DEFAULT 1", "required": False},
        {"name": "first_seen", "type": "TIMESTAMP", "required": False},
        {"name": "last_seen", "type": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP", "required": True},
        {"name": "classification", "type": "TEXT", "required": False}
    ],
    "x_connection_statistics": [
        {"name": "id", "type": "INTEGER PRIMARY KEY AUTOINCREMENT", "required": True},
        {"name": "timestamp", "type": "REAL", "required": True},
        {"name": "total_connections", "type": "INTEGER", "required": False},
        {"name": "active_connections", "type": "INTEGER", "required": False},
        {"name": "total_bytes", "type": "REAL", "required": False},
        {"name": "unique_src_ips", "type": "INTEGER", "required": False},
        {"name": "unique_dst_ips", "type": "INTEGER", "required": False},
        {"name": "rdp_connections", "type": "INTEGER", "required": False},
        {"name": "http_connections", "type": "INTEGER", "required": False},
        {"name": "https_connections", "type": "INTEGER", "required": False},
        {"name": "dns_queries", "type": "INTEGER", "required": False}
    ]
}

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
    
    def _setup_analysis1_db(self):
        """Set up analysis_1 database tables with centralized and extended schema"""
        cursor = self.analysis1_conn.cursor()
        try:
            # Configure for performance
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA cache_size=10000")
            
            # Get integrated schema merging core and extended tables
            integrated_schema = capture_fields.get_integrated_schema(EXTENDED_TABLE_DEFINITIONS)
            
            # Create all tables from the integrated schema
            tables_created = []
            for table_name, columns in integrated_schema.items():
                # Prepare column definitions
                column_defs = []
                
                # Add primary key if it's not defined
                if not any(col["name"] == "id" for col in columns if "PRIMARY KEY" in col.get("type", "")):
                    has_pk = any("PRIMARY KEY" in col.get("type", "") for col in columns)
                    if not has_pk:
                        column_defs.append("id INTEGER PRIMARY KEY AUTOINCREMENT")
                
                # Add each column
                for column in columns:
                    # Skip if already added (e.g., id column)
                    if column["name"] == "id" and "id INTEGER PRIMARY KEY AUTOINCREMENT" in column_defs:
                        continue
                        
                    nullable = "" if column.get("required", False) else " DEFAULT NULL"
                    column_defs.append(f"{column['name']} {column['type']}{nullable}")
                
                # Add timestamp if not already included
                if not any(col["name"] == "timestamp" for col in columns):
                    column_defs.append("timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                
                # Create the table
                create_table_sql = f"""
                    CREATE TABLE IF NOT EXISTS {table_name} (
                        {', '.join(column_defs)}
                    )
                """
                cursor.execute(create_table_sql)
                tables_created.append(table_name)
            
            logger.info(f"Created {len(tables_created)} tables in analysis_1.db")
            
            # Create standard indices for core tables
            capture_fields.create_standard_indices(cursor)
            
            # Create additional indices for extended tables
            self._create_extended_indices(cursor)
            
            self.analysis1_conn.commit()
            logger.info("Analysis_1 database tables initialized with integrated schema")
        finally:
            cursor.close()
    
    def _create_extended_indices(self, cursor):
        """Create indices for extended tables"""
        # Indices for tables moved from capture.db
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_alerts_ip ON x_alerts(ip_address)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_alerts_rule ON x_alerts(rule_name)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_alerts_timestamp ON x_alerts(timestamp DESC)")
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_port_scans_src ON x_port_scans(src_ip)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_port_scans_dst ON x_port_scans(dst_ip, dst_port)")
        
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_app_protocols_protocol ON x_app_protocols(app_protocol)")
        
        # IP geolocation indices
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_geolocation_country ON x_ip_geolocation(country)")
        
        # Threat intelligence indices
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_threat_score ON x_ip_threat_intel(threat_score DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_threat_type ON x_ip_threat_intel(threat_type)")
        
        # Traffic patterns indices
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_traffic_pattern_periodic ON x_traffic_patterns(periodic_score DESC)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_traffic_pattern_class ON x_traffic_patterns(classification)")
        
        # Connection statistics indices
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_conn_stats_time ON x_connection_statistics(timestamp)")
    
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
                    'connections',
                    'app_protocols',    # Added this table
                    'http_headers',     # Added this table
                    'port_scan_timestamps',
                    'smb_files'
                ]
                
                # Use dedicated connections for sync
                analysis_conn = self.db_manager.analysis_conn
                analysis1_conn = self.analysis1_conn
                
                # Begin transaction for better performance
                analysis1_conn.execute("BEGIN TRANSACTION")
                
                for table in tables:
                    try:
                        # Check if table exists in source database
                        if not capture_fields.table_exists(analysis_conn.cursor(), table):
                            logger.info(f"Table {table} not found in analysis.db, skipping")
                            continue
                        
                        # Check if table exists in destination database
                        if not capture_fields.table_exists(analysis1_conn.cursor(), table):
                            # Create table in destination if it doesn't exist
                            logger.info(f"Table {table} not found in analysis_1.db, creating it")
                            
                            # Get schema from source
                            source_cursor = analysis_conn.cursor()
                            source_cursor.execute(
                                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                                (table,)
                            )
                            create_table_sql = source_cursor.fetchone()
                            
                            if create_table_sql and create_table_sql[0]:
                                dest_cursor = analysis1_conn.cursor()
                                dest_cursor.execute(create_table_sql[0])
                                logger.info(f"Created table {table} in analysis_1.db")
                        
                        # Get sync identifier column (prefer 'id' or 'timestamp')
                        sync_column = 'id'  # Default
                        
                        # Check if 'id' column exists
                        columns = capture_fields.get_table_columns(analysis_conn.cursor(), table)
                        column_names = [col[1] for col in columns]  # Column name is at index 1
                        
                        if 'id' not in column_names and 'timestamp' in column_names:
                            sync_column = 'timestamp'
                        
                        # Get last synced value
                        source_cursor = analysis_conn.cursor()
                        dest_cursor = analysis1_conn.cursor()
                        
                        if sync_column == 'id':
                            dest_cursor.execute(f"SELECT MAX({sync_column}) FROM {table}")
                            last_value = dest_cursor.fetchone()[0] or 0
                            
                            # Get new records from analysis.db
                            source_cursor.execute(f"SELECT * FROM {table} WHERE {sync_column} > ?", (last_value,))
                        else:  # timestamp-based sync
                            dest_cursor.execute(f"SELECT MAX({sync_column}) FROM {table}")
                            last_timestamp = dest_cursor.fetchone()[0] or 0
                            
                            # Get new records from analysis.db
                            source_cursor.execute(f"SELECT * FROM {table} WHERE {sync_column} > ?", (last_timestamp,))
                        
                        # Get column names from source database
                        columns = [desc[0] for desc in source_cursor.description]
                        
                        # Process rows
                        rows = source_cursor.fetchall()
                        if rows:
                            # Prepare SQL for insertion
                            columns_str = ', '.join(columns)
                            placeholders = ', '.join(['?' for _ in columns])
                            
                            # Insert rows into destination
                            for row in rows:
                                try:
                                    dest_cursor.execute(
                                        f"INSERT OR IGNORE INTO {table} ({columns_str}) VALUES ({placeholders})",
                                        row
                                    )
                                    sync_count += 1
                                except Exception as e:
                                    logger.error(f"Error inserting row into {table}: {e}")
                            
                            logger.info(f"Synchronized {len(rows)} records from {table}")
                        
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
        """Add an alert to analysis_1.db in the x_alerts table"""
        try:
            cursor = self.analysis1_conn.cursor()
            cursor.execute("""
                INSERT INTO x_alerts (ip_address, alert_message, rule_name)
                VALUES (?, ?, ?)
            """, (ip_address, alert_message, rule_name))
            self.analysis1_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error adding alert: {e}")
            return False
        
    def add_port_scan_data(self, src_ip, dst_ip, dst_port):
        """Store port scan detection data in x_port_scans table"""
        try:
            cursor = self.analysis1_conn.cursor()
            current_time = time.time()
            cursor.execute("""
                INSERT OR REPLACE INTO x_port_scans
                (src_ip, dst_ip, dst_port, timestamp)
                VALUES (?, ?, ?, ?)
            """, (src_ip, dst_ip, dst_port, current_time))
            self.analysis1_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error updating port scan data: {e}")
            return False
    
    def add_app_protocol(self, connection_key, app_protocol, protocol_details=None, detection_method=None):
        """Store application protocol information in x_app_protocols table"""
        try:
            cursor = self.analysis1_conn.cursor()
            current_time = time.time()
            cursor.execute("""
                INSERT OR REPLACE INTO x_app_protocols
                (connection_key, app_protocol, protocol_details, detection_method, timestamp)
                VALUES (?, ?, ?, ?, ?)
            """, (connection_key, app_protocol, protocol_details, detection_method, current_time))
            self.analysis1_conn.commit()
            cursor.close()
            
            # Also update the protocol field in connections table for backward compatibility
            if self.db_manager:
                self.db_manager.queue_query(
                    self.db_manager.update_connection_field,
                    None,
                    connection_key, 
                    "protocol", 
                    app_protocol
                )
            
            return True
        except Exception as e:
            logger.error(f"Error storing application protocol: {e}")
            return False
        
    def clear_alerts(self):
        """Clear all alerts from x_alerts table"""
        try:
            cursor = self.analysis1_conn.cursor()
            cursor.execute("DELETE FROM x_alerts")
            self.analysis1_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error clearing alerts: {e}")
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
                INSERT OR REPLACE INTO x_ip_threat_intel
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
                INSERT OR REPLACE INTO x_ip_geolocation
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