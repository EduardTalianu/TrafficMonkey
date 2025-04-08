import sqlite3
import os
import time
import threading
import logging
import queue
import json
import capture_fields  # Import the field definitions

# Configure logging
logger = logging.getLogger('database_manager')

class DatabaseManager:
    def __init__(self, app_root):
        self.app_root = app_root
        self.db_dir = os.path.join(app_root, "db")
        os.makedirs(self.db_dir, exist_ok=True)
        
        # Set up capture database (for writing packet data)
        self.capture_db_path = os.path.join(self.db_dir, "capture.db")
        self.capture_conn = sqlite3.connect(self.capture_db_path, check_same_thread=False)
        
        # Set up analysis database (for querying statistics)
        self.analysis_db_path = os.path.join(self.db_dir, "analysis.db")
        self.analysis_conn = sqlite3.connect(self.analysis_db_path, check_same_thread=False)
        
        # Setup databases
        self._setup_capture_db()
        self._setup_analysis_db()
        
        # Set up synchronization
        self.sync_lock = threading.Lock()
        self.last_sync_time = time.time()
        self.sync_interval = 10  # seconds between syncs
        
        # Set up query queue and processing thread
        self.query_queue = queue.Queue()
        self.queue_running = True
        self.queue_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.queue_thread.start()
        
        # Set up alert queue for fully decoupled alerting
        self.alert_queue = queue.Queue()
        self.alert_processor_running = True
        self.alert_processor_thread = threading.Thread(target=self._process_alerts, daemon=True)
        self.alert_processor_thread.start()
        
        # Set up sync thread
        self.sync_thread = threading.Thread(target=self._sync_thread, daemon=True)
        self.sync_thread.start()
        
        # Check and update schema version
        self._check_schema_version()
        
        # Start periodic connection health checks
        self.check_connection_health()
        
        logger.info("Database manager initialized with separate capture and analysis databases")
    
    
    def _setup_capture_db(self):
        """Set up capture database optimized for writing"""
        cursor = self.capture_conn.cursor()
        try:
            # Enable WAL mode for better write performance
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            
            # Create tables for capture
            self._create_tables(cursor)
            self.capture_conn.commit()
            logger.info("Capture database initialized for write operations")
        finally:
            cursor.close()
    
    def _setup_analysis_db(self):
        """Set up analysis database optimized for reading"""
        cursor = self.analysis_conn.cursor()
        try:
            # Configure for read performance
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA cache_size=10000")
            
            # Create the same tables
            self._create_tables(cursor)
            
            # Add additional indices for query performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_connections_bytes ON connections(total_bytes DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
            self.analysis_conn.commit()
            logger.info("Analysis database initialized for read operations")
        finally:
            cursor.close()
    
    def _check_schema_version(self):
        """Check and update schema version if needed"""
        try:
            # Use dedicated cursors for schema version operations
            capture_cursor = self.capture_conn.cursor()
            
            # Check current version in capture database
            capture_cursor.execute("PRAGMA user_version")
            current_version = capture_cursor.fetchone()[0]
            
            target_version = capture_fields.SCHEMA_VERSION
            
            if current_version < target_version:
                logger.info(f"Updating schema from version {current_version} to {target_version}")
                # For a simple implementation, we just update the version number
                capture_cursor.execute(f"PRAGMA user_version = {target_version}")
                self.capture_conn.commit()
            
            capture_cursor.close()
            
            # Also update analysis database version with its own cursor
            analysis_cursor = self.analysis_conn.cursor()
            analysis_cursor.execute("PRAGMA user_version")
            analysis_version = analysis_cursor.fetchone()[0]
            
            if analysis_version < target_version:
                analysis_cursor.execute(f"PRAGMA user_version = {target_version}")
                self.analysis_conn.commit()
            
            analysis_cursor.close()
        except Exception as e:
            logger.error(f"Error checking schema version: {e}")
    
    def _create_tables(self, cursor):
        """Create tables based on field definitions from capture_fields.py only"""
        # Get table schemas from field definitions
        table_schemas = capture_fields.get_tables_schema()
        
        # Always create the core connections table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS connections (
                connection_key TEXT PRIMARY KEY,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER DEFAULT NULL,
                dst_port INTEGER DEFAULT NULL,
                total_bytes INTEGER DEFAULT 0,
                packet_count INTEGER DEFAULT 0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                vt_result TEXT DEFAULT 'unknown',
                is_rdp_client BOOLEAN DEFAULT 0,
                protocol TEXT DEFAULT NULL,
                ttl INTEGER DEFAULT NULL
            )
        """)
        
        # Create standard indices for the connections table
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_ips 
            ON connections(src_ip, dst_ip)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_ports 
            ON connections(src_port, dst_port)
        """)
        
        # Create alerts table (standard table not derived from field definitions)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT,
                alert_message TEXT,
                rule_name TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_ip 
            ON alerts(ip_address)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_rule
            ON alerts(rule_name)
        """)
        
        # Create tables dynamically based on field definitions
        for table_name, columns in table_schemas.items():
            # Skip connections and alerts tables that were already created
            if table_name in ('connections', 'alerts', 'app_protocols'):
                continue
                
            # Prepare column definitions
            column_defs = []
            
            # Add primary key if it's not defined
            if not any(col["name"] == "id" for col in columns):
                column_defs.append("id INTEGER PRIMARY KEY AUTOINCREMENT")
            
            # Add each column
            for column in columns:
                nullable = "" if column["required"] else " DEFAULT NULL"
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
            
            # Create index on timestamp for most tables
            cursor.execute(f"""
                CREATE INDEX IF NOT EXISTS idx_{table_name}_timestamp 
                ON {table_name}(timestamp)
            """)
        
        # Create port scan tracking table (this is essential for the application)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS port_scan_timestamps (
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                timestamp REAL,
                PRIMARY KEY (src_ip, dst_ip, dst_port)
            )
        """)
        
        # Create application protocols table (essential for protocol detection)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_protocols (
                connection_key TEXT PRIMARY KEY,
                app_protocol TEXT,
                protocol_details TEXT,
                detection_method TEXT,
                timestamp REAL,
                FOREIGN KEY (connection_key) REFERENCES connections (connection_key)
            )
        """)

    def add_http_headers(self, request_id, connection_key, headers_json, is_request=True):
        """Parses headers JSON and adds individual headers to the http_headers table"""
        try:
            cursor = self.capture_conn.cursor()
            current_time = time.time()
            if headers_json:
                headers = json.loads(headers_json)
                for name, value in headers.items():
                    cursor.execute("""
                        INSERT INTO http_headers
                        (connection_key, request_id, header_name, header_value, is_request, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (connection_key, request_id, name, value, is_request, current_time))
            self.capture_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error adding HTTP headers: {e}")
            return False
    
    def _sync_thread(self):
        """Thread that periodically synchronizes databases"""
        logger.info("Database sync thread started")
        while self.queue_running:
            try:
                current_time = time.time()
                if current_time - self.last_sync_time >= self.sync_interval:
                    self.sync_databases()
                
                # Sleep for a short time before checking again
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in sync thread: {e}")
    
    def _process_alerts(self):
        """Process queued alerts in a separate thread with improved transaction handling"""
        while self.alert_processor_running:
            try:
                # Get next alert from queue with a timeout
                alert_data = self.alert_queue.get(timeout=0.5)
                
                if alert_data:
                    ip_address, alert_message, rule_name = alert_data
                    
                    try:
                        # Use our transaction context for proper transaction handling
                        with self.transaction(self.capture_conn) as cursor:
                            cursor.execute("""
                                INSERT INTO alerts (ip_address, alert_message, rule_name)
                                VALUES (?, ?, ?)
                            """, (ip_address, alert_message, rule_name))
                            logger.debug(f"Added alert to capture DB: {alert_message[:50]}...")
                    except Exception as e:
                        # Use message checking to determine if it's a real error
                        error_msg = str(e).lower()
                        if "not an error" in error_msg or "error return without exception set" in error_msg:
                            # These are often not actual errors but SQLite status messages
                            logger.debug(f"Non-critical SQLite message: {e}")
                        else:
                            logger.error(f"Error writing alert to capture DB: {e}")
                    
                    # Mark as done
                    self.alert_queue.task_done()
                    
            except queue.Empty:
                # No alerts in queue, just continue
                pass
            except Exception as e:
                logger.error(f"Error in alert processor: {e}")

    def queue_connection_update(self, connection_key, field, value):
        """Add a connection update to the processing queue"""
        self.query_queue.put((self.update_connection_field, (connection_key, field, value), {}, None))
        logger.debug(f"Queued update for connection {connection_key}, field {field}")
        return True
    
    def get_table_columns(self, conn, table_name):
        """Helper function to get column names and types for a table."""
        cursor = conn.cursor()
        try:
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns_info = cursor.fetchall()
            # Returns list of tuples: (cid, name, type, notnull, default_value, pk)
            return columns_info
        except Exception as e:
            logger.error(f"Error getting columns for table {table_name}: {e}")
            return []
        finally:
            cursor.close()
    
    def _process_queue(self):
        """Process database query queue in a separate thread"""
        logger.info("Query processing thread started")
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
                logger.error(f"Error in queue processor: {e}")
    
    def queue_query(self, query_func, callback=None, *args, **kwargs):
        """Add a query to the processing queue"""
        self.query_queue.put((query_func, args, kwargs, callback))
        logger.debug("Query added to processing queue")
    
    def queue_alert(self, ip_address, alert_message, rule_name):
        """Add an alert to the queue instead of writing directly"""
        try:
            self.alert_queue.put((ip_address, alert_message, rule_name))
            return True
        except Exception as e:
            logger.error(f"Error queuing alert: {e}")
            return False
    
    def add_packet(self, connection_key, src_ip, dst_ip, src_port, dst_port, length, is_rdp=0):
        """Add packet to the capture database (write-only operation)"""
        try:
            cursor = self.capture_conn.cursor()
            cursor.execute("""
                UPDATE connections 
                SET total_bytes = total_bytes + ?,
                    packet_count = packet_count + 1,
                    timestamp = CURRENT_TIMESTAMP
                WHERE connection_key = ?
            """, (length, connection_key))
            
            if cursor.rowcount == 0:
                cursor.execute("""
                    INSERT INTO connections 
                    (connection_key, src_ip, dst_ip, src_port, dst_port, total_bytes, packet_count, is_rdp_client)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """, (connection_key, src_ip, dst_ip, src_port, dst_port, length, is_rdp))
            
            self.capture_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error adding packet: {e}")
            return False
    
    def add_port_scan_data(self, src_ip, dst_ip, dst_port):
        """Update port scan detection data"""
        try:
            cursor = self.capture_conn.cursor()
            current_time = time.time()
            cursor.execute("""
                INSERT OR REPLACE INTO port_scan_timestamps
                (src_ip, dst_ip, dst_port, timestamp)
                VALUES (?, ?, ?, ?)
            """, (src_ip, dst_ip, dst_port, current_time))
            self.capture_conn.commit()  # Commit immediately
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error updating port scan data: {e}")
            return False
    
    def add_dns_query(self, src_ip, query_domain, query_type, response_domain=None, response_type=None):
        """Store DNS query information with optional response fields"""
        try:
            current_time = time.time()
            # Create a dedicated cursor for this operation
            cursor = self.capture_conn.cursor()
            cursor.execute("""
                INSERT INTO dns_queries
                (timestamp, src_ip, query_domain, query_type, response_domain, response_type)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (current_time, src_ip, query_domain, query_type, response_domain, response_type))
            self.capture_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error storing DNS query: {e}")
            return False
    
    def add_icmp_packet(self, src_ip, dst_ip, icmp_type):
        """Store ICMP packet information"""
        try:
            current_time = time.time()
            # Create a dedicated cursor for this operation
            cursor = self.capture_conn.cursor()
            cursor.execute("""
                INSERT INTO icmp_packets
                (src_ip, dst_ip, icmp_type, timestamp)
                VALUES (?, ?, ?, ?)
            """, (src_ip, dst_ip, icmp_type, current_time))
            self.capture_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error storing ICMP packet: {e}")
            return False
    
    def add_alert(self, ip_address, alert_message, rule_name):
        """Add an alert to the capture database (write-only operation) with improved transaction handling"""
        try:
            with self.transaction(self.capture_conn) as cursor:
                cursor.execute("""
                    INSERT INTO alerts (ip_address, alert_message, rule_name)
                    VALUES (?, ?, ?)
                """, (ip_address, alert_message, rule_name))
                return True
        except Exception as e:
            logger.error(f"Error adding alert: {e}")
            return False
        
    def add_http_request(self, connection_key, method, host, uri, version, user_agent, referer, content_type, headers_json, request_size):
        """Store HTTP request information"""
        try:
            cursor = self.capture_conn.cursor()
            current_time = time.time()
            cursor.execute("""
                INSERT INTO http_requests
                (connection_key, timestamp, method, host, uri, version, user_agent, referer, content_type, request_headers, request_size)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (connection_key, current_time, method, host, uri, version, user_agent, referer, content_type, headers_json, request_size))
            
            request_id = cursor.lastrowid
            if headers_json:
                self.add_http_headers(request_id, connection_key, headers_json, is_request=True)
            
            self.capture_conn.commit()
            cursor.close()
            return request_id
        except Exception as e:
            logger.error(f"Error storing HTTP request: {e}")
            return None

    def add_http_response(self, http_request_id, status_code, content_type, content_length, server, headers_json):
        """Store HTTP response information"""
        try:
            current_time = time.time()
            # Create a dedicated cursor for this operation
            cursor = self.capture_conn.cursor()
            cursor.execute("""
                INSERT INTO http_responses
                (http_request_id, status_code, content_type, content_length, server, response_headers, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (http_request_id, status_code, content_type, content_length, server, headers_json, current_time))
            self.capture_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error storing HTTP response: {e}")
            return False

    def add_tls_connection(self, connection_key, tls_version, cipher_suite, server_name, ja3_fingerprint, 
                        ja3s_fingerprint, cert_issuer, cert_subject, cert_valid_from, cert_valid_to, cert_serial):
        """Store TLS connection information"""
        try:
            cursor = self.capture_conn.cursor()
            current_time = time.time()
            cursor.execute("""
                INSERT OR REPLACE INTO tls_connections
                (connection_key, timestamp, tls_version, cipher_suite, server_name, ja3_fingerprint, 
                ja3s_fingerprint, certificate_issuer, certificate_subject, certificate_validity_start, 
                certificate_validity_end, certificate_serial)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (connection_key, current_time, tls_version, cipher_suite, server_name, ja3_fingerprint, 
                ja3s_fingerprint, cert_issuer, cert_subject, cert_valid_from, cert_valid_to, cert_serial))
            self.capture_conn.commit()  # Commit immediately
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error storing TLS connection: {e}")
            return False
        
    def add_arp_data(self, src_ip, dst_ip, operation, timestamp):
        """Store ARP packet information"""
        try:
            cursor = self.capture_conn.cursor()
            cursor.execute("""
                INSERT INTO arp_data
                (timestamp, src_ip, dst_ip, operation, src_mac)
                VALUES (?, ?, ?, ?, ?)
            """, (timestamp, src_ip, dst_ip, operation, None))  # Add NULL for src_mac
            self.capture_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error storing ARP data: {e}")
            return False
        
    def update_connection_ttl(self, connection_key, ttl):
        """Update TTL value for a connection"""
        try:
            cursor = self.capture_conn.cursor()
            cursor.execute("""
                UPDATE connections
                SET ttl = ?
                WHERE connection_key = ?
            """, (ttl, connection_key))
            self.capture_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error updating TTL: {e}")
            return False

    def add_app_protocol(self, connection_key, app_protocol, protocol_details=None, detection_method=None):
        """Store application protocol information with automatic connection creation and improved transaction handling"""
        try:
            with self.transaction(self.capture_conn) as cursor:
                # First check if the connection_key exists
                cursor.execute("SELECT COUNT(*) FROM connections WHERE connection_key = ?", (connection_key,))
                if cursor.fetchone()[0] == 0:
                    # Connection doesn't exist, try to create it from the connection key
                    try:
                        # Parse connection key format: src_ip:src_port->dst_ip:dst_port
                        parts = connection_key.split('->')
                        if len(parts) == 2:
                            src_part = parts[0].split(':')
                            dst_part = parts[1].split(':')
                            
                            if len(src_part) >= 2 and len(dst_part) >= 2:
                                # Extract IP and port
                                src_ip = ':'.join(src_part[:-1])  # Handle IPv6 addresses with colons
                                dst_ip = ':'.join(dst_part[:-1])
                                
                                try:
                                    src_port = int(src_part[-1])
                                    dst_port = int(dst_part[-1])
                                except ValueError:
                                    src_port = 0
                                    dst_port = 0
                                
                                # Create a minimal connection record
                                logger.info(f"Auto-creating connection for {connection_key}")
                                cursor.execute("""
                                    INSERT INTO connections 
                                    (connection_key, src_ip, dst_ip, src_port, dst_port, total_bytes, packet_count)
                                    VALUES (?, ?, ?, ?, ?, 0, 1)
                                """, (connection_key, src_ip, dst_ip, src_port, dst_port))
                            else:
                                logger.warning(f"Couldn't parse IP:port from connection key: {connection_key}")
                                return False
                        else:
                            logger.warning(f"Invalid connection key format: {connection_key}")
                            return False
                    except Exception as e:
                        logger.warning(f"Failed to auto-create connection for key {connection_key}: {e}")
                        return False
                        
                # Insert app protocol info
                current_time = time.time()
                cursor.execute("""
                    INSERT OR REPLACE INTO app_protocols
                    (connection_key, app_protocol, protocol_details, detection_method, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                """, (connection_key, app_protocol, protocol_details, detection_method, current_time))
                
                # Update connection protocol
                cursor.execute("""
                    UPDATE connections
                    SET protocol = ?
                    WHERE connection_key = ?
                """, (app_protocol, connection_key))
                
                return True
        except Exception as e:
            logger.error(f"Error storing application protocol: {e}")
            return False

    def create_connection_key(src_ip, dst_ip, src_port, dst_port):
        """Create a standardized connection key that handles both IPv4 and IPv6"""
        # For IPv6, wrap the address in square brackets to distinguish from port separator
        src_part = f"[{src_ip}]:{src_port}" if ':' in src_ip else f"{src_ip}:{src_port}"
        dst_part = f"[{dst_ip}]:{dst_port}" if ':' in dst_ip else f"{dst_ip}:{dst_port}"
        return f"{src_part}->{dst_part}"
    
    def parse_connection_key(connection_key):
        """Parse a connection key into its components, handling IPv4 and IPv6"""
        try:
            src_part, dst_part = connection_key.split('->')
            
            # Extract source IP and port
            if '[' in src_part and ']' in src_part:  # IPv6
                src_ip = src_part[src_part.find('[')+1:src_part.find(']')]
                src_port_str = src_part[src_part.find(']')+2:]  # +2 to skip ]:
            else:  # IPv4
                src_ip, src_port_str = src_part.rsplit(':', 1)
                
            # Extract destination IP and port
            if '[' in dst_part and ']' in dst_part:  # IPv6
                dst_ip = dst_part[dst_part.find('[')+1:dst_part.find(']')]
                dst_port_str = dst_part[dst_part.find(']')+2:]  # +2 to skip ]:
            else:  # IPv4
                dst_ip, dst_port_str = dst_part.rsplit(':', 1)
                
            # Convert ports to integers
            try:
                src_port = int(src_port_str)
                dst_port = int(dst_port_str)
            except ValueError:
                src_port = 0
                dst_port = 0
                
            return src_ip, dst_ip, src_port, dst_port
        except Exception as e:
            logger.error(f"Failed to parse connection key {connection_key}: {e}")
            return None, None, None, None

    def sync_databases(self):
        """Synchronize data from capture DB to analysis DB with improved table detection and creation"""
        try:
            with self.sync_lock:
                current_time = time.time()
                logger.info("Starting database synchronization")
                sync_count = 0
                tables_created = 0
                
                # Create dedicated cursors for synchronization
                sync_capture_cursor = self.capture_conn.cursor()
                sync_analysis_cursor = self.analysis_conn.cursor()
                
                # Begin transaction on analysis DB
                self.analysis_conn.execute("BEGIN TRANSACTION")
                
                # Get all tables from capture database
                sync_capture_cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
                )
                all_tables = [row[0] for row in sync_capture_cursor.fetchall()]
                logger.info(f"Found {len(all_tables)} tables to synchronize: {', '.join(all_tables)}")
                
                # Sync each table
                for table_name in all_tables:
                    try:
                        # Check if table exists in analysis DB - if not, create it
                        sync_analysis_cursor.execute(
                            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                            (table_name,)
                        )
                        table_exists = sync_analysis_cursor.fetchone() is not None
                        
                        if not table_exists:
                            logger.info(f"Table {table_name} missing in analysis DB - creating it")
                            
                            # Get table creation SQL from capture DB
                            sync_capture_cursor.execute(
                                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                                (table_name,)
                            )
                            create_table_sql = sync_capture_cursor.fetchone()
                            
                            if create_table_sql and create_table_sql[0]:
                                # Execute the CREATE TABLE statement on analysis DB
                                sync_analysis_cursor.execute(create_table_sql[0])
                                tables_created += 1
                                
                                # Also create any indices for this table
                                sync_capture_cursor.execute(
                                    "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name=? AND sql IS NOT NULL",
                                    (table_name,)
                                )
                                for index_row in sync_capture_cursor.fetchall():
                                    if index_row[0]:
                                        try:
                                            sync_analysis_cursor.execute(index_row[0])
                                        except Exception as e:
                                            logger.warning(f"Error creating index for {table_name}: {e}")
                        
                        # Special case for ARP data table
                        if table_name == 'arp_data':
                            logger.info("Performing special sync for ARP data table")
                            # For ARP, just get all records regardless of timestamp
                            sync_capture_cursor.execute("SELECT * FROM arp_data")
                            
                            # Delete existing records in analysis DB
                            if table_exists:
                                sync_analysis_cursor.execute("DELETE FROM arp_data")
                                logger.info("Cleared existing ARP data in analysis DB")
                        else:
                            # For other tables, use timestamp-based sync
                            # Get column info for the current table
                            columns_info = self.get_table_columns(self.capture_conn, table_name)
                            if not columns_info:
                                logger.warning(f"Could not get column info for table {table_name}. Skipping.")
                                continue
                            
                            column_names = [col[1] for col in columns_info]
                            column_types = {col[1]: col[2] for col in columns_info}
                            
                            # Determine sync strategy based on table structure
                            if 'timestamp' in column_names and table_exists:
                                # For timestamp-based tables, use incremental sync
                                if column_types.get('timestamp', '').upper() in ['REAL', 'INTEGER', 'NUMERIC', 'NUMBER']:
                                    # Numeric timestamp (epoch)
                                    last_timestamp = sync_analysis_cursor.execute(
                                        f"SELECT MAX(timestamp) FROM {table_name}"
                                    ).fetchone()[0] or 0
                                    
                                    # Get new records from capture DB
                                    sync_capture_cursor.execute(
                                        f"SELECT * FROM {table_name} WHERE timestamp > ?", 
                                        (last_timestamp,)
                                    )
                                else:
                                    # Text/date timestamp
                                    last_timestamp = sync_analysis_cursor.execute(
                                        f"SELECT MAX(timestamp) FROM {table_name}"
                                    ).fetchone()[0] or '1970-01-01'
                                    
                                    # Get new records from capture DB
                                    sync_capture_cursor.execute(
                                        f"SELECT * FROM {table_name} WHERE timestamp > datetime(?)", 
                                        (last_timestamp,)
                                    )
                            else:
                                # For tables without timestamp or new tables, sync all records
                                sync_capture_cursor.execute(f"SELECT * FROM {table_name}")
                        
                        # Process query results
                        if sync_capture_cursor.description:
                            fetch_column_names = [desc[0] for desc in sync_capture_cursor.description]
                            
                            # Process rows from capture DB
                            rows = sync_capture_cursor.fetchall()
                            
                            for row in rows:
                                try:
                                    # Construct column-specific insert to handle schema differences
                                    placeholders = ", ".join(["?"] * len(fetch_column_names))
                                    column_names_str = ", ".join(fetch_column_names)
                                    
                                    query = f"INSERT OR REPLACE INTO {table_name} ({column_names_str}) VALUES ({placeholders})"
                                    sync_analysis_cursor.execute(query, row)
                                    sync_count += 1
                                except Exception as e:
                                    logger.error(f"Error syncing row in {table_name}: {e}")
                            
                            logger.info(f"Synchronized {len(rows)} records from table {table_name}")
                    except Exception as e:
                        logger.error(f"Error syncing table {table_name}: {e}")
                
                # Commit the transaction
                self.analysis_conn.commit()
                self.last_sync_time = current_time
                
                # Close the sync-specific cursors
                sync_capture_cursor.close()
                sync_analysis_cursor.close()
                
                if tables_created > 0:
                    logger.info(f"Created {tables_created} missing tables in analysis database")
                logger.info(f"Synchronized {sync_count} records between databases")
                
                return sync_count
                    
        except Exception as e:
            # Rollback on error
            try:
                self.analysis_conn.rollback()
            except:
                pass
            logger.error(f"Database sync error: {e}")
            import traceback
            traceback.print_exc()
            return 0
    
    def clear_alerts(self):
        """Clear all alerts from both databases"""
        try:
            # Use dedicated cursor for capture DB
            capture_cursor = self.capture_conn.cursor()
            capture_cursor.execute("DELETE FROM alerts")
            self.capture_conn.commit()
            capture_cursor.close()
            
            # Use dedicated cursor for analysis DB
            analysis_cursor = self.analysis_conn.cursor()
            analysis_cursor.execute("DELETE FROM alerts")
            self.analysis_conn.commit()
            analysis_cursor.close()
            
            return True
        except Exception as e:
            logger.error(f"Error clearing alerts: {e}")
            return False
    
    def commit_capture(self):
        """Commit changes to the capture database"""
        try:
            self.capture_conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error committing to capture DB: {e}")
            return False
    
    def get_cursor_for_rules(self):
        """Get a dedicated cursor to the analysis database for rules to use"""
        return self.analysis_conn.cursor()
    
    def update_connection_field(self, connection_key, field, value):
        """Update a specific field in the connections table (used by rules) with improved error handling"""
        try:
            with self.transaction(self.capture_conn) as cursor:
                cursor.execute(
                    f"UPDATE connections SET {field} = ? WHERE connection_key = ?",
                    (value, connection_key)
                )
                return True
        except Exception as e:
            # Distinguish between real errors and "not an error" conditions
            error_msg = str(e).lower()
            if "not an error" in error_msg or "error return without exception set" in error_msg:
                # These are often not actual errors but SQLite status messages
                logger.debug(f"Non-critical SQLite message: {e}")
                return True
            logger.error(f"Error updating connection field: {e}")
            return False
        
    def check_connection_health(self):
        """Check database connections health and reconnect if needed"""
        try:
            # Check capture database connection
            if not self._ensure_connection_valid(self.capture_conn):
                logger.warning("Capture database connection was reset")
            
            # Check analysis database connection
            if not self._ensure_connection_valid(self.analysis_conn):
                logger.warning("Analysis database connection was reset")
                
            # Schedule periodic health checks (every 5 minutes)
            if self.queue_running:
                threading.Timer(300, self.check_connection_health).start()
                
            return True
        except Exception as e:
            logger.error(f"Error in connection health check: {e}")
            return False

    def _ensure_connection_valid(self, conn):
        """Ensure the database connection is valid and reconnect if needed"""
        try:
            # Try a simple query to check connection
            conn.execute("SELECT 1").fetchone()
            return True
        except Exception:
            try:
                # Try to recreate the connection
                if conn == self.capture_conn:
                    old_conn = self.capture_conn
                    # Create new connection
                    self.capture_conn = sqlite3.connect(self.capture_db_path, check_same_thread=False)
                    self.capture_conn.execute("PRAGMA journal_mode=WAL")
                    self.capture_conn.execute("PRAGMA synchronous=NORMAL")
                    # Close old connection if possible
                    try:
                        old_conn.close()
                    except:
                        pass
                    return True
                elif conn == self.analysis_conn:
                    old_conn = self.analysis_conn
                    # Create new connection
                    self.analysis_conn = sqlite3.connect(self.analysis_db_path, check_same_thread=False)
                    self.analysis_conn.execute("PRAGMA journal_mode=WAL")
                    self.analysis_conn.execute("PRAGMA synchronous=NORMAL")
                    self.analysis_conn.execute("PRAGMA cache_size=10000")
                    # Close old connection if possible
                    try:
                        old_conn.close()
                    except:
                        pass
                    return True
            except Exception as e:
                logger.error(f"Failed to reconnect to database: {e}")
                return False
                
        return False
    
    def close(self):
        """Close all database connections and stop all threads"""
        try:
            # Stop all threads
            self.queue_running = False
            self.alert_processor_running = False
            
            if self.queue_thread:
                self.queue_thread.join(timeout=2)
            if self.sync_thread:
                self.sync_thread.join(timeout=2)
            if self.alert_processor_thread:
                self.alert_processor_thread.join(timeout=2)
            
            # Close connections
            if self.capture_conn:
                self.capture_conn.close()
            if self.analysis_conn:
                self.analysis_conn.close()
                
            logger.info("Database connections and threads closed")
        except Exception as e:
            logger.error(f"Error closing database connections: {e}")
    
    def transaction(self, connection):
        """Return a transaction context manager for the given connection"""
        return TransactionContext(connection)
            
class TransactionContext:
    """Enhanced context manager for database transactions with better error handling"""
    def __init__(self, connection):
        self.connection = connection
        self.cursor = None
        self.transaction_active = False
        
    def __enter__(self):
        self.cursor = self.connection.cursor()
        
        # Check if a transaction is already active
        try:
            # Try to check if we're in a transaction by running a simple query
            self.cursor.execute("SELECT 1")
            
            # Start a transaction if one isn't already active
            try:
                self.cursor.execute("BEGIN TRANSACTION")
                self.transaction_active = True
            except sqlite3.OperationalError as e:
                if "already a transaction in progress" in str(e) or "cannot start a transaction within a transaction" in str(e):
                    # Transaction already active, we'll use it but not commit/rollback
                    logger.debug("Using existing transaction")
                    self.transaction_active = False
                else:
                    # Some other error occurred
                    raise
        except Exception as e:
            logger.error(f"Error starting transaction: {e}")
            if self.cursor:
                self.cursor.close()
                self.cursor = None
            raise
            
        return self.cursor
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if self.transaction_active:
                if exc_type is None:
                    # No exception occurred, commit the transaction
                    try:
                        self.connection.commit()
                    except sqlite3.OperationalError as e:
                        if "cannot commit - no transaction is active" in str(e):
                            logger.debug("No transaction to commit")
                        else:
                            logger.error(f"Transaction commit error: {e}")
                            raise
                else:
                    # An exception occurred, roll back
                    try:
                        self.connection.rollback()
                    except sqlite3.OperationalError as e:
                        if "cannot rollback - no transaction is active" in str(e):
                            logger.debug("No transaction to rollback")
                        else:
                            logger.error(f"Transaction rollback error: {e}")
                
                if exc_type:
                    logger.error(f"Transaction error: {exc_val}")
        finally:
            # Always close the cursor
            if self.cursor:
                self.cursor.close()
                self.cursor = None
        
        # Don't suppress exceptions
        return False