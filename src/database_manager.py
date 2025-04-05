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
                protocol TEXT DEFAULT NULL
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
        """Process queued alerts in a separate thread"""
        while self.alert_processor_running:
            try:
                # Get next alert from queue with a timeout
                alert_data = self.alert_queue.get(timeout=0.5)
                
                if alert_data:
                    ip_address, alert_message, rule_name = alert_data
                    
                    # Write alert to capture database with a dedicated cursor
                    try:
                        cursor = self.capture_conn.cursor()
                        cursor.execute("""
                            INSERT INTO alerts (ip_address, alert_message, rule_name)
                            VALUES (?, ?, ?)
                        """, (ip_address, alert_message, rule_name))
                        self.capture_conn.commit()
                        cursor.close()
                        logger.debug(f"Added alert to capture DB: {alert_message[:50]}...")
                    except Exception as e:
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
    
    def sync_databases(self):
        """Synchronize data from capture DB to analysis DB with improved reliability"""
        try:
            with self.sync_lock:
                current_time = time.time()
                logger.info("Starting database synchronization")
                sync_count = 0
                
                # Create dedicated cursors for synchronization
                sync_capture_cursor = self.capture_conn.cursor()
                sync_analysis_cursor = self.analysis_conn.cursor()
                
                # Begin transaction on analysis DB
                self.analysis_conn.execute("BEGIN TRANSACTION")
                
                # Sync connections table
                last_timestamp = sync_analysis_cursor.execute(
                    "SELECT MAX(timestamp) FROM connections"
                ).fetchone()[0] or '1970-01-01'
                
                # Get new connections from capture DB
                sync_capture_cursor.execute(
                    "SELECT * FROM connections WHERE timestamp > datetime(?)", 
                    (last_timestamp,)
                )
                
                for row in sync_capture_cursor.fetchall():
                    try:
                        # Get column count to ensure we use the right number of placeholders
                        column_count = len(row)
                        placeholders = ", ".join(["?"] * column_count)
                        query = f"INSERT OR REPLACE INTO connections VALUES ({placeholders})"
                        sync_analysis_cursor.execute(query, row)
                        sync_count += 1
                    except Exception as e:
                        logger.error(f"Error syncing connections row: {e}")
                
                # Sync TLS connections table - special handling for better compatibility
                last_tls_timestamp = sync_analysis_cursor.execute(
                    "SELECT MAX(timestamp) FROM tls_connections"
                ).fetchone()[0] or 0
                
                sync_capture_cursor.execute(
                    "SELECT * FROM tls_connections WHERE timestamp > ?",
                    (last_tls_timestamp,)
                )
                
                # First get column names to ensure we handle any schema differences
                tls_columns = [column[0] for column in sync_capture_cursor.description]
                
                for row in sync_capture_cursor.fetchall():
                    try:
                        # Construct column-specific insert to handle potential schema differences
                        column_names = ", ".join(tls_columns)
                        placeholders = ", ".join(["?"] * len(tls_columns))
                        query = f"INSERT OR REPLACE INTO tls_connections ({column_names}) VALUES ({placeholders})"
                        sync_analysis_cursor.execute(query, row)
                        sync_count += 1
                    except Exception as e:
                        logger.error(f"Error syncing TLS connection: {e}")
                
                # Similar approach for HTTP requests and responses
                # HTTP requests
                last_http_timestamp = sync_analysis_cursor.execute(
                    "SELECT MAX(timestamp) FROM http_requests"
                ).fetchone()[0] or 0
                
                sync_capture_cursor.execute(
                    "SELECT * FROM http_requests WHERE timestamp > ?",
                    (last_http_timestamp,)
                )
                
                http_req_columns = [column[0] for column in sync_capture_cursor.description]
                
                for row in sync_capture_cursor.fetchall():
                    try:
                        column_names = ", ".join(http_req_columns)
                        placeholders = ", ".join(["?"] * len(http_req_columns))
                        query = f"INSERT OR REPLACE INTO http_requests ({column_names}) VALUES ({placeholders})"
                        sync_analysis_cursor.execute(query, row)
                        sync_count += 1
                    except Exception as e:
                        logger.error(f"Error syncing HTTP request: {e}")
                
                # Sync all other tables normally
                # Sync alerts table
                last_alert_timestamp = sync_analysis_cursor.execute(
                    "SELECT MAX(timestamp) FROM alerts"
                ).fetchone()[0] or '1970-01-01'
                
                sync_capture_cursor.execute(
                    "SELECT * FROM alerts WHERE timestamp > datetime(?)",
                    (last_alert_timestamp,)
                )
                
                for row in sync_capture_cursor.fetchall():
                    try:
                        column_count = len(row)
                        placeholders = ", ".join(["?"] * column_count)
                        query = f"INSERT OR REPLACE INTO alerts VALUES ({placeholders})"
                        sync_analysis_cursor.execute(query, row)
                        sync_count += 1
                    except Exception as e:
                        logger.error(f"Error syncing alert: {e}")
                
                # After all syncing is done, perform DNS resolution for TLS connections
                # that have IP addresses instead of hostnames
                resolved = self.resolve_domain_names(sync_analysis_cursor)
                if resolved > 0:
                    logger.info(f"Resolved {resolved} domain names")
                    sync_count += resolved
                
                # Commit the transaction
                self.analysis_conn.commit()
                self.last_sync_time = current_time
                
                # Close the sync-specific cursors
                sync_capture_cursor.close()
                sync_analysis_cursor.close()
                
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
    
    def add_dns_query(self, src_ip, query_domain, query_type):
        """Store DNS query information"""
        try:
            current_time = time.time()
            # Create a dedicated cursor for this operation
            cursor = self.capture_conn.cursor()
            cursor.execute("""
                INSERT INTO dns_queries
                (timestamp, src_ip, query_domain, query_type)
                VALUES (?, ?, ?, ?)
            """, (current_time, src_ip, query_domain, query_type))
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
        """Add an alert to the capture database (write-only operation)"""
        try:
            cursor = self.capture_conn.cursor()
            cursor.execute("""
                INSERT INTO alerts (ip_address, alert_message, rule_name)
                VALUES (?, ?, ?)
            """, (ip_address, alert_message, rule_name))
            self.capture_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error adding alert: {e}")
            try:
                # Try to rollback in case of error
                self.capture_conn.rollback()
            except:
                pass
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

    def add_app_protocol(self, connection_key, app_protocol, protocol_details=None, detection_method=None):
        """Store application protocol information"""
        cursor = None
        try:
            cursor = self.capture_conn.cursor()
            current_time = time.time()
            
            # First check if the connection_key exists
            cursor.execute("SELECT COUNT(*) FROM connections WHERE connection_key = ?", (connection_key,))
            if cursor.fetchone()[0] == 0:
                logger.warning(f"Connection key {connection_key} not found, cannot add protocol")
                return False
                
            # Insert app protocol info
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
            
            self.capture_conn.commit()
            return True
        except Exception as e:
            logger.error(f"Error storing application protocol: {e}")
            try:
                if self.capture_conn:
                    self.capture_conn.rollback()
            except:
                pass
            return False
        finally:
            if cursor:
                cursor.close()

    def sync_databases(self):
        """Synchronize data from capture DB to analysis DB"""
        try:
            with self.sync_lock:
                current_time = time.time()
                logger.info("Starting database synchronization")
                sync_count = 0
                
                # Create dedicated cursors for synchronization
                sync_capture_cursor = self.capture_conn.cursor()
                sync_analysis_cursor = self.analysis_conn.cursor()
                
                # Begin transaction on analysis DB
                self.analysis_conn.execute("BEGIN TRANSACTION")
                
                # Sync connections table
                last_timestamp = sync_analysis_cursor.execute(
                    "SELECT MAX(timestamp) FROM connections"
                ).fetchone()[0] or '1970-01-01'
                
                # Get new connections from capture DB
                sync_capture_cursor.execute(
                    "SELECT * FROM connections WHERE timestamp > datetime(?)", 
                    (last_timestamp,)
                )
                
                for row in sync_capture_cursor.fetchall():
                    # Get column count to ensure we use the right number of placeholders
                    column_count = len(row)
                    placeholders = ", ".join(["?"] * column_count)
                    query = f"INSERT OR REPLACE INTO connections VALUES ({placeholders})"
                    sync_analysis_cursor.execute(query, row)
                    sync_count += 1
                
                # Sync alerts table
                last_alert_timestamp = sync_analysis_cursor.execute(
                    "SELECT MAX(timestamp) FROM alerts"
                ).fetchone()[0] or '1970-01-01'
                
                sync_capture_cursor.execute(
                    "SELECT * FROM alerts WHERE timestamp > datetime(?)",
                    (last_alert_timestamp,)
                )
                
                for row in sync_capture_cursor.fetchall():
                    # Get column count to ensure we use the right number of placeholders
                    column_count = len(row)
                    placeholders = ", ".join(["?"] * column_count)
                    query = f"INSERT OR REPLACE INTO alerts VALUES ({placeholders})"
                    sync_analysis_cursor.execute(query, row)
                    sync_count += 1
                
                # Sync port_scan_timestamps table
                sync_capture_cursor.execute("SELECT * FROM port_scan_timestamps")
                for row in sync_capture_cursor.fetchall():
                    # Get column count to ensure we use the right number of placeholders
                    column_count = len(row)
                    placeholders = ", ".join(["?"] * column_count)
                    query = f"INSERT OR REPLACE INTO port_scan_timestamps VALUES ({placeholders})"
                    sync_analysis_cursor.execute(query, row)
                    sync_count += 1
                
                # Sync dns_queries table (last 24 hours only)
                day_ago = time.time() - 86400
                sync_capture_cursor.execute(
                    "SELECT * FROM dns_queries WHERE timestamp > ?",
                    (day_ago,)
                )
                
                # Clear old DNS queries from analysis DB
                sync_analysis_cursor.execute(
                    "DELETE FROM dns_queries WHERE timestamp < ?",
                    (day_ago,)
                )
                
                for row in sync_capture_cursor.fetchall():
                    # Get column count to ensure we use the right number of placeholders
                    column_count = len(row)
                    placeholders = ", ".join(["?"] * column_count)
                    query = f"INSERT OR REPLACE INTO dns_queries VALUES ({placeholders})"
                    sync_analysis_cursor.execute(query, row)
                    sync_count += 1
                
                # Sync icmp_packets table (last 24 hours only)
                sync_capture_cursor.execute(
                    "SELECT * FROM icmp_packets WHERE timestamp > ?",
                    (day_ago,)
                )
                
                # Clear old ICMP packets from analysis DB
                sync_analysis_cursor.execute(
                    "DELETE FROM icmp_packets WHERE timestamp < ?",
                    (day_ago,)
                )
                
                for row in sync_capture_cursor.fetchall():
                    # Get column count to ensure we use the right number of placeholders
                    column_count = len(row)
                    placeholders = ", ".join(["?"] * column_count)
                    query = f"INSERT OR REPLACE INTO icmp_packets VALUES ({placeholders})"
                    sync_analysis_cursor.execute(query, row)
                    sync_count += 1
                    
                # Sync HTTP requests (new)
                last_http_timestamp = sync_analysis_cursor.execute(
                    "SELECT MAX(timestamp) FROM http_requests"
                ).fetchone()[0] or 0
                
                sync_capture_cursor.execute(
                    "SELECT * FROM http_requests WHERE timestamp > ?",
                    (last_http_timestamp,)
                )
                
                for row in sync_capture_cursor.fetchall():
                    # Get column count to ensure we use the right number of placeholders
                    column_count = len(row)
                    placeholders = ", ".join(["?"] * column_count)
                    query = f"INSERT OR REPLACE INTO http_requests VALUES ({placeholders})"
                    sync_analysis_cursor.execute(query, row)
                    sync_count += 1
                
                # Sync HTTP responses (new)
                last_http_resp_timestamp = sync_analysis_cursor.execute(
                    "SELECT MAX(timestamp) FROM http_responses"
                ).fetchone()[0] or 0
                
                sync_capture_cursor.execute(
                    "SELECT * FROM http_responses WHERE timestamp > ?",
                    (last_http_resp_timestamp,)
                )
                
                for row in sync_capture_cursor.fetchall():
                    # Get column count to ensure we use the right number of placeholders
                    column_count = len(row)
                    placeholders = ", ".join(["?"] * column_count)
                    query = f"INSERT OR REPLACE INTO http_responses VALUES ({placeholders})"
                    sync_analysis_cursor.execute(query, row)
                    sync_count += 1
                
                # Sync TLS connections (new)
                last_tls_timestamp = sync_analysis_cursor.execute(
                    "SELECT MAX(timestamp) FROM tls_connections"
                ).fetchone()[0] or 0
                
                sync_capture_cursor.execute(
                    "SELECT * FROM tls_connections WHERE timestamp > ?",
                    (last_tls_timestamp,)
                )
                
                for row in sync_capture_cursor.fetchall():
                    # Get column count to ensure we use the right number of placeholders
                    column_count = len(row)
                    placeholders = ", ".join(["?"] * column_count)
                    query = f"INSERT OR REPLACE INTO tls_connections VALUES ({placeholders})"
                    sync_analysis_cursor.execute(query, row)
                    sync_count += 1
                
                # Sync App protocols (new)
                last_app_timestamp = sync_analysis_cursor.execute(
                    "SELECT MAX(timestamp) FROM app_protocols"
                ).fetchone()[0] or 0
                
                sync_capture_cursor.execute(
                    "SELECT * FROM app_protocols WHERE timestamp > ?",
                    (last_app_timestamp,)
                )
                
                for row in sync_capture_cursor.fetchall():
                    # Get column count to ensure we use the right number of placeholders
                    column_count = len(row)
                    placeholders = ", ".join(["?"] * column_count)
                    query = f"INSERT OR REPLACE INTO app_protocols VALUES ({placeholders})"
                    sync_analysis_cursor.execute(query, row)
                    sync_count += 1
                
                # Commit the transaction
                self.analysis_conn.commit()
                self.last_sync_time = current_time
                
                # Close the sync-specific cursors
                sync_capture_cursor.close()
                sync_analysis_cursor.close()
                
                logger.info(f"Synchronized {sync_count} records between databases")
                return sync_count
                    
        except Exception as e:
            # Rollback on error
            try:
                self.analysis_conn.rollback()
            except:
                pass
            logger.error(f"Database sync error: {e}")
            return 0

    # Query methods for HTTP and TLS data
    def get_http_requests_by_host(self, host_filter=None, limit=100):
        """Get HTTP requests filtered by host pattern with improved error handling"""
        try:
            cursor = self.analysis_conn.cursor()
            
            # First check if we have any HTTP requests (for debugging)
            count = cursor.execute("SELECT COUNT(*) FROM http_requests").fetchone()[0]
            logger.info(f"Total HTTP requests in database: {count}")
            
            if count == 0:
                cursor.close()
                return []
            
            if host_filter:
                filter_pattern = f"%{host_filter}%"
                cursor.execute("""
                    SELECT r.id, r.method, r.host, r.uri, r.user_agent, r.timestamp, 
                        resp.status_code, resp.content_type
                    FROM http_requests r
                    LEFT JOIN http_responses resp ON r.id = resp.http_request_id
                    WHERE r.host LIKE ?
                    ORDER BY r.timestamp DESC
                    LIMIT ?
                """, (filter_pattern, limit))
            else:
                cursor.execute("""
                    SELECT r.id, r.method, r.host, r.uri, r.user_agent, r.timestamp, 
                        resp.status_code, resp.content_type
                    FROM http_requests r
                    LEFT JOIN http_responses resp ON r.id = resp.http_request_id
                    ORDER BY r.timestamp DESC
                    LIMIT ?
                """, (limit,))
            
            # Process results safely
            results = []
            for row in cursor.fetchall():
                try:
                    # Make sure we have a complete row
                    if len(row) < 8:
                        continue
                    
                    # Format timestamps consistently
                    timestamp = row[5]
                    if isinstance(timestamp, (int, float)):
                        formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                    else:
                        formatted_time = timestamp
                    
                    # Create a new row with the formatted timestamp
                    new_row = list(row)
                    new_row[5] = formatted_time
                    
                    results.append(tuple(new_row))
                except Exception as e:
                    logger.error(f"Error processing HTTP request row: {e}")
            
            cursor.close()
            return results
        except Exception as e:
            logger.error(f"Error retrieving HTTP requests: {e}")
            return []


    def get_tls_connections(self, filter_pattern=None, limit=100):
        """Get TLS connections with optional filtering and improved error handling"""
        try:
            cursor = self.analysis_conn.cursor()
            
            # First check if we have any TLS connections at all (for debugging)
            count = cursor.execute("SELECT COUNT(*) FROM tls_connections").fetchone()[0]
            logger.info(f"Total TLS connections in database: {count}")
            
            if count == 0:
                cursor.close()
                return []
            
            # Try the query with modified JOIN logic that's more tolerant
            if filter_pattern:
                pattern = f"%{filter_pattern}%"
                query = """
                    SELECT t.server_name, t.tls_version, t.cipher_suite, t.ja3_fingerprint,
                        c.src_ip, c.dst_ip, c.src_port, c.dst_port, t.timestamp,
                        t.connection_key
                    FROM tls_connections t
                    LEFT JOIN connections c ON t.connection_key = c.connection_key
                    WHERE (t.server_name LIKE ? OR t.ja3_fingerprint LIKE ?)
                    ORDER BY t.timestamp DESC
                    LIMIT ?
                """
                cursor.execute(query, (pattern, pattern, limit))
            else:
                query = """
                    SELECT t.server_name, t.tls_version, t.cipher_suite, t.ja3_fingerprint,
                        c.src_ip, c.dst_ip, c.src_port, c.dst_port, t.timestamp,
                        t.connection_key
                    FROM tls_connections t
                    LEFT JOIN connections c ON t.connection_key = c.connection_key
                    ORDER BY t.timestamp DESC
                    LIMIT ?
                """
                cursor.execute(query, (limit,))
            
            rows = cursor.fetchall()
            
            # Process results to handle possible NULL values from LEFT JOIN
            results = []
            for row in rows:
                try:
                    # Extract values with safety
                    server_name = row[0] if row[0] is not None else "Unknown"
                    tls_version = row[1] if row[1] is not None else "Unknown"
                    cipher_suite = row[2] if row[2] is not None else "Unknown"
                    ja3_fp = row[3] if row[3] is not None else "N/A"
                    src_ip = row[4]
                    dst_ip = row[5]
                    src_port = row[6]
                    dst_port = row[7]
                    timestamp = row[8]
                    conn_key = row[9]
                    
                    # If the JOIN failed (connection record not found), extract IPs from connection_key
                    if src_ip is None or dst_ip is None:
                        try:
                            # Try to parse connection key in format "src_ip:src_port->dst_ip:dst_port"
                            parts = conn_key.split('->')
                            if len(parts) == 2:
                                src_part = parts[0].split(':')
                                dst_part = parts[1].split(':')
                                if len(src_part) == 2 and len(dst_part) == 2:
                                    src_ip = src_part[0]
                                    try:
                                        src_port = int(src_part[1])
                                    except ValueError:
                                        src_port = 0
                                    dst_ip = dst_part[0]
                                    try:
                                        dst_port = int(dst_part[1])
                                    except ValueError:
                                        dst_port = 0
                        except Exception:
                            # If parsing fails, use placeholders
                            src_ip = src_ip or "Unknown"
                            dst_ip = dst_ip or "Unknown"
                            src_port = src_port or 0
                            dst_port = dst_port or 0
                    
                    # Create a new result tuple with guaranteed non-NULL values
                    result = (
                        server_name,
                        tls_version,
                        cipher_suite,
                        ja3_fp,
                        src_ip or "Unknown",
                        dst_ip or "Unknown",
                        src_port or 0,
                        dst_port or 0,
                        timestamp
                    )
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error processing TLS connection row: {e}")
            
            cursor.close()
            return results
        except Exception as e:
            logger.error(f"Error retrieving TLS connections: {e}")
            import traceback
            traceback.print_exc()
            return []

    def check_tls_tables(self):
        """Check TLS tables and log status for debugging"""
        try:
            cursor = self.analysis_conn.cursor()
            
            # Check connections table
            conn_count = cursor.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
            logger.info(f"Total connections: {conn_count}")
            
            # Check TLS connections table
            tls_count = cursor.execute("SELECT COUNT(*) FROM tls_connections").fetchone()[0]
            logger.info(f"Total TLS connections: {tls_count}")
            
            # Check HTTPS connections specifically
            https_count = cursor.execute(
                "SELECT COUNT(*) FROM connections WHERE dst_port = 443"
            ).fetchone()[0]
            logger.info(f"HTTPS connections (port 443): {https_count}")
            
            # Check for successful joins
            join_count = cursor.execute("""
                SELECT COUNT(*) FROM tls_connections t
                JOIN connections c ON t.connection_key = c.connection_key
            """).fetchone()[0]
            logger.info(f"Successful TLS-connections joins: {join_count}")
            
            # Sample TLS connection keys
            cursor.execute("SELECT connection_key FROM tls_connections LIMIT 5")
            tls_keys = [row[0] for row in cursor.fetchall()]
            logger.info(f"Sample TLS connection keys: {tls_keys}")
            
            # Sample connection keys
            cursor.execute("SELECT connection_key FROM connections LIMIT 5")
            conn_keys = [row[0] for row in cursor.fetchall()]
            logger.info(f"Sample connection keys: {conn_keys}")
            
            # Check last sync time
            last_sync = getattr(self, 'last_sync_time', 0)
            current_time = time.time()
            time_since_sync = current_time - last_sync
            logger.info(f"Time since last database sync: {time_since_sync:.1f} seconds")
            
            cursor.close()
            return {
                "connections": conn_count,
                "https_connections": https_count,
                "tls_connections": tls_count,
                "successful_joins": join_count,
                "tls_keys": tls_keys,
                "conn_keys": conn_keys,
                "time_since_sync": time_since_sync
            }
        except Exception as e:
            logger.error(f"Error checking TLS tables: {e}")
            return None

    def get_suspicious_tls_connections(self):
        """Get potentially suspicious TLS connections based on version and cipher suite with improved error handling"""
        try:
            cursor = self.analysis_conn.cursor()
            
            # Check if we have any TLS connections first
            count = cursor.execute("SELECT COUNT(*) FROM tls_connections").fetchone()[0]
            if count == 0:
                cursor.close()
                return []
            
            # Query for old TLS versions and weak ciphers using LEFT JOIN for better compatibility
            cursor.execute("""
                SELECT t.server_name, t.tls_version, t.cipher_suite, t.ja3_fingerprint,
                    c.src_ip, c.dst_ip, t.timestamp
                FROM tls_connections t
                LEFT JOIN connections c ON t.connection_key = c.connection_key
                WHERE t.tls_version IN ('SSLv3', 'TLSv1.0', 'TLSv1.1')
                OR t.cipher_suite LIKE '%NULL%'
                OR t.cipher_suite LIKE '%EXPORT%'
                OR t.cipher_suite LIKE '%DES%'
                OR t.cipher_suite LIKE '%RC4%'
                OR t.cipher_suite LIKE '%MD5%'
                ORDER BY t.timestamp DESC
            """)
            
            # Process results safely
            results = []
            for row in cursor.fetchall():
                try:
                    # Handle potential NULL values from LEFT JOIN
                    server_name = row[0] if row[0] else "Unknown"
                    tls_version = row[1] if row[1] else "Unknown"
                    cipher_suite = row[2] if row[2] else "Unknown"
                    ja3_fp = row[3] if row[3] else "N/A"
                    
                    # Extract source and destination IPs from connection key if needed
                    src_ip = row[4]
                    dst_ip = row[5]
                    timestamp = row[6]
                    
                    if src_ip is None or dst_ip is None:
                        # If the connection lookup failed, try to extract from the connection_key
                        connection_key = cursor.execute(
                            "SELECT connection_key FROM tls_connections WHERE server_name = ? AND tls_version = ? AND timestamp = ?",
                            (server_name, tls_version, timestamp)
                        ).fetchone()
                        
                        if connection_key and '->' in connection_key[0]:
                            parts = connection_key[0].split('->')
                            src_part = parts[0].split(':')[0] if ':' in parts[0] else parts[0]
                            dst_part = parts[1].split(':')[0] if ':' in parts[1] else parts[1]
                            src_ip = src_part
                            dst_ip = dst_part
                    
                    # Create result with non-NULL values
                    result = (
                        server_name,
                        tls_version,
                        cipher_suite,
                        ja3_fp,
                        src_ip or "Unknown",
                        dst_ip or "Unknown",
                        timestamp
                    )
                    results.append(result)
                except Exception as e:
                    logger.error(f"Error processing suspicious TLS connection: {e}")
            
            cursor.close()
            return results
        except Exception as e:
            logger.error(f"Error retrieving suspicious TLS connections: {e}")
            return []
    
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
        """Update a specific field in the connections table (used by rules)"""
        try:
            cursor = self.capture_conn.cursor()
            cursor.execute(
                f"UPDATE connections SET {field} = ? WHERE connection_key = ?",
                (value, connection_key)
            )
            self.capture_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error updating connection field: {e}")
            return False
    
    # Analysis DB read methods - these will be used as query functions
    
    def get_database_stats(self):
        """Get database statistics from analysis DB using a dedicated cursor"""
        try:
            # Create dedicated cursor for this operation
            cursor = self.analysis_conn.cursor()
            
            # Get file size
            db_file_size = os.path.getsize(self.analysis_db_path)
            
            # Get connection stats
            conn_count = cursor.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
            total_bytes = cursor.execute("SELECT SUM(total_bytes) FROM connections").fetchone()[0] or 0
            total_packets = cursor.execute("SELECT SUM(packet_count) FROM connections").fetchone()[0] or 0
            unique_src_ips = cursor.execute("SELECT COUNT(DISTINCT src_ip) FROM connections").fetchone()[0]
            unique_dst_ips = cursor.execute("SELECT COUNT(DISTINCT dst_ip) FROM connections").fetchone()[0]
            
            # Close the cursor
            cursor.close()
            
            return {
                "db_file_size": db_file_size,
                "conn_count": conn_count,
                "total_bytes": total_bytes,
                "total_packets": total_packets,
                "unique_src_ips": unique_src_ips,
                "unique_dst_ips": unique_dst_ips
            }
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            return {
                "db_file_size": 0,
                "conn_count": 0,
                "total_bytes": 0,
                "total_packets": 0,
                "unique_src_ips": 0,
                "unique_dst_ips": 0
            }
    
    def get_top_connections(self, limit=200):
        """Get top connections by bytes from analysis DB using a dedicated cursor"""
        try:
            # Create dedicated cursor for this operation
            cursor = self.analysis_conn.cursor()
            
            cursor.execute("""
                SELECT src_ip, dst_ip, total_bytes, packet_count, timestamp
                FROM connections
                ORDER BY total_bytes DESC
                LIMIT ?
            """, (limit,))
            
            results = cursor.fetchall()
            
            # Close the cursor
            cursor.close()
            
            return results
        except Exception as e:
            logger.error(f"Error getting top connections: {e}")
            return []
    
    def get_alerts_by_ip(self):
        """Get aggregated alerts by IP address from analysis DB using a dedicated cursor"""
        try:
            # Create dedicated cursor for this operation
            cursor = self.analysis_conn.cursor()
            
            cursor.execute("""
                SELECT ip_address, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM alerts 
                GROUP BY ip_address
                ORDER BY last_seen DESC
            """)
            
            results = cursor.fetchall()
            
            # Close the cursor
            cursor.close()
            
            return results
        except Exception as e:
            logger.error(f"Error getting alerts by IP: {e}")
            return []
    
    def get_alerts_by_rule_type(self):
        """Get aggregated alerts by rule type from analysis DB using a dedicated cursor"""
        try:
            # Create dedicated cursor for this operation
            cursor = self.analysis_conn.cursor()
            
            cursor.execute("""
                SELECT rule_name, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM alerts 
                GROUP BY rule_name
                ORDER BY last_seen DESC
            """)
            
            results = cursor.fetchall()
            
            # Close the cursor
            cursor.close()
            
            return results
        except Exception as e:
            logger.error(f"Error getting alerts by rule type: {e}")
            return []
    
    def get_rule_alerts(self, rule_name):
        """Get alerts for a specific rule from analysis DB using a dedicated cursor"""
        try:
            # Create dedicated cursor for this operation
            cursor = self.analysis_conn.cursor()
            
            cursor.execute("""
                SELECT ip_address, alert_message, timestamp
                FROM alerts
                WHERE rule_name = ?
                ORDER BY timestamp DESC
            """, (rule_name,))
            
            results = cursor.fetchall()
            
            # Close the cursor
            cursor.close()
            
            return results
        except Exception as e:
            logger.error(f"Error getting alerts for rule {rule_name}: {e}")
            return []
    
    def get_ip_alerts(self, ip_address):
        """Get alerts for a specific IP address from analysis DB using a dedicated cursor"""
        try:
            # Create dedicated cursor for this operation
            cursor = self.analysis_conn.cursor()
            
            cursor.execute("""
                SELECT alert_message, rule_name, timestamp
                FROM alerts
                WHERE ip_address = ?
                ORDER BY timestamp DESC
            """, (ip_address,))
            
            results = cursor.fetchall()
            
            # Close the cursor
            cursor.close()
            
            return results
        except Exception as e:
            logger.error(f"Error getting alerts for IP {ip_address}: {e}")
            return []
    
    def get_filtered_alerts_by_ip(self, ip_filter):
        """Get alerts filtered by IP address pattern from analysis DB using a dedicated cursor"""
        try:
            # Create dedicated cursor for this operation
            cursor = self.analysis_conn.cursor()
            
            filter_pattern = f"%{ip_filter}%"
            cursor.execute("""
                SELECT ip_address, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM alerts 
                WHERE ip_address LIKE ?
                GROUP BY ip_address
                ORDER BY last_seen DESC
            """, (filter_pattern,))
            
            results = cursor.fetchall()
            
            # Close the cursor
            cursor.close()
            
            return results
        except Exception as e:
            logger.error(f"Error getting filtered alerts by IP: {e}")
            return []
    
    def get_filtered_alerts_by_rule(self, rule_filter):
        """Get alerts filtered by rule name pattern from analysis DB using a dedicated cursor"""
        try:
            # Create dedicated cursor for this operation
            cursor = self.analysis_conn.cursor()
            
            filter_pattern = f"%{rule_filter}%"
            cursor.execute("""
                SELECT rule_name, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM alerts 
                WHERE rule_name LIKE ?
                GROUP BY rule_name
                ORDER BY last_seen DESC
            """, (filter_pattern,))
            
            results = cursor.fetchall()
            
            # Close the cursor
            cursor.close()
            
            return results
        except Exception as e:
            logger.error(f"Error getting filtered alerts by rule: {e}")
            return []
    
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
    
    def resolve_domain_names(self, db_cursor):
        """Add this method to DatabaseManager to resolve IP addresses to hostnames"""
        import socket
        
        try:
            # Get all TLS connections with server names that look like IP addresses
            db_cursor.execute("""
                SELECT id, server_name, connection_key
                FROM tls_connections
                WHERE server_name LIKE '%\\.%\\.%\\.%' 
                OR server_name IS NULL
                LIMIT 100
            """)
            
            rows = db_cursor.fetchall()
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
                        db_cursor.execute("""
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