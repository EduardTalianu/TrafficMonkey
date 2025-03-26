import sqlite3
import os
import time
import threading
import logging
import queue

# Configure logging
logger = logging.getLogger('database_manager')

class DatabaseManager:
    """Manages separate databases for capture and analysis with query queue"""
    
    def __init__(self, app_root):
        self.app_root = app_root
        self.db_dir = os.path.join(app_root, "db")
        os.makedirs(self.db_dir, exist_ok=True)
        
        # Set up capture database (for writing packet data)
        self.capture_db_path = os.path.join(self.db_dir, "capture.db")
        self.capture_conn = sqlite3.connect(self.capture_db_path, check_same_thread=False)
        self.capture_cursor = self.capture_conn.cursor()
        self._setup_capture_db()
        
        # Set up analysis database (for querying statistics)
        self.analysis_db_path = os.path.join(self.db_dir, "analysis.db")
        self.analysis_conn = sqlite3.connect(self.analysis_db_path, check_same_thread=False)
        self.analysis_cursor = self.analysis_conn.cursor()
        self._setup_analysis_db()
        
        # Set up synchronization
        self.sync_lock = threading.Lock()  # Lock for synchronization operations
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
        
        logger.info("Database manager initialized with separate capture and analysis databases")
    
    def _setup_capture_db(self):
        """Set up capture database optimized for writing"""
        # Enable WAL mode for better write performance
        self.capture_cursor.execute("PRAGMA journal_mode=WAL")
        self.capture_cursor.execute("PRAGMA synchronous=NORMAL")
        
        # Create tables for capture
        self._create_tables(self.capture_cursor)
        self.capture_conn.commit()
        logger.info("Capture database initialized for write operations")
    
    def _setup_analysis_db(self):
        """Set up analysis database optimized for reading"""
        # Configure for read performance
        self.analysis_cursor.execute("PRAGMA journal_mode=WAL")
        self.analysis_cursor.execute("PRAGMA synchronous=NORMAL")
        self.analysis_cursor.execute("PRAGMA cache_size=10000")
        
        # Create the same tables
        self._create_tables(self.analysis_cursor)
        
        # Add additional indices for query performance
        self.analysis_cursor.execute("CREATE INDEX IF NOT EXISTS idx_connections_bytes ON connections(total_bytes DESC)")
        self.analysis_cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp DESC)")
        self.analysis_conn.commit()
        logger.info("Analysis database initialized for read operations")
    
    def _create_tables(self, cursor):
        """Create required tables in the database"""
        # Connections table
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
                is_rdp_client BOOLEAN DEFAULT 0
            )
        """)
        
        # Create indices
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_ips 
            ON connections(src_ip, dst_ip)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_connections_ports 
            ON connections(src_port, dst_port)
        """)
        
        # Alerts table
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
        
        # Port scan table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS port_scan_timestamps (
                src_ip TEXT,
                dst_ip TEXT,
                dst_port INTEGER,
                timestamp REAL,
                PRIMARY KEY (src_ip, dst_ip, dst_port)
            )
        """)
        
        # DNS queries table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dns_queries (
                timestamp REAL,
                src_ip TEXT,
                query_domain TEXT,
                query_type TEXT
            )
        """)
        
        # ICMP packets table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS icmp_packets (
                src_ip TEXT,
                dst_ip TEXT,
                icmp_type INTEGER,
                timestamp REAL
            )
        """)
    
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
                    
                    # Write alert to capture database
                    try:
                        self.capture_cursor.execute("""
                            INSERT INTO alerts (ip_address, alert_message, rule_name)
                            VALUES (?, ?, ?)
                        """, (ip_address, alert_message, rule_name))
                        self.capture_conn.commit()
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
                    sync_analysis_cursor.execute(
                        "INSERT OR REPLACE INTO connections VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        row
                    )
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
                    sync_analysis_cursor.execute(
                        "INSERT OR REPLACE INTO alerts VALUES (?, ?, ?, ?, ?)",
                        row
                    )
                    sync_count += 1
                
                # Sync port_scan_timestamps table
                sync_capture_cursor.execute("SELECT * FROM port_scan_timestamps")
                for row in sync_capture_cursor.fetchall():
                    sync_analysis_cursor.execute(
                        "INSERT OR REPLACE INTO port_scan_timestamps VALUES (?, ?, ?, ?)",
                        row
                    )
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
                    sync_analysis_cursor.execute(
                        "INSERT OR REPLACE INTO dns_queries VALUES (?, ?, ?, ?)",
                        row
                    )
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
                    sync_analysis_cursor.execute(
                        "INSERT OR REPLACE INTO icmp_packets VALUES (?, ?, ?, ?)",
                        row
                    )
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
            # Update existing connection if it exists
            self.capture_cursor.execute("""
                UPDATE connections 
                SET total_bytes = total_bytes + ?,
                    packet_count = packet_count + 1,
                    timestamp = CURRENT_TIMESTAMP
                WHERE connection_key = ?
            """, (length, connection_key))
            
            # If no rows updated, insert new connection
            if self.capture_cursor.rowcount == 0:
                self.capture_cursor.execute("""
                    INSERT INTO connections 
                    (connection_key, src_ip, dst_ip, src_port, dst_port, total_bytes, packet_count, is_rdp_client)
                    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
                """, (connection_key, src_ip, dst_ip, src_port, dst_port, length, is_rdp))
            
            return True
        except Exception as e:
            logger.error(f"Error adding packet: {e}")
            return False
    
    def add_port_scan_data(self, src_ip, dst_ip, dst_port):
        """Update port scan detection data"""
        try:
            # Update or insert port scan timestamp
            current_time = time.time()
            self.capture_cursor.execute("""
                INSERT OR REPLACE INTO port_scan_timestamps
                (src_ip, dst_ip, dst_port, timestamp)
                VALUES (?, ?, ?, ?)
            """, (src_ip, dst_ip, dst_port, current_time))
            return True
        except Exception as e:
            logger.error(f"Error updating port scan data: {e}")
            return False
    
    def add_dns_query(self, src_ip, query_domain, query_type):
        """Store DNS query information"""
        try:
            current_time = time.time()
            self.capture_cursor.execute("""
                INSERT INTO dns_queries
                (timestamp, src_ip, query_domain, query_type)
                VALUES (?, ?, ?, ?)
            """, (current_time, src_ip, query_domain, query_type))
            return True
        except Exception as e:
            logger.error(f"Error storing DNS query: {e}")
            return False
    
    def add_icmp_packet(self, src_ip, dst_ip, icmp_type):
        """Store ICMP packet information"""
        try:
            current_time = time.time()
            self.capture_cursor.execute("""
                INSERT INTO icmp_packets
                (src_ip, dst_ip, icmp_type, timestamp)
                VALUES (?, ?, ?, ?)
            """, (src_ip, dst_ip, icmp_type, current_time))
            return True
        except Exception as e:
            logger.error(f"Error storing ICMP packet: {e}")
            return False
    
    def add_alert(self, ip_address, alert_message, rule_name):
        """Add an alert to the capture database (write-only operation)"""
        try:
            self.capture_cursor.execute("""
                INSERT INTO alerts (ip_address, alert_message, rule_name)
                VALUES (?, ?, ?)
            """, (ip_address, alert_message, rule_name))
            return True
        except Exception as e:
            logger.error(f"Error adding alert: {e}")
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
        """Update a specific field in the connections table (used by rules)"""
        try:
            # Update in capture DB
            self.capture_cursor.execute(
                f"UPDATE connections SET {field} = ? WHERE connection_key = ?",
                (value, connection_key)
            )
            self.capture_conn.commit()
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
            # Clear from capture DB first
            self.capture_cursor.execute("DELETE FROM alerts")
            self.capture_conn.commit()
            
            # Then clear from analysis DB
            self.analysis_cursor.execute("DELETE FROM alerts")
            self.analysis_conn.commit()
            
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