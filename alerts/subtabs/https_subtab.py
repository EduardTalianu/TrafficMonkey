# Save this as 'alerts/subtabs/http_tls_subtab.py'

import tkinter as tk
from tkinter import ttk
import time
import datetime
from subtab_base import SubtabBase

class HttpTlsMonitor(SubtabBase):
    """Subtab for monitoring HTTP and TLS traffic"""
    
    def __init__(self):
        super().__init__("HTTP/TLS Monitor", "Monitor HTTP requests and TLS connections")
        self.selected_ip = tk.StringVar()
        self.http_filter = tk.StringVar()
        self.tls_filter = tk.StringVar()
        self.last_refresh_time = 0
        self.refresh_interval = 5  # seconds
    
    def create_ui(self):
        """Create HTTP/TLS monitoring UI components"""
        # Main notebook for HTTP vs TLS tabs
        self.monitor_notebook = ttk.Notebook(self.tab_frame)
        self.monitor_notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # HTTP tab
        self.http_tab = ttk.Frame(self.monitor_notebook)
        self.monitor_notebook.add(self.http_tab, text="HTTP Traffic")
        self.create_http_tab()
        
        # TLS tab
        self.tls_tab = ttk.Frame(self.monitor_notebook)
        self.monitor_notebook.add(self.tls_tab, text="TLS/SSL Connections")
        self.create_tls_tab()
        
        # Suspicious TLS tab
        self.suspicious_tls_tab = ttk.Frame(self.monitor_notebook)
        self.monitor_notebook.add(self.suspicious_tls_tab, text="Suspicious TLS")
        self.create_suspicious_tls_tab()
        
        # Refresh button for the entire subtab
        refresh_frame = ttk.Frame(self.tab_frame)
        refresh_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(refresh_frame, text="Refresh Data", 
                  command=self.refresh).pack(side="right", padx=5)
        ttk.Button(refresh_frame, text="Check Tables", 
                  command=self.check_database_status).pack(side="right", padx=5)
                  
        ttk.Label(refresh_frame, 
                 text="Monitor HTTP and TLS traffic for security issues").pack(side="left", padx=5)
        
        # Initial data load
        self.refresh()
    
    def create_http_tab(self):
        """Create HTTP traffic monitoring components"""
        # Filter frame
        filter_frame = ttk.Frame(self.http_tab)
        filter_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Filter by host:").pack(side="left", padx=5)
        host_filter = ttk.Entry(filter_frame, textvariable=self.http_filter, width=30)
        host_filter.pack(side="left", padx=5)
        
        ttk.Button(filter_frame, text="Apply Filter", 
                  command=lambda: self.refresh_http_requests(self.http_filter.get())).pack(side="left", padx=5)
        ttk.Button(filter_frame, text="Clear Filter", 
                  command=lambda: (self.http_filter.set(""), self.refresh_http_requests())).pack(side="left", padx=5)
        
        # HTTP requests tree
        frame = ttk.Frame(self.http_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("method", "host", "path", "status", "content_type", "timestamp")
        self.http_tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        
        self.http_tree.heading("method", text="Method")
        self.http_tree.heading("host", text="Host")
        self.http_tree.heading("path", text="Path")
        self.http_tree.heading("status", text="Status")
        self.http_tree.heading("content_type", text="Content Type")
        self.http_tree.heading("timestamp", text="Timestamp")
        
        # Set column widths
        self.http_tree.column("method", width=60)
        self.http_tree.column("host", width=200)
        self.http_tree.column("path", width=250)
        self.http_tree.column("status", width=60)
        self.http_tree.column("content_type", width=150)
        self.http_tree.column("timestamp", width=150)
        
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.http_tree.yview)
        self.http_tree.configure(yscrollcommand=scrollbar.set)
        
        self.http_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Details frame
        details_frame = ttk.LabelFrame(self.http_tab, text="HTTP Request Details")
        details_frame.pack(fill="x", padx=10, pady=5)
        
        self.http_details_text = tk.Text(details_frame, height=6, wrap=tk.WORD)
        self.http_details_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bind tree selection event
        self.http_tree.bind("<<TreeviewSelect>>", self.show_http_details)
    
    def create_tls_tab(self):
        """Create TLS/SSL monitoring components with added debug button"""
        # Filter frame
        filter_frame = ttk.Frame(self.tls_tab)
        filter_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Filter by server name:").pack(side="left", padx=5)
        tls_filter = ttk.Entry(filter_frame, textvariable=self.tls_filter, width=30)
        tls_filter.pack(side="left", padx=5)
        
        ttk.Button(filter_frame, text="Apply Filter", 
                command=lambda: self.refresh_tls_connections(self.tls_filter.get())).pack(side="left", padx=5)
        ttk.Button(filter_frame, text="Clear Filter", 
                command=lambda: (self.tls_filter.set(""), self.refresh_tls_connections())).pack(side="left", padx=5)
        
        # Add debug button for TLS troubleshooting
        ttk.Button(filter_frame, text="Debug TLS", 
                command=self.debug_tls_processing).pack(side="right", padx=5)
        ttk.Button(filter_frame, text="Force Refresh", 
                command=lambda: self.refresh_tls_connections(None, force=True)).pack(side="right", padx=5)
        
        # TLS connections tree
        frame = ttk.Frame(self.tls_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("server", "version", "cipher", "src_ip", "dst_ip", "timestamp")
        self.tls_tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        
        self.tls_tree.heading("server", text="Server Name")
        self.tls_tree.heading("version", text="TLS Version")
        self.tls_tree.heading("cipher", text="Cipher Suite")
        self.tls_tree.heading("src_ip", text="Source IP")
        self.tls_tree.heading("dst_ip", text="Destination IP")
        self.tls_tree.heading("timestamp", text="Timestamp")
        
        # Set column widths
        self.tls_tree.column("server", width=200)
        self.tls_tree.column("version", width=80)
        self.tls_tree.column("cipher", width=200)
        self.tls_tree.column("src_ip", width=100)
        self.tls_tree.column("dst_ip", width=100)
        self.tls_tree.column("timestamp", width=150)
        
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.tls_tree.yview)
        self.tls_tree.configure(yscrollcommand=scrollbar.set)
        
        self.tls_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Details frame
        details_frame = ttk.LabelFrame(self.tls_tab, text="TLS Connection Details")
        details_frame.pack(fill="x", padx=10, pady=5)
        
        self.tls_details_text = tk.Text(details_frame, height=6, wrap=tk.WORD)
        self.tls_details_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bind tree selection event
        self.tls_tree.bind("<<TreeviewSelect>>", self.show_tls_details)
        
        # Initial message
        self.tls_details_text.insert(tk.END, "Select a TLS connection to view details.\n\n")
        self.tls_details_text.insert(tk.END, "If no connections are showing, visit an HTTPS website to generate TLS traffic.\n")
        self.tls_details_text.insert(tk.END, "Use the 'Debug TLS' button to check database status.")
    
    def create_suspicious_tls_tab(self):
        """Create suspicious TLS connections tab"""
        # TLS connections tree
        frame = ttk.Frame(self.suspicious_tls_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ttk.Label(frame, text="TLS connections with outdated versions or weak ciphers:").pack(anchor="w", padx=5, pady=5)
        
        columns = ("server", "version", "cipher", "src_ip", "dst_ip", "timestamp")
        self.suspicious_tls_tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        
        self.suspicious_tls_tree.heading("server", text="Server Name")
        self.suspicious_tls_tree.heading("version", text="TLS Version")
        self.suspicious_tls_tree.heading("cipher", text="Cipher Suite")
        self.suspicious_tls_tree.heading("src_ip", text="Source IP")
        self.suspicious_tls_tree.heading("dst_ip", text="Destination IP")
        self.suspicious_tls_tree.heading("timestamp", text="Timestamp")
        
        # Set column widths
        self.suspicious_tls_tree.column("server", width=200)
        self.suspicious_tls_tree.column("version", width=80)
        self.suspicious_tls_tree.column("cipher", width=200)
        self.suspicious_tls_tree.column("src_ip", width=100)
        self.suspicious_tls_tree.column("dst_ip", width=100)
        self.suspicious_tls_tree.column("timestamp", width=150)
        
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.suspicious_tls_tree.yview)
        self.suspicious_tls_tree.configure(yscrollcommand=scrollbar.set)
        
        self.suspicious_tls_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Information frame
        info_frame = ttk.Frame(self.suspicious_tls_tab)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Security issues: SSLv3, TLSv1.0, TLSv1.1, or weak cipher suites (NULL, EXPORT, DES, RC4, MD5)").pack(side="left", padx=5)
        
        # Export button
        ttk.Button(info_frame, text="Export to Log", 
                  command=self.export_suspicious_tls).pack(side="right", padx=5)
    
    def check_database_status(self):
        """Check database table status for debugging using queue system"""
        self.update_output("Checking database tables...")
        
        # Create a debug information window
        debug_window = tk.Toplevel(self.gui.master)
        debug_window.title("Database Status")
        debug_window.geometry("600x400")
        
        # Create text widget for display
        debug_text = tk.Text(debug_window, wrap=tk.WORD)
        debug_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(debug_text, command=debug_text.yview)
        scrollbar.pack(side="right", fill="y")
        debug_text.config(yscrollcommand=scrollbar.set)
        
        # Define query functions using analysis_manager
        def get_table_counts():
            conn = self.gui.analysis_manager.analysis1_conn
            cursor = conn.cursor()
            
            tables = {}
            
            # Get list of tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            for row in cursor.fetchall():
                table_name = row[0]
                # Get count
                count_cursor = conn.cursor()
                count_cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                count = count_cursor.fetchone()[0]
                tables[table_name] = count
                count_cursor.close()
            
            cursor.close()
            return tables
        
        def check_tls_connections():
            conn = self.gui.analysis_manager.analysis1_conn
            cursor = conn.cursor()
            
            # Look for port 443 connections
            cursor.execute("""
                SELECT COUNT(*) FROM connections 
                WHERE dst_port = 443
            """)
            https_connections = cursor.fetchone()[0]
            
            # Check actual TLS connections
            cursor.execute("SELECT COUNT(*) FROM tls_connections")
            tls_records = cursor.fetchone()[0]
            
            # Get recent connections
            cursor.execute("""
                SELECT src_ip, dst_ip, dst_port, timestamp 
                FROM connections 
                WHERE dst_port = 443
                ORDER BY timestamp DESC
                LIMIT 5
            """)
            recent_https = cursor.fetchall()
            
            cursor.close()
            
            return {
                "https_connections": https_connections,
                "tls_records": tls_records,
                "recent_https": recent_https
            }
        
        def check_http_requests():
            conn = self.gui.analysis_manager.analysis1_conn
            cursor = conn.cursor()
            
            # Count HTTP requests
            cursor.execute("SELECT COUNT(*) FROM http_requests")
            http_requests = cursor.fetchone()[0]
            
            # Count HTTP responses
            try:
                cursor.execute("SELECT COUNT(*) FROM http_responses")
                http_responses = cursor.fetchone()[0]
            except:
                http_responses = 0
            
            # Get sample HTTP requests
            cursor.execute("""
                SELECT method, host, uri, timestamp
                FROM http_requests
                ORDER BY timestamp DESC
                LIMIT 5
            """)
            recent_requests = cursor.fetchall()
            
            cursor.close()
            
            return {
                "http_requests": http_requests,
                "http_responses": http_responses,
                "recent_requests": recent_requests
            }
        
        # Queue the database queries using analysis_manager
        self.gui.analysis_manager.queue_query(
            get_table_counts,
            lambda tables: self.gui.analysis_manager.queue_query(
                check_tls_connections,
                lambda tls_info: self.gui.analysis_manager.queue_query(
                    check_http_requests,
                    lambda http_info: self._display_debug_info(debug_text, tables, tls_info, http_info),
                ),
            ),
        )
        
        # Close button
        ttk.Button(debug_window, text="Close", 
                command=debug_window.destroy).pack(pady=10)
        
    def _display_debug_info(self, debug_text, tables, tls_info, http_info):
        """Display collected debug information in the text widget"""
        # Display the information
        debug_text.insert(tk.END, "=== DATABASE TABLE COUNTS ===\n\n")
        for table, count in tables.items():
            debug_text.insert(tk.END, f"{table}: {count} rows\n")
            
        debug_text.insert(tk.END, "\n=== TLS CONNECTION INFO ===\n\n")
        debug_text.insert(tk.END, f"HTTPS Connections (port 443): {tls_info['https_connections']}\n")
        debug_text.insert(tk.END, f"TLS Connection Records: {tls_info['tls_records']}\n\n")
        
        if tls_info['recent_https']:
            debug_text.insert(tk.END, "Recent HTTPS Connections:\n")
            for conn in tls_info['recent_https']:
                src_ip, dst_ip, dst_port, timestamp = conn
                debug_text.insert(tk.END, f"  {src_ip} -> {dst_ip}:{dst_port} at {timestamp}\n")
        else:
            debug_text.insert(tk.END, "No recent HTTPS connections found\n")
            
        debug_text.insert(tk.END, "\n=== HTTP REQUEST INFO ===\n\n")
        debug_text.insert(tk.END, f"HTTP Requests: {http_info['http_requests']}\n")
        debug_text.insert(tk.END, f"HTTP Responses: {http_info['http_responses']}\n\n")
        
        if http_info['recent_requests']:
            debug_text.insert(tk.END, "Recent HTTP Requests:\n")
            for req in http_info['recent_requests']:
                method, host, uri, timestamp = req
                debug_text.insert(tk.END, f"  {method} {host}{uri} at {timestamp}\n")
        else:
            debug_text.insert(tk.END, "No recent HTTP requests found\n")
            
        # Add suggestions
        debug_text.insert(tk.END, "\n=== TROUBLESHOOTING SUGGESTIONS ===\n\n")
        
        if tls_info['https_connections'] > 0 and tls_info['tls_records'] == 0:
            debug_text.insert(tk.END, "⚠️ HTTPS connections detected but no TLS records found!\n")
            debug_text.insert(tk.END, "This indicates that TLS field extraction is failing.\n")
            debug_text.insert(tk.END, "Check that tshark is capturing TLS handshake fields.\n")
        
        if http_info['http_requests'] == 0:
            debug_text.insert(tk.END, "ℹ️ No HTTP requests found.\n")
            debug_text.insert(tk.END, "Visit some HTTP websites to generate traffic.\n")
            
        debug_text.insert(tk.END, "\nIf tables have low counts, try these steps:\n")
        debug_text.insert(tk.END, "1. Make sure capture is running\n")
        debug_text.insert(tk.END, "2. Visit multiple websites to generate traffic\n")
        debug_text.insert(tk.END, "3. Check tshark command has correct -e parameters\n")
        debug_text.insert(tk.END, "4. Force a database sync\n")
        
        # Make text read-only
        debug_text.config(state=tk.DISABLED)
    
    def refresh(self):
        """Refresh all data in the subtab"""
        # Check if enough time has passed since last refresh
        current_time = time.time()
        if current_time - self.last_refresh_time < self.refresh_interval:
            return
        
        self.last_refresh_time = current_time
        
        # Refresh each tab's data
        self.refresh_http_requests(self.http_filter.get())
        self.refresh_tls_connections(self.tls_filter.get())
        self.refresh_suspicious_tls()
        
        # Update log
        self.update_output("HTTP/TLS monitor refreshed")
    
    def refresh_http_requests(self, host_filter=None):
        """Refresh HTTP request data using analysis_manager"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            return
            
        # Clear tree
        for item in self.http_tree.get_children():
            self.http_tree.delete(item)
        
        # Get HTTP requests using analysis_manager
        self.gui.analysis_manager.queue_query(
            lambda: self._get_http_requests(host_filter),
            self._update_http_display
        )
        
    def _get_http_requests(self, host_filter=None):
        """Get HTTP requests from analysis_1.db"""
        try:
            limit = 200
            cursor = self.gui.analysis_manager.get_cursor()
            
            # First, check table structure to see if http_responses exists and has content_type
            has_content_type = False
            try:
                cursor.execute("PRAGMA table_info(http_responses)")
                columns = cursor.fetchall()
                column_names = [col[1] for col in columns]
                has_content_type = 'content_type' in column_names
            except:
                has_content_type = False
            
            # Build query based on available columns
            if host_filter:
                filter_pattern = f"%{host_filter}%"
                if has_content_type:
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
                    # Fallback query without content_type
                    cursor.execute("""
                        SELECT r.id, r.method, r.host, r.uri, r.user_agent, r.timestamp, 
                            resp.status_code, 'text/html'
                        FROM http_requests r
                        LEFT JOIN http_responses resp ON r.id = resp.http_request_id
                        WHERE r.host LIKE ?
                        ORDER BY r.timestamp DESC
                        LIMIT ?
                    """, (filter_pattern, limit))
            else:
                if has_content_type:
                    cursor.execute("""
                        SELECT r.id, r.method, r.host, r.uri, r.user_agent, r.timestamp, 
                            resp.status_code, resp.content_type
                        FROM http_requests r
                        LEFT JOIN http_responses resp ON r.id = resp.http_request_id
                        ORDER BY r.timestamp DESC
                        LIMIT ?
                    """, (limit,))
                else:
                    # Fallback query without content_type
                    cursor.execute("""
                        SELECT r.id, r.method, r.host, r.uri, r.user_agent, r.timestamp, 
                            resp.status_code, 'text/html'
                        FROM http_requests r
                        LEFT JOIN http_responses resp ON r.id = resp.http_request_id
                        ORDER BY r.timestamp DESC
                        LIMIT ?
                    """, (limit,))
            
            results = cursor.fetchall()
            cursor.close()
            return results
        except Exception as e:
            self.update_output(f"Error getting HTTP requests: {e}")
            return []
    
    def _update_http_display(self, http_requests):
        """Update HTTP requests display with the query results"""
        if not http_requests:
            self.update_output("No HTTP requests found")
            return
            
        # Add to tree
        for req in http_requests:
            req_id = req[0]
            method = req[1] if req[1] else "GET"  # Default to GET if method is None
            host = req[2] if req[2] else "Unknown"
            uri = req[3] if req[3] else "/"       # Default to / if URI is None
            user_agent = req[4]
            timestamp = req[5]
            status_code = req[6] if req[6] is not None else "N/A"
            content_type = req[7] if req[7] else "N/A"
            
            # Format the timestamp
            if isinstance(timestamp, float):
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
            
            # Add to tree - ensure column order matches tree definition
            self.http_tree.insert("", "end", values=(method, host, uri, status_code, content_type, timestamp), tags=(str(req_id),))
        
        self.update_output(f"Loaded {len(http_requests)} HTTP requests")
    
    def refresh_tls_connections(self, filter_pattern=None, force=False):
        """Refresh TLS connection data with improved error handling and debugging"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("GUI or analysis manager not available")
            return
            
        # Clear tree
        for item in self.tls_tree.get_children():
            self.tls_tree.delete(item)
        
        # Force a database sync if requested
        if force and hasattr(self.gui.analysis_manager, 'sync_from_analysis_db'):
            self.update_output("Forcing database sync before refreshing TLS data...")
            self.gui.analysis_manager.queue_query(
                self.gui.analysis_manager.sync_from_analysis_db,
                lambda sync_count: self.update_output(f"Synced {sync_count} records between databases")
            )
        
        # Queue the TLS connections query
        self.gui.analysis_manager.queue_query(
            lambda: self._get_tls_connections(filter_pattern),
            self._update_tls_display
        )
        
    def _get_tls_connections(self, filter_pattern=None):
        """Get TLS connections from analysis_1.db"""
        try:
            limit = 200
            cursor = self.gui.analysis_manager.get_cursor()
            
            # First check if we have any TLS connections at all (for debugging)
            count = cursor.execute("SELECT COUNT(*) FROM tls_connections").fetchone()[0]
            self.update_output(f"Total TLS connections in database: {count}")
            
            if count == 0:
                cursor.close()
                return []
            
            # Check if ja3_fingerprint column exists
            cursor.execute("PRAGMA table_info(tls_connections)")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]
            has_ja3 = 'ja3_fingerprint' in column_names
            
            # Try the query with modified JOIN logic that's more tolerant
            if filter_pattern:
                pattern = f"%{filter_pattern}%"
                if has_ja3:
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
                    rows = cursor.execute(query, (pattern, pattern, limit)).fetchall()
                else:
                    # Modified query without ja3_fingerprint
                    query = """
                        SELECT t.server_name, t.tls_version, t.cipher_suite, 'N/A',
                            c.src_ip, c.dst_ip, c.src_port, c.dst_port, t.timestamp,
                            t.connection_key
                        FROM tls_connections t
                        LEFT JOIN connections c ON t.connection_key = c.connection_key
                        WHERE t.server_name LIKE ?
                        ORDER BY t.timestamp DESC
                        LIMIT ?
                    """
                    rows = cursor.execute(query, (pattern, limit)).fetchall()
            else:
                if has_ja3:
                    query = """
                        SELECT t.server_name, t.tls_version, t.cipher_suite, t.ja3_fingerprint,
                            c.src_ip, c.dst_ip, c.src_port, c.dst_port, t.timestamp,
                            t.connection_key
                        FROM tls_connections t
                        LEFT JOIN connections c ON t.connection_key = c.connection_key
                        ORDER BY t.timestamp DESC
                        LIMIT ?
                    """
                    rows = cursor.execute(query, (limit,)).fetchall()
                else:
                    # Modified query without ja3_fingerprint
                    query = """
                        SELECT t.server_name, t.tls_version, t.cipher_suite, 'N/A',
                            c.src_ip, c.dst_ip, c.src_port, c.dst_port, t.timestamp,
                            t.connection_key
                        FROM tls_connections t
                        LEFT JOIN connections c ON t.connection_key = c.connection_key
                        ORDER BY t.timestamp DESC
                        LIMIT ?
                    """
                    rows = cursor.execute(query, (limit,)).fetchall()
            
            cursor.close()
            return rows
        except Exception as e:
            self.update_output(f"Error getting TLS connections: {e}")
            import traceback
            traceback.print_exc()
            return []
            
    def _update_tls_display(self, tls_connections):
        """Update TLS connections display with the query results"""
        if not tls_connections:
            self.update_output("No TLS connections found in database")
            
            # Add debug information to help diagnose the issue
            self.tls_details_text.delete(1.0, tk.END)
            self.tls_details_text.insert(tk.END, "TLS Debug Information:\n\n")
            
            # Check if capture is running
            if hasattr(self.gui, 'running') and self.gui.running:
                self.tls_details_text.insert(tk.END, "Capture is RUNNING\n")
            else:
                self.tls_details_text.insert(tk.END, "Capture is NOT running\n")
            
            # Check TShark command
            if hasattr(self.gui, 'capture_engine') and hasattr(self.gui.capture_engine, 'tshark_process'):
                if self.gui.capture_engine.tshark_process:
                    self.tls_details_text.insert(tk.END, "TShark process is active\n")
                else:
                    self.tls_details_text.insert(tk.END, "TShark process is not active\n")
            
            # Check connection counts
            try:
                conn_cursor = self.gui.analysis_manager.get_cursor()
                https_count = conn_cursor.execute("SELECT COUNT(*) FROM connections WHERE dst_port = 443").fetchone()[0]
                self.tls_details_text.insert(tk.END, f"\nHTTPS connections in database: {https_count}\n")
                conn_cursor.close()
            except Exception as e:
                self.tls_details_text.insert(tk.END, f"\nError checking connections: {e}\n")
            
            # Suggest possible solutions
            self.tls_details_text.insert(tk.END, "\nPossible solutions:\n")
            self.tls_details_text.insert(tk.END, "1. Make sure capture is started\n")
            self.tls_details_text.insert(tk.END, "2. Visit some HTTPS sites to generate TLS traffic\n")
            self.tls_details_text.insert(tk.END, "3. Check log for any TLS processing errors\n")
            self.tls_details_text.insert(tk.END, "4. Use the 'Debug TLS' button for more information\n")
            self.tls_details_text.insert(tk.END, "5. Use 'Check Tables' button to verify database status\n")
            
            return
        
        # Add to tree - with better error handling
        for conn in tls_connections:
            try:
                # Make sure we have enough elements in the tuple
                if len(conn) < 6:
                    self.update_output(f"Warning: Incomplete TLS data: {conn}")
                    continue
                    
                server_name = conn[0] if conn[0] else "Unknown"
                tls_version = conn[1] if conn[1] else "Unknown"
                cipher_suite = conn[2] if conn[2] else "Unknown"
                src_ip = conn[4] if len(conn) > 4 and conn[4] else "Unknown"
                dst_ip = conn[5] if len(conn) > 5 and conn[5] else "Unknown"
                timestamp = conn[8] if len(conn) > 8 and conn[8] else time.time()
                
                # Format the timestamp
                if isinstance(timestamp, float):
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                
                # Add to tree
                self.tls_tree.insert("", "end", values=(server_name, tls_version, cipher_suite, src_ip, dst_ip, timestamp))
            except Exception as e:
                self.update_output(f"Error displaying TLS connection: {e}")
        
        self.update_output(f"Loaded {len(tls_connections)} TLS connections")

    def debug_tls_processing(self):
        """Force a check of TLS processing and database status using queue system"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("GUI or analysis manager not available")
            return
                
        # Clear the details text area
        self.tls_details_text.delete(1.0, tk.END)
        self.tls_details_text.insert(tk.END, "TLS Debug Information:\n\n")
        
        # Queue the query using analysis_manager
        self.gui.analysis_manager.queue_query(
            self._check_tls_tables,
            self._update_tls_debug_display
        )
    
    def _check_tls_tables(self):
        """Check TLS tables using analysis_1.db"""
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            
            # Check connections table
            conn_count = cursor.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
            
            # Check TLS connections table
            tls_count = cursor.execute("SELECT COUNT(*) FROM tls_connections").fetchone()[0]
            
            # Check HTTPS connections specifically
            https_count = cursor.execute(
                "SELECT COUNT(*) FROM connections WHERE dst_port = 443"
            ).fetchone()[0]
            
            # Check for successful joins
            try:
                join_count = cursor.execute("""
                    SELECT COUNT(*) FROM tls_connections t
                    JOIN connections c ON t.connection_key = c.connection_key
                """).fetchone()[0]
            except:
                join_count = 0
            
            # Sample TLS connection keys
            cursor.execute("SELECT connection_key FROM tls_connections LIMIT 5")
            tls_keys = [row[0] for row in cursor.fetchall()]
            
            # Sample connection keys
            cursor.execute("SELECT connection_key FROM connections LIMIT 5")
            conn_keys = [row[0] for row in cursor.fetchall()]
            
            # Check recent HTTPS connections
            cursor.execute("""
                SELECT src_ip, dst_ip, timestamp FROM connections 
                WHERE dst_port = 443
                ORDER BY timestamp DESC
                LIMIT 5
            """)
            recent_https = cursor.fetchall()
            
            cursor.close()
            
            return {
                "connections": conn_count,
                "https_connections": https_count,
                "tls_connections": tls_count,
                "successful_joins": join_count,
                "tls_keys": tls_keys,
                "conn_keys": conn_keys,
                "recent_https": recent_https
            }
        except Exception as e:
            self.update_output(f"Error checking TLS tables: {e}")
            return None
    
    def _update_tls_debug_display(self, status):
        """Update TLS debug display with the query results"""
        if status:
            self.tls_details_text.insert(tk.END, f"Database Status:\n")
            self.tls_details_text.insert(tk.END, f"- Total connections: {status['connections']}\n")
            self.tls_details_text.insert(tk.END, f"- Total TLS connections: {status['tls_connections']}\n")
            self.tls_details_text.insert(tk.END, f"- Successful joins: {status['successful_joins']}\n\n")
            
            if status['tls_keys']:
                self.tls_details_text.insert(tk.END, f"Sample TLS keys:\n")
                for key in status['tls_keys']:
                    self.tls_details_text.insert(tk.END, f"- {key}\n")
                self.tls_details_text.insert(tk.END, "\n")
                
            if status['conn_keys']:
                self.tls_details_text.insert(tk.END, f"Sample connection keys:\n")
                for key in status['conn_keys']:
                    self.tls_details_text.insert(tk.END, f"- {key}\n")
            
            self.tls_details_text.insert(tk.END, f"\nHTTPS Connections (port 443): {status['https_connections']}\n")
            
            # Check recent HTTPS connections
            if status['recent_https']:
                self.tls_details_text.insert(tk.END, "\nRecent HTTPS connections:\n")
                for row in status['recent_https']:
                    src, dst, ts = row
                    self.tls_details_text.insert(tk.END, f"- {src} → {dst} at {ts}\n")
        else:
            self.tls_details_text.insert(tk.END, "Could not retrieve database status\n")
        
        # Add suggestions
        self.tls_details_text.insert(tk.END, "\nTroubleshooting steps:\n")
        
        if status and status['connections'] > 0 and status['tls_connections'] == 0:
            self.tls_details_text.insert(tk.END, "1. ⚠️ You have connections but no TLS data - check tshark field extraction\n")
        else:
            self.tls_details_text.insert(tk.END, "1. Visit some HTTPS websites to generate TLS traffic\n")
            
        self.tls_details_text.insert(tk.END, "2. Verify tshark command includes TLS fields (-e tls.handshake.*)\n")
        self.tls_details_text.insert(tk.END, "3. Check that TLS field extraction is working in traffic_capture.py\n")
        self.tls_details_text.insert(tk.END, "4. Force a database sync using the 'Force Refresh' button\n")
        self.tls_details_text.insert(tk.END, "5. Check sample packets in logs/packets directory for TLS fields\n")

    def refresh_suspicious_tls(self):
        """Refresh suspicious TLS connection data"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            return
            
        # Clear tree
        for item in self.suspicious_tls_tree.get_children():
            self.suspicious_tls_tree.delete(item)
        
        # Get suspicious TLS connections using analysis_manager
        self.gui.analysis_manager.queue_query(
            self._get_suspicious_tls_connections,
            self._update_suspicious_tls_display
        )
        
    def _get_suspicious_tls_connections(self):
        """Get suspicious TLS connections from analysis_1.db"""
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            
            # Check if we have any TLS connections first
            count = cursor.execute("SELECT COUNT(*) FROM tls_connections").fetchone()[0]
            if count == 0:
                cursor.close()
                return []
            
            # Check if ja3_fingerprint column exists
            cursor.execute("PRAGMA table_info(tls_connections)")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]
            has_ja3 = 'ja3_fingerprint' in column_names
                
            # Query for old TLS versions and weak ciphers
            if has_ja3:
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
            else:
                # Modified query without ja3_fingerprint
                cursor.execute("""
                    SELECT t.server_name, t.tls_version, t.cipher_suite, 'N/A',
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
            
            results = cursor.fetchall()
            cursor.close()
            return results
        except Exception as e:
            self.update_output(f"Error getting suspicious TLS connections: {e}")
            return []
    
    def _update_suspicious_tls_display(self, suspicious_connections):
        """Update suspicious TLS display with the query results"""
        if not suspicious_connections:
            self.update_output("No suspicious TLS connections found")
            return
            
        # Add to tree
        for conn in suspicious_connections:
            server_name = conn[0] if conn[0] else "Unknown"
            tls_version = conn[1] if conn[1] else "Unknown"
            cipher_suite = conn[2] if conn[2] else "Unknown"
            src_ip = conn[4] if len(conn) > 4 and conn[4] else "Unknown"
            dst_ip = conn[5] if len(conn) > 5 and conn[5] else "Unknown"
            timestamp = conn[6] if len(conn) > 6 and conn[6] else time.time()
            
            # Format the timestamp
            if isinstance(timestamp, float):
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
            
            # Add to tree
            self.suspicious_tls_tree.insert("", "end", values=(server_name, tls_version, cipher_suite, src_ip, dst_ip, timestamp))
        
        self.update_output(f"Loaded {len(suspicious_connections)} suspicious TLS connections")
    
    def show_http_details(self, event):
        """Show HTTP request details when selected"""
        selected = self.http_tree.selection()
        if not selected:
            return
            
        # Clear details
        self.http_details_text.delete(1.0, tk.END)
        
        item = selected[0]
        values = self.http_tree.item(item, 'values')
        if not values or len(values) < 6:
            return
            
        # Extract values
        method = values[0]
        host = values[1]
        path = values[2]
        status = values[3]
        content_type = values[4]
        
        # Get the request ID from tags
        req_id = None
        tags = self.http_tree.item(item, 'tags')
        if tags and len(tags) > 0:
            req_id = tags[0]
        
        # Display basic details
        details = f"Method: {method}\nHost: {host}\nPath: {path}\nStatus: {status}\nContent-Type: {content_type}\n\n"
        
        # If we have the request ID, we could get more details from the database
        if req_id and req_id.isdigit():
            # Queue query to get more details using analysis_manager
            self.gui.analysis_manager.queue_query(
                lambda: self._get_http_request_details(int(req_id)),
                lambda result: self._update_http_details_display(result, details)
            )
        else:
            # Just display the basic details if we don't have an ID
            self.http_details_text.insert(tk.END, details)
    
    def _get_http_request_details(self, req_id):
        """Get HTTP request details from analysis_1.db"""
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            
            # Get request headers
            cursor.execute("""
                SELECT request_headers, user_agent 
                FROM http_requests 
                WHERE id = ?
            """, (req_id,))
            
            request_result = cursor.fetchone()
            
            # Check if http_responses has the proper columns
            response_result = None
            try:
                # See if the http_responses table exists and has the right columns
                cursor.execute("PRAGMA table_info(http_responses)")
                columns = cursor.fetchall()
                column_names = [col[1] for col in columns]
                
                # Only proceed if necessary columns exist
                if 'http_request_id' in column_names:
                    # Adjust column names based on what's available
                    columns_to_select = ['status_code']
                    if 'content_type' in column_names:
                        columns_to_select.append('content_type')
                    else:
                        columns_to_select.append("'unknown' as content_type")
                        
                    if 'content_length' in column_names:
                        columns_to_select.append('content_length')
                    else:
                        columns_to_select.append("0 as content_length")
                        
                    if 'server' in column_names:
                        columns_to_select.append('server')
                    else:
                        columns_to_select.append("'unknown' as server")
                        
                    if 'response_headers' in column_names:
                        columns_to_select.append('response_headers')
                    else:
                        columns_to_select.append("'' as response_headers")
                    
                    # Build the query with available columns
                    query = f"""
                        SELECT {', '.join(columns_to_select)}
                        FROM http_responses 
                        WHERE http_request_id = ?
                    """
                    cursor.execute(query, (req_id,))
                    response_result = cursor.fetchone()
            except Exception as e:
                self.update_output(f"Error checking http_responses: {e}")
                response_result = None
            
            cursor.close()
            return {
                "request": request_result,
                "response": response_result
            }
        except Exception as e:
            self.update_output(f"Error getting HTTP request details: {e}")
            return {"request": None, "response": None}
    
    def _update_http_details_display(self, result, basic_details):
        """Update HTTP details display with the query results"""
        details = basic_details
        
        # Add request details
        request_result = result["request"]
        if request_result:
            headers_json = request_result[0]
            user_agent = request_result[1]
            
            if headers_json:
                import json
                try:
                    headers = json.loads(headers_json)
                    details += "Headers:\n"
                    for name, value in headers.items():
                        details += f"  {name}: {value}\n"
                except:
                    pass
            
            if user_agent:
                details += f"\nUser-Agent: {user_agent}\n"
        
        # Add response details
        response_result = result["response"]
        if response_result:
            details += "\nResponse:\n"
            details += f"  Status: {response_result[0]}\n"
            
            # Check if we have content-type (index 1)
            if len(response_result) > 1:
                details += f"  Content-Type: {response_result[1] or 'unknown'}\n"
            
            # Check if we have content-length (index 2)
            if len(response_result) > 2:
                details += f"  Content-Length: {response_result[2] or 'unknown'}\n"
            
            # Check if we have server (index 3)
            if len(response_result) > 3:
                details += f"  Server: {response_result[3] or 'unknown'}\n"
            
            # Parse response headers if available (index 4)
            if len(response_result) > 4 and response_result[4]:
                response_headers = response_result[4]
                import json
                try:
                    headers = json.loads(response_headers)
                    details += "  Headers:\n"
                    for name, value in headers.items():
                        details += f"    {name}: {value}\n"
                except:
                    pass
        
        # Display the details
        self.http_details_text.delete(1.0, tk.END)
        self.http_details_text.insert(tk.END, details)
    
    def show_tls_details(self, event):
        """Show TLS connection details when selected"""
        selected = self.tls_tree.selection()
        if not selected:
            return
            
        # Clear details
        self.tls_details_text.delete(1.0, tk.END)
        
        item = selected[0]
        values = self.tls_tree.item(item, 'values')
        if not values or len(values) < 6:
            return
            
        # Extract values
        server_name = values[0]
        tls_version = values[1]
        cipher_suite = values[2]
        src_ip = values[3]
        dst_ip = values[4]
        
        # Display basic details
        details = f"Server Name: {server_name}\nTLS Version: {tls_version}\nCipher Suite: {cipher_suite}\n"
        details += f"Source IP: {src_ip}\nDestination IP: {dst_ip}\n\n"
        
        # Get certificate info using analysis_manager
        self.gui.analysis_manager.queue_query(
            lambda: self._get_tls_details(server_name, src_ip, dst_ip),
            lambda result: self._update_tls_details_display(result, details, tls_version, cipher_suite)
        )
    
    def _get_tls_details(self, server_name, src_ip, dst_ip):
        """Get TLS details from analysis_1.db"""
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            
            # Check what columns are available
            cursor.execute("PRAGMA table_info(tls_connections)")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]
            
            # Build a list of columns to select based on what's available
            select_columns = []
            if 'ja3_fingerprint' in column_names:
                select_columns.append('ja3_fingerprint')
            else:
                select_columns.append("'N/A' as ja3_fingerprint")
                
            if 'ja3s_fingerprint' in column_names:
                select_columns.append('ja3s_fingerprint')
            else:
                select_columns.append("'N/A' as ja3s_fingerprint")
                
            if 'certificate_issuer' in column_names:
                select_columns.append('certificate_issuer')
            else:
                select_columns.append("'Unknown' as certificate_issuer")
                
            if 'certificate_subject' in column_names:
                select_columns.append('certificate_subject')
            else:
                select_columns.append("'Unknown' as certificate_subject")
                
            if 'certificate_validity_start' in column_names:
                select_columns.append('certificate_validity_start')
            else:
                select_columns.append("'Unknown' as certificate_validity_start")
                
            if 'certificate_validity_end' in column_names:
                select_columns.append('certificate_validity_end')
            else:
                select_columns.append("'Unknown' as certificate_validity_end")
            
            # Build the query
            query = f"""
                SELECT {', '.join(select_columns)}
                FROM tls_connections
                WHERE server_name = ? AND 
                      (connection_key LIKE ? OR connection_key LIKE ?)
                ORDER BY timestamp DESC
                LIMIT 1
            """
            
            cursor.execute(query, (server_name, f"{src_ip}:%->%", f"%->{dst_ip}:%"))
            
            result = cursor.fetchone()
            cursor.close()
            return result
        except Exception as e:
            self.update_output(f"Error getting TLS details: {e}")
            return None
    
    def _update_tls_details_display(self, result, details, tls_version, cipher_suite):
        """Update TLS details display with the query results"""
        if result:
            ja3 = result[0] if len(result) > 0 else None
            ja3s = result[1] if len(result) > 1 else None
            cert_issuer = result[2] if len(result) > 2 else None
            cert_subject = result[3] if len(result) > 3 else None
            cert_valid_from = result[4] if len(result) > 4 else None
            cert_valid_to = result[5] if len(result) > 5 else None
            
            if ja3 and ja3 != 'N/A':
                details += f"JA3 Fingerprint: {ja3}\n"
            if ja3s and ja3s != 'N/A':
                details += f"JA3S Fingerprint: {ja3s}\n"
            
            details += "\nCertificate Information:\n"
            if cert_issuer and cert_issuer != 'Unknown':
                details += f"  Issuer: {cert_issuer}\n"
            if cert_subject and cert_subject != 'Unknown':
                details += f"  Subject: {cert_subject}\n"
            if cert_valid_from and cert_valid_from != 'Unknown':
                details += f"  Valid From: {cert_valid_from}\n"
            if cert_valid_to and cert_valid_to != 'Unknown':
                details += f"  Valid To: {cert_valid_to}\n"
        
        # Display the details
        self.tls_details_text.delete(1.0, tk.END)
        self.tls_details_text.insert(tk.END, details)
        
        # Add security assessment
        self.add_security_assessment(tls_version, cipher_suite)
    
    def add_security_assessment(self, tls_version, cipher_suite):
        """Add security assessment for TLS version and cipher suite with more detailed analysis"""
        self.tls_details_text.insert(tk.END, "\n--- Security Assessment ---\n")
        
        # Check TLS version
        version_status = "Unknown"
        version_message = "Could not determine TLS version"
        
        if tls_version:
            if "Unknown" in tls_version:
                version_status = "Unknown"
                version_message = "Could not determine TLS version"
            elif any(old in tls_version for old in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]):
                version_status = "Vulnerable"
                version_message = f"{tls_version} is deprecated and has known vulnerabilities:"
                
                if "SSLv2" in tls_version:
                    version_message += "\n  - SSLv2 has significant cryptographic weaknesses"
                elif "SSLv3" in tls_version:
                    version_message += "\n  - SSLv3 is vulnerable to the POODLE attack"
                elif "TLSv1.0" in tls_version:
                    version_message += "\n  - TLSv1.0 is vulnerable to BEAST and other attacks"
                elif "TLSv1.1" in tls_version:
                    version_message += "\n  - TLSv1.1 uses outdated cryptographic primitives"
                    
            elif "TLSv1.2" in tls_version:
                version_status = "Acceptable"
                version_message = "TLSv1.2 is currently acceptable but will be phased out.\nIt provides adequate security when configured properly with strong cipher suites."
            elif "TLSv1.3" in tls_version:
                version_status = "Good"
                version_message = "TLSv1.3 is the current recommended version with improved security, privacy, and performance.\nIt removes support for many obsolete and insecure features present in older TLS versions."
            elif "assumed" in tls_version.lower():
                version_status = "Assumed"
                version_message = "TLS version was not detected directly but assumed based on the connection type."
        
        self.tls_details_text.insert(tk.END, f"TLS Version: {version_status} - {version_message}\n\n")
        
        # Check cipher suite
        cipher_status = "Unknown"
        cipher_message = "Could not determine cipher suite"
        
        if cipher_suite and "Unknown" not in cipher_suite:
            cipher_suite_lower = cipher_suite.lower()
            
            # Check for weak ciphers
            if any(weak in cipher_suite_lower for weak in ["null", "export", "des", "rc4", "md5"]):
                cipher_status = "Weak"
                cipher_message = "This cipher suite is considered weak and should not be used:\n"
                
                if "null" in cipher_suite_lower:
                    cipher_message += "  - NULL ciphers provide no encryption\n"
                if "export" in cipher_suite_lower:
                    cipher_message += "  - EXPORT grade ciphers use deliberately weakened encryption\n"
                if "des" in cipher_suite_lower and "3des" not in cipher_suite_lower:
                    cipher_message += "  - DES is vulnerable to brute force attacks\n"
                if "rc4" in cipher_suite_lower:
                    cipher_message += "  - RC4 has multiple cryptographic weaknesses\n"
                if "md5" in cipher_suite_lower:
                    cipher_message += "  - MD5 is cryptographically broken\n"
                    
            # Check for medium-strength ciphers
            elif any(medium in cipher_suite_lower for medium in ["sha1", "cbc", "3des"]):
                cipher_status = "Medium"
                cipher_message = "This cipher suite provides moderate security but stronger options are available:\n"
                
                if "sha1" in cipher_suite_lower:
                    cipher_message += "  - SHA1 is no longer considered collision-resistant\n"
                if "cbc" in cipher_suite_lower:
                    cipher_message += "  - CBC mode is vulnerable to padding oracle attacks if not implemented correctly\n"
                if "3des" in cipher_suite_lower:
                    cipher_message += "  - 3DES provides less than optimal performance and security margins\n"
                    
            # Check for strong ciphers
            elif any(strong in cipher_suite_lower for strong in ["aes_256", "aes256", "chacha20", "poly1305", "gcm", "sha384", "sha256"]):
                cipher_status = "Strong"
                cipher_message = "This cipher suite provides strong security:\n"
                
                if any(aes in cipher_suite_lower for aes in ["aes_256", "aes256"]):
                    cipher_message += "  - AES-256 provides a high security margin\n"
                if "gcm" in cipher_suite_lower:
                    cipher_message += "  - GCM mode provides authenticated encryption\n"
                if any(chacha in cipher_suite_lower for chacha in ["chacha20", "chacha", "poly1305"]):
                    cipher_message += "  - ChaCha20-Poly1305 is a strong modern AEAD cipher\n"
                if "sha384" in cipher_suite_lower:
                    cipher_message += "  - SHA-384 provides strong integrity protection\n"
                elif "sha256" in cipher_suite_lower:
                    cipher_message += "  - SHA-256 provides good integrity protection\n"
            else:
                cipher_status = "Unrecognized"
                cipher_message = f"This cipher suite ({cipher_suite}) is not recognized in our security database.\nPlease consult current cryptographic standards for its security assessment."
        
        self.tls_details_text.insert(tk.END, f"Cipher Suite: {cipher_status} - {cipher_message}\n")
        
        # Overall assessment
        self.tls_details_text.insert(tk.END, "\nOverall Security Assessment: ")
        
        if version_status == "Vulnerable" or cipher_status == "Weak":
            self.tls_details_text.insert(tk.END, "VULNERABLE - This connection has serious security issues.\n")
        elif version_status == "Unknown" or cipher_status == "Unknown" or cipher_status == "Unrecognized":
            self.tls_details_text.insert(tk.END, "UNCERTAIN - Some aspects of this connection could not be fully assessed.\n")
        elif version_status == "Acceptable" and cipher_status in ["Medium", "Strong"]:
            self.tls_details_text.insert(tk.END, "ACCEPTABLE - This connection uses adequate security but could be improved.\n")
        elif version_status == "Good" and cipher_status == "Strong":
            self.tls_details_text.insert(tk.END, "STRONG - This connection uses recommended security settings.\n")
        else:
            self.tls_details_text.insert(tk.END, "MIXED - This connection has mixed security characteristics.\n")
    
    def export_suspicious_tls(self):
        """Export suspicious TLS connections to log"""
        items = self.suspicious_tls_tree.get_children()
        if not items:
            self.update_output("No suspicious TLS connections to export")
            return
            
        self.update_output("=== SUSPICIOUS TLS CONNECTIONS REPORT ===")
        for item in items:
            values = self.suspicious_tls_tree.item(item, 'values')
            if values and len(values) >= 6:
                server = values[0]
                version = values[1]
                cipher = values[2]
                src_ip = values[3]
                dst_ip = values[4]
                
                self.update_output(f"Server: {server}, Version: {version}, Cipher: {cipher}")
                self.update_output(f"  Connection: {src_ip} -> {dst_ip}")
                
                # Determine issue
                issues = []
                if version in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
                    issues.append(f"Outdated {version}")
                
                if cipher:
                    cipher_lower = cipher.lower()
                    if "null" in cipher_lower:
                        issues.append("NULL cipher (no encryption)")
                    if "export" in cipher_lower:
                        issues.append("EXPORT grade cipher (weak)")
                    if "des" in cipher_lower:
                        issues.append("DES cipher (broken)")
                    if "rc4" in cipher_lower:
                        issues.append("RC4 cipher (weak)")
                    if "md5" in cipher_lower:
                        issues.append("MD5 hashing (vulnerable)")
                
                if issues:
                    self.update_output(f"  Issues: {', '.join(issues)}")
                
                self.update_output("---")
        
        self.update_output("=== END OF REPORT ===")
        self.update_output(f"Exported {len(items)} suspicious TLS connections")