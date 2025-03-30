# Save this as 'alerts/subtabs/http_tls_subtab.py'

import tkinter as tk
from tkinter import ttk
import time
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
                command=lambda: self.refresh_tls_connections(None)).pack(side="right", padx=5)
        
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
        """Refresh HTTP request data"""
        if not self.gui or not hasattr(self.gui, 'db_manager'):
            return
            
        # Clear tree
        for item in self.http_tree.get_children():
            self.http_tree.delete(item)
        
        # Get HTTP requests
        db_manager = self.gui.db_manager
        
        # Format query results
        http_requests = db_manager.get_http_requests_by_host(host_filter, limit=200)
        
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
    
    def refresh_tls_connections(self, filter_pattern=None):
        """Refresh TLS connection data with improved error handling and debugging"""
        if not self.gui or not hasattr(self.gui, 'db_manager'):
            self.update_output("GUI or database manager not available")
            return
            
        # Clear tree
        for item in self.tls_tree.get_children():
            self.tls_tree.delete(item)
        
        db_manager = self.gui.db_manager
        
        # Check TLS table status for debugging
        if hasattr(db_manager, 'check_tls_tables'):
            status = db_manager.check_tls_tables()
            if status:
                self.update_output(f"TLS status: {status['tls_connections']} records, {status['successful_joins']} successful joins")
        
        # Get TLS connections
        tls_connections = db_manager.get_tls_connections(filter_pattern, limit=200)
        
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
            
            # Suggest possible solutions
            self.tls_details_text.insert(tk.END, "\nPossible solutions:\n")
            self.tls_details_text.insert(tk.END, "1. Make sure capture is started\n")
            self.tls_details_text.insert(tk.END, "2. Visit some HTTPS sites to generate TLS traffic\n")
            self.tls_details_text.insert(tk.END, "3. Check log for any TLS processing errors\n")
            
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
                src_ip = conn[4] if len(conn) > 4 else "Unknown"
                dst_ip = conn[5] if len(conn) > 5 else "Unknown"
                timestamp = conn[8] if len(conn) > 8 else time.time()
                
                # Format the timestamp
                if isinstance(timestamp, float):
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                
                # Add to tree
                self.tls_tree.insert("", "end", values=(server_name, tls_version, cipher_suite, src_ip, dst_ip, timestamp))
            except Exception as e:
                self.update_output(f"Error displaying TLS connection: {e}")
        
        self.update_output(f"Loaded {len(tls_connections)} TLS connections")

    def debug_tls_processing(self):
        """Force a check of TLS processing and database status"""
        if not self.gui or not hasattr(self.gui, 'db_manager'):
            self.update_output("GUI or database manager not available")
            return
            
        db_manager = self.gui.db_manager
        
        # Clear the details text area
        self.tls_details_text.delete(1.0, tk.END)
        self.tls_details_text.insert(tk.END, "TLS Debug Information:\n\n")
        
        # Check database tables
        if hasattr(db_manager, 'check_tls_tables'):
            status = db_manager.check_tls_tables()
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
            else:
                self.tls_details_text.insert(tk.END, "Could not retrieve database status\n")
    
    def refresh_suspicious_tls(self):
        """Refresh suspicious TLS connection data"""
        if not self.gui or not hasattr(self.gui, 'db_manager'):
            return
            
        # Clear tree
        for item in self.suspicious_tls_tree.get_children():
            self.suspicious_tls_tree.delete(item)
        
        # Get suspicious TLS connections
        db_manager = self.gui.db_manager
        
        # Format query results
        suspicious_connections = db_manager.get_suspicious_tls_connections()
        
        if not suspicious_connections:
            self.update_output("No suspicious TLS connections found")
            return
            
        # Add to tree
        for conn in suspicious_connections:
            server_name = conn[0] if conn[0] else "Unknown"
            tls_version = conn[1] if conn[1] else "Unknown"
            cipher_suite = conn[2] if conn[2] else "Unknown"
            src_ip = conn[4]
            dst_ip = conn[5]
            timestamp = conn[6]
            
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
        if req_id and req_id.isdigit() and self.gui and hasattr(self.gui, 'db_manager'):
            db_manager = self.gui.db_manager
            cursor = db_manager.analysis_conn.cursor()
            
            # Get request headers
            cursor.execute("""
                SELECT request_headers, user_agent 
                FROM http_requests 
                WHERE id = ?
            """, (int(req_id),))
            
            request_result = cursor.fetchone()
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
            
            # Get response details if available
            cursor.execute("""
                SELECT status_code, content_type, content_length, server, response_headers 
                FROM http_responses 
                WHERE http_request_id = ?
            """, (int(req_id),))
            
            response_result = cursor.fetchone()
            if response_result:
                details += "\nResponse:\n"
                details += f"  Status: {response_result[0]}\n"
                details += f"  Content-Type: {response_result[1] or 'unknown'}\n"
                details += f"  Content-Length: {response_result[2] or 'unknown'}\n"
                details += f"  Server: {response_result[3] or 'unknown'}\n"
                
                # Parse response headers if available
                response_headers = response_result[4]
                if response_headers:
                    import json
                    try:
                        headers = json.loads(response_headers)
                        details += "  Headers:\n"
                        for name, value in headers.items():
                            details += f"    {name}: {value}\n"
                    except:
                        pass
            
            cursor.close()
        
        # Display the details
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
        
        # Get JA3 fingerprint if available
        if self.gui and hasattr(self.gui, 'db_manager'):
            db_manager = self.gui.db_manager
            cursor = db_manager.analysis_conn.cursor()
            
            # Construct connection key
            src_port = 0
            dst_port = 443  # Assume HTTPS
            
            # Try to find the connection from both directions
            cursor.execute("""
                SELECT ja3_fingerprint, ja3s_fingerprint, certificate_issuer, certificate_subject,
                       certificate_validity_start, certificate_validity_end
                FROM tls_connections
                WHERE server_name = ? AND 
                      (connection_key LIKE ? OR connection_key LIKE ?)
                ORDER BY timestamp DESC
                LIMIT 1
            """, (server_name, f"{src_ip}:%->%", f"%->{dst_ip}:%"))
            
            result = cursor.fetchone()
            if result:
                ja3 = result[0]
                ja3s = result[1]
                cert_issuer = result[2]
                cert_subject = result[3]
                cert_valid_from = result[4]
                cert_valid_to = result[5]
                
                if ja3:
                    details += f"JA3 Fingerprint: {ja3}\n"
                if ja3s:
                    details += f"JA3S Fingerprint: {ja3s}\n"
                
                details += "\nCertificate Information:\n"
                if cert_issuer:
                    details += f"  Issuer: {cert_issuer}\n"
                if cert_subject:
                    details += f"  Subject: {cert_subject}\n"
                if cert_valid_from:
                    details += f"  Valid From: {cert_valid_from}\n"
                if cert_valid_to:
                    details += f"  Valid To: {cert_valid_to}\n"
            
            cursor.close()
        
        # Display the details
        self.tls_details_text.insert(tk.END, details)
        
        # Add security assessment
        self.add_security_assessment(tls_version, cipher_suite)
    
    def add_security_assessment(self, tls_version, cipher_suite):
        """Add security assessment for TLS version and cipher suite"""
        self.tls_details_text.insert(tk.END, "\n--- Security Assessment ---\n")
        
        # Check TLS version
        version_status = "Good"
        version_message = ""
        
        if tls_version in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]:
            version_status = "Vulnerable"
            version_message = f"{tls_version} is deprecated and has known vulnerabilities."
        elif tls_version == "TLSv1.2":
            version_status = "Acceptable"
            version_message = "TLSv1.2 is currently acceptable but will become deprecated in the future."
        elif tls_version == "TLSv1.3":
            version_status = "Good"
            version_message = "TLSv1.3 is the current recommended version with improved security and performance."
        
        self.tls_details_text.insert(tk.END, f"TLS Version: {version_status} - {version_message}\n")
        
        # Check cipher suite
        cipher_status = "Unknown"
        cipher_message = ""
        
        if cipher_suite:
            cipher_suite_lower = cipher_suite.lower()
            if any(weak in cipher_suite_lower for weak in ["null", "export", "des", "rc4", "md5"]):
                cipher_status = "Weak"
                cipher_message = "This cipher suite is considered weak and should not be used."
            elif any(medium in cipher_suite_lower for medium in ["sha1", "cbc"]):
                cipher_status = "Medium"
                cipher_message = "This cipher suite provides moderate security but stronger options are available."
            elif any(strong in cipher_suite_lower for strong in ["aes_256", "chacha20", "poly1305", "gcm", "sha384"]):
                cipher_status = "Strong"
                cipher_message = "This cipher suite provides strong security."
        
        self.tls_details_text.insert(tk.END, f"Cipher Suite: {cipher_status} - {cipher_message}\n")
    
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