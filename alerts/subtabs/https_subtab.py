# Save this as 'alerts/subtabs/http_tls_subtab.py'

import tkinter as tk
from tkinter import ttk, messagebox
import time
import datetime
import json

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
        
        # Threat Intelligence tab - NEW
        self.threat_intel_tab = ttk.Frame(self.monitor_notebook)
        self.monitor_notebook.add(self.threat_intel_tab, text="Threat Intel")
        self.create_threat_intel_tab()
        
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
        
        columns = ("method", "host", "path", "status", "content_type", "timestamp", "risk")
        self.http_tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        
        self.http_tree.heading("method", text="Method")
        self.http_tree.heading("host", text="Host")
        self.http_tree.heading("path", text="Path")
        self.http_tree.heading("status", text="Status")
        self.http_tree.heading("content_type", text="Content Type")
        self.http_tree.heading("timestamp", text="Timestamp")
        self.http_tree.heading("risk", text="Risk Score")
        
        # Set column widths
        self.http_tree.column("method", width=60)
        self.http_tree.column("host", width=180)
        self.http_tree.column("path", width=220)
        self.http_tree.column("status", width=60)
        self.http_tree.column("content_type", width=120)
        self.http_tree.column("timestamp", width=130)
        self.http_tree.column("risk", width=80)
        
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
        
        # Add right-click menu
        self.http_context_menu = tk.Menu(self.http_tree, tearoff=0)
        self.http_tree.bind("<Button-3>", self.show_http_context_menu)
    
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
        
        columns = ("server", "version", "cipher", "src_ip", "dst_ip", "timestamp", "risk")
        self.tls_tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        
        self.tls_tree.heading("server", text="Server Name")
        self.tls_tree.heading("version", text="TLS Version")
        self.tls_tree.heading("cipher", text="Cipher Suite")
        self.tls_tree.heading("src_ip", text="Source IP")
        self.tls_tree.heading("dst_ip", text="Destination IP")
        self.tls_tree.heading("timestamp", text="Timestamp")
        self.tls_tree.heading("risk", text="Risk Score")
        
        # Set column widths
        self.tls_tree.column("server", width=180)
        self.tls_tree.column("version", width=80)
        self.tls_tree.column("cipher", width=180)
        self.tls_tree.column("src_ip", width=100)
        self.tls_tree.column("dst_ip", width=100)
        self.tls_tree.column("timestamp", width=130)
        self.tls_tree.column("risk", width=80)
        
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
        
        # Add right-click menu
        self.tls_context_menu = tk.Menu(self.tls_tree, tearoff=0)
        self.tls_tree.bind("<Button-3>", self.show_tls_context_menu)
        
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
        
        columns = ("server", "version", "cipher", "src_ip", "dst_ip", "timestamp", "risk", "status")
        self.suspicious_tls_tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        
        self.suspicious_tls_tree.heading("server", text="Server Name")
        self.suspicious_tls_tree.heading("version", text="TLS Version")
        self.suspicious_tls_tree.heading("cipher", text="Cipher Suite")
        self.suspicious_tls_tree.heading("src_ip", text="Source IP")
        self.suspicious_tls_tree.heading("dst_ip", text="Destination IP")
        self.suspicious_tls_tree.heading("timestamp", text="Timestamp")
        self.suspicious_tls_tree.heading("risk", text="Risk Score")
        self.suspicious_tls_tree.heading("status", text="Status")
        
        # Set column widths
        self.suspicious_tls_tree.column("server", width=160)
        self.suspicious_tls_tree.column("version", width=70)
        self.suspicious_tls_tree.column("cipher", width=160)
        self.suspicious_tls_tree.column("src_ip", width=100)
        self.suspicious_tls_tree.column("dst_ip", width=100)
        self.suspicious_tls_tree.column("timestamp", width=130)
        self.suspicious_tls_tree.column("risk", width=70)
        self.suspicious_tls_tree.column("status", width=80)
        
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.suspicious_tls_tree.yview)
        self.suspicious_tls_tree.configure(yscrollcommand=scrollbar.set)
        
        self.suspicious_tls_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Information frame
        info_frame = ttk.Frame(self.suspicious_tls_tab)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(info_frame, text="Security issues: SSLv3, TLSv1.0, TLSv1.1, or weak cipher suites (NULL, EXPORT, DES, RC4, MD5)").pack(side="left", padx=5)
        
        # Add buttons
        btn_frame = ttk.Frame(self.suspicious_tls_tab)
        btn_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(btn_frame, text="Export to Log", 
                  command=self.export_suspicious_tls).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Create Alerts", 
                  command=self.create_alerts_for_suspicious_tls).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Update Threat Intel", 
                  command=self.update_threat_intel_for_suspicious).pack(side="left", padx=5)
        
        # Add right-click menu
        self.suspicious_context_menu = tk.Menu(self.suspicious_tls_tree, tearoff=0)
        self.suspicious_tls_tree.bind("<Button-3>", self.show_suspicious_context_menu)
        
        # Bind tree selection event
        self.suspicious_tls_tree.bind("<<TreeviewSelect>>", self.show_tls_details)
    
    def create_threat_intel_tab(self):
        """Create TLS threat intelligence tab"""
        # Control frame
        control_frame = ttk.Frame(self.threat_intel_tab)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(control_frame, text="TLS connections with threat intelligence:").pack(side="left", padx=5)
        ttk.Button(control_frame, text="Refresh Threats", 
                 command=self.refresh_threat_intel).pack(side="right", padx=5)
        
        # Threat intelligence tree
        frame = ttk.Frame(self.threat_intel_tab)
        frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        columns = ("ip", "score", "type", "server", "timestamp", "details", "status")
        self.threat_intel_tree = ttk.Treeview(frame, columns=columns, show="headings", height=15)
        
        self.threat_intel_tree.heading("ip", text="IP Address")
        self.threat_intel_tree.heading("score", text="Threat Score")
        self.threat_intel_tree.heading("type", text="Threat Type")
        self.threat_intel_tree.heading("server", text="Server Name")
        self.threat_intel_tree.heading("timestamp", text="Last Seen")
        self.threat_intel_tree.heading("details", text="Details")
        self.threat_intel_tree.heading("status", text="Status")
        
        # Set column widths
        self.threat_intel_tree.column("ip", width=120)
        self.threat_intel_tree.column("score", width=80)
        self.threat_intel_tree.column("type", width=120)
        self.threat_intel_tree.column("server", width=160)
        self.threat_intel_tree.column("timestamp", width=130)
        self.threat_intel_tree.column("details", width=200)
        self.threat_intel_tree.column("status", width=80)
        
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.threat_intel_tree.yview)
        self.threat_intel_tree.configure(yscrollcommand=scrollbar.set)
        
        self.threat_intel_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Details frame
        details_frame = ttk.LabelFrame(self.threat_intel_tab, text="Threat Details")
        details_frame.pack(fill="x", padx=10, pady=5)
        
        self.threat_details_text = tk.Text(details_frame, height=8, wrap=tk.WORD)
        self.threat_details_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bind tree selection event
        self.threat_intel_tree.bind("<<TreeviewSelect>>", self.show_threat_intel_details)
        
        # Add right-click menu
        self.threat_intel_context_menu = tk.Menu(self.threat_intel_tree, tearoff=0)
        self.threat_intel_tree.bind("<Button-3>", self.show_threat_intel_context_menu)
    
    def show_http_context_menu(self, event):
        """Show context menu for HTTP requests"""
        selected = self.http_tree.selection()
        if not selected:
            return
            
        # Configure menu options
        self.http_context_menu.delete(0, tk.END)
        item = selected[0]
        values = self.http_tree.item(item, 'values')
        
        # Get host and IP
        host = values[1] if len(values) > 1 else None
        
        # Add menu items
        if host:
            self.http_context_menu.add_command(
                label=f"Copy Host: {host}", 
                command=lambda: self.copy_to_clipboard(host)
            )
            
            # Add threat intelligence check option
            self.http_context_menu.add_separator()
            self.http_context_menu.add_command(
                label="Check Host Reputation", 
                command=lambda: self.check_host_reputation(host)
            )
        
        # Add export option
        self.http_context_menu.add_separator()
        self.http_context_menu.add_command(
            label="Export This Request", 
            command=lambda: self.export_selected_http(selected[0])
        )
        
        # Show the menu
        self.http_context_menu.post(event.x_root, event.y_root)
    
    def show_tls_context_menu(self, event):
        """Show context menu for TLS connections"""
        selected = self.tls_tree.selection()
        if not selected:
            return
            
        # Configure menu options
        self.tls_context_menu.delete(0, tk.END)
        item = selected[0]
        values = self.tls_tree.item(item, 'values')
        
        # Get server and IP
        server = values[0] if len(values) > 0 else None
        dst_ip = values[4] if len(values) > 4 else None
        
        # Add menu items
        if server:
            self.tls_context_menu.add_command(
                label=f"Copy Server: {server}", 
                command=lambda: self.copy_to_clipboard(server)
            )
        
        if dst_ip:
            self.tls_context_menu.add_command(
                label=f"Copy IP: {dst_ip}", 
                command=lambda: self.copy_to_clipboard(dst_ip)
            )
            
            # Add security analysis options
            self.tls_context_menu.add_separator()
            self.tls_context_menu.add_command(
                label="Security Assessment", 
                command=lambda: self.show_security_assessment_dialog(values)
            )
            
            # Add threat intelligence option
            self.tls_context_menu.add_command(
                label="Check IP Reputation", 
                command=lambda: self.check_ip_reputation(dst_ip)
            )
        
        # Add flag as suspicious option
        self.tls_context_menu.add_separator()
        self.tls_context_menu.add_command(
            label="Flag as Suspicious", 
            command=lambda: self.flag_as_suspicious(values)
        )
        
        # Show the menu
        self.tls_context_menu.post(event.x_root, event.y_root)
    
    def show_suspicious_context_menu(self, event):
        """Show context menu for suspicious TLS connections"""
        selected = self.suspicious_tls_tree.selection()
        if not selected:
            return
            
        # Configure menu options
        self.suspicious_context_menu.delete(0, tk.END)
        item = selected[0]
        values = self.suspicious_tls_tree.item(item, 'values')
        
        # Get server and IP
        server = values[0] if len(values) > 0 else None
        dst_ip = values[4] if len(values) > 4 else None
        
        # Add menu items
        if dst_ip:
            self.suspicious_context_menu.add_command(
                label=f"Create Alert for {dst_ip}", 
                command=lambda: self.create_alert_for_connection(values)
            )
            
            self.suspicious_context_menu.add_command(
                label="Update Threat Intelligence", 
                command=lambda: self.update_threat_intel_for_connection(values)
            )
        
        # Add false positive option
        if server and dst_ip:
            self.suspicious_context_menu.add_separator()
            self.suspicious_context_menu.add_command(
                label="Mark as False Positive", 
                command=lambda: self.mark_as_false_positive(values)
            )
        
        # Show the menu
        self.suspicious_context_menu.post(event.x_root, event.y_root)
    
    def show_threat_intel_context_menu(self, event):
        """Show context menu for threat intelligence entries"""
        selected = self.threat_intel_tree.selection()
        if not selected:
            return
            
        # Configure menu options
        self.threat_intel_context_menu.delete(0, tk.END)
        item = selected[0]
        values = self.threat_intel_tree.item(item, 'values')
        
        # Get IP
        ip = values[0] if len(values) > 0 else None
        
        if ip:
            # Add menu items
            self.threat_intel_context_menu.add_command(
                label=f"Copy IP: {ip}", 
                command=lambda: self.copy_to_clipboard(ip)
            )
            
            self.threat_intel_context_menu.add_separator()
            self.threat_intel_context_menu.add_command(
                label="View Full Details", 
                command=lambda: self.show_full_threat_details(ip)
            )
            
            self.threat_intel_context_menu.add_command(
                label="Update Threat Score", 
                command=lambda: self.update_threat_score(ip)
            )
            
            self.threat_intel_context_menu.add_separator()
            self.threat_intel_context_menu.add_command(
                label="Mark as False Positive", 
                command=lambda: self.mark_threat_as_false_positive(ip)
            )
            
            self.threat_intel_context_menu.add_command(
                label="Export Threat Data", 
                command=lambda: self.export_threat_data(ip)
            )
        
        # Show the menu
        self.threat_intel_context_menu.post(event.x_root, event.y_root)
    
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
            
            # Check threat intel table
            try:
                cursor.execute("SELECT COUNT(*) FROM x_ip_threat_intel")
                threat_intel_count = cursor.fetchone()[0]
            except:
                threat_intel_count = 0
            
            cursor.close()
            
            return {
                "https_connections": https_connections,
                "tls_records": tls_records,
                "recent_https": recent_https,
                "threat_intel_count": threat_intel_count
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
            
            # Check alerts table for HTTP related alerts
            try:
                cursor.execute("""
                    SELECT COUNT(*) FROM x_alerts
                    WHERE rule_name LIKE '%http%' OR rule_name LIKE '%web%'
                """)
                http_alerts = cursor.fetchone()[0]
            except:
                http_alerts = 0
            
            cursor.close()
            
            return {
                "http_requests": http_requests,
                "http_responses": http_responses,
                "recent_requests": recent_requests,
                "http_alerts": http_alerts
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
        debug_text.insert(tk.END, f"TLS Connection Records: {tls_info['tls_records']}\n")
        debug_text.insert(tk.END, f"Threat Intel Records: {tls_info.get('threat_intel_count', 'N/A')}\n\n")
        
        if tls_info['recent_https']:
            debug_text.insert(tk.END, "Recent HTTPS Connections:\n")
            for conn in tls_info['recent_https']:
                src_ip, dst_ip, dst_port, timestamp = conn
                debug_text.insert(tk.END, f"  {src_ip} -> {dst_ip}:{dst_port} at {timestamp}\n")
        else:
            debug_text.insert(tk.END, "No recent HTTPS connections found\n")
            
        debug_text.insert(tk.END, "\n=== HTTP REQUEST INFO ===\n\n")
        debug_text.insert(tk.END, f"HTTP Requests: {http_info['http_requests']}\n")
        debug_text.insert(tk.END, f"HTTP Responses: {http_info['http_responses']}\n")
        debug_text.insert(tk.END, f"HTTP-related Alerts: {http_info.get('http_alerts', 'N/A')}\n\n")
        
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
        
        if "x_ip_threat_intel" not in tables or tables.get("x_ip_threat_intel", 0) == 0:
            debug_text.insert(tk.END, "ℹ️ No threat intelligence data found.\n")
            debug_text.insert(tk.END, "Visit the 'Suspicious TLS' tab and use 'Update Threat Intel' to generate data.\n")
        
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
        self.refresh_threat_intel()
        
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
                
            # Check if we have threat intel table
            has_threat_intel = False
            try:
                cursor.execute("SELECT COUNT(*) FROM x_ip_threat_intel")
                has_threat_intel = True
            except:
                has_threat_intel = False
            
            # Build query based on available columns
            if host_filter:
                filter_pattern = f"%{host_filter}%"
                if has_content_type:
                    if has_threat_intel:
                        cursor.execute("""
                            SELECT r.id, r.method, r.host, r.uri, r.user_agent, r.timestamp, 
                                resp.status_code, resp.content_type,
                                COALESCE(ti.threat_score, 0) as threat_score,
                                COALESCE(ti.threat_type, '') as threat_type
                            FROM http_requests r
                            LEFT JOIN http_responses resp ON r.id = resp.http_request_id
                            LEFT JOIN connections c ON r.connection_key = c.connection_key
                            LEFT JOIN x_ip_threat_intel ti ON c.dst_ip = ti.ip_address
                            WHERE r.host LIKE ?
                            ORDER BY r.timestamp DESC
                            LIMIT ?
                        """, (filter_pattern, limit))
                    else:
                        cursor.execute("""
                            SELECT r.id, r.method, r.host, r.uri, r.user_agent, r.timestamp, 
                                resp.status_code, resp.content_type,
                                0 as threat_score,
                                '' as threat_type
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
                            resp.status_code, 'text/html',
                            0 as threat_score,
                            '' as threat_type
                        FROM http_requests r
                        LEFT JOIN http_responses resp ON r.id = resp.http_request_id
                        WHERE r.host LIKE ?
                        ORDER BY r.timestamp DESC
                        LIMIT ?
                    """, (filter_pattern, limit))
            else:
                if has_content_type:
                    if has_threat_intel:
                        cursor.execute("""
                            SELECT r.id, r.method, r.host, r.uri, r.user_agent, r.timestamp, 
                                resp.status_code, resp.content_type,
                                COALESCE(ti.threat_score, 0) as threat_score,
                                COALESCE(ti.threat_type, '') as threat_type
                            FROM http_requests r
                            LEFT JOIN http_responses resp ON r.id = resp.http_request_id
                            LEFT JOIN connections c ON r.connection_key = c.connection_key
                            LEFT JOIN x_ip_threat_intel ti ON c.dst_ip = ti.ip_address
                            ORDER BY r.timestamp DESC
                            LIMIT ?
                        """, (limit,))
                    else:
                        cursor.execute("""
                            SELECT r.id, r.method, r.host, r.uri, r.user_agent, r.timestamp, 
                                resp.status_code, resp.content_type,
                                0 as threat_score,
                                '' as threat_type
                            FROM http_requests r
                            LEFT JOIN http_responses resp ON r.id = resp.http_request_id
                            ORDER BY r.timestamp DESC
                            LIMIT ?
                        """, (limit,))
                else:
                    # Fallback query without content_type
                    cursor.execute("""
                        SELECT r.id, r.method, r.host, r.uri, r.user_agent, r.timestamp, 
                            resp.status_code, 'text/html',
                            0 as threat_score,
                            '' as threat_type
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
            threat_score = req[8] if len(req) > 8 else 0
            
            # Format the timestamp
            if isinstance(timestamp, float):
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                
            # Format risk score
            risk_display = f"{threat_score}%" if threat_score > 0 else ""
            
            # Set tag based on risk score for coloring
            tag = ""
            if threat_score > 70:
                tag = "high_risk"
            elif threat_score > 30:
                tag = "medium_risk"
            
            # Add to tree - ensure column order matches tree definition
            item_id = self.http_tree.insert("", "end", 
                values=(method, host, uri, status_code, content_type, timestamp, risk_display), 
                tags=(str(req_id), tag))
            
            # Store threat info in the item for use in details view
            if len(req) > 9 and req[9]:
                self.http_tree.item(item_id, values=(method, host, uri, status_code, content_type, timestamp, risk_display))
                
        # Configure tags for coloring
        self.http_tree.tag_configure("high_risk", background="#ffcccc")
        self.http_tree.tag_configure("medium_risk", background="#ffffcc")
        
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
        """Get TLS connections from analysis_1.db with threat intelligence"""
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
            
            # Check if threat intel table exists
            has_threat_intel = False
            try:
                cursor.execute("SELECT COUNT(*) FROM x_ip_threat_intel")
                has_threat_intel = True
            except:
                has_threat_intel = False
            
            # Build query based on available tables and columns
            if has_threat_intel:
                # Include threat intelligence data
                if filter_pattern:
                    pattern = f"%{filter_pattern}%"
                    if has_ja3:
                        query = """
                            SELECT t.server_name, t.tls_version, t.cipher_suite, t.ja3_fingerprint,
                                c.src_ip, c.dst_ip, c.src_port, c.dst_port, t.timestamp,
                                t.connection_key,
                                COALESCE(ti.threat_score, 0) as threat_score,
                                COALESCE(ti.threat_type, '') as threat_type
                            FROM tls_connections t
                            LEFT JOIN connections c ON t.connection_key = c.connection_key
                            LEFT JOIN x_ip_threat_intel ti ON c.dst_ip = ti.ip_address
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
                                t.connection_key,
                                COALESCE(ti.threat_score, 0) as threat_score,
                                COALESCE(ti.threat_type, '') as threat_type
                            FROM tls_connections t
                            LEFT JOIN connections c ON t.connection_key = c.connection_key
                            LEFT JOIN x_ip_threat_intel ti ON c.dst_ip = ti.ip_address
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
                                t.connection_key,
                                COALESCE(ti.threat_score, 0) as threat_score,
                                COALESCE(ti.threat_type, '') as threat_type
                            FROM tls_connections t
                            LEFT JOIN connections c ON t.connection_key = c.connection_key
                            LEFT JOIN x_ip_threat_intel ti ON c.dst_ip = ti.ip_address
                            ORDER BY t.timestamp DESC
                            LIMIT ?
                        """
                        rows = cursor.execute(query, (limit,)).fetchall()
                    else:
                        # Modified query without ja3_fingerprint
                        query = """
                            SELECT t.server_name, t.tls_version, t.cipher_suite, 'N/A',
                                c.src_ip, c.dst_ip, c.src_port, c.dst_port, t.timestamp,
                                t.connection_key,
                                COALESCE(ti.threat_score, 0) as threat_score,
                                COALESCE(ti.threat_type, '') as threat_type
                            FROM tls_connections t
                            LEFT JOIN connections c ON t.connection_key = c.connection_key
                            LEFT JOIN x_ip_threat_intel ti ON c.dst_ip = ti.ip_address
                            ORDER BY t.timestamp DESC
                            LIMIT ?
                        """
                        rows = cursor.execute(query, (limit,)).fetchall()
            else:
                # Original queries without threat intel
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
                
                # Get threat score if available
                threat_score = conn[10] if len(conn) > 10 else 0
                risk_display = f"{threat_score}%" if threat_score > 0 else ""
                
                # Format the timestamp
                if isinstance(timestamp, float):
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                
                # Set tag based on risk score and TLS version for coloring
                tag = ""
                if threat_score > 70:
                    tag = "high_risk"
                elif threat_score > 30:
                    tag = "medium_risk"
                elif tls_version in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
                    tag = "outdated_tls"
                
                # Add to tree
                self.tls_tree.insert("", "end", 
                    values=(server_name, tls_version, cipher_suite, src_ip, dst_ip, timestamp, risk_display),
                    tags=(tag,))
                
            except Exception as e:
                self.update_output(f"Error displaying TLS connection: {e}")
        
        # Configure tags for coloring
        self.tls_tree.tag_configure("high_risk", background="#ffcccc")
        self.tls_tree.tag_configure("medium_risk", background="#ffffcc")
        self.tls_tree.tag_configure("outdated_tls", background="#e6e6ff")
        
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
            
            # Check threat intel table
            try:
                cursor.execute("SELECT COUNT(*) FROM x_ip_threat_intel")
                threat_intel_count = cursor.fetchone()[0]
                
                cursor.execute("""
                    SELECT COUNT(*) FROM x_ip_threat_intel
                    WHERE threat_score > 0
                """)
                active_threats = cursor.fetchone()[0]
            except:
                threat_intel_count = 0
                active_threats = 0
            
            cursor.close()
            return {
                    "connections": conn_count,
                    "https_connections": https_count,
                    "tls_connections": tls_count,
                    "successful_joins": join_count,
                    "tls_keys": tls_keys,
                    "conn_keys": conn_keys,
                    "recent_https": recent_https,
                    "threat_intel_count": threat_intel_count,
                    "active_threats": active_threats
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
            self.tls_details_text.insert(tk.END, f"- Successful joins: {status['successful_joins']}\n")
            self.tls_details_text.insert(tk.END, f"- Threat intel records: {status.get('threat_intel_count', 0)}\n")
            self.tls_details_text.insert(tk.END, f"- Active threats: {status.get('active_threats', 0)}\n\n")
            
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
        
        # Add threat intel specific suggestions
        if status and status.get('threat_intel_count', 0) == 0:
            self.tls_details_text.insert(tk.END, "\nTo generate threat intelligence data:\n")
            self.tls_details_text.insert(tk.END, "1. Visit the 'Suspicious TLS' tab and check for outdated/weak TLS\n")
            self.tls_details_text.insert(tk.END, "2. Use the 'Update Threat Intel' button to create threat entries\n")
            self.tls_details_text.insert(tk.END, "3. Check that the x_ip_threat_intel table exists in analysis_1.db\n")

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
        """Get suspicious TLS connections from analysis_1.db with threat intelligence"""
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            
            # Check if we have any TLS connections first
            count = cursor.execute("SELECT COUNT(*) FROM tls_connections").fetchone()[0]
            if count == 0:
                cursor.close()
                return []
            
            # Check if we have threat intel table
            has_threat_intel = False
            try:
                cursor.execute("SELECT COUNT(*) FROM x_ip_threat_intel")
                has_threat_intel = True
            except:
                has_threat_intel = False
            
            # Check if ja3_fingerprint column exists
            cursor.execute("PRAGMA table_info(tls_connections)")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]
            has_ja3 = 'ja3_fingerprint' in column_names
                
            # Query for old TLS versions and weak ciphers
            if has_threat_intel:
                if has_ja3:
                    cursor.execute("""
                        SELECT t.server_name, t.tls_version, t.cipher_suite, t.ja3_fingerprint,
                            c.src_ip, c.dst_ip, t.timestamp,
                            COALESCE(ti.threat_score, 0) as threat_score,
                            COALESCE(ti.threat_type, '') as threat_type,
                            t.connection_key
                        FROM tls_connections t
                        LEFT JOIN connections c ON t.connection_key = c.connection_key
                        LEFT JOIN x_ip_threat_intel ti ON c.dst_ip = ti.ip_address
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
                            c.src_ip, c.dst_ip, t.timestamp,
                            COALESCE(ti.threat_score, 0) as threat_score,
                            COALESCE(ti.threat_type, '') as threat_type,
                            t.connection_key
                        FROM tls_connections t
                        LEFT JOIN connections c ON t.connection_key = c.connection_key
                        LEFT JOIN x_ip_threat_intel ti ON c.dst_ip = ti.ip_address
                        WHERE t.tls_version IN ('SSLv3', 'TLSv1.0', 'TLSv1.1')
                        OR t.cipher_suite LIKE '%NULL%'
                        OR t.cipher_suite LIKE '%EXPORT%'
                        OR t.cipher_suite LIKE '%DES%'
                        OR t.cipher_suite LIKE '%RC4%'
                        OR t.cipher_suite LIKE '%MD5%'
                        ORDER BY t.timestamp DESC
                    """)
            else:
                # Query without threat intel join
                if has_ja3:
                    cursor.execute("""
                        SELECT t.server_name, t.tls_version, t.cipher_suite, t.ja3_fingerprint,
                            c.src_ip, c.dst_ip, t.timestamp, 0, '', t.connection_key
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
                            c.src_ip, c.dst_ip, t.timestamp, 0, '', t.connection_key
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
            
            # Check which ones already have alerts in x_alerts
            alerted_ips = {}
            if has_threat_intel:
                try:
                    cursor.execute("""
                        SELECT ip_address FROM x_alerts
                        WHERE rule_name = 'tls_security_issue'
                    """)
                    for row in cursor.fetchall():
                        alerted_ips[row[0]] = True
                except:
                    pass
            
            cursor.close()
            
            # Add alert status to results
            final_results = []
            for row in results:
                if len(row) >= 10:
                    dst_ip = row[5]
                    status = "Alerted" if dst_ip in alerted_ips else ""
                    final_results.append(row + (status,))
                else:
                    final_results.append(row + ("",))
            
            return final_results
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
            if len(conn) < 10:
                continue
                
            server_name = conn[0] if conn[0] else "Unknown"
            tls_version = conn[1] if conn[1] else "Unknown"
            cipher_suite = conn[2] if conn[2] else "Unknown"
            src_ip = conn[4] if len(conn) > 4 and conn[4] else "Unknown"
            dst_ip = conn[5] if len(conn) > 5 and conn[5] else "Unknown"
            timestamp = conn[6] if len(conn) > 6 and conn[6] else time.time()
            threat_score = conn[7] if len(conn) > 7 else 0
            threat_type = conn[8] if len(conn) > 8 else ""
            status = conn[10] if len(conn) > 10 else ""
            
            # Format the timestamp
            if isinstance(timestamp, float):
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
            
            # Determine risk score based on TLS issues and any threat intel
            risk_score = max(threat_score, 30)  # Minimum 30% risk for suspicious TLS
            if tls_version in ["SSLv3", "TLSv1.0"]:
                risk_score = max(risk_score, 70)  # Higher risk for very old versions
            elif "NULL" in cipher_suite or "EXPORT" in cipher_suite:
                risk_score = max(risk_score, 80)  # Critical risk for broken ciphers
                
            # Set tag based on risk score
            tag = ""
            if risk_score > 70:
                tag = "high_risk"
            elif risk_score > 30:
                tag = "medium_risk"
                
            # Add to tree
            self.suspicious_tls_tree.insert("", "end", 
                values=(server_name, tls_version, cipher_suite, src_ip, dst_ip, timestamp, 
                       f"{risk_score}%", status),
                tags=(tag,))
        
        # Configure tags for coloring
        self.suspicious_tls_tree.tag_configure("high_risk", background="#ffcccc")
        self.suspicious_tls_tree.tag_configure("medium_risk", background="#ffffcc")
        
        self.update_output(f"Loaded {len(suspicious_connections)} suspicious TLS connections")
    
    def refresh_threat_intel(self):
        """Refresh threat intelligence data"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            return
            
        # Clear tree
        for item in self.threat_intel_tree.get_children():
            self.threat_intel_tree.delete(item)
        
        # Get threat intel data using analysis_manager
        self.gui.analysis_manager.queue_query(
            self._get_threat_intel_data,
            self._update_threat_intel_display
        )
    
    def _get_threat_intel_data(self):
        """Get threat intelligence data from analysis_1.db"""
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            
            # Check if we have the threat intel table
            try:
                cursor.execute("SELECT COUNT(*) FROM x_ip_threat_intel")
            except:
                cursor.close()
                return []
            
            # Get threat intel data
            cursor.execute("""
                SELECT ip_address, threat_score, threat_type, detection_method,
                       last_seen, details, alert_count, first_seen, confidence,
                       protocol, destination_ip
                FROM x_ip_threat_intel
                WHERE threat_score > 0
                ORDER BY threat_score DESC, last_seen DESC
            """)
            
            results = cursor.fetchall()
            
            # Get latest TLS server names for these IPs
            server_names = {}
            for row in results:
                ip = row[0]
                # Find recent TLS connection for this IP
                cursor.execute("""
                    SELECT t.server_name
                    FROM tls_connections t
                    JOIN connections c ON t.connection_key = c.connection_key
                    WHERE c.dst_ip = ? OR c.src_ip = ?
                    ORDER BY t.timestamp DESC
                    LIMIT 1
                """, (ip, ip))
                
                server_row = cursor.fetchone()
                server_names[ip] = server_row[0] if server_row else ""
            
            # Get alert status
            alert_status = {}
            try:
                cursor.execute("""
                    SELECT ip_address, COUNT(*)
                    FROM x_alerts
                    GROUP BY ip_address
                """)
                for row in cursor.fetchall():
                    alert_status[row[0]] = "Alerted" if row[1] > 0 else ""
            except:
                pass
            
            cursor.close()
            
            # Combine results with server names
            final_results = []
            for row in results:
                ip = row[0]
                server_name = server_names.get(ip, "")
                status = alert_status.get(ip, "")
                final_results.append(row + (server_name, status))
            
            return final_results
        except Exception as e:
            self.update_output(f"Error getting threat intelligence data: {e}")
            return []
    
    def _update_threat_intel_display(self, threat_intel_data):
        """Update threat intelligence display with the query results"""
        if not threat_intel_data:
            self.update_output("No threat intelligence data found")
            self.threat_details_text.delete(1.0, tk.END)
            self.threat_details_text.insert(tk.END, "No threat intelligence data found.\n\n")
            self.threat_details_text.insert(tk.END, "Visit the 'Suspicious TLS' tab and use 'Update Threat Intel' to generate threat data.")
            return
            
        # Add to tree
        for data in threat_intel_data:
            if len(data) < 7:
                continue
                
            ip = data[0]
            score = data[1]
            threat_type = data[2] if data[2] else "Unknown"
            detection = data[3] if data[3] else "local"
            last_seen = data[4]
            
            # Parse details
            details_json = data[5]
            details_str = ""
            if details_json:
                try:
                    details = json.loads(details_json)
                    if "detected_by" in details:
                        details_str = f"Detected by: {details['detected_by']}"
                    elif "reason" in details:
                        details_str = details["reason"]
                    else:
                        details_str = list(details.keys())[0] if details else ""
                except:
                    details_str = str(details_json)[:30]
            
            # Format timestamp
            if isinstance(last_seen, float):
                last_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_seen))
                
            # Get server name and status if available
            server = data[11] if len(data) > 11 else ""
            status = data[12] if len(data) > 12 else ""
                
            # Set tag based on risk score
            tag = ""
            if score > 70:
                tag = "high_risk"
            elif score > 30:
                tag = "medium_risk"
                
            # Add to tree
            self.threat_intel_tree.insert("", "end", 
                values=(ip, f"{score}%", threat_type, server, last_seen, details_str, status),
                tags=(tag, ip))
        
        # Configure tags for coloring
        self.threat_intel_tree.tag_configure("high_risk", background="#ffcccc")
        self.threat_intel_tree.tag_configure("medium_risk", background="#ffffcc")
        
        self.update_output(f"Loaded {len(threat_intel_data)} threat intelligence entries")
    
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
        risk = values[6] if len(values) > 6 else ""
        
        # Get the request ID from tags
        req_id = None
        tags = self.http_tree.item(item, 'tags')
        if tags and len(tags) > 0:
            req_id = tags[0]
        
        # Display basic details
        details = f"Method: {method}\nHost: {host}\nPath: {path}\nStatus: {status}\nContent-Type: {content_type}\n"
        
        if risk:
            details += f"Risk Score: {risk}\n"
        
        details += "\n"
        
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
                SELECT request_headers, user_agent, connection_key 
                FROM http_requests 
                WHERE id = ?
            """, (req_id,))
            
            request_result = cursor.fetchone()
            connection_key = request_result[2] if request_result and len(request_result) > 2 else None
            
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
            
            # Get IP addresses from connection
            ip_addresses = {}
            if connection_key:
                cursor.execute("""
                    SELECT src_ip, dst_ip
                    FROM connections
                    WHERE connection_key = ?
                """, (connection_key,))
                conn_result = cursor.fetchone()
                if conn_result:
                    ip_addresses = {
                        "src_ip": conn_result[0],
                        "dst_ip": conn_result[1]
                    }
                    
                    # Check for threat intel on destination IP
                    try:
                        dst_ip = conn_result[1]
                        cursor.execute("""
                            SELECT threat_score, threat_type, details
                            FROM x_ip_threat_intel
                            WHERE ip_address = ? AND threat_score > 0
                        """, (dst_ip,))
                        threat_result = cursor.fetchone()
                        if threat_result:
                            ip_addresses["threat_score"] = threat_result[0]
                            ip_addresses["threat_type"] = threat_result[1]
                            ip_addresses["threat_details"] = threat_result[2]
                    except:
                        pass
            
            cursor.close()
            return {
                "request": request_result,
                "response": response_result,
                "ip_addresses": ip_addresses
            }
        except Exception as e:
            self.update_output(f"Error getting HTTP request details: {e}")
            return {"request": None, "response": None, "ip_addresses": {}}
    
    def _update_http_details_display(self, result, basic_details):
        """Update HTTP details display with the query results"""
        details = basic_details
        
        # Add request details
        request_result = result["request"]
        if request_result:
            headers_json = request_result[0]
            user_agent = request_result[1]
            
            if headers_json:
                try:
                    headers = json.loads(headers_json)
                    details += "Headers:\n"
                    for name, value in headers.items():
                        details += f"  {name}: {value}\n"
                except:
                    pass
            
            if user_agent:
                details += f"\nUser-Agent: {user_agent}\n"
        
        # Add IP addresses
        ip_addresses = result["ip_addresses"]
        if ip_addresses:
            details += "\nConnection Details:\n"
            if "src_ip" in ip_addresses:
                details += f"  Source IP: {ip_addresses['src_ip']}\n"
            if "dst_ip" in ip_addresses:
                details += f"  Destination IP: {ip_addresses['dst_ip']}\n"
                
            # Add threat intel if available
            if "threat_score" in ip_addresses:
                details += f"\nThreat Intelligence:\n"
                details += f"  Threat Score: {ip_addresses['threat_score']}%\n"
                if "threat_type" in ip_addresses:
                    details += f"  Threat Type: {ip_addresses['threat_type']}\n"
                
                # Parse and display threat details if available
                if "threat_details" in ip_addresses:
                    try:
                        threat_details = json.loads(ip_addresses["threat_details"])
                        if threat_details:
                            details += "  Details:\n"
                            for key, value in threat_details.items():
                                if isinstance(value, dict):
                                    details += f"    {key}:\n"
                                    for k, v in value.items():
                                        details += f"      {k}: {v}\n"
                                else:
                                    details += f"    {key}: {value}\n"
                    except:
                        pass
        
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
        # Determine which tree triggered the event
        widget = event.widget
        
        # Get the selected item
        selected = widget.selection()
        if not selected:
            return
            
        # Clear details
        self.tls_details_text.delete(1.0, tk.END)
        
        item = selected[0]
        values = widget.item(item, 'values')
        if not values or len(values) < 6:
            return
            
        # Extract values - column order should be the same in all trees
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
            
            tls_result = cursor.fetchone()
            
            # Get threat intelligence for this destination IP
            threat_result = None
            try:
                cursor.execute("""
                    SELECT threat_score, threat_type, details, 
                           detection_method, first_seen, last_seen,
                           confidence, alert_count
                    FROM x_ip_threat_intel
                    WHERE ip_address = ? AND threat_score > 0
                """, (dst_ip,))
                threat_result = cursor.fetchone()
            except:
                pass
            
            cursor.close()
            return {
                "tls": tls_result,
                "threat": threat_result
            }
        except Exception as e:
            self.update_output(f"Error getting TLS details: {e}")
            return None
    
    def _update_tls_details_display(self, result, details, tls_version, cipher_suite):
        """Update TLS details display with the query results"""
        tls_result = result.get("tls") if result else None
        threat_result = result.get("threat") if result else None
        
        if tls_result:
            ja3 = tls_result[0] if len(tls_result) > 0 else None
            ja3s = tls_result[1] if len(tls_result) > 1 else None
            cert_issuer = tls_result[2] if len(tls_result) > 2 else None
            cert_subject = tls_result[3] if len(tls_result) > 3 else None
            cert_valid_from = tls_result[4] if len(tls_result) > 4 else None
            cert_valid_to = tls_result[5] if len(tls_result) > 5 else None
            
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
        
        # Display threat intelligence if available
        if threat_result:
            score = threat_result[0]
            threat_type = threat_result[1]
            
            details += f"\nThreat Intelligence:\n"
            details += f"  Score: {score}%\n"
            details += f"  Type: {threat_type}\n"
            
            # Show confidence if available
            if len(threat_result) > 6 and threat_result[6] is not None:
                confidence = threat_result[6] * 100
                details += f"  Confidence: {confidence:.1f}%\n"
                
            # Show detection method
            if len(threat_result) > 3 and threat_result[3]:
                details += f"  Detection: {threat_result[3]}\n"
                
            # Show first/last seen
            if len(threat_result) > 5 and threat_result[5]:
                last_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(threat_result[5]))
                details += f"  Last Seen: {last_seen}\n"
                
            # Show alert count if available
            if len(threat_result) > 7 and threat_result[7]:
                details += f"  Alert Count: {threat_result[7]}\n"
            
            # Parse and display details
            if len(threat_result) > 2 and threat_result[2]:
                try:
                    threat_details = json.loads(threat_result[2])
                    if threat_details:
                        details += "\nThreat Details:\n"
                        for key, value in threat_details.items():
                            if isinstance(value, dict):
                                details += f"  {key}:\n"
                                for k, v in value.items():
                                    details += f"    {k}: {v}\n"
                            else:
                                details += f"  {key}: {value}\n"
                except:
                    pass
        
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
            # Add recommendation for adding to threat intel
            self.tls_details_text.insert(tk.END, "\nRecommendation: Consider adding this connection to the threat intelligence database using the 'Flag as Suspicious' option in the right-click menu.")
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
                risk = values[6] if len(values) > 6 else ""
                
                self.update_output(f"Server: {server}, Version: {version}, Cipher: {cipher}")
                self.update_output(f"  Connection: {src_ip} -> {dst_ip}")
                self.update_output(f"  Risk Score: {risk}")
                
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
    
    def create_alerts_for_suspicious_tls(self):
        """Create alerts in x_alerts table for all suspicious TLS connections"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        items = self.suspicious_tls_tree.get_children()
        if not items:
            self.update_output("No suspicious TLS connections to process")
            return
            
        # Ask for confirmation
        confirm = messagebox.askyesno(
            "Create Alerts",
            f"Create alerts for {len(items)} suspicious TLS connections?\n\nThis will add entries to the x_alerts table in the analysis database.",
            parent=self.tab_frame
        )
        
        if not confirm:
            return
            
        # Process each suspicious TLS connection
        alert_count = 0
        for item in items:
            values = self.suspicious_tls_tree.item(item, 'values')
            if values and len(values) >= 6:
                server = values[0]
                version = values[1]
                cipher = values[2]
                dst_ip = values[4]
                status = values[7] if len(values) > 7 else ""
                
                # Skip if already alerted
                if status == "Alerted":
                    continue
                
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
                
                if issues and dst_ip:
                    # Create alert message
                    alert_message = f"Suspicious TLS: {', '.join(issues)} for {server}"
                    
                    # Use the analysis_manager to add the alert
                    success = self.gui.analysis_manager.add_alert(dst_ip, alert_message, "tls_security_issue")
                    if success:
                        alert_count += 1
                        
                        # Update the display
                        self.suspicious_tls_tree.item(item, values=(
                            server, version, cipher, values[3], dst_ip, values[5], values[6], "Alerted"
                        ))
        
        self.update_output(f"Created {alert_count} alerts for suspicious TLS connections")
        messagebox.showinfo(
            "Alerts Created",
            f"Created {alert_count} alerts for suspicious TLS connections",
            parent=self.tab_frame
        )
    
    def update_threat_intel_for_suspicious(self):
        """Update threat intelligence for all suspicious TLS connections"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        items = self.suspicious_tls_tree.get_children()
        if not items:
            self.update_output("No suspicious TLS connections to process")
            return
            
        # Ask for confirmation
        confirm = messagebox.askyesno(
            "Update Threat Intelligence",
            f"Update threat intelligence for {len(items)} suspicious TLS connections?\n\nThis will add entries to the x_ip_threat_intel table.",
            parent=self.tab_frame
        )
        
        if not confirm:
            return
            
        # Process each suspicious TLS connection
        threat_count = 0
        for item in items:
            values = self.suspicious_tls_tree.item(item, 'values')
            if values and len(values) >= 6:
                server = values[0]
                version = values[1]
                cipher = values[2]
                dst_ip = values[4]
                
                # Determine issue and risk score
                issues = []
                risk_score = 30  # Default moderate risk
                
                if version in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
                    issues.append(f"Outdated {version}")
                    if version in ["SSLv3", "TLSv1.0"]:
                        risk_score = max(risk_score, 70)  # Higher risk for very old versions
                    else:
                        risk_score = max(risk_score, 50)  # Medium risk for TLSv1.1
                
                if cipher:
                    cipher_lower = cipher.lower()
                    if "null" in cipher_lower:
                        issues.append("NULL cipher (no encryption)")
                        risk_score = 85  # Critical risk
                    if "export" in cipher_lower:
                        issues.append("EXPORT grade cipher (weak)")
                        risk_score = 80  # Critical risk
                    if "des" in cipher_lower and "3des" not in cipher_lower:
                        issues.append("DES cipher (broken)")
                        risk_score = 75  # High risk
                    if "rc4" in cipher_lower:
                        issues.append("RC4 cipher (weak)")
                        risk_score = 70  # High risk
                    if "md5" in cipher_lower:
                        issues.append("MD5 hashing (vulnerable)")
                        risk_score = 65  # Moderately high risk
                
                if issues and dst_ip:
                    # Create threat intel data
                    threat_data = {
                        'score': risk_score,
                        'type': 'tls_vulnerability',
                        'confidence': 0.85,
                        'source': 'tls_monitor',
                        'details': {
                            'server_name': server,
                            'version': version,
                            'cipher_suite': cipher,
                            'issues': issues,
                            'reason': ', '.join(issues)
                        },
                        'protocol': 'tls',
                        'destination_ip': dst_ip,
                        'detection_method': 'tls_analysis'
                    }
                    
                    # Use the analysis_manager to update threat intel
                    if hasattr(self.gui.analysis_manager, 'update_threat_intel'):
                        self.gui.analysis_manager.update_threat_intel(dst_ip, threat_data)
                        threat_count += 1
                    else:
                        # Fallback direct database update if method not available
                        try:
                            cursor = self.gui.analysis_manager.get_cursor()
                            cursor.execute("""
                                INSERT OR REPLACE INTO x_ip_threat_intel
                                (ip_address, threat_score, threat_type, confidence, source, details, 
                                detection_method, protocol, first_seen, last_seen)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """, (
                                dst_ip,
                                risk_score,
                                'tls_vulnerability',
                                0.85,
                                'tls_monitor',
                                json.dumps(threat_data['details']),
                                'tls_analysis',
                                'tls',
                                time.time(),
                                time.time()
                            ))
                            self.gui.analysis_manager.analysis1_conn.commit()
                            cursor.close()
                            threat_count += 1
                        except Exception as e:
                            self.update_output(f"Error updating threat intel: {e}")
        
        self.update_output(f"Updated threat intelligence for {threat_count} suspicious TLS connections")
        messagebox.showinfo(
            "Threat Intelligence Updated",
            f"Added threat intel for {threat_count} suspicious TLS connections",
            parent=self.tab_frame
        )
        
        # Refresh the threat intel tab
        self.refresh_threat_intel()
    
    def show_threat_intel_details(self, event):
        """Show threat intelligence details when selected"""
        selected = self.threat_intel_tree.selection()
        if not selected:
            return
            
        # Clear details
        self.threat_details_text.delete(1.0, tk.END)
        
        item = selected[0]
        values = self.threat_intel_tree.item(item, 'values')
        if not values or len(values) < 3:
            return
            
        # Extract values
        ip = values[0]
        score = values[1]
        threat_type = values[2]
        
        # Get detailed threat intel using analysis_manager
        self.gui.analysis_manager.queue_query(
            lambda: self._get_detailed_threat_intel(ip),
            lambda result: self._display_detailed_threat_intel(result, ip)
        )
    
    def _get_detailed_threat_intel(self, ip):
        """Get detailed threat intel for an IP address"""
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            
            # Get threat intel data
            cursor.execute("""
                SELECT threat_score, threat_type, confidence, source, details, 
                       detection_method, protocol, first_seen, last_seen, 
                       alert_count, destination_ip, destination_port
                FROM x_ip_threat_intel
                WHERE ip_address = ?
            """, (ip,))
            
            threat_data = cursor.fetchone()
            
            # Get alerts for this IP
            cursor.execute("""
                SELECT alert_message, rule_name, timestamp
                FROM x_alerts
                WHERE ip_address = ?
                ORDER BY timestamp DESC
                LIMIT 5
            """, (ip,))
            
            alerts = cursor.fetchall()
            
            # Get TLS connections for this IP
            cursor.execute("""
                SELECT t.server_name, t.tls_version, t.cipher_suite, t.timestamp
                FROM tls_connections t
                JOIN connections c ON t.connection_key = c.connection_key
                WHERE c.src_ip = ? OR c.dst_ip = ?
                ORDER BY t.timestamp DESC
                LIMIT 5
            """, (ip, ip))
            
            tls_connections = cursor.fetchall()
            
            # Get HTTP requests for this IP
            cursor.execute("""
                SELECT r.method, r.host, r.uri, r.timestamp
                FROM http_requests r
                JOIN connections c ON r.connection_key = c.connection_key
                WHERE c.src_ip = ? OR c.dst_ip = ?
                ORDER BY r.timestamp DESC
                LIMIT 5
            """, (ip, ip))
            
            http_requests = cursor.fetchall()
            
            cursor.close()
            
            return {
                "threat_data": threat_data,
                "alerts": alerts,
                "tls_connections": tls_connections,
                "http_requests": http_requests
            }
        except Exception as e:
            self.update_output(f"Error getting detailed threat intel: {e}")
            return {"threat_data": None}
    
    def _display_detailed_threat_intel(self, result, ip):
        """Display detailed threat intelligence information"""
        self.threat_details_text.delete(1.0, tk.END)
        
        threat_data = result.get("threat_data")
        if not threat_data:
            self.threat_details_text.insert(tk.END, f"No threat intelligence found for {ip}")
            return
            
        # Display basic threat info
        self.threat_details_text.insert(tk.END, f"Threat Intelligence for {ip}\n", "header")
        self.threat_details_text.insert(tk.END, f"Score: {threat_data[0]}%\n")
        self.threat_details_text.insert(tk.END, f"Type: {threat_data[1]}\n")
        
        if threat_data[2]:  # confidence
            confidence = threat_data[2] * 100
            self.threat_details_text.insert(tk.END, f"Confidence: {confidence:.1f}%\n")
            
        if threat_data[3]:  # source
            self.threat_details_text.insert(tk.END, f"Source: {threat_data[3]}\n")
            
        # Format timestamps
        if len(threat_data) > 7 and threat_data[7]:  # first_seen
            first_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(threat_data[7]))
            self.threat_details_text.insert(tk.END, f"First Seen: {first_seen}\n")
            
        if len(threat_data) > 8 and threat_data[8]:  # last_seen
            last_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(threat_data[8]))
            self.threat_details_text.insert(tk.END, f"Last Updated: {last_seen}\n")
            
        # Add connection details if available
        if len(threat_data) > 10:
            self.threat_details_text.insert(tk.END, "\nConnection Details:\n", "subheader")
            if threat_data[6]:  # protocol
                self.threat_details_text.insert(tk.END, f"Protocol: {threat_data[6]}\n")
            if threat_data[10]:  # destination_ip
                self.threat_details_text.insert(tk.END, f"Destination IP: {threat_data[10]}\n")
            if threat_data[11]:  # destination_port
                self.threat_details_text.insert(tk.END, f"Destination Port: {threat_data[11]}\n")
        
        # Parse and display details
        if threat_data[4]:  # details
            self.threat_details_text.insert(tk.END, "\nThreat Details:\n", "subheader")
            try:
                details = json.loads(threat_data[4])
                for key, value in details.items():
                    if isinstance(value, dict):
                        self.threat_details_text.insert(tk.END, f"{key}:\n", "item")
                        for k, v in value.items():
                            self.threat_details_text.insert(tk.END, f"  {k}: {v}\n")
                    elif isinstance(value, list):
                        self.threat_details_text.insert(tk.END, f"{key}:\n", "item")
                        for item in value:
                            self.threat_details_text.insert(tk.END, f"  - {item}\n")
                    else:
                        self.threat_details_text.insert(tk.END, f"{key}: {value}\n")
            except:
                # If JSON parsing fails, just display the raw details
                self.threat_details_text.insert(tk.END, threat_data[4])
        
        # Display related alerts
        alerts = result.get("alerts", [])
        if alerts:
            self.threat_details_text.insert(tk.END, "\nRelated Alerts:\n", "subheader")
            for alert in alerts:
                if len(alert) >= 3:
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alert[2]))
                    self.threat_details_text.insert(tk.END, f"[{timestamp}] {alert[0]}\n")
        
        # Display TLS connections
        tls_connections = result.get("tls_connections", [])
        if tls_connections:
            self.threat_details_text.insert(tk.END, "\nRecent TLS Connections:\n", "subheader")
            for conn in tls_connections:
                if len(conn) >= 4:
                    server = conn[0] or "Unknown"
                    version = conn[1] or "Unknown"
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(conn[3]))
                    self.threat_details_text.insert(tk.END, f"[{timestamp}] {server} - {version}\n")
        
        # Display HTTP requests
        http_requests = result.get("http_requests", [])
        if http_requests:
            self.threat_details_text.insert(tk.END, "\nRecent HTTP Requests:\n", "subheader")
            for req in http_requests:
                if len(req) >= 4:
                    method = req[0] or "GET"
                    host = req[1] or "Unknown"
                    uri = req[2] or "/"
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(req[3]))
                    self.threat_details_text.insert(tk.END, f"[{timestamp}] {method} {host}{uri}\n")
        
        # Configure tags for text formatting
        self.threat_details_text.tag_configure("header", font=("TkDefaultFont", 10, "bold"))
        self.threat_details_text.tag_configure("subheader", font=("TkDefaultFont", 9, "bold"))
        self.threat_details_text.tag_configure("item", font=("TkDefaultFont", 9, "italic"))
    
    def create_alert_for_connection(self, values):
        """Create an alert for a suspicious connection"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        if len(values) < 5:
            return
            
        server_name = values[0]
        tls_version = values[1]
        cipher_suite = values[2]
        dst_ip = values[4]
        
        # Determine issue
        issues = []
        if tls_version in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
            issues.append(f"Outdated {tls_version}")
        
        if cipher_suite:
            cipher_lower = cipher_suite.lower()
            if "null" in cipher_lower:
                issues.append("NULL cipher (no encryption)")
            if "export" in cipher_lower:
                issues.append("EXPORT grade cipher (weak)")
            if "des" in cipher_lower and "3des" not in cipher_lower:
                issues.append("DES cipher (broken)")
            if "rc4" in cipher_lower:
                issues.append("RC4 cipher (weak)")
            if "md5" in cipher_lower:
                issues.append("MD5 hashing (vulnerable)")
        
        if issues:
            # Create alert message
            alert_message = f"Suspicious TLS: {', '.join(issues)} for {server_name}"
            
            # Use the analysis_manager to add the alert
            success = self.gui.analysis_manager.add_alert(dst_ip, alert_message, "tls_security_issue")
            if success:
                self.update_output(f"Created alert for {dst_ip}: {alert_message}")
                messagebox.showinfo(
                    "Alert Created",
                    f"Created alert for {dst_ip}",
                    parent=self.tab_frame
                )
                
                # Update the display
                item = self.suspicious_tls_tree.selection()[0]
                self.suspicious_tls_tree.item(item, values=(
                    values[0], values[1], values[2], values[3], values[4], 
                    values[5], values[6], "Alerted"
                ))
            else:
                self.update_output(f"Failed to create alert for {dst_ip}")
                messagebox.showerror(
                    "Alert Creation Failed",
                    f"Failed to create alert for {dst_ip}",
                    parent=self.tab_frame
                )
    
    def update_threat_intel_for_connection(self, values):
        """Update threat intelligence for a suspicious connection"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        if len(values) < 5:
            return
            
        server_name = values[0]
        tls_version = values[1]
        cipher_suite = values[2]
        dst_ip = values[4]
        
        # Determine issue and risk score
        issues = []
        risk_score = 30  # Default moderate risk
        
        if tls_version in ["SSLv3", "TLSv1.0", "TLSv1.1"]:
            issues.append(f"Outdated {tls_version}")
            if tls_version in ["SSLv3", "TLSv1.0"]:
                risk_score = max(risk_score, 70)  # Higher risk for very old versions
            else:
                risk_score = max(risk_score, 50)  # Medium risk for TLSv1.1
        
        if cipher_suite:
            cipher_lower = cipher_suite.lower()
            if "null" in cipher_lower:
                issues.append("NULL cipher (no encryption)")
                risk_score = 85  # Critical risk
            if "export" in cipher_lower:
                issues.append("EXPORT grade cipher (weak)")
                risk_score = 80  # Critical risk
            if "des" in cipher_lower and "3des" not in cipher_lower:
                issues.append("DES cipher (broken)")
                risk_score = 75  # High risk
            if "rc4" in cipher_lower:
                issues.append("RC4 cipher (weak)")
                risk_score = 70  # High risk
            if "md5" in cipher_lower:
                issues.append("MD5 hashing (vulnerable)")
                risk_score = 65  # Moderately high risk
        
        if issues:
            # Create threat intel data
            threat_data = {
                'score': risk_score,
                'type': 'tls_vulnerability',
                'confidence': 0.85,
                'source': 'tls_monitor',
                'details': {
                    'server_name': server_name,
                    'version': tls_version,
                    'cipher_suite': cipher_suite,
                    'issues': issues,
                    'reason': ', '.join(issues),
                    'manual_submission': True
                },
                'protocol': 'tls',
                'destination_ip': dst_ip,
                'detection_method': 'tls_analysis'
            }
            
            # Use the analysis_manager to update threat intel
            if hasattr(self.gui.analysis_manager, 'update_threat_intel'):
                self.gui.analysis_manager.update_threat_intel(dst_ip, threat_data)
                self.update_output(f"Updated threat intelligence for {dst_ip}")
                messagebox.showinfo(
                    "Threat Intel Updated",
                    f"Added threat intel for {dst_ip} with score {risk_score}%",
                    parent=self.tab_frame
                )
                
                # Refresh the threat intel tab
                self.refresh_threat_intel()
            else:
                self.update_output(f"Failed to update threat intel for {dst_ip}")
                messagebox.showerror(
                    "Threat Intel Update Failed",
                    f"Failed to update threat intel for {dst_ip}",
                    parent=self.tab_frame
                )
    
    def mark_as_false_positive(self, values):
        """Mark a suspicious connection as a false positive"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        if len(values) < 5:
            return
            
        dst_ip = values[4]
        
        # Confirm with the user
        confirm = messagebox.askyesno(
            "Confirm False Positive",
            f"Are you sure you want to mark {dst_ip} as a false positive?\n\n"
            "This will add a note to the alerts and threat intel database.",
            parent=self.tab_frame
        )
        
        if not confirm:
            return
            
        # Queue the update using analysis_manager
        self.gui.analysis_manager.queue_query(
            lambda: self._update_false_positive(dst_ip, values),
            lambda result: self._handle_false_positive_result(result, dst_ip)
        )
    
    def _update_false_positive(self, ip_address, values):
        """Update database to mark an IP as false positive"""
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            
            # Add note to alerts table
            cursor.execute("""
                INSERT INTO x_alerts
                (ip_address, alert_message, rule_name, timestamp)
                VALUES (?, ?, ?, ?)
            """, (
                ip_address,
                f"Marked as false positive - {values[0]} (manual verification)",
                "false_positive",
                time.time()
            ))
            
            # Check if the IP exists in threat intel table
            cursor.execute("SELECT threat_score FROM x_ip_threat_intel WHERE ip_address = ?", (ip_address,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing threat intel with lower score
                cursor.execute("""
                    UPDATE x_ip_threat_intel
                    SET threat_score = 0,
                        confidence = 0.95,
                        details = JSON_SET(details, '$.false_positive', true),
                        detection_method = 'manual_verification'
                    WHERE ip_address = ?
                """, (ip_address,))
            else:
                # Add new entry with zero threat score
                details = {
                    'false_positive': True,
                    'server_name': values[0],
                    'version': values[1],
                    'cipher_suite': values[2],
                    'verification_note': 'Manually verified as false positive'
                }
                
                cursor.execute("""
                    INSERT INTO x_ip_threat_intel
                    (ip_address, threat_score, threat_type, confidence, source,
                     details, detection_method, protocol, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip_address,
                    0,
                    'verified_clean',
                    0.95,
                    'tls_monitor',
                    json.dumps(details),
                    'manual_verification',
                    'tls',
                    time.time(),
                    time.time()
                ))
            
            self.gui.analysis_manager.analysis1_conn.commit()
            cursor.close()
            return True
        except Exception as e:
            self.update_output(f"Error marking as false positive: {e}")
            return False
    
    def _handle_false_positive_result(self, success, ip_address):
        """Handle the result of marking a connection as false positive"""
        if success:
            self.update_output(f"Marked {ip_address} as false positive")
            messagebox.showinfo(
                "False Positive Recorded",
                f"The connection to {ip_address} has been marked as a false positive.",
                parent=self.tab_frame
            )
            
            # Update the item display
            for item in self.suspicious_tls_tree.selection():
                values = list(self.suspicious_tls_tree.item(item, 'values'))
                values[7] = "False Positive"  # Set status column
                self.suspicious_tls_tree.item(item, values=values)
                
            # Refresh threat intel display
            self.refresh_threat_intel()
        else:
            self.update_output(f"Failed to mark {ip_address} as false positive")
            messagebox.showerror(
                "Error",
                f"Failed to mark {ip_address} as false positive",
                parent=self.tab_frame
            )
    
    def show_security_assessment_dialog(self, values):
        """Show security assessment dialog for a TLS connection"""
        if len(values) < 3:
            return
            
        server_name = values[0]
        tls_version = values[1]
        cipher_suite = values[2]
        
        # Create dialog
        dialog = tk.Toplevel(self.tab_frame)
        dialog.title(f"Security Assessment: {server_name}")
        dialog.geometry("600x400")
        dialog.transient(self.tab_frame)
        dialog.grab_set()
        
        # Add header
        ttk.Label(dialog, text=f"TLS Security Assessment for {server_name}", 
                font=("TkDefaultFont", 12, "bold")).pack(pady=10)
        
        # Create scrollable text area
        frame = ttk.Frame(dialog)
        frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        text = tk.Text(frame, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        
        # Add assessment content
        text.insert(tk.END, f"Server: {server_name}\n")
        text.insert(tk.END, f"TLS Version: {tls_version}\n")
        text.insert(tk.END, f"Cipher Suite: {cipher_suite}\n\n")
        
        # Add version assessment
        text.insert(tk.END, "TLS VERSION ASSESSMENT\n", "section")
        if tls_version:
            if any(old in tls_version for old in ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]):
                text.insert(tk.END, "⚠️ VULNERABLE\n\n", "vulnerable")
                
                if "SSLv2" in tls_version:
                    text.insert(tk.END, "SSLv2 has significant cryptographic weaknesses and is explicitly prohibited by RFC 6176.\n")
                elif "SSLv3" in tls_version:
                    text.insert(tk.END, "SSLv3 is vulnerable to the POODLE attack (CVE-2014-3566) and other attacks.\n")
                    text.insert(tk.END, "It is explicitly prohibited by RFC 7568.\n")
                elif "TLSv1.0" in tls_version:
                    text.insert(tk.END, "TLSv1.0 is vulnerable to the BEAST attack and other weaknesses.\n")
                    text.insert(tk.END, "It has been deprecated by the IETF and major browsers.\n")
                elif "TLSv1.1" in tls_version:
                    text.insert(tk.END, "TLSv1.1 uses outdated cryptographic primitives and has been deprecated.\n")
                    text.insert(tk.END, "Major browsers have removed support as of 2020.\n")
                    
                text.insert(tk.END, "\nPCI DSS compliance requires TLSv1.2 or higher.\n")
                text.insert(tk.END, "NIST recommends disabling TLSv1.1 and below.\n")
                
            elif "TLSv1.2" in tls_version:
                text.insert(tk.END, "✓ ACCEPTABLE\n\n", "acceptable")
                text.insert(tk.END, "TLSv1.2 is currently acceptable when configured with strong cipher suites.\n")
                text.insert(tk.END, "It provides adequate security for most environments.\n")
                text.insert(tk.END, "However, migration to TLSv1.3 is recommended.\n")
                
            elif "TLSv1.3" in tls_version:
                text.insert(tk.END, "✓ SECURE\n\n", "secure")
                text.insert(tk.END, "TLSv1.3 is the current recommended version with improved security.\n")
                text.insert(tk.END, "It removes support for many insecure features and algorithms.\n")
                text.insert(tk.END, "It provides better privacy, security, and performance.\n")
        
        # Add cipher suite assessment
        text.insert(tk.END, "\nCIPHER SUITE ASSESSMENT\n", "section")
        if cipher_suite and "Unknown" not in cipher_suite:
            cipher_suite_lower = cipher_suite.lower()
            
            # Check for weak ciphers
            if any(weak in cipher_suite_lower for weak in ["null", "export", "des", "rc4", "md5"]):
                text.insert(tk.END, "⚠️ INSECURE CIPHER\n\n", "vulnerable")
                
                if "null" in cipher_suite_lower:
                    text.insert(tk.END, "NULL ciphers provide no encryption and offer no confidentiality.\n")
                if "export" in cipher_suite_lower:
                    text.insert(tk.END, "EXPORT ciphers use deliberately weakened encryption (512-bit or less).\n")
                    text.insert(tk.END, "These were created for compliance with US export restrictions that no longer exist.\n")
                if "des" in cipher_suite_lower and "3des" not in cipher_suite_lower:
                    text.insert(tk.END, "DES has been broken and is vulnerable to brute force attacks.\n")
                if "rc4" in cipher_suite_lower:
                    text.insert(tk.END, "RC4 has multiple cryptographic weaknesses leading to practical attacks.\n")
                    text.insert(tk.END, "It is prohibited by RFC 7465.\n")
                if "md5" in cipher_suite_lower:
                    text.insert(tk.END, "MD5 is cryptographically broken and vulnerable to collision attacks.\n")
                
            # Check for medium-strength ciphers
            elif any(medium in cipher_suite_lower for medium in ["sha1", "cbc", "3des"]):
                text.insert(tk.END, "⚠️ MODERATE SECURITY CONCERNS\n\n", "warning")
                
                if "sha1" in cipher_suite_lower:
                    text.insert(tk.END, "SHA1 is no longer considered collision-resistant.\n")
                    text.insert(tk.END, "It should be replaced with SHA-256 or SHA-384.\n")
                if "cbc" in cipher_suite_lower:
                    text.insert(tk.END, "CBC mode may be vulnerable to padding oracle attacks.\n")
                    text.insert(tk.END, "AEAD ciphers like GCM are preferred.\n")
                if "3des" in cipher_suite_lower:
                    text.insert(tk.END, "3DES provides less than optimal performance and security margins.\n")
                    text.insert(tk.END, "AES should be used instead.\n")
                
            # Check for strong ciphers
            elif any(strong in cipher_suite_lower for strong in ["aes_256", "aes256", "chacha20", "poly1305", "gcm", "sha384", "sha256"]):
                text.insert(tk.END, "✓ STRONG CIPHER\n\n", "secure")
                
                if any(aes in cipher_suite_lower for aes in ["aes_256", "aes256"]):
                    text.insert(tk.END, "AES-256 provides a high security margin.\n")
                if "gcm" in cipher_suite_lower:
                    text.insert(tk.END, "GCM mode provides authenticated encryption.\n")
                if any(chacha in cipher_suite_lower for chacha in ["chacha20", "chacha", "poly1305"]):
                    text.insert(tk.END, "ChaCha20-Poly1305 is a strong modern AEAD cipher.\n")
                if "sha384" in cipher_suite_lower:
                    text.insert(tk.END, "SHA-384 provides strong integrity protection.\n")
                elif "sha256" in cipher_suite_lower:
                    text.insert(tk.END, "SHA-256 provides good integrity protection.\n")
            else:
                text.insert(tk.END, "UNRECOGNIZED CIPHER\n\n", "warning")
                text.insert(tk.END, f"The cipher {cipher_suite} is not recognized in our security database.\n")
        else:
            text.insert(tk.END, "Unknown cipher suite\n\n")
        
        # Add overall assessment
        text.insert(tk.END, "\nOVERALL ASSESSMENT\n", "section")
        if "SSLv2" in tls_version or "SSLv3" in tls_version or "TLSv1.0" in tls_version or any(weak in cipher_suite.lower() for weak in ["null", "export", "des", "rc4"]):
            text.insert(tk.END, "⚠️ VULNERABLE - IMMEDIATE ACTION RECOMMENDED\n\n", "vulnerable")
            text.insert(tk.END, "This connection has serious security issues that should be addressed immediately.\n")
            text.insert(tk.END, "Recommended actions:\n")
            text.insert(tk.END, "1. Upgrade to TLSv1.2 or TLSv1.3\n")
            text.insert(tk.END, "2. Disable weak cipher suites\n")
            text.insert(tk.END, "3. Configure secure cipher order\n")
            text.insert(tk.END, "4. Implement HSTS if applicable\n")
        elif "TLSv1.1" in tls_version or any(medium in cipher_suite.lower() for medium in ["sha1", "cbc", "3des"]):
            text.insert(tk.END, "⚠️ MODERATE RISK - IMPROVEMENTS NEEDED\n\n", "warning")
            text.insert(tk.END, "This connection has moderate security concerns that should be addressed.\n")
            text.insert(tk.END, "Recommended actions:\n")
            text.insert(tk.END, "1. Upgrade to TLSv1.2 or preferably TLSv1.3\n")
            text.insert(tk.END, "2. Replace outdated cryptographic primitives\n")
            text.insert(tk.END, "3. Configure ECDHE for perfect forward secrecy\n")
        elif "TLSv1.2" in tls_version and any(strong in cipher_suite.lower() for strong in ["aes", "chacha", "gcm"]):
            text.insert(tk.END, "✓ ACCEPTABLE - MINOR IMPROVEMENTS POSSIBLE\n\n", "acceptable")
            text.insert(tk.END, "This connection uses adequate security settings but could be improved.\n")
            text.insert(tk.END, "Recommended actions:\n")
            text.insert(tk.END, "1. Consider upgrading to TLSv1.3 when possible\n")
            text.insert(tk.END, "2. Ensure cipher order prioritizes AEAD ciphers\n")
        elif "TLSv1.3" in tls_version:
            text.insert(tk.END, "✓ STRONG - CURRENT BEST PRACTICE\n\n", "secure")
            text.insert(tk.END, "This connection uses the currently recommended security settings.\n")
        else:
            text.insert(tk.END, "UNCERTAIN - MORE INFORMATION NEEDED\n\n", "warning")
            text.insert(tk.END, "Some aspects of this connection could not be fully assessed.\n")
        
        # Configure tags
        text.tag_configure("section", font=("TkDefaultFont", 11, "bold"))
        text.tag_configure("vulnerable", font=("TkDefaultFont", 10, "bold"), foreground="red")
        text.tag_configure("warning", font=("TkDefaultFont", 10, "bold"), foreground="orange")
        text.tag_configure("acceptable", font=("TkDefaultFont", 10, "bold"), foreground="blue")
        text.tag_configure("secure", font=("TkDefaultFont", 10, "bold"), foreground="green")
        
        # Make text read-only
        text.config(state=tk.DISABLED)
        
        # Add action buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", pady=10)
        
        # Flag As Suspicious button
        ttk.Button(btn_frame, text="Flag As Suspicious", 
                  command=lambda: [self.flag_as_suspicious(values), dialog.destroy()]).pack(side="left", padx=10)
        
        # Export Report button
        ttk.Button(btn_frame, text="Export Report", 
                  command=lambda: self.export_security_report(server_name, text.get(1.0, tk.END))).pack(side="left", padx=10)
        
        # Close button
        ttk.Button(btn_frame, text="Close", 
                  command=dialog.destroy).pack(side="right", padx=10)
    
    def export_security_report(self, server_name, report_text):
        """Export security assessment report to a file"""
        try:
            import os
            
            # Generate filename
            safe_name = "".join(c if c.isalnum() else "_" for c in server_name)
            filename = f"tls_security_{safe_name}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            filepath = os.path.join(desktop_path, filename)
            
            # Write to file
            with open(filepath, 'w') as f:
                f.write("TLS SECURITY ASSESSMENT REPORT\n")
                f.write("============================\n\n")
                f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(report_text)
            
            self.update_output(f"Exported security report to {filepath}")
            messagebox.showinfo(
                "Export Successful",
                f"Security report exported to {filepath}",
                parent=self.tab_frame
            )
        except Exception as e:
            self.update_output(f"Error exporting report: {e}")
            messagebox.showerror(
                "Export Error",
                f"Failed to export report: {str(e)}",
                parent=self.tab_frame
            )
    
    def flag_as_suspicious(self, values):
        """Flag a TLS connection as suspicious and add to threat intel"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        if len(values) < 5:
            return
            
        server_name = values[0]
        tls_version = values[1]
        cipher_suite = values[2]
        dst_ip = values[4]
        
        # Calculate threat score based on TLS version and cipher
        score = 30  # Default moderate score
        reasons = []
        
        if tls_version in ["SSLv2", "SSLv3", "TLSv1.0"]:
            score = max(score, 75)
            reasons.append(f"Outdated {tls_version}")
        elif tls_version == "TLSv1.1":
            score = max(score, 50)
            reasons.append("Outdated TLSv1.1")
            
        if cipher_suite:
            cipher_lower = cipher_suite.lower()
            if "null" in cipher_lower:
                score = max(score, 85)
                reasons.append("NULL cipher (no encryption)")
            if "export" in cipher_lower:
                score = max(score, 80)
                reasons.append("EXPORT grade cipher (weak)")
            if "des" in cipher_lower and "3des" not in cipher_lower:
                score = max(score, 75)
                reasons.append("DES cipher (broken)")
            if "rc4" in cipher_lower:
                score = max(score, 70)
                reasons.append("RC4 cipher (weak)")
            if "md5" in cipher_lower:
                score = max(score, 65)
                reasons.append("MD5 hashing (vulnerable)")
                
        # If no specific issues found, use a more generic reason
        if not reasons:
            reasons.append("Manually flagged as suspicious")
        
        # Create threat data
        threat_data = {
            'score': score,
            'type': 'tls_vulnerability',
            'confidence': 0.8,
            'source': 'manual_inspection',
            'details': {
                'server_name': server_name,
                'version': tls_version,
                'cipher_suite': cipher_suite,
                'issues': reasons,
                'manual_flag': True,
                'reason': ', '.join(reasons)
            },
            'protocol': 'tls',
            'destination_ip': dst_ip,
            'detection_method': 'user_flagged'
        }
        
        # Update threat intel
        self.gui.analysis_manager.queue_query(
            lambda: self._add_to_threat_intel(dst_ip, threat_data),
            lambda result: self._handle_flag_result(result, dst_ip, score)
        )
    
    def _add_to_threat_intel(self, ip, threat_data):
        """Add an entry to the threat intelligence database"""
        try:
            if hasattr(self.gui.analysis_manager, 'update_threat_intel'):
                # Use the dedicated method if available
                self.gui.analysis_manager.update_threat_intel(ip, threat_data)
                return True
            else:
                # Fall back to direct database access
                cursor = self.gui.analysis_manager.get_cursor()
                
                cursor.execute("""
                    INSERT OR REPLACE INTO x_ip_threat_intel
                    (ip_address, threat_score, threat_type, confidence, source, details, 
                    detection_method, protocol, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip,
                    threat_data['score'],
                    threat_data['type'],
                    threat_data['confidence'],
                    threat_data['source'],
                    json.dumps(threat_data['details']),
                    threat_data['detection_method'],
                    threat_data['protocol'],
                    time.time(),
                    time.time()
                ))
                
                self.gui.analysis_manager.analysis1_conn.commit()
                cursor.close()
                return True
        except Exception as e:
            self.update_output(f"Error adding to threat intel: {e}")
            return False
    
    def _handle_flag_result(self, success, ip, score):
        """Handle the result of flagging a connection"""
        if success:
            self.update_output(f"Added {ip} to threat intelligence with score {score}%")
            messagebox.showinfo(
                "Connection Flagged",
                f"Added {ip} to threat intelligence database with score {score}%",
                parent=self.tab_frame
            )
            
            # Refresh the threat intel display
            self.refresh_threat_intel()
        else:
            self.update_output(f"Failed to add {ip} to threat intelligence")
            messagebox.showerror(
                "Error",
                f"Failed to add {ip} to threat intelligence database",
                parent=self.tab_frame
            )
    
    def show_full_threat_details(self, ip):
        """Show full threat details dialog"""
        # Create dialog
        dialog = tk.Toplevel(self.tab_frame)
        dialog.title(f"Threat Details: {ip}")
        dialog.geometry("700x500")
        dialog.transient(self.tab_frame)
        dialog.grab_set()
        
        # Create notebook with multiple tabs
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Summary tab
        summary_tab = ttk.Frame(notebook)
        notebook.add(summary_tab, text="Summary")
        
        # Details tab
        details_tab = ttk.Frame(notebook)
        notebook.add(details_tab, text="Details")
        
        # Connections tab
        connections_tab = ttk.Frame(notebook)
        notebook.add(connections_tab, text="Connections")
        
        # Alerts tab
        alerts_tab = ttk.Frame(notebook)
        notebook.add(alerts_tab, text="Alerts")
        
        # Add loading indicator
        loading_label = ttk.Label(summary_tab, text="Loading threat data...")
        loading_label.pack(pady=20)
        
        # Queue data fetching
        self.gui.analysis_manager.queue_query(
            lambda: self._get_comprehensive_threat_data(ip),
            lambda data: self._display_comprehensive_threat_data(data, notebook, summary_tab, details_tab, connections_tab, alerts_tab, loading_label)
        )
        
        # Add buttons at the bottom
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", pady=10)
        
        ttk.Button(btn_frame, text="Update Threat Score", 
                  command=lambda: self.update_threat_score(ip, dialog)).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Mark as False Positive", 
                  command=lambda: [self.mark_threat_as_false_positive(ip), dialog.destroy()]).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Export Data", 
                  command=lambda: self.export_threat_data(ip)).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Close", 
                  command=dialog.destroy).pack(side="right", padx=10)
    
    def _get_comprehensive_threat_data(self, ip):
        """Get comprehensive threat data for an IP"""
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            
            # Get basic threat intel
            cursor.execute("""
                SELECT threat_score, threat_type, confidence, source, details,
                       detection_method, protocol, first_seen, last_seen,
                       alert_count, destination_ip, destination_port,
                       bytes_transferred, packet_count, timing_variance,
                       encoding_type
                FROM x_ip_threat_intel
                WHERE ip_address = ?
            """, (ip,))
            
            threat_data = cursor.fetchone()
            
            # Get alerts
            cursor.execute("""
                SELECT alert_message, rule_name, timestamp
                FROM x_alerts
                WHERE ip_address = ?
                ORDER BY timestamp DESC
                LIMIT 20
            """, (ip,))
            
            alerts = cursor.fetchall()
            
            # Get recent connections
            cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port, protocol, total_bytes, packet_count, timestamp
                FROM connections
                WHERE src_ip = ? OR dst_ip = ?
                ORDER BY timestamp DESC
                LIMIT 50
            """, (ip, ip))
            
            connections = cursor.fetchall()
            
            # Get TLS connections
            cursor.execute("""
                SELECT t.server_name, t.tls_version, t.cipher_suite, t.timestamp
                FROM tls_connections t
                JOIN connections c ON t.connection_key = c.connection_key
                WHERE c.src_ip = ? OR c.dst_ip = ?
                ORDER BY t.timestamp DESC
                LIMIT 20
            """, (ip, ip))
            
            tls_connections = cursor.fetchall()
            
            # Get HTTP requests
            cursor.execute("""
                SELECT r.method, r.host, r.uri, r.timestamp
                FROM http_requests r
                JOIN connections c ON r.connection_key = c.connection_key
                WHERE c.src_ip = ? OR c.dst_ip = ?
                ORDER BY r.timestamp DESC
                LIMIT 20
            """, (ip, ip))
            
            http_requests = cursor.fetchall()
            
            # Get geolocation if available
            geo_data = None
            try:
                cursor.execute("""
                    SELECT country, region, city, latitude, longitude, asn, asn_name
                    FROM x_ip_geolocation
                    WHERE ip_address = ?
                """, (ip,))
                geo_data = cursor.fetchone()
            except:
                pass
            
            # Get traffic patterns if available
            traffic_patterns = None
            try:
                cursor.execute("""
                    SELECT avg_packet_size, std_dev_packet_size, periodic_score, burst_score, 
                           classification, session_count
                    FROM x_traffic_patterns
                    WHERE connection_key LIKE ? OR connection_key LIKE ?
                    LIMIT 1
                """, (f"{ip}:%->%", f"%->{ip}:%"))
                traffic_patterns = cursor.fetchone()
            except:
                pass
            
            cursor.close()
            
            return {
                "ip": ip,
                "threat_data": threat_data,
                "alerts": alerts,
                "connections": connections,
                "tls_connections": tls_connections,
                "http_requests": http_requests,
                "geo_data": geo_data,
                "traffic_patterns": traffic_patterns
            }
        except Exception as e:
            self.update_output(f"Error getting comprehensive threat data: {e}")
            return {"ip": ip, "error": str(e)}
    
    def _display_comprehensive_threat_data(self, data, notebook, summary_tab, details_tab, connections_tab, alerts_tab, loading_label=None):
        """Display comprehensive threat data in dialog tabs"""
        ip = data.get("ip", "Unknown")
        
        # Remove loading indicator if present
        if loading_label:
            loading_label.destroy()
        
        # Check for errors
        if "error" in data:
            ttk.Label(summary_tab, text=f"Error loading data: {data['error']}", 
                    foreground="red").pack(pady=20)
            return
            
        # Populate Summary tab
        self._populate_summary_tab(summary_tab, data)
        
        # Populate Details tab
        self._populate_details_tab(details_tab, data)
        
        # Populate Connections tab
        self._populate_connections_tab(connections_tab, data)
        
        # Populate Alerts tab
        self._populate_alerts_tab(alerts_tab, data)
    
    def _populate_summary_tab(self, tab, data):
        """Populate the summary tab with threat overview"""
        ip = data.get("ip", "Unknown")
        threat_data = data.get("threat_data")
        geo_data = data.get("geo_data")
        
        # Create scrollable frame
        frame = ttk.Frame(tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create canvas with scrollbar
        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Header
        ttk.Label(scrollable_frame, text=f"Threat Intelligence Summary for {ip}", 
                font=("TkDefaultFont", 12, "bold")).pack(anchor="w", pady=(0, 10))
        
        # Create info frames
        if threat_data:
            # Main info frame
            info_frame = ttk.LabelFrame(scrollable_frame, text="Threat Information")
            info_frame.pack(fill="x", pady=5)
            
            # Format data
            score = threat_data[0] if len(threat_data) > 0 else 0
            threat_type = threat_data[1] if len(threat_data) > 1 else "Unknown"
            confidence = threat_data[2] * 100 if len(threat_data) > 2 and threat_data[2] is not None else 0
            source = threat_data[3] if len(threat_data) > 3 else "Unknown"
            detection = threat_data[5] if len(threat_data) > 5 else "Unknown"
            
            # Add score with color coding
            score_frame = ttk.Frame(info_frame)
            score_frame.pack(fill="x", padx=10, pady=5)
            
            ttk.Label(score_frame, text="Threat Score:").grid(row=0, column=0, sticky="w")
            score_label = ttk.Label(score_frame, text=f"{score}%")
            score_label.grid(row=0, column=1, sticky="w", padx=5)
            
            # Set color based on score
            if score > 70:
                score_label.configure(foreground="red")
            elif score > 30:
                score_label.configure(foreground="orange")
            else:
                score_label.configure(foreground="green")
            
            # Add other threat details
            ttk.Label(score_frame, text="Threat Type:").grid(row=1, column=0, sticky="w")
            ttk.Label(score_frame, text=threat_type).grid(row=1, column=1, sticky="w", padx=5)
            
            ttk.Label(score_frame, text="Confidence:").grid(row=2, column=0, sticky="w")
            ttk.Label(score_frame, text=f"{confidence:.1f}%").grid(row=2, column=1, sticky="w", padx=5)
            
            ttk.Label(score_frame, text="Source:").grid(row=3, column=0, sticky="w")
            ttk.Label(score_frame, text=source).grid(row=3, column=1, sticky="w", padx=5)
            
            ttk.Label(score_frame, text="Detection Method:").grid(row=4, column=0, sticky="w")
            ttk.Label(score_frame, text=detection).grid(row=4, column=1, sticky="w", padx=5)
            
            # Add timestamps
            if len(threat_data) > 8:
                time_frame = ttk.Frame(info_frame)
                time_frame.pack(fill="x", padx=10, pady=5)
                
                first_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(threat_data[7])) if threat_data[7] else "Unknown"
                last_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(threat_data[8])) if threat_data[8] else "Unknown"
                
                ttk.Label(time_frame, text="First Seen:").grid(row=0, column=0, sticky="w")
                ttk.Label(time_frame, text=first_seen).grid(row=0, column=1, sticky="w", padx=5)
                
                ttk.Label(time_frame, text="Last Updated:").grid(row=1, column=0, sticky="w")
                ttk.Label(time_frame, text=last_seen).grid(row=1, column=1, sticky="w", padx=5)
                
                if len(threat_data) > 9 and threat_data[9]:
                    ttk.Label(time_frame, text="Alert Count:").grid(row=2, column=0, sticky="w")
                    ttk.Label(time_frame, text=str(threat_data[9])).grid(row=2, column=1, sticky="w", padx=5)
            
            # Parse and display details if available
            if len(threat_data) > 4 and threat_data[4]:
                details_frame = ttk.LabelFrame(scrollable_frame, text="Threat Details")
                details_frame.pack(fill="x", pady=5)
                
                try:
                    details = json.loads(threat_data[4])
                    
                    details_text = tk.Text(details_frame, height=8, wrap=tk.WORD)
                    details_text.pack(fill="both", expand=True, padx=5, pady=5)
                    
                    # Format details
                    for key, value in details.items():
                        if isinstance(value, dict):
                            details_text.insert(tk.END, f"{key}:\n", "bold")
                            for k, v in value.items():
                                details_text.insert(tk.END, f"  {k}: {v}\n")
                        elif isinstance(value, list):
                            details_text.insert(tk.END, f"{key}:\n", "bold")
                            for item in value:
                                details_text.insert(tk.END, f"  - {item}\n")
                        else:
                            details_text.insert(tk.END, f"{key}: ", "bold")
                            details_text.insert(tk.END, f"{value}\n")
                    
                    details_text.tag_configure("bold", font=("TkDefaultFont", 9, "bold"))
                    details_text.config(state=tk.DISABLED)
                except:
                    ttk.Label(details_frame, text="Could not parse threat details").pack(padx=10, pady=5)
        else:
            ttk.Label(scrollable_frame, text="No threat intelligence data available").pack(pady=10)
        
        # Add geolocation if available
        if geo_data:
            geo_frame = ttk.LabelFrame(scrollable_frame, text="Geolocation")
            geo_frame.pack(fill="x", pady=5)
            
            geo_info = ttk.Frame(geo_frame)
            geo_info.pack(fill="x", padx=10, pady=5)
            
            if geo_data[0]:  # country
                ttk.Label(geo_info, text="Country:").grid(row=0, column=0, sticky="w")
                ttk.Label(geo_info, text=geo_data[0]).grid(row=0, column=1, sticky="w", padx=5)
            
            if geo_data[1] and geo_data[2]:  # region, city
                ttk.Label(geo_info, text="Location:").grid(row=1, column=0, sticky="w")
                ttk.Label(geo_info, text=f"{geo_data[2]}, {geo_data[1]}").grid(row=1, column=1, sticky="w", padx=5)
            
            if len(geo_data) > 5 and geo_data[5] and geo_data[6]:  # asn, asn_name
                ttk.Label(geo_info, text="Network:").grid(row=2, column=0, sticky="w")
                ttk.Label(geo_info, text=f"AS{geo_data[5]} ({geo_data[6]})").grid(row=2, column=1, sticky="w", padx=5)
        
        # Add statistics
        stats_frame = ttk.LabelFrame(scrollable_frame, text="Statistics")
        stats_frame.pack(fill="x", pady=5)
        
        stats = ttk.Frame(stats_frame)
        stats.pack(fill="x", padx=10, pady=5)
        
        alerts = data.get("alerts", [])
        connections = data.get("connections", [])
        tls_conns = data.get("tls_connections", [])
        http_reqs = data.get("http_requests", [])
        
        ttk.Label(stats, text="Total Alerts:").grid(row=0, column=0, sticky="w")
        ttk.Label(stats, text=str(len(alerts))).grid(row=0, column=1, sticky="w", padx=5)
        
        ttk.Label(stats, text="Total Connections:").grid(row=1, column=0, sticky="w")
        ttk.Label(stats, text=str(len(connections))).grid(row=1, column=1, sticky="w", padx=5)
        
        ttk.Label(stats, text="TLS Connections:").grid(row=2, column=0, sticky="w")
        ttk.Label(stats, text=str(len(tls_conns))).grid(row=2, column=1, sticky="w", padx=5)
        
        ttk.Label(stats, text="HTTP Requests:").grid(row=3, column=0, sticky="w")
        ttk.Label(stats, text=str(len(http_reqs))).grid(row=3, column=1, sticky="w", padx=5)
        
        # Add traffic pattern info if available
        traffic = data.get("traffic_patterns")
        if traffic:
            traffic_frame = ttk.LabelFrame(scrollable_frame, text="Traffic Pattern Analysis")
            traffic_frame.pack(fill="x", pady=5)
            
            traffic_info = ttk.Frame(traffic_frame)
            traffic_info.pack(fill="x", padx=10, pady=5)
            
            if traffic[0]:  # avg_packet_size
                ttk.Label(traffic_info, text="Avg Packet Size:").grid(row=0, column=0, sticky="w")
                ttk.Label(traffic_info, text=f"{traffic[0]:.1f} bytes").grid(row=0, column=1, sticky="w", padx=5)
            
            if traffic[2]:  # periodic_score
                ttk.Label(traffic_info, text="Periodicity Score:").grid(row=1, column=0, sticky="w")
                ttk.Label(traffic_info, text=f"{traffic[2]:.2f}").grid(row=1, column=1, sticky="w", padx=5)
            
            if traffic[3]:  # burst_score
                ttk.Label(traffic_info, text="Burst Score:").grid(row=2, column=0, sticky="w")
                ttk.Label(traffic_info, text=f"{traffic[3]:.2f}").grid(row=2, column=1, sticky="w", padx=5)
            
            if traffic[4]:  # classification
                ttk.Label(traffic_info, text="Classification:").grid(row=3, column=0, sticky="w")
                ttk.Label(traffic_info, text=traffic[4]).grid(row=3, column=1, sticky="w", padx=5)
    
    def _populate_details_tab(self, tab, data):
        """Populate the details tab with raw threat data"""
        threat_data = data.get("threat_data")
        
        # Create text widget with scrollbar
        details_frame = ttk.Frame(tab)
        details_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        details_text = tk.Text(details_frame, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(details_frame, orient="vertical", command=details_text.yview)
        details_text.configure(yscrollcommand=scrollbar.set)
        
        details_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        if threat_data:
            # Header
            details_text.insert(tk.END, "Raw Threat Intelligence Data\n\n", "header")
            
            # Format each field
            fields = [
                ("Threat Score", threat_data[0]),
                ("Threat Type", threat_data[1]),
                ("Confidence", threat_data[2]),
                ("Source", threat_data[3]),
                ("Detection Method", threat_data[5]),
                ("Protocol", threat_data[6]),
                ("First Seen", threat_data[7]),
                ("Last Seen", threat_data[8])
            ]
            
            for label, value in fields:
                if value is not None:
                    # Format timestamp fields
                    if label in ["First Seen", "Last Seen"] and isinstance(value, float):
                        value = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(value))
                    
                    # Format confidence as percentage
                    if label == "Confidence" and isinstance(value, float):
                        value = f"{value * 100:.1f}%"
                        
                    details_text.insert(tk.END, f"{label}: ", "bold")
                    details_text.insert(tk.END, f"{value}\n")
            
            # Add extended fields if available
            extended_fields = []
            
            if len(threat_data) > 9:
                extended_fields.append(("Alert Count", threat_data[9]))
            
            if len(threat_data) > 10 and threat_data[10]:
                extended_fields.append(("Destination IP", threat_data[10]))
                
            if len(threat_data) > 11 and threat_data[11]:
                extended_fields.append(("Destination Port", threat_data[11]))
                
            if len(threat_data) > 12 and threat_data[12]:
                extended_fields.append(("Bytes Transferred", threat_data[12]))
                
            if len(threat_data) > 13 and threat_data[13]:
                extended_fields.append(("Packet Count", threat_data[13]))
                
            if len(threat_data) > 14 and threat_data[14]:
                extended_fields.append(("Timing Variance", threat_data[14]))
            
            if extended_fields:
                details_text.insert(tk.END, "\nExtended Information\n", "header")
                for label, value in extended_fields:
                    details_text.insert(tk.END, f"{label}: ", "bold")
                    details_text.insert(tk.END, f"{value}\n")
            
            # Add raw JSON if available
            if len(threat_data) > 4 and threat_data[4]:
                details_text.insert(tk.END, "\nRaw Details JSON\n", "header")
                try:
                    details = json.loads(threat_data[4])
                    details_text.insert(tk.END, json.dumps(details, indent=2))
                except:
                    details_text.insert(tk.END, threat_data[4])
        else:
            details_text.insert(tk.END, "No threat intelligence data available")
        
        # Configure tags
        details_text.tag_configure("header", font=("TkDefaultFont", 11, "bold"))
        details_text.tag_configure("bold", font=("TkDefaultFont", 9, "bold"))
        
        # Make text read-only
        details_text.config(state=tk.DISABLED)
    
    def _populate_connections_tab(self, tab, data):
        """Populate connections tab with connection history"""
        # Create notebook for connection types
        conn_notebook = ttk.Notebook(tab)
        conn_notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Create tabs for different connection types
        all_tab = ttk.Frame(conn_notebook)
        tls_tab = ttk.Frame(conn_notebook)
        http_tab = ttk.Frame(conn_notebook)
        
        conn_notebook.add(all_tab, text="All Connections")
        conn_notebook.add(tls_tab, text="TLS Connections")
        conn_notebook.add(http_tab, text="HTTP Requests")
        
        # Populate All Connections tab
        connections = data.get("connections", [])
        if connections:
            # Create treeview
            columns = ("direction", "remote_ip", "port", "protocol", "bytes", "packets", "timestamp")
            tree = ttk.Treeview(all_tab, columns=columns, show="headings")
            
            tree.heading("direction", text="Direction")
            tree.heading("remote_ip", text="Remote IP")
            tree.heading("port", text="Port")
            tree.heading("protocol", text="Protocol")
            tree.heading("bytes", text="Bytes")
            tree.heading("packets", text="Packets")
            tree.heading("timestamp", text="Timestamp")
            
            # Configure columns
            tree.column("direction", width=70)
            tree.column("remote_ip", width=120)
            tree.column("port", width=60)
            tree.column("protocol", width=70)
            tree.column("bytes", width=80)
            tree.column("packets", width=70)
            tree.column("timestamp", width=150)
            
            # Add scrollbar
            scrollbar = ttk.Scrollbar(all_tab, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=scrollbar.set)
            
            tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Add data
            ip = data.get("ip")
            for conn in connections:
                if len(conn) >= 8:
                    src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, timestamp = conn
                    
                    # Determine direction and remote IP
                    if src_ip == ip:
                        direction = "Outbound"
                        remote_ip = dst_ip
                        port = dst_port
                    else:
                        direction = "Inbound"
                        remote_ip = src_ip
                        port = src_port
                    
                    # Format timestamp
                    if isinstance(timestamp, float):
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                    
                    # Add to tree
                    tree.insert("", "end", values=(direction, remote_ip, port, protocol, bytes, packets, timestamp))
        else:
            ttk.Label(all_tab, text="No connection data available").pack(pady=10)
        
        # Populate TLS Connections tab
        tls_connections = data.get("tls_connections", [])
        if tls_connections:
            # Create treeview
            columns = ("server", "version", "cipher", "timestamp")
            tls_tree = ttk.Treeview(tls_tab, columns=columns, show="headings")
            
            tls_tree.heading("server", text="Server Name")
            tls_tree.heading("version", text="TLS Version")
            tls_tree.heading("cipher", text="Cipher Suite")
            tls_tree.heading("timestamp", text="Timestamp")
            
            # Configure columns
            tls_tree.column("server", width=200)
            tls_tree.column("version", width=80)
            tls_tree.column("cipher", width=250)
            tls_tree.column("timestamp", width=150)
            
            # Add scrollbar
            scrollbar = ttk.Scrollbar(tls_tab, orient="vertical", command=tls_tree.yview)
            tls_tree.configure(yscrollcommand=scrollbar.set)
            
            tls_tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Add data
            for tls in tls_connections:
                if len(tls) >= 4:
                    server, version, cipher, timestamp = tls
                    
                    # Format timestamp
                    if isinstance(timestamp, float):
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                    
                    # Add to tree
                    tls_tree.insert("", "end", values=(server, version, cipher, timestamp))
        else:
            ttk.Label(tls_tab, text="No TLS connection data available").pack(pady=10)
        
        # Populate HTTP Requests tab
        http_requests = data.get("http_requests", [])
        if http_requests:
            # Create treeview
            columns = ("method", "host", "path", "timestamp")
            http_tree = ttk.Treeview(http_tab, columns=columns, show="headings")
            
            http_tree.heading("method", text="Method")
            http_tree.heading("host", text="Host")
            http_tree.heading("path", text="Path")
            http_tree.heading("timestamp", text="Timestamp")
            
            # Configure columns
            http_tree.column("method", width=70)
            http_tree.column("host", width=200)
            http_tree.column("path", width=300)
            http_tree.column("timestamp", width=150)
            
            # Add scrollbar
            scrollbar = ttk.Scrollbar(http_tab, orient="vertical", command=http_tree.yview)
            http_tree.configure(yscrollcommand=scrollbar.set)
            
            http_tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Add data
            for req in http_requests:
                if len(req) >= 4:
                    method, host, path, timestamp = req
                    
                    # Format timestamp
                    if isinstance(timestamp, float):
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                    
                    # Add to tree
                    http_tree.insert("", "end", values=(method, host, path, timestamp))
        else:
            ttk.Label(http_tab, text="No HTTP request data available").pack(pady=10)
    
    def _populate_alerts_tab(self, tab, data):
        """Populate alerts tab with alert history"""
        alerts = data.get("alerts", [])
        
        if alerts:
            # Create treeview
            columns = ("message", "rule", "timestamp")
            tree = ttk.Treeview(tab, columns=columns, show="headings")
            
            tree.heading("message", text="Alert Message")
            tree.heading("rule", text="Rule Name")
            tree.heading("timestamp", text="Timestamp")
            
            # Configure columns
            tree.column("message", width=400)
            tree.column("rule", width=150)
            tree.column("timestamp", width=150)
            
            # Add scrollbar
            scrollbar = ttk.Scrollbar(tab, orient="vertical", command=tree.yview)
            tree.configure(yscrollcommand=scrollbar.set)
            
            tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
            
            # Add data
            for alert in alerts:
                if len(alert) >= 3:
                    message, rule, timestamp = alert
                    
                    # Format timestamp
                    if isinstance(timestamp, float):
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                    
                    # Set tag based on rule type
                    tag = ""
                    if "security" in rule.lower() or "suspicious" in rule.lower():
                        tag = "security"
                    elif "false_positive" in rule.lower():
                        tag = "false_positive"
                    
                    # Add to tree
                    tree.insert("", "end", values=(message, rule, timestamp), tags=(tag,))
            
            # Configure tags
            tree.tag_configure("security", background="#ffcccc")
            tree.tag_configure("false_positive", background="#e6ffe6")
        else:
            ttk.Label(tab, text="No alerts found for this IP").pack(pady=10)
    
    def update_threat_score(self, ip, parent_dialog=None):
        """Update the threat score for an IP address"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        # Check if the IP exists in threat intel
        self.gui.analysis_manager.queue_query(
            lambda: self._check_threat_exists(ip),
            lambda exists: self._show_update_score_dialog(ip, exists, parent_dialog)
        )
    
    def _check_threat_exists(self, ip):
        """Check if an IP exists in the threat intelligence database"""
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            cursor.execute("SELECT threat_score FROM x_ip_threat_intel WHERE ip_address = ?", (ip,))
            result = cursor.fetchone()
            cursor.close()
            
            return result[0] if result else None
        except Exception as e:
            self.update_output(f"Error checking threat intel: {e}")
            return None
    
    def _show_update_score_dialog(self, ip, current_score, parent_dialog=None):
        """Show dialog to update threat score"""
        # Create dialog
        dialog = tk.Toplevel(parent_dialog if parent_dialog else self.tab_frame)
        dialog.title(f"Update Threat Score: {ip}")
        dialog.geometry("400x300")
        dialog.transient(parent_dialog if parent_dialog else self.tab_frame)
        dialog.grab_set()
        
        # Add header
        ttk.Label(dialog, text=f"Update Threat Intelligence for {ip}", 
                font=("TkDefaultFont", 11, "bold")).pack(pady=10)
        
        # Current score
        if current_score is not None:
            ttk.Label(dialog, text=f"Current Threat Score: {current_score}%").pack(pady=5)
        else:
            ttk.Label(dialog, text="No existing threat intelligence found for this IP").pack(pady=5)
        
        # Score entry
        score_frame = ttk.Frame(dialog)
        score_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(score_frame, text="New Threat Score (0-100):").pack(side="left")
        score_var = tk.IntVar(value=current_score if current_score is not None else 50)
        score_scale = ttk.Scale(score_frame, from_=0, to=100, variable=score_var, orient="horizontal")
        score_scale.pack(side="right", fill="x", expand=True, padx=5)
        
        # Score display
        score_label = ttk.Label(dialog, text=f"Score: {score_var.get()}%")
        score_label.pack(pady=5)
        
        # Update score label when scale changes
        def update_score_label(*args):
            score_label.config(text=f"Score: {score_var.get()}%")
        
        score_var.trace_add("write", update_score_label)
        
        # Threat type
        type_frame = ttk.Frame(dialog)
        type_frame.pack(fill="x", padx=20, pady=10)
        
        ttk.Label(type_frame, text="Threat Type:").pack(side="left")
        type_var = tk.StringVar(value="manual_assessment")
        type_combo = ttk.Combobox(type_frame, textvariable=type_var, width=20)
        type_combo['values'] = (
            "manual_assessment",
            "tls_vulnerability",
            "suspicious_behavior",
            "port_scanning",
            "malware",
            "c2_traffic",
            "data_exfiltration",
            "false_positive"
        )
        type_combo.pack(side="right", fill="x", expand=True, padx=5)
        
        # Notes
        notes_frame = ttk.LabelFrame(dialog, text="Notes")
        notes_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        notes_var = tk.StringVar()
        notes_entry = tk.Text(notes_frame, height=5, wrap=tk.WORD)
        notes_entry.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", pady=10)
        
        ttk.Button(btn_frame, text="Update", 
                  command=lambda: self._do_update_threat_score(
                      ip, score_var.get(), type_var.get(), notes_entry.get("1.0", tk.END).strip(), dialog
                  )).pack(side="left", padx=10)
        
        ttk.Button(btn_frame, text="Cancel", 
                  command=dialog.destroy).pack(side="right", padx=10)
    
    def _do_update_threat_score(self, ip, score, threat_type, notes, dialog):
        """Actually update the threat score in the database"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        # Create threat data
        threat_data = {
            'score': score,
            'type': threat_type,
            'confidence': 0.9,
            'source': 'manual_update',
            'details': {
                'notes': notes,
                'manual_update': True,
                'update_time': time.time()
            },
            'detection_method': 'manual_assessment'
        }
        
        # Update threat intel
        self.gui.analysis_manager.queue_query(
            lambda: self._update_threat_data(ip, threat_data),
            lambda success: self._handle_score_update_result(success, ip, score, dialog)
        )
    
    def _update_threat_data(self, ip, threat_data):
        """Update threat data in the database"""
        try:
            if hasattr(self.gui.analysis_manager, 'update_threat_intel'):
                # Use the dedicated method if available
                self.gui.analysis_manager.update_threat_intel(ip, threat_data)
                return True
            else:
                # Fall back to direct database access
                cursor = self.gui.analysis_manager.get_cursor()
                
                # Check if entry exists
                cursor.execute("SELECT details FROM x_ip_threat_intel WHERE ip_address = ?", (ip,))
                existing = cursor.fetchone()
                
                if existing and existing[0]:
                    # Merge with existing details
                    try:
                        existing_details = json.loads(existing[0])
                        # Store previous score in history
                        if 'score_history' not in existing_details:
                            existing_details['score_history'] = []
                        
                        cursor.execute("SELECT threat_score FROM x_ip_threat_intel WHERE ip_address = ?", (ip,))
                        prev_score = cursor.fetchone()[0]
                        
                        existing_details['score_history'].append({
                            'previous_score': prev_score,
                            'updated_to': threat_data['score'],
                            'update_time': time.time(),
                            'update_reason': threat_data['details'].get('notes', 'Manual update')
                        })
                        
                        # Merge other details
                        for key, value in threat_data['details'].items():
                            existing_details[key] = value
                        
                        # Update with merged details
                        details_json = json.dumps(existing_details)
                    except:
                        # If merge fails, use new details
                        details_json = json.dumps(threat_data['details'])
                else:
                    # New entry
                    details_json = json.dumps(threat_data['details'])
                
                # Insert or replace
                cursor.execute("""
                    INSERT OR REPLACE INTO x_ip_threat_intel
                    (ip_address, threat_score, threat_type, confidence, source, details, 
                    detection_method, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip,
                    threat_data['score'],
                    threat_data['type'],
                    threat_data['confidence'],
                    threat_data['source'],
                    details_json,
                    threat_data['detection_method'],
                    time.time() if not existing else None,  # Keep original first_seen if exists
                    time.time()
                ))
                
                # Also add an alert
                cursor.execute("""
                    INSERT INTO x_alerts
                    (ip_address, alert_message, rule_name, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (
                    ip,
                    f"Threat score manually updated to {threat_data['score']}%",
                    "manual_assessment",
                    time.time()
                ))
                
                self.gui.analysis_manager.analysis1_conn.commit()
                cursor.close()
                return True
        except Exception as e:
            self.update_output(f"Error updating threat data: {e}")
            return False
    
    def _handle_score_update_result(self, success, ip, score, dialog):
        """Handle the result of updating the threat score"""
        if success:
            self.update_output(f"Updated threat score for {ip} to {score}%")
            messagebox.showinfo(
                "Score Updated",
                f"Threat score for {ip} updated to {score}%",
                parent=dialog
            )
            dialog.destroy()
            
            # Refresh the threat intel display
            self.refresh_threat_intel()
        else:
            self.update_output(f"Failed to update threat score for {ip}")
            messagebox.showerror(
                "Update Failed",
                f"Failed to update threat score for {ip}",
                parent=dialog
            )
    
    def mark_threat_as_false_positive(self, ip):
        """Mark a threat as a false positive"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        # Confirm with the user
        confirm = messagebox.askyesno(
            "Confirm False Positive",
            f"Are you sure you want to mark {ip} as a false positive?\n\n"
            "This will set the threat score to 0 and add a note to the database.",
            parent=self.tab_frame
        )
        
        if not confirm:
            return
            
        # Create false positive threat data
        threat_data = {
            'score': 0,
            'type': 'false_positive',
            'confidence': 0.95,
            'source': 'manual_verification',
            'details': {
                'false_positive': True,
                'verified_by': 'user',
                'verification_time': time.time(),
                'notes': 'Manually verified as false positive'
            },
            'detection_method': 'manual_verification'
        }
        
        # Update threat intel
        self.gui.analysis_manager.queue_query(
            lambda: self._update_threat_data(ip, threat_data),
            lambda success: self._handle_false_positive_update(success, ip)
        )
    
    def _handle_false_positive_update(self, success, ip):
        """Handle the result of marking a threat as false positive"""
        if success:
            self.update_output(f"Marked {ip} as false positive")
            messagebox.showinfo(
                "False Positive Recorded",
                f"The IP {ip} has been marked as a false positive and its threat score set to 0.",
                parent=self.tab_frame
            )
            
            # Refresh the threat intel display
            self.refresh_threat_intel()
        else:
            self.update_output(f"Failed to mark {ip} as false positive")
            messagebox.showerror(
                "Error",
                f"Failed to mark {ip} as false positive",
                parent=self.tab_frame
            )
    
    def export_threat_data(self, ip):
        """Export threat data for an IP to a file"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        # Get the threat data
        self.gui.analysis_manager.queue_query(
            lambda: self._get_comprehensive_threat_data(ip),
            self._export_threat_data_to_file
        )
    
    def _export_threat_data_to_file(self, data):
        """Export threat data to a file"""
        try:
            import os
            
            ip = data.get("ip", "unknown_ip")
            threat_data = data.get("threat_data")
            
            if not threat_data:
                self.update_output(f"No threat data available for {ip}")
                messagebox.showinfo(
                    "No Data",
                    f"No threat data available for {ip}",
                    parent=self.tab_frame
                )
                return
                
            # Generate filename
            filename = f"threat_data_{ip}_{time.strftime('%Y%m%d_%H%M%S')}.json"
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            filepath = os.path.join(desktop_path, filename)
            
            # Prepare export data
            export_data = {
                "ip_address": ip,
                "export_time": time.strftime("%Y-%m-%d %H:%M:%S"),
                "threat_data": {
                    "score": threat_data[0] if len(threat_data) > 0 else None,
                    "type": threat_data[1] if len(threat_data) > 1 else None,
                    "confidence": threat_data[2] if len(threat_data) > 2 else None,
                    "source": threat_data[3] if len(threat_data) > 3 else None,
                    "details": json.loads(threat_data[4]) if len(threat_data) > 4 and threat_data[4] else {},
                    "detection_method": threat_data[5] if len(threat_data) > 5 else None,
                    "protocol": threat_data[6] if len(threat_data) > 6 else None,
                    "first_seen": threat_data[7] if len(threat_data) > 7 else None,
                    "last_seen": threat_data[8] if len(threat_data) > 8 else None
                }
            }
            
            # Add related data
            export_data["alerts"] = []
            for alert in data.get("alerts", []):
                if len(alert) >= 3:
                    export_data["alerts"].append({
                        "message": alert[0],
                        "rule": alert[1],
                        "timestamp": alert[2]
                    })
            
            export_data["connections"] = []
            for conn in data.get("connections", [])[:20]:  # Limit to 20 connections
                if len(conn) >= 8:
                    export_data["connections"].append({
                        "src_ip": conn[0],
                        "dst_ip": conn[1],
                        "src_port": conn[2],
                        "dst_port": conn[3],
                        "protocol": conn[4],
                        "bytes": conn[5],
                        "packets": conn[6],
                        "timestamp": conn[7]
                    })
            
            export_data["tls_connections"] = []
            for tls in data.get("tls_connections", []):
                if len(tls) >= 4:
                    export_data["tls_connections"].append({
                        "server": tls[0],
                        "version": tls[1],
                        "cipher": tls[2],
                        "timestamp": tls[3]
                    })
                    
            # Add geolocation if available
            geo_data = data.get("geo_data")
            if geo_data:
                export_data["geolocation"] = {
                    "country": geo_data[0] if len(geo_data) > 0 else None,
                    "region": geo_data[1] if len(geo_data) > 1 else None,
                    "city": geo_data[2] if len(geo_data) > 2 else None,
                    "latitude": geo_data[3] if len(geo_data) > 3 else None,
                    "longitude": geo_data[4] if len(geo_data) > 4 else None,
                    "asn": geo_data[5] if len(geo_data) > 5 else None,
                    "asn_name": geo_data[6] if len(geo_data) > 6 else None
                }
            
            # Write to file
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            
            self.update_output(f"Exported threat data for {ip} to {filepath}")
            messagebox.showinfo(
                "Export Successful",
                f"Threat data for {ip} exported to {filepath}",
                parent=self.tab_frame
            )
        except Exception as e:
            self.update_output(f"Error exporting threat data: {e}")
            messagebox.showerror(
                "Export Error",
                f"Failed to export threat data: {str(e)}",
                parent=self.tab_frame
            )
    
    def check_host_reputation(self, hostname):
        """Check reputation for a hostname"""
        # Create simple dialog showing we're checking
        dialog = tk.Toplevel(self.tab_frame)
        dialog.title(f"Checking Host: {hostname}")
        dialog.geometry("400x150")
        dialog.transient(self.tab_frame)
        dialog.grab_set()
        
        ttk.Label(dialog, text=f"Checking reputation for {hostname}...",
                font=("TkDefaultFont", 10, "bold")).pack(pady=10)
        
        progress = ttk.Progressbar(dialog, mode="indeterminate")
        progress.pack(fill="x", padx=20, pady=10)
        progress.start()
        
        # Check if we can resolve hostname to IP
        def resolve_and_check():
            import socket
            try:
                ip = socket.gethostbyname(hostname)
                return {"hostname": hostname, "ip": ip, "resolved": True}
            except:
                return {"hostname": hostname, "resolved": False}
        
        # Queue the hostname lookup
        self.gui.analysis_manager.queue_query(
            resolve_and_check,
            lambda result: self._handle_host_lookup(result, dialog, progress)
        )
    
    def _handle_host_lookup(self, result, dialog, progress):
        """Handle the hostname lookup results"""
        if result.get("resolved", False):
            # Successfully resolved, check IP reputation
            progress.stop()
            ip = result["ip"]
            hostname = result["hostname"]
            
            ttk.Label(dialog, text=f"Resolved to IP: {ip}").pack(pady=5)
            
            # Check if we have threat intel for this IP
            progress.start()
            self.gui.analysis_manager.queue_query(
                lambda: self._check_threat_exists(ip),
                lambda threat_score: self._display_host_reputation(hostname, ip, threat_score, dialog, progress)
            )
        else:
            # Failed to resolve
            progress.stop()
            ttk.Label(dialog, text="Could not resolve hostname to IP address",
                    foreground="red").pack(pady=5)
            
            ttk.Button(dialog, text="Close",
                      command=dialog.destroy).pack(pady=10)
    
    def _display_host_reputation(self, hostname, ip, threat_score, dialog, progress):
        """Display host reputation results"""
        progress.stop()
        progress.destroy()
        
        if threat_score is not None:
            # We have threat intel
            if threat_score > 70:
                risk_level = "HIGH RISK"
                color = "red"
            elif threat_score > 30:
                risk_level = "MEDIUM RISK"
                color = "orange"
            elif threat_score > 0:
                risk_level = "LOW RISK"
                color = "blue"
            else:
                risk_level = "NO RISK DETECTED"
                color = "green"
                
            ttk.Label(dialog, text=f"Risk Level: {risk_level} ({threat_score}%)",
                    foreground=color, font=("TkDefaultFont", 10, "bold")).pack(pady=5)
            
            ttk.Button(dialog, text="View Details",
                      command=lambda: [dialog.destroy(), self.show_full_threat_details(ip)]).pack(side="left", padx=10, pady=10)
        else:
            # No threat intel, offer to check
            ttk.Label(dialog, text="No existing threat intelligence for this host",
                    foreground="green").pack(pady=5)
            
            ttk.Button(dialog, text="Run Reputation Check",
                      command=lambda: [dialog.destroy(), self.check_ip_reputation(ip)]).pack(side="left", padx=10, pady=10)
        
        ttk.Button(dialog, text="Close",
                  command=dialog.destroy).pack(side="right", padx=10, pady=10)
    
    def check_ip_reputation(self, ip):
        """Check reputation of an IP address"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        # Create dialog
        dialog = tk.Toplevel(self.tab_frame)
        dialog.title(f"IP Reputation Check: {ip}")
        dialog.geometry("500x300")
        dialog.transient(self.tab_frame)
        dialog.grab_set()
        
        # Add header
        ttk.Label(dialog, text=f"Checking Reputation for {ip}", 
                font=("TkDefaultFont", 11, "bold")).pack(pady=10)
        
        # Add progress bar
        progress_frame = ttk.Frame(dialog)
        progress_frame.pack(fill="x", padx=20, pady=10)
        
        progress = ttk.Progressbar(progress_frame, mode="indeterminate")
        progress.pack(fill="x")
        progress.start()
        
        # Status label
        status_var = tk.StringVar(value="Checking IP reputation...")
        status = ttk.Label(dialog, textvariable=status_var)
        status.pack(pady=5)
        
        # Results text widget
        results_frame = ttk.Frame(dialog)
        results_frame.pack(fill="both", expand=True, padx=20, pady=10)
        
        results_text = tk.Text(results_frame, height=10, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=results_text.yview)
        results_text.configure(yscrollcommand=scrollbar.set)
        
        results_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Queue the reputation check
        self.gui.analysis_manager.queue_query(
            lambda: self._check_comprehensive_ip_reputation(ip),
            lambda result: self._display_ip_reputation_results(result, ip, dialog, progress, status_var, results_text)
        )
    
    def _check_comprehensive_ip_reputation(self, ip):
        """Check reputation of an IP from multiple sources"""
        result = {"ip": ip, "checks": []}
        
        # Check existing threat intel
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            cursor.execute("SELECT threat_score, threat_type, confidence, source FROM x_ip_threat_intel WHERE ip_address = ?", (ip,))
            threat_data = cursor.fetchone()
            cursor.close()
            
            if threat_data:
                result["checks"].append({
                    "source": "Local DB",
                    "score": threat_data[0],
                    "type": threat_data[1],
                    "confidence": threat_data[2]
                })
        except Exception as e:
            result["checks"].append({
                "source": "Local DB",
                "error": str(e)
            })
        
        # Check geolocation
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            cursor.execute("SELECT country, region, city, asn, asn_name FROM x_ip_geolocation WHERE ip_address = ?", (ip,))
            geo_data = cursor.fetchone()
            cursor.close()
            
            if geo_data:
                result["geo"] = {
                    "country": geo_data[0],
                    "region": geo_data[1],
                    "city": geo_data[2],
                    "asn": geo_data[3],
                    "asn_name": geo_data[4]
                }
        except:
            pass
        
        # Check alerts
        try:
            cursor = self.gui.analysis_manager.get_cursor()
            cursor.execute("SELECT COUNT(*) FROM x_alerts WHERE ip_address = ?", (ip,))
            alert_count = cursor.fetchone()[0]
            cursor.close()
            
            result["alert_count"] = alert_count
        except:
            pass
        
        # Simulated external threat intel check
        # In a real implementation, you would call external APIs here
        import random
        time.sleep(2)  # Simulate API call delay
        
        # Simulate a positive or negative result
        is_suspicious = random.random() < 0.3  # 30% chance of being flagged
        
        if is_suspicious:
            categories = ["malware", "phishing", "spam", "scanning", "botnet"]
            category = random.choice(categories)
            score = random.randint(50, 90)
            
            result["checks"].append({
                "source": "Mock External Service",
                "score": score,
                "type": category,
                "confidence": 0.7
            })
        else:
            result["checks"].append({
                "source": "Mock External Service",
                "score": 0,
                "type": "clean",
                "confidence": 0.8
            })
        
        return result
    
    def _display_ip_reputation_results(self, result, ip, dialog, progress, status_var, results_text):
        """Display IP reputation check results"""
        # Stop progress and update status
        progress.stop()
        progress.destroy()
        
        # Display results
        results_text.delete(1.0, tk.END)
        results_text.insert(tk.END, f"Reputation Check Results for {ip}\n\n", "header")
        
        # Show geolocation if available
        if "geo" in result:
            geo = result["geo"]
            results_text.insert(tk.END, "Location Information:\n", "section")
            if geo.get("country"):
                results_text.insert(tk.END, f"Country: {geo['country']}\n")
            if geo.get("region") and geo.get("city"):
                results_text.insert(tk.END, f"Location: {geo['city']}, {geo['region']}\n")
            if geo.get("asn") and geo.get("asn_name"):
                results_text.insert(tk.END, f"Network: AS{geo['asn']} ({geo['asn_name']})\n")
            results_text.insert(tk.END, "\n")
        
        # Show alert count if available
        if "alert_count" in result:
            results_text.insert(tk.END, f"Alerts related to this IP: {result['alert_count']}\n\n")
        
        # Process check results
        found_threat = False
        highest_score = 0
        checks = result.get("checks", [])
        
        for check in checks:
            source = check.get("source", "Unknown")
            
            if "error" in check:
                results_text.insert(tk.END, f"{source}: Error - {check['error']}\n")
                continue
                
            score = check.get("score", 0)
            if score > highest_score:
                highest_score = score
                
            if score > 0:
                found_threat = True
                confidence = check.get("confidence", 0) * 100
                
                # Format with color based on score
                if score > 70:
                    results_text.insert(tk.END, f"{source}: ", "bold")
                    results_text.insert(tk.END, f"HIGH RISK ({score}%)\n", "high_risk")
                elif score > 30:
                    results_text.insert(tk.END, f"{source}: ", "bold")
                    results_text.insert(tk.END, f"MEDIUM RISK ({score}%)\n", "medium_risk")
                else:
                    results_text.insert(tk.END, f"{source}: ", "bold")
                    results_text.insert(tk.END, f"LOW RISK ({score}%)\n", "low_risk")
                    
                results_text.insert(tk.END, f"  Type: {check.get('type', 'Unknown')}\n")
                results_text.insert(tk.END, f"  Confidence: {confidence:.1f}%\n\n")
            else:
                results_text.insert(tk.END, f"{source}: ", "bold")
                results_text.insert(tk.END, f"No risk detected\n", "clean")
                results_text.insert(tk.END, f"  Assessment: Clean\n\n")
        
        # Update status based on results
        if found_threat:
            if highest_score > 70:
                status_var.set("HIGH RISK DETECTED")
                btn_color = "red"
            elif highest_score > 30:
                status_var.set("MEDIUM RISK DETECTED")
                btn_color = "orange"
            else:
                status_var.set("LOW RISK DETECTED")
                btn_color = "blue"
        else:
            status_var.set("No threats detected")
            btn_color = "green"
        
        # Configure text tags
        results_text.tag_configure("header", font=("TkDefaultFont", 11, "bold"))
        results_text.tag_configure("section", font=("TkDefaultFont", 10, "bold"))
        results_text.tag_configure("bold", font=("TkDefaultFont", 9, "bold"))
        results_text.tag_configure("high_risk", foreground="red")
        results_text.tag_configure("medium_risk", foreground="orange")
        results_text.tag_configure("low_risk", foreground="blue")
        results_text.tag_configure("clean", foreground="green")
        
        # Add action buttons based on results
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", pady=10)
        
        if found_threat:
            # Create threat intel button
            ttk.Button(btn_frame, text="Add to Threat Intel", 
                      command=lambda: [dialog.destroy(), self.flag_as_suspicious([None, None, None, None, ip])]).pack(side="left", padx=10)
        else:
            # Add false positive entry option
            ttk.Button(btn_frame, text="Mark as Clean", 
                      command=lambda: [dialog.destroy(), self.mark_as_clean(ip)]).pack(side="left", padx=10)
        
        ttk.Button(btn_frame, text="Close", 
                  command=dialog.destroy).pack(side="right", padx=10)
    
    def mark_as_clean(self, ip):
        """Mark an IP as clean in the threat intelligence database"""
        if not self.gui or not hasattr(self.gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        # Confirm with the user
        confirm = messagebox.askyesno(
            "Confirm Clean Status",
            f"Are you sure you want to mark {ip} as clean?\n\n"
            "This will add a verified clean entry to the threat intelligence database.",
            parent=self.tab_frame
        )
        
        if not confirm:
            return
            
        # Create clean threat data (score 0)
        threat_data = {
            'score': 0,
            'type': 'clean',
            'confidence': 0.9,
            'source': 'manual_verification',
            'details': {
                'verified_clean': True,
                'verification_time': time.time(),
                'notes': 'Manually verified as clean'
            },
            'detection_method': 'manual_verification'
        }
        
        # Update threat intel
        self.gui.analysis_manager.queue_query(
            lambda: self._update_threat_data(ip, threat_data),
            lambda success: self._handle_clean_update(success, ip)
        )
    
    def _handle_clean_update(self, success, ip):
        """Handle the result of marking an IP as clean"""
        if success:
            self.update_output(f"Marked {ip} as clean in threat intelligence database")
            messagebox.showinfo(
                "Clean Status Recorded",
                f"The IP {ip} has been marked as clean in the threat intelligence database.",
                parent=self.tab_frame
            )
            
            # Refresh the threat intel display
            self.refresh_threat_intel()
        else:
            self.update_output(f"Failed to mark {ip} as clean")
            messagebox.showerror(
                "Error",
                f"Failed to mark {ip} as clean",
                parent=self.tab_frame
            )
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.tab_frame.clipboard_clear()
        self.tab_frame.clipboard_append(text)
        self.update_output(f"Copied to clipboard: {text}")