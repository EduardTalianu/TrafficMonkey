# SubtabBase class is injected by the Loader
import time
import tkinter as tk
from tkinter import ttk
import json

class LeaderboardSubtab(SubtabBase):
    """Subtab that displays a threat leaderboard"""
    
    def __init__(self):
        super().__init__(
            name="Threat Leaderboard",
            description="Displays a leaderboard of threats by IP address"
        )
        self.leaderboard_tree = None
        self.leaderboard_details_tree = None
        self.leaderboard_ip_var = None
    
    def create_ui(self):
        # Control buttons
        gui.tab_factory.create_control_buttons(
            self.tab_frame,
            [
                {"text": "Refresh Leaderboard", "command": self.refresh},
                {"text": "Manage False Positives", "command": gui.manage_false_positives}
            ]
        )
        
        # Leaderboard treeview with enhanced columns for threat score
        self.leaderboard_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            self.tab_frame,
            columns=("ip", "distinct_rules", "total_alerts", "threat_score", "status"),
            headings=["IP Address", "Distinct Alert Types", "Total Alerts", "Threat Score", "Status"],
            widths=[150, 120, 100, 100, 100],
            height=15
        )
        
        # Detail frame for showing triggered rules
        details_frame = ttk.LabelFrame(self.tab_frame, text="Triggered Rules")
        details_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create treeview for rule details
        self.leaderboard_details_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            details_frame,
            columns=("rule", "count", "last_alert"),
            headings=["Rule Name", "Alert Count", "Last Alert"],
            widths=[250, 100, 150],
            height=8
        )
        
        # Info and button frame
        info_frame = ttk.Frame(self.tab_frame)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.leaderboard_ip_var = tk.StringVar()
        ttk.Label(info_frame, text="Selected IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(info_frame, textvariable=self.leaderboard_ip_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        button_frame = ttk.Frame(info_frame)
        button_frame.grid(row=0, column=2, sticky="e", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Copy IP", 
                  command=lambda: gui.ip_manager.copy_ip_to_clipboard(self.leaderboard_ip_var.get())
                 ).pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Mark as False Positive", 
                  command=lambda: gui.ip_manager.mark_as_false_positive(self.leaderboard_ip_var.get())
                 ).pack(side="left", padx=5)
        
        # Add view threat intel button
        ttk.Button(button_frame, text="View Threat Intel", 
                  command=self.view_threat_intel
                 ).pack(side="left", padx=5)
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)
        
        # Create context menu with enhanced options
        self._create_context_menu()
        
        # Bind selection event
        self.leaderboard_tree.bind("<<TreeviewSelect>>", self.show_leaderboard_details)
    
    def _create_context_menu(self):
        """Create a context menu with threat intelligence options"""
        # Get parent window reference correctly
        parent_window = self.tab_frame.winfo_toplevel()
        
        menu = tk.Menu(parent_window, tearoff=0)
        menu.add_command(label="Copy IP", 
                        command=lambda: gui.ip_manager.copy_ip_to_clipboard(self.leaderboard_ip_var.get()))
        menu.add_command(label="Mark as False Positive", 
                        command=lambda: gui.ip_manager.mark_as_false_positive(self.leaderboard_ip_var.get()))
        menu.add_separator()
        menu.add_command(label="View Threat Intelligence", 
                        command=self.view_threat_intel)
        menu.add_command(label="View Connection History", 
                        command=lambda: self._view_connection_history(self.leaderboard_ip_var.get()))
        
        # Bind context menu
        def show_context_menu(event):
            # Update IP variable
            selected = self.leaderboard_tree.selection()
            if selected:
                ip = self.leaderboard_tree.item(selected[0], "values")[0]
                self.leaderboard_ip_var.set(ip)
                # Show menu
                menu.post(event.x_root, event.y_root)
        
        self.leaderboard_tree.bind("<Button-3>", show_context_menu)
    
    def refresh(self):
        """Refresh the threat leaderboard display"""
        gui.update_output("Refreshing threat leaderboard...")
        
        # Clear current items
        gui.tree_manager.clear_tree(self.leaderboard_tree)
        
        # Queue the leaderboard query using analysis_manager
        gui.analysis_manager.queue_query(
            self._get_leaderboard_data,
            self._update_leaderboard_display
        )
        
        self.update_output("Refreshing threat leaderboard...")
    
    def _get_leaderboard_data(self):
        """Get leaderboard data from analysis_1.db with threat intelligence integration"""
        try:
            # Either use the provided method in analysis_manager if it exists
            if hasattr(gui.analysis_manager, 'get_leaderboard_data'):
                return gui.analysis_manager.get_leaderboard_data(limit=100)
            
            # Or implement the query directly
            cursor = gui.analysis_manager.get_cursor()
            
            # Enhanced query pulling from both x_alerts and x_ip_threat_intel
            cursor.execute("""
                SELECT 
                    a.ip_address, 
                    COUNT(DISTINCT a.rule_name) as distinct_rules,
                    COUNT(*) as total_alerts,
                    COALESCE(t.threat_score, 0) as threat_score,
                    CASE 
                        WHEN a.ip_address IN (
                            SELECT ip_address FROM x_alerts 
                            WHERE timestamp > datetime('now', '-1 hour')
                        ) THEN 'Active' 
                        ELSE 'Inactive' 
                    END as status,
                    MAX(a.timestamp) as last_alert
                FROM x_alerts a
                LEFT JOIN x_ip_threat_intel t ON a.ip_address = t.ip_address
                GROUP BY a.ip_address
                ORDER BY threat_score DESC, distinct_rules DESC, total_alerts DESC
                LIMIT 100
            """)
            
            results = []
            for row in cursor.fetchall():
                # Skip false positives
                if row[0] in gui.false_positives:
                    continue
                
                # Include all fields including timestamp for sorting
                results.append(row)
            
            cursor.close()
            return results
        except Exception as e:
            gui.update_output(f"Error getting leaderboard data: {e}")
            return []
    
    def _update_leaderboard_display(self, data):
        """Update the leaderboard display with the results"""
        try:
            if isinstance(data, list) and data and isinstance(data[0], dict):
                # Handle data from analysis_manager.get_leaderboard_data()
                display_data = []
                for item in data:
                    # Skip false positives
                    if item["ip_address"] in gui.false_positives:
                        continue
                    
                    # Format timestamp if present
                    last_alert = item.get("last_alert_time")
                    if isinstance(last_alert, (int, float)):
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_alert))
                        # Determine activity status based on numeric timestamp
                        status = "Active" if time.time() - last_alert < 3600 else "Inactive"
                    else:
                        timestamp = str(last_alert) if last_alert else "Unknown"
                        # Default status if we can't determine activity
                        status = "Unknown"
                    
                    # Get threat score with default
                    threat_score = item.get("threat_score", 0)
                    
                    display_data.append((
                        item["ip_address"],
                        item["distinct_rule_count"],
                        item["total_alert_count"],
                        f"{threat_score:.1f}" if threat_score else "0.0",
                        status
                    ))
                
                # Populate tree using TreeViewManager
                gui.tree_manager.populate_tree(self.leaderboard_tree, display_data)
            else:
                # Handle direct SQL query results
                # Extract fields we want to display
                display_data = []
                for row in data:
                    ip, distinct_rules, total_alerts, threat_score, status, last_alert = row
                    
                    # Format threat score
                    formatted_score = f"{threat_score:.1f}" if threat_score else "0.0"
                    
                    display_data.append((ip, distinct_rules, total_alerts, formatted_score, status))
                
                # Populate tree using TreeViewManager
                gui.tree_manager.populate_tree(self.leaderboard_tree, display_data)
                
                # Color rows based on threat score
                for i, item_id in enumerate(self.leaderboard_tree.get_children()):
                    values = self.leaderboard_tree.item(item_id, "values")
                    score = float(values[3])
                    
                    # Apply color based on threat score
                    if score > 6:
                        self.leaderboard_tree.item(item_id, tags=("high_threat",))
                    elif score > 3:
                        self.leaderboard_tree.item(item_id, tags=("medium_threat",))
                
                # Configure tag colors
                self.leaderboard_tree.tag_configure("high_threat", background="#ffe6e6")  # Light red
                self.leaderboard_tree.tag_configure("medium_threat", background="#fff6e6")  # Light orange
            
            self.update_output(f"Leaderboard updated with {len(data)} IP addresses")
        except Exception as e:
            self.update_output(f"Error updating leaderboard display: {e}")
    
    def show_leaderboard_details(self, event):
        """Show rule details for the selected IP in leaderboard"""
        # Clear existing items
        gui.tree_manager.clear_tree(self.leaderboard_details_tree)
        
        # Get selected IP
        selected = self.leaderboard_tree.selection()
        if not selected:
            return
            
        ip = self.leaderboard_tree.item(selected[0], "values")[0]
        self.leaderboard_ip_var.set(ip)
        
        # Queue the query for rule details by IP using analysis_manager
        gui.analysis_manager.queue_query(
            lambda: self._get_ip_rule_details(ip),
            lambda rows: self._update_leaderboard_details_display(rows, ip)
        )
    
    def _get_ip_rule_details(self, ip_address):
        """Get rule details for an IP from analysis_1.db"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            
            # Get rule statistics for this IP
            cursor.execute("""
                SELECT 
                    rule_name,
                    COUNT(*) as alert_count,
                    MAX(timestamp) as last_alert
                FROM x_alerts
                WHERE ip_address = ?
                GROUP BY rule_name
                ORDER BY alert_count DESC, last_alert DESC
            """, (ip_address,))
            
            results = []
            for rule_name, count, timestamp in cursor.fetchall():
                # Format timestamp
                if isinstance(timestamp, (int, float)):
                    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                else:
                    formatted_time = str(timestamp)
                
                results.append((rule_name, count, formatted_time))
            
            cursor.close()
            return results
        except Exception as e:
            gui.update_output(f"Error getting rule details for IP {ip_address}: {e}")
            return []
    
    def _update_leaderboard_details_display(self, rows, ip):
        """Update the leaderboard details display with rule information"""
        try:
            # Populate tree using TreeViewManager
            gui.tree_manager.populate_tree(self.leaderboard_details_tree, rows)
            self.update_output(f"Showing {len(rows)} rule types triggered by IP: {ip}")
        except Exception as e:
            self.update_output(f"Error fetching rule details for {ip}: {e}")
    
    def view_threat_intel(self):
        """View detailed threat intelligence for the selected IP"""
        ip = self.leaderboard_ip_var.get()
        if not ip:
            gui.update_output("No IP selected")
            return
        
        # Show a dialog with threat intelligence data
        try:
            # Queue the query to get threat intel
            gui.analysis_manager.queue_query(
                self._fetch_threat_intel_details,
                self._display_threat_intel_details,
                ip
            )
        except Exception as e:
            gui.update_output(f"Error fetching threat intelligence: {e}")
    
    def _fetch_threat_intel_details(self, ip):
        """Fetch detailed threat intelligence for an IP"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            
            # Get threat intelligence data
            cursor.execute("""
                SELECT
                    threat_score,
                    threat_type,
                    confidence,
                    source,
                    first_seen,
                    last_seen,
                    details,
                    protocol,
                    destination_ip,
                    destination_port,
                    detection_method,
                    alert_count
                FROM x_ip_threat_intel
                WHERE ip_address = ?
            """, (ip,))
            
            threat_intel = cursor.fetchone()
            
            # Get recent alerts for this IP
            cursor.execute("""
                SELECT
                    alert_message,
                    rule_name,
                    timestamp
                FROM x_alerts
                WHERE ip_address = ?
                ORDER BY timestamp DESC
                LIMIT 10
            """, (ip,))
            
            alerts = cursor.fetchall()
            
            # Get geolocation data if available
            cursor.execute("""
                SELECT
                    country,
                    region,
                    city,
                    asn,
                    asn_name
                FROM x_ip_geolocation
                WHERE ip_address = ?
            """, (ip,))
            
            geolocation = cursor.fetchone()
            
            cursor.close()
            
            return {
                "ip": ip,
                "threat_intel": threat_intel,
                "alerts": alerts,
                "geolocation": geolocation
            }
            
        except Exception as e:
            gui.update_output(f"Error fetching threat intelligence details: {e}")
            return {"ip": ip, "error": str(e)}
    
    def _display_threat_intel_details(self, data):
        """Display threat intelligence details in a dialog"""
        ip = data.get("ip", "Unknown")
        
        # Get parent window reference correctly
        parent_window = self.tab_frame.winfo_toplevel()
        
        # Create dialog window
        dialog = tk.Toplevel(parent_window)
        dialog.title(f"Threat Intelligence for {ip}")
        dialog.geometry("600x500")
        
        # Make dialog modal
        dialog.transient(parent_window)
        dialog.grab_set()
        
        # Main frame with padding
        main_frame = ttk.Frame(dialog, padding="10")
        main_frame.pack(fill="both", expand=True)
        
        # IP and score information
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill="x", pady=5)
        
        ttk.Label(header_frame, text=f"IP Address: {ip}", font=("TkDefaultFont", 12, "bold")).pack(side="left")
        
        if "error" in data:
            ttk.Label(main_frame, text=f"Error: {data['error']}", foreground="red").pack(pady=10)
        else:
            # Threat intelligence details
            threat_intel = data.get("threat_intel")
            geolocation = data.get("geolocation")
            
            if threat_intel:
                score, threat_type, confidence, source, first_seen, last_seen, details, protocol, destination_ip, destination_port, detection_method, alert_count = threat_intel
                
                # Format timestamps
                if isinstance(first_seen, (int, float)):
                    first_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(first_seen))
                if isinstance(last_seen, (int, float)):
                    last_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_seen))
                
                # Score indicator
                score_frame = ttk.Frame(header_frame)
                score_frame.pack(side="right")
                
                score_color = "green"
                if score > 3:
                    score_color = "orange"
                if score > 6:
                    score_color = "red"
                
                ttk.Label(score_frame, text=f"Threat Score: ", font=("TkDefaultFont", 10)).pack(side="left")
                ttk.Label(score_frame, text=f"{score:.1f}", foreground=score_color, font=("TkDefaultFont", 12, "bold")).pack(side="left")
                
                # Create notebook for tabs
                notebook = ttk.Notebook(main_frame)
                notebook.pack(fill="both", expand=True, pady=10)
                
                # Details tab
                details_frame = ttk.Frame(notebook, padding=10)
                notebook.add(details_frame, text="Threat Details")
                
                # Grid for details
                fields = [
                    ("Threat Type", threat_type),
                    ("Confidence", f"{confidence:.2f}" if confidence else "Unknown"),
                    ("Detection Source", source or "Unknown"),
                    ("Protocol", protocol or "Multiple/Unknown"),
                    ("Detection Method", detection_method or "Heuristic"),
                    ("First Seen", first_seen),
                    ("Last Seen", last_seen),
                    ("Alert Count", str(alert_count) if alert_count else "1")
                ]
                
                # Add destination fields if present
                if destination_ip:
                    fields.append(("Destination IP", destination_ip))
                if destination_port:
                    fields.append(("Destination Port", str(destination_port)))
                
                for i, (label, value) in enumerate(fields):
                    ttk.Label(details_frame, text=f"{label}:", font=("TkDefaultFont", 10, "bold")).grid(row=i, column=0, sticky="w", pady=3)
                    ttk.Label(details_frame, text=value).grid(row=i, column=1, sticky="w", pady=3, padx=10)
                
                # Geolocation tab if data available
                if geolocation:
                    geo_frame = ttk.Frame(notebook, padding=10)
                    notebook.add(geo_frame, text="Geolocation")
                    
                    country, region, city, asn, asn_name = geolocation
                    
                    geo_fields = [
                        ("Country", country or "Unknown"),
                        ("Region", region or "Unknown"),
                        ("City", city or "Unknown"),
                        ("ASN", asn or "Unknown"),
                        ("Network", asn_name or "Unknown")
                    ]
                    
                    for i, (label, value) in enumerate(geo_fields):
                        ttk.Label(geo_frame, text=f"{label}:", font=("TkDefaultFont", 10, "bold")).grid(row=i, column=0, sticky="w", pady=3)
                        ttk.Label(geo_frame, text=value).grid(row=i, column=1, sticky="w", pady=3, padx=10)
                
                # Alerts tab
                alerts_frame = ttk.Frame(notebook, padding=10)
                notebook.add(alerts_frame, text="Recent Alerts")
                
                # Create alerts treeview
                alerts_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
                    alerts_frame,
                    columns=("message", "rule", "timestamp"),
                    headings=["Alert Message", "Rule", "Timestamp"],
                    widths=[300, 150, 150],
                    height=10
                )
                
                # Populate alerts
                alerts = data.get("alerts", [])
                for alert_message, rule_name, timestamp in alerts:
                    # Format timestamp
                    if isinstance(timestamp, (int, float)):
                        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                    
                    alerts_tree.insert("", "end", values=(alert_message, rule_name, timestamp))
                
                # JSON details tab if available
                if details:
                    import json
                    try:
                        # Try to parse the JSON details
                        json_data = json.loads(details)
                        
                        json_frame = ttk.Frame(notebook, padding=10)
                        notebook.add(json_frame, text="Raw Details")
                        
                        # Create text widget with scrollbar for JSON data
                        json_text = tk.Text(json_frame, wrap="word", height=15)
                        json_scroll = ttk.Scrollbar(json_frame, orient="vertical", command=json_text.yview)
                        json_text.configure(yscrollcommand=json_scroll.set)
                        
                        json_scroll.pack(side="right", fill="y")
                        json_text.pack(side="left", fill="both", expand=True)
                        
                        # Insert formatted JSON
                        json_text.insert("1.0", json.dumps(json_data, indent=2))
                        json_text.configure(state="disabled")  # Make read-only
                    except:
                        pass  # Skip JSON tab if parsing fails
            else:
                ttk.Label(main_frame, text="No threat intelligence data available for this IP", 
                         font=("TkDefaultFont", 10, "italic")).pack(pady=20)
                
                # Show geolocation if available
                if geolocation:
                    ttk.Label(main_frame, text="Geolocation Information:", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(20, 5))
                    
                    geo_frame = ttk.Frame(main_frame)
                    geo_frame.pack(fill="x", expand=False, pady=5)
                    
                    country, region, city, asn, asn_name = geolocation
                    
                    geo_info = f"Location: {city or 'Unknown'}, {region or 'Unknown'}, {country or 'Unknown'}"
                    network_info = f"Network: ASN {asn or 'Unknown'} - {asn_name or 'Unknown'}"
                    
                    ttk.Label(geo_frame, text=geo_info).pack(anchor="w")
                    ttk.Label(geo_frame, text=network_info).pack(anchor="w")
                
                # Show alerts if available
                alerts = data.get("alerts", [])
                if alerts:
                    ttk.Label(main_frame, text="Recent Alerts:", font=("TkDefaultFont", 10, "bold")).pack(anchor="w", pady=(20, 5))
                    
                    alerts_frame = ttk.Frame(main_frame)
                    alerts_frame.pack(fill="both", expand=True)
                    
                    # Create alerts treeview
                    alerts_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
                        alerts_frame,
                        columns=("message", "rule", "timestamp"),
                        headings=["Alert Message", "Rule", "Timestamp"],
                        widths=[300, 150, 150],
                        height=10
                    )
                    
                    # Populate alerts
                    for alert_message, rule_name, timestamp in alerts:
                        # Format timestamp
                        if isinstance(timestamp, (int, float)):
                            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                        
                        alerts_tree.insert("", "end", values=(alert_message, rule_name, timestamp))
        
        # Action buttons frame
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill="x", pady=10)
        
        # Add button to classify threat manually
        ttk.Button(action_frame, text="Add to Block List", 
                  command=lambda: self._add_to_blocklist(ip)).pack(side="left", padx=5)
        
        # Add button to update threat information
        ttk.Button(action_frame, text="Update Threat Data", 
                  command=lambda: self._update_threat_data(ip)).pack(side="left", padx=5)
        
        # Close button
        ttk.Button(action_frame, text="Close", command=dialog.destroy).pack(side="right", padx=5)
        
        # Center the dialog on the parent window
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = parent_window.winfo_x() + (parent_window.winfo_width() - width) // 2
        y = parent_window.winfo_y() + (parent_window.winfo_height() - height) // 2
        dialog.geometry(f"{width}x{height}+{x}+{y}")
        
        # Wait until the dialog is closed
        dialog.wait_window()
    
    def _view_connection_history(self, ip):
        """View connection history for the selected IP"""
        if not ip:
            gui.update_output("No IP selected")
            return
        
        # Queue the query to get connection history
        gui.analysis_manager.queue_query(
            lambda: self._get_connection_history(ip),
            lambda data: self._display_connection_history(data, ip)
        )
    
    def _get_connection_history(self, ip):
        """Get connection history from the database"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            
            # Get connection data from connections table
            cursor.execute("""
                SELECT 
                    src_ip, 
                    dst_ip, 
                    src_port, 
                    dst_port,
                    protocol,
                    total_bytes,
                    timestamp
                FROM connections
                WHERE src_ip = ? OR dst_ip = ?
                ORDER BY timestamp DESC
                LIMIT 100
            """, (ip, ip))
            
            connections = cursor.fetchall()
            
            # Get traffic patterns if available
            cursor.execute("""
                SELECT
                    connection_key,
                    avg_packet_size,
                    periodic_score,
                    burst_score,
                    direction_ratio,
                    classification
                FROM x_traffic_patterns
                WHERE connection_key IN (
                    SELECT connection_key 
                    FROM connections
                    WHERE src_ip = ? OR dst_ip = ?
                )
            """, (ip, ip))
            
            patterns = cursor.fetchall()
            
            # Structure the patterns by connection key for easier lookup
            pattern_lookup = {}
            if patterns:
                for key, avg_size, periodic, burst, direction, classification in patterns:
                    pattern_lookup[key] = {
                        "avg_packet_size": avg_size,
                        "periodic_score": periodic,
                        "burst_score": burst,
                        "direction_ratio": direction,
                        "classification": classification
                    }
            
            cursor.close()
            
            return {
                "connections": connections,
                "patterns": pattern_lookup
            }
            
        except Exception as e:
            gui.update_output(f"Error fetching connection history: {e}")
            return {"error": str(e)}
    
    def _display_connection_history(self, data, ip):
        """Display connection history in a dialog"""
        if "error" in data:
            gui.update_output(f"Error: {data['error']}")
            return
            
        connections = data.get("connections", [])
        patterns = data.get("patterns", {})
        
        if not connections:
            gui.update_output(f"No connection history found for {ip}")
            return
        
        # Get parent window reference correctly
        parent_window = self.tab_frame.winfo_toplevel()
        
        # Create dialog window
        dialog = tk.Toplevel(parent_window)
        dialog.title(f"Connection History for {ip}")
        dialog.geometry("700x500")
        
        # Make dialog modal
        dialog.transient(parent_window)
        dialog.grab_set()
        
        # Main frame with padding
        main_frame = ttk.Frame(dialog, padding="10")
        main_frame.pack(fill="both", expand=True)
        
        # Header
        ttk.Label(main_frame, text=f"Recent Connections for {ip}", 
                 font=("TkDefaultFont", 12, "bold")).pack(anchor="w", pady=(0, 10))
        
        # Connections treeview
        connections_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            main_frame,
            columns=("direction", "peer_ip", "local_port", "remote_port", "protocol", "bytes", "timestamp", "classification"),
            headings=["Direction", "Peer IP", "Local Port", "Remote Port", "Protocol", "Bytes", "Timestamp", "Classification"],
            widths=[80, 130, 80, 80, 80, 80, 150, 130],
            height=20
        )
        
        # Populate connections
        for src, dst, src_port, dst_port, protocol, bytes, timestamp in connections:
            # Determine direction
            direction = "Outbound" if src == ip else "Inbound"
            
            # Determine peer IP
            peer_ip = dst if direction == "Outbound" else src
            
            # Determine ports
            local_port = src_port if direction == "Outbound" else dst_port
            remote_port = dst_port if direction == "Outbound" else src_port
            
            # Format timestamp
            if isinstance(timestamp, (int, float)):
                formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
            else:
                formatted_time = str(timestamp)
            
            # Try to find traffic pattern classification
            connection_key = f"{src}:{src_port}-{dst}:{dst_port}"
            classification = "Unknown"
            if connection_key in patterns:
                classification = patterns[connection_key].get("classification", "Unknown")
            
            # Add to tree
            connections_tree.insert("", "end", values=(
                direction, peer_ip, local_port, remote_port, 
                protocol or "Unknown", bytes, formatted_time, classification
            ))
        
        # Close button
        ttk.Button(main_frame, text="Close", command=dialog.destroy).pack(pady=10)
        
        # Center the dialog on the parent window
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = parent_window.winfo_x() + (parent_window.winfo_width() - width) // 2
        y = parent_window.winfo_y() + (parent_window.winfo_height() - height) // 2
        dialog.geometry(f"{width}x{height}+{x}+{y}")
        
        # Wait until the dialog is closed
        dialog.wait_window()
    
    def _add_to_blocklist(self, ip):
        """Add the IP to a blocklist"""
        try:
            # Example implementation - add to a blocklist table or file
            # This would need to be implemented based on your specific requirements
            gui.update_output(f"Adding {ip} to blocklist...")
            
            # For now, just add an alert recording this action
            gui.analysis_manager.add_alert(
                ip_address=ip,
                alert_message=f"IP manually added to blocklist by user",
                rule_name="Manual:BlocklistAddition"
            )
            
            # Update threat intel with this information
            threat_data = {
                "score": 8.0,  # High score for blocklisted IP
                "type": "UserBlocklist",
                "confidence": 1.0,
                "source": "User",
                "detection_method": "Manual"
            }
            
            gui.analysis_manager.update_threat_intel(ip, threat_data)
            
            gui.update_output(f"Added {ip} to blocklist successfully")
            
            # Refresh the leaderboard to reflect changes
            self.refresh()
            
        except Exception as e:
            gui.update_output(f"Error adding IP to blocklist: {e}")
    
    def _update_threat_data(self, ip):
        """Update threat data for an IP via a dialog"""
        # Get parent window reference correctly
        parent_window = self.tab_frame.winfo_toplevel()
        
        # Create dialog for updating threat information
        dialog = tk.Toplevel(parent_window)
        dialog.title(f"Update Threat Data for {ip}")
        dialog.geometry("400x350")
        
        # Make dialog modal
        dialog.transient(parent_window)
        dialog.grab_set()
        
        # Main frame with padding
        main_frame = ttk.Frame(dialog, padding="10")
        main_frame.pack(fill="both", expand=True)
        
        # Header
        ttk.Label(main_frame, text=f"Update Threat Information for {ip}", 
                 font=("TkDefaultFont", 12, "bold")).pack(anchor="w", pady=(0, 10))
        
        # Form for threat data
        form_frame = ttk.Frame(main_frame)
        form_frame.pack(fill="x", expand=False)
        
        # Threat score
        ttk.Label(form_frame, text="Threat Score (0-10):").grid(row=0, column=0, sticky="w", pady=5)
        threat_score_var = tk.StringVar(value="5.0")
        ttk.Spinbox(form_frame, from_=0, to=10, increment=0.5, textvariable=threat_score_var, width=10).grid(row=0, column=1, sticky="w", pady=5)
        
        # Threat type
        ttk.Label(form_frame, text="Threat Type:").grid(row=1, column=0, sticky="w", pady=5)
        threat_type_var = tk.StringVar()
        threat_types = [
            "Malware", "Botnet", "Scanning", "BruteForce", "Spam",
            "CommandAndControl", "ExploitAttempt", "DDoS", "TorExitNode", "Other"
        ]
        ttk.Combobox(form_frame, textvariable=threat_type_var, values=threat_types, width=20).grid(row=1, column=1, sticky="w", pady=5)
        
        # Confidence
        ttk.Label(form_frame, text="Confidence (0-1):").grid(row=2, column=0, sticky="w", pady=5)
        confidence_var = tk.StringVar(value="0.8")
        ttk.Spinbox(form_frame, from_=0, to=1, increment=0.1, textvariable=confidence_var, width=10).grid(row=2, column=1, sticky="w", pady=5)
        
        # Source
        ttk.Label(form_frame, text="Source:").grid(row=3, column=0, sticky="w", pady=5)
        source_var = tk.StringVar(value="Manual")
        ttk.Entry(form_frame, textvariable=source_var, width=20).grid(row=3, column=1, sticky="w", pady=5)
        
        # Detection method
        ttk.Label(form_frame, text="Detection Method:").grid(row=4, column=0, sticky="w", pady=5)
        detection_method_var = tk.StringVar(value="UserSubmission")
        ttk.Entry(form_frame, textvariable=detection_method_var, width=20).grid(row=4, column=1, sticky="w", pady=5)
        
        # Additional notes
        ttk.Label(form_frame, text="Notes:").grid(row=5, column=0, sticky="nw", pady=5)
        notes_text = tk.Text(form_frame, height=5, width=30, wrap="word")
        notes_text.grid(row=5, column=1, sticky="w", pady=5)
        
        # Make columns expand properly
        form_frame.columnconfigure(1, weight=1)
        
        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x", pady=15)
        
        # Save button
        def save_threat_data():
            try:
                # Parse values
                score = float(threat_score_var.get())
                threat_type = threat_type_var.get()
                confidence = float(confidence_var.get())
                source = source_var.get()
                detection_method = detection_method_var.get()
                notes = notes_text.get("1.0", "end-1c")
                
                # Create threat data dictionary
                threat_data = {
                    "score": score,
                    "type": threat_type,
                    "confidence": confidence,
                    "source": source,
                    "detection_method": detection_method,
                    "details": json.dumps({"notes": notes, "added_by": "user", "added_at": time.time()})
                }
                
                # Update threat intel
                gui.analysis_manager.update_threat_intel(ip, threat_data)
                
                # Add an alert if threat score is high
                if score > 7:
                    gui.analysis_manager.add_alert(
                        ip_address=ip,
                        alert_message=f"High threat score ({score}) manually assigned to IP",
                        rule_name="Manual:ThreatAssessment"
                    )
                
                gui.update_output(f"Threat data for {ip} updated successfully")
                dialog.destroy()
                
                # Refresh the leaderboard
                self.refresh()
                
            except Exception as e:
                gui.update_output(f"Error updating threat data: {e}")
        
        ttk.Button(button_frame, text="Save", command=save_threat_data).pack(side="right", padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side="right", padx=5)
        
        # Center the dialog on the parent window
        dialog.update_idletasks()
        width = dialog.winfo_width()
        height = dialog.winfo_height()
        x = parent_window.winfo_x() + (parent_window.winfo_width() - width) // 2
        y = parent_window.winfo_y() + (parent_window.winfo_height() - height) // 2
        dialog.geometry(f"{width}x{height}+{x}+{y}")
        
        # Wait until the dialog is closed
        dialog.wait_window()