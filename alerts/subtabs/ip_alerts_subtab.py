# SubtabBase class is injected by the Loader
import time

class IPAlertsSubtab(SubtabBase):
    """Subtab that displays alerts grouped by IP address"""
    
    def __init__(self):
        super().__init__(
            name="By IP Address",
            description="Displays alerts grouped by IP address"
        )
        self.alerts_tree = None
        self.alerts_details_tree = None
        self.alerts_ip_var = None
        self.ip_filter = None
    
    def create_ui(self):
        # Control buttons frame
        gui.tab_factory.create_control_buttons(
            self.tab_frame,
            [
                {"text": "Refresh Alerts", "command": self.refresh},
                {"text": "Clear All Alerts", "command": gui.clear_alerts}
            ]
        )
        
        # IP filter frame
        self.ip_filter = gui.tab_factory.create_filter_frame(
            self.tab_frame,
            "Filter by IP:",
            self.apply_ip_filter,
            self.refresh
        )
        
        # Alerts treeview
        self.alerts_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            self.tab_frame,
            columns=("ip", "alert_count", "last_seen"),
            headings=["IP Address", "Alert Count", "Last Detected"],
            widths=[150, 100, 150],
            height=10
        )
        
        # Create alerts details list
        details_frame = ttk.LabelFrame(self.tab_frame, text="Alert Details")
        details_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.alerts_details_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            details_frame,
            columns=("alert", "rule", "timestamp"),
            headings=["Alert Message", "Rule Name", "Timestamp"],
            widths=[300, 150, 150],
            height=10
        )
        
        # Info and button frame for selected IP
        info_frame = ttk.Frame(self.tab_frame)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.alerts_ip_var = tk.StringVar()
        ttk.Label(info_frame, text="Selected IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(info_frame, textvariable=self.alerts_ip_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        button_frame = ttk.Frame(info_frame)
        button_frame.grid(row=0, column=2, sticky="e", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Copy IP", 
                  command=lambda: gui.ip_manager.copy_ip_to_clipboard(self.alerts_ip_var.get())
                 ).pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Mark as False Positive", 
                  command=lambda: gui.ip_manager.mark_as_false_positive(self.alerts_ip_var.get())
                 ).pack(side="left", padx=5)
        
        # Add view threat intel button (new enhancement)
        ttk.Button(button_frame, text="View Threat Intel", 
                  command=self.view_threat_intel
                 ).pack(side="left", padx=5)
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)
        
        # Bind event to show alerts for selected IP
        self.alerts_tree.bind("<<TreeviewSelect>>", self.show_ip_alerts)
        
        # Create context menu
        self._create_context_menu()
    
    def _create_context_menu(self):
        """Create a context menu with enhanced options"""
        # Get parent window reference correctly
        parent_window = self.tab_frame.winfo_toplevel()
        
        menu = tk.Menu(parent_window, tearoff=0)
        menu.add_command(label="Copy IP", 
                        command=lambda: gui.ip_manager.copy_ip_to_clipboard(self.alerts_ip_var.get()))
        menu.add_command(label="Mark as False Positive", 
                        command=lambda: gui.ip_manager.mark_as_false_positive(self.alerts_ip_var.get()))
        menu.add_separator()
        menu.add_command(label="View Threat Intelligence", 
                        command=self.view_threat_intel)
        
        # Bind context menu
        def show_context_menu(event):
            # Update IP variable
            selected = self.alerts_tree.selection()
            if selected:
                ip = self.alerts_tree.item(selected[0], "values")[0]
                self.alerts_ip_var.set(ip)
                # Show menu
                menu.post(event.x_root, event.y_root)
                
                # Also update the details display
                self.show_ip_alerts(None)
        
        self.alerts_tree.bind("<Button-3>", show_context_menu)
    
    def refresh(self):
        """Refresh alerts by IP display"""
        # Clear existing items
        gui.tree_manager.clear_tree(self.alerts_tree)
        
        # Queue the alerts query using analysis_manager
        gui.analysis_manager.queue_query(
            self._get_alerts_by_ip,
            self._update_alerts_display
        )
        
        self.update_output("Alerts refresh queued")
    
    def _get_alerts_by_ip(self):
        """Get alerts grouped by IP address from analysis_1.db"""
        try:
            # First check if analysis_manager has a dedicated method
            if hasattr(gui.analysis_manager, 'get_alerts_by_ip'):
                return gui.analysis_manager.get_alerts_by_ip()
            
            # Otherwise, implement directly
            cursor = gui.analysis_manager.get_cursor()
            
            # Updated to use x_alerts table instead of alerts
            cursor.execute("""
                SELECT ip_address, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM x_alerts 
                GROUP BY ip_address
                ORDER BY last_seen DESC
            """)
            
            results = []
            for ip, count, timestamp in cursor.fetchall():
                # Skip false positives
                if ip in gui.false_positives:
                    continue
                    
                # Format timestamp
                if isinstance(timestamp, (int, float)):
                    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                else:
                    formatted_time = str(timestamp)
                
                results.append((ip, count, formatted_time))
            
            cursor.close()
            return results
        except Exception as e:
            gui.update_output(f"Error getting alerts by IP: {e}")
            return []
    
    def _update_alerts_display(self, rows):
        """Update the alerts treeview with the results"""
        try:
            # Handle data from analysis_manager.get_alerts_by_ip() method
            if isinstance(rows, list) and rows and isinstance(rows[0], dict):
                display_data = []
                for item in rows:
                    # Skip false positives
                    if item.get("ip_address") in gui.false_positives:
                        continue
                        
                    # Format timestamp
                    last_seen = item.get("last_seen")
                    if isinstance(last_seen, (int, float)):
                        formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(last_seen))
                    else:
                        formatted_time = str(last_seen) if last_seen else "Unknown"
                    
                    display_data.append((
                        item["ip_address"],
                        item["alert_count"],
                        formatted_time
                    ))
                
                # Populate tree using TreeViewManager
                gui.tree_manager.populate_tree(self.alerts_tree, display_data)
            else:
                # Handle direct SQL results
                gui.tree_manager.populate_tree(self.alerts_tree, rows)
            
            self.update_output(f"Found alerts for {len(rows)} IP addresses")
        except Exception as e:
            self.update_output(f"Error refreshing alerts: {e}")
    
    def show_ip_alerts(self, event):
        """Show alerts for the selected IP"""
        # Clear existing items
        gui.tree_manager.clear_tree(self.alerts_details_tree)
        
        # Get selected IP
        selected = self.alerts_tree.selection()
        if not selected:
            return
            
        ip = self.alerts_tree.item(selected[0], "values")[0]
        self.alerts_ip_var.set(ip)
        
        # Queue the IP alerts query using analysis_manager
        gui.analysis_manager.queue_query(
            lambda: self._get_ip_alerts(ip),
            lambda rows: self._update_ip_alerts_display(rows, ip)
        )
    
    def _get_ip_alerts(self, ip_address):
        """Get alerts for a specific IP address from analysis_1.db"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            
            # Updated to use x_alerts table instead of alerts
            cursor.execute("""
                SELECT alert_message, rule_name, timestamp
                FROM x_alerts
                WHERE ip_address = ?
                ORDER BY timestamp DESC
            """, (ip_address,))
            
            results = []
            for alert, rule, timestamp in cursor.fetchall():
                # Format timestamp
                if isinstance(timestamp, (int, float)):
                    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                else:
                    formatted_time = str(timestamp)
                
                results.append((alert, rule, formatted_time))
            
            cursor.close()
            return results
        except Exception as e:
            gui.update_output(f"Error getting alerts for IP {ip_address}: {e}")
            return []
    
    def _update_ip_alerts_display(self, rows, ip):
        """Update the IP alerts display with the results"""
        try:
            # Populate tree using TreeViewManager
            gui.tree_manager.populate_tree(self.alerts_details_tree, rows)
            self.update_output(f"Showing {len(rows)} alerts for IP: {ip}")
        except Exception as e:
            self.update_output(f"Error fetching alerts for {ip}: {e}")
    
    def apply_ip_filter(self, ip_filter):
        """Apply IP filter to alerts"""
        if not ip_filter:
            self.update_output("No filter entered")
            return
            
        # Clear existing items
        gui.tree_manager.clear_tree(self.alerts_tree)
        
        # Queue the filtered query using analysis_manager
        gui.analysis_manager.queue_query(
            lambda: self._get_filtered_alerts_by_ip(ip_filter),
            self._update_alerts_display
        )
        
        self.update_output(f"Querying alerts matching filter: {ip_filter}")
    
    def _get_filtered_alerts_by_ip(self, ip_filter):
        """Get alerts filtered by IP address pattern from analysis_1.db"""
        try:
            # Check if analysis_manager has a dedicated method
            if hasattr(gui.analysis_manager, 'get_alerts_by_ip'):
                return gui.analysis_manager.get_alerts_by_ip(ip_filter=ip_filter)
                
            # Otherwise, implement directly
            cursor = gui.analysis_manager.get_cursor()
            
            filter_pattern = f"%{ip_filter}%"
            # Updated to use x_alerts table instead of alerts
            cursor.execute("""
                SELECT ip_address, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM x_alerts 
                WHERE ip_address LIKE ?
                GROUP BY ip_address
                ORDER BY last_seen DESC
            """, (filter_pattern,))
            
            results = []
            for ip, count, timestamp in cursor.fetchall():
                # Skip false positives
                if ip in gui.false_positives:
                    continue
                    
                # Format timestamp
                if isinstance(timestamp, (int, float)):
                    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                else:
                    formatted_time = str(timestamp)
                
                results.append((ip, count, formatted_time))
            
            cursor.close()
            return results
        except Exception as e:
            gui.update_output(f"Error getting filtered alerts by IP: {e}")
            return []
    
    def view_threat_intel(self):
        """View detailed threat intelligence for the selected IP"""
        ip = self.alerts_ip_var.get()
        if not ip:
            gui.update_output("No IP selected")
            return
        
        # Show a dialog with threat intelligence data
        try:
            # Queue the query to get threat intel - reuse implementation from LeaderboardSubtab
            parent_window = self.tab_frame.winfo_toplevel()
            
            # Check if MaliciousSubtab has view_threat_intel method we can reuse
            malicious_subtab = None
            for subtab in gui.subtab_loader.subtabs:
                if subtab.name == "Possible Malicious":
                    malicious_subtab = subtab
                    break
            
            if malicious_subtab and hasattr(malicious_subtab, 'view_threat_intel'):
                # Reuse MaliciousSubtab's implementation
                malicious_subtab.ip_var.set(ip)
                malicious_subtab.view_threat_intel()
            else:
                # Queue our own implementation
                gui.analysis_manager.queue_query(
                    lambda: self._fetch_threat_intel_details(ip),
                    lambda data: self._display_threat_intel_details(data, parent_window)
                )
        except Exception as e:
            gui.update_output(f"Error fetching threat intelligence: {e}")
    
    def _fetch_threat_intel_details(self, ip):
        """Fetch detailed threat intelligence for an IP"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            
            # Get threat intelligence data from x_ip_threat_intel
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
                    detection_method,
                    alert_count
                FROM x_ip_threat_intel
                WHERE ip_address = ?
            """, (ip,))
            
            threat_intel = cursor.fetchone()
            
            # Get recent alerts for this IP from x_alerts
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
            
            cursor.close()
            
            return {
                "ip": ip,
                "threat_intel": threat_intel,
                "alerts": alerts
            }
            
        except Exception as e:
            gui.update_output(f"Error fetching threat intelligence details: {e}")
            return {"ip": ip, "error": str(e)}
    
    def _display_threat_intel_details(self, data, parent_window):
        """Display threat intelligence details in a dialog"""
        ip = data.get("ip", "Unknown")
        
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
            
            if threat_intel:
                score, threat_type, confidence, source, first_seen, last_seen, details, protocol, detection_method, alert_count = threat_intel
                
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
                
                for i, (label, value) in enumerate(fields):
                    ttk.Label(details_frame, text=f"{label}:", font=("TkDefaultFont", 10, "bold")).grid(row=i, column=0, sticky="w", pady=3)
                    ttk.Label(details_frame, text=value).grid(row=i, column=1, sticky="w", pady=3, padx=10)
                
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