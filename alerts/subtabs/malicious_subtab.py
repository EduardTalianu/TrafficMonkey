# SubtabBase class is injected by the Loader

class MaliciousSubtab(SubtabBase):
    """Subtab that displays potentially malicious IPs"""
    
    def __init__(self):
        super().__init__(
            name="Possible Malicious",
            description="Displays potentially malicious IP addresses"
        )
        self.malicious_tree = None
        self.ip_var = None
    
    def create_ui(self):
        # Control buttons
        gui.tab_factory.create_control_buttons(
            self.tab_frame,
            [
                {"text": "Refresh List", "command": self.refresh},
                {"text": "Manage False Positives", "command": gui.manage_false_positives}
            ]
        )
        
        # Malicious IP treeview
        self.malicious_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            self.tab_frame,
            columns=("ip", "alert_type", "status", "timestamp"),
            headings=["IP Address", "Alert Type", "Status", "Detected"],
            widths=[150, 150, 100, 150],
            height=15
        )
        
        # Info and button frame
        info_frame = ttk.Frame(self.tab_frame)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.ip_var = tk.StringVar()
        ttk.Label(info_frame, text="Selected IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(info_frame, textvariable=self.ip_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        button_frame = ttk.Frame(info_frame)
        button_frame.grid(row=0, column=2, sticky="e", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Copy IP", 
                  command=lambda: gui.ip_manager.copy_ip_to_clipboard(self.ip_var.get())
                 ).pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Mark as False Positive", 
                  command=lambda: gui.ip_manager.mark_as_false_positive(self.ip_var.get())
                 ).pack(side="left", padx=5)
        
        # Add a button to view threat intelligence 
        ttk.Button(button_frame, text="View Threat Intel", 
                  command=self.view_threat_intel
                 ).pack(side="left", padx=5)
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)
        
        # Create context menu
        gui.ip_manager.create_context_menu(self.malicious_tree, self.ip_var)
        
        # Bind selection event to update IP variable
        self.malicious_tree.bind("<<TreeviewSelect>>", lambda event: gui.update_selected_ip(self.malicious_tree, self.ip_var))
    
    def refresh(self):
        """Refresh the malicious IPs list"""
        # Use local status flag instead of gui's
        gui.update_output("Refreshing malicious IP list...")
        
        # Clear current items
        gui.tree_manager.clear_tree(self.malicious_tree)
        
        # Use analysis_manager instead of db_manager
        # Queue the query to get malicious IP data directly through analysis_manager
        gui.analysis_manager.queue_query(
            self._get_malicious_ip_data,
            self._update_malicious_display
        )
        
        self.update_output("Refreshing malicious IP list...")
    
    def _get_malicious_ip_data(self):
        """Get malicious IP data from analysis_1.db using the new x_alerts table"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            
            # Query to find malicious IPs from x_alerts table
            cursor.execute("""
                SELECT 
                    ip_address,
                    rule_name,
                    'Active' as status,
                    MAX(timestamp) as last_seen
                FROM x_alerts
                WHERE 
                    rule_name LIKE '%Malicious%' OR 
                    rule_name LIKE '%Suspicious%' OR 
                    rule_name LIKE '%VirusTotal%' OR
                    rule_name LIKE '%Threat%'
                GROUP BY ip_address
                ORDER BY last_seen DESC
            """)
            
            alert_results = cursor.fetchall()
            
            # Also query the x_ip_threat_intel table for additional threat data
            cursor.execute("""
                SELECT 
                    ip_address,
                    threat_type,
                    'Active' as status,
                    last_seen
                FROM x_ip_threat_intel
                WHERE threat_score > 5.0
                ORDER BY threat_score DESC, last_seen DESC
            """)
            
            threat_intel_results = cursor.fetchall()
            
            # Combine results from both tables
            combined_results = {}
            
            # Process alert results
            for ip, rule_name, status, timestamp in alert_results:
                # Skip false positives
                if ip in gui.false_positives:
                    continue
                    
                # Format timestamp
                if isinstance(timestamp, (int, float)):
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                
                combined_results[ip] = (ip, rule_name, status, timestamp)
            
            # Process threat intel results and add any not already included
            for ip, threat_type, status, timestamp in threat_intel_results:
                # Skip false positives
                if ip in gui.false_positives:
                    continue
                
                # Format timestamp
                if isinstance(timestamp, (int, float)):
                    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                
                # Only add if not already present from alerts
                if ip not in combined_results:
                    combined_results[ip] = (ip, f"Threat: {threat_type}", status, timestamp)
            
            cursor.close()
            return list(combined_results.values())
            
        except Exception as e:
            gui.update_output(f"Error getting malicious IP data: {e}")
            return []
    
    def _update_malicious_display(self, data):
        """Update the malicious IP display"""
        try:
            # Populate tree using TreeViewManager
            gui.tree_manager.populate_tree(self.malicious_tree, data)
            self.update_output(f"Found {len(data)} potentially malicious IPs from all alerts")
        except Exception as e:
            self.update_output(f"Error updating malicious IP display: {e}")
    
    def view_threat_intel(self):
        """View detailed threat intelligence for the selected IP"""
        ip = self.ip_var.get()
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
            
            cursor.close()
            
            return {
                "ip": ip,
                "threat_intel": threat_intel,
                "alerts": alerts
            }
            
        except Exception as e:
            gui.update_output(f"Error fetching threat intelligence details: {e}")
            return {"ip": ip, "error": str(e)}
    
    def _display_threat_intel_details(self, data):
        """Display threat intelligence details in a dialog"""
        ip = data.get("ip", "Unknown")
        
        # Create dialog window
        dialog = tk.Toplevel(gui.root)
        dialog.title(f"Threat Intelligence for {ip}")
        dialog.geometry("600x500")
        
        # Make dialog modal
        dialog.transient(gui.root)
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
                    ("Confidence", f"{confidence:.2f}"),
                    ("Detection Source", source),
                    ("Protocol", protocol or "Multiple/Unknown"),
                    ("Detection Method", detection_method),
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
        x = gui.root.winfo_x() + (gui.root.winfo_width() - width) // 2
        y = gui.root.winfo_y() + (gui.root.winfo_height() - height) // 2
        dialog.geometry(f"{width}x{height}+{x}+{y}")
        
        # Wait until the dialog is closed
        dialog.wait_window()