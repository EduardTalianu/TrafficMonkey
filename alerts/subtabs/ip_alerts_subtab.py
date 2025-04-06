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
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)
        
        # Bind event to show alerts for selected IP
        self.alerts_tree.bind("<<TreeviewSelect>>", self.show_ip_alerts)
        
        # Create context menu
        gui.ip_manager.create_context_menu(
            self.alerts_tree, 
            self.alerts_ip_var, 
            lambda: self.show_ip_alerts(None)
        )
    
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
            
            cursor.execute("""
                SELECT ip_address, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM alerts 
                GROUP BY ip_address
                ORDER BY last_seen DESC
            """)
            
            results = []
            for ip, count, timestamp in cursor.fetchall():
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
            
            cursor.execute("""
                SELECT alert_message, rule_name, timestamp
                FROM alerts
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
            cursor.execute("""
                SELECT ip_address, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM alerts 
                WHERE ip_address LIKE ?
                GROUP BY ip_address
                ORDER BY last_seen DESC
            """, (filter_pattern,))
            
            results = []
            for ip, count, timestamp in cursor.fetchall():
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