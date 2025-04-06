# SubtabBase class is injected by the Loader
import time

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
        
        # Leaderboard treeview
        self.leaderboard_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            self.tab_frame,
            columns=("ip", "distinct_rules", "total_alerts", "status"),
            headings=["IP Address", "Distinct Alert Types", "Total Alerts", "Status"],
            widths=[150, 150, 100, 100],
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
            height=10
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
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)
        
        # Create context menu
        gui.ip_manager.create_context_menu(
            self.leaderboard_tree, 
            self.leaderboard_ip_var, 
            lambda: self.show_leaderboard_details(None)
        )
        
        # Bind selection event
        self.leaderboard_tree.bind("<<TreeviewSelect>>", self.show_leaderboard_details)
    
    def refresh(self):
        """Refresh the threat leaderboard display"""
        gui.update_output("Refreshing threat leaderboard...")
        
        # Clear current items
        gui.tree_manager.clear_tree(self.leaderboard_tree)
        
        # Queue the leaderboard query using analysis_manager instead of db_manager
        gui.analysis_manager.queue_query(
            self._get_leaderboard_data,
            self._update_leaderboard_display
        )
        
        self.update_output("Refreshing threat leaderboard...")
    
    def _get_leaderboard_data(self):
        """Get leaderboard data from analysis_1.db"""
        try:
            # Either use the provided method in analysis_manager if it exists
            if hasattr(gui.analysis_manager, 'get_leaderboard_data'):
                return gui.analysis_manager.get_leaderboard_data(limit=100)
            
            # Or implement the query directly
            cursor = gui.analysis_manager.get_cursor()
            
            # Get IPs with the most distinct rule types triggered
            cursor.execute("""
                SELECT 
                    ip_address, 
                    COUNT(DISTINCT rule_name) as distinct_rules,
                    COUNT(*) as total_alerts,
                    CASE WHEN ip_address IN (
                        SELECT ip_address FROM alerts 
                        WHERE timestamp > datetime('now', '-1 hour')
                    ) THEN 'Active' ELSE 'Inactive' END as status,
                    MAX(timestamp) as last_alert
                FROM alerts
                GROUP BY ip_address
                ORDER BY distinct_rules DESC, total_alerts DESC
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
                    
                    display_data.append((
                        item["ip_address"],
                        item["distinct_rule_count"],
                        item["total_alert_count"],
                        status
                    ))
                
                # Populate tree using TreeViewManager
                gui.tree_manager.populate_tree(self.leaderboard_tree, display_data)
            else:
                # Handle direct SQL query results
                # Extract just the fields we want to display (excluding timestamp which is used for sorting)
                display_data = [(row[0], row[1], row[2], row[3]) for row in data]
                
                # Populate tree using TreeViewManager
                gui.tree_manager.populate_tree(self.leaderboard_tree, display_data)
            
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
                FROM alerts
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