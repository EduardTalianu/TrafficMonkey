# SubtabBase class is injected by the Loader

class AlertTypeSubtab(SubtabBase):
    """Subtab that displays alerts grouped by alert type"""
    
    def __init__(self):
        super().__init__(
            name="By Alert Type",
            description="Displays alerts grouped by rule or alert type"
        )
        self.alert_types_tree = None
        self.rule_alerts_tree = None
        self.rule_filter = None
    
    def create_ui(self):
        # Control buttons
        gui.tab_factory.create_control_buttons(
            self.tab_frame,
            [{"text": "Refresh Alerts", "command": self.refresh}]
        )
        
        # Rule filter
        self.rule_filter = gui.tab_factory.create_filter_frame(
            self.tab_frame,
            "Filter by Rule:",
            self.apply_rule_filter,
            self.refresh
        )
        
        # Alert types treeview
        self.alert_types_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            self.tab_frame,
            columns=("rule", "alert_count", "last_seen"),
            headings=["Rule Name", "Alert Count", "Last Detected"],
            widths=[200, 100, 150],
            height=10
        )
        
        # Alert instances frame
        instances_frame = ttk.LabelFrame(self.tab_frame, text="Alert Instances")
        instances_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create rule alerts instances list
        self.rule_alerts_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            instances_frame,
            columns=("ip", "alert", "timestamp"),
            headings=["IP Address", "Alert Message", "Timestamp"],
            widths=[150, 300, 150],
            height=10
        )
        
        # Bind event to show alerts for selected rule
        self.alert_types_tree.bind("<<TreeviewSelect>>", self.show_rule_alerts)
    
    def refresh(self):
        """Refresh alerts by type display"""
        # Clear existing items
        gui.tree_manager.clear_tree(self.alert_types_tree)
        
        # Queue the alerts query using analysis_manager
        gui.analysis_manager.queue_query(
            self._get_alerts_by_rule_type,
            self._update_alerts_by_type_display
        )
        
        self.update_output("Alerts by type refresh queued")
    
    def _get_alerts_by_rule_type(self):
        """Get alerts grouped by rule type from analysis_1.db"""
        try:
            # Check if analysis_manager has this method already
            if hasattr(gui.analysis_manager, 'get_alerts_by_rule_type'):
                return gui.analysis_manager.get_alerts_by_rule_type()
            
            # Otherwise implement directly
            cursor = gui.analysis_manager.get_cursor()
            
            cursor.execute("""
                SELECT rule_name, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM alerts
                GROUP BY rule_name
                ORDER BY alert_count DESC, last_seen DESC
            """)
            
            results = []
            for rule, count, timestamp in cursor.fetchall():
                # Format timestamp
                if isinstance(timestamp, (int, float)):
                    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                else:
                    formatted_time = str(timestamp)
                
                results.append((rule, count, formatted_time))
                
            cursor.close()
            return results
        except Exception as e:
            gui.update_output(f"Error getting alerts by rule type: {e}")
            return []
    
    def _update_alerts_by_type_display(self, rows):
        """Update the alerts by type treeview with the results"""
        try:
            if not rows:
                self.update_output("No alerts found in database")
                return
            
            # Handle data from analysis_manager.get_alerts_by_rule_type() method
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
                        item["rule_name"],
                        item["alert_count"],
                        formatted_time
                    ))
                
                # Populate tree using TreeViewManager
                gui.tree_manager.populate_tree(self.alert_types_tree, display_data)
            else:
                # Populate tree using TreeViewManager for direct SQL results
                gui.tree_manager.populate_tree(self.alert_types_tree, rows)
            
            self.update_output(f"Found alerts for {len(rows)} rule types")
        except Exception as e:
            self.update_output(f"Error refreshing alerts by type: {e}")
    
    def show_rule_alerts(self, event):
        """Show alerts for the selected rule"""
        # Clear existing items
        gui.tree_manager.clear_tree(self.rule_alerts_tree)
        
        # Get selected rule
        selected = self.alert_types_tree.selection()
        if not selected:
            return
            
        rule_name = self.alert_types_tree.item(selected[0], "values")[0]
        
        # Queue the query using analysis_manager
        gui.analysis_manager.queue_query(
            lambda: self._get_rule_alerts(rule_name),
            lambda rows: self._update_rule_alerts_display(rows, rule_name)
        )
    
    def _get_rule_alerts(self, rule_name):
        """Get alerts for a specific rule from analysis_1.db"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            
            cursor.execute("""
                SELECT ip_address, alert_message, timestamp
                FROM alerts
                WHERE rule_name = ?
                ORDER BY timestamp DESC
            """, (rule_name,))
            
            results = []
            for ip, alert, timestamp in cursor.fetchall():
                # Format timestamp
                if isinstance(timestamp, (int, float)):
                    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                else:
                    formatted_time = str(timestamp)
                
                results.append((ip, alert, formatted_time))
                
            cursor.close()
            return results
        except Exception as e:
            gui.update_output(f"Error getting alerts for rule {rule_name}: {e}")
            return []
    
    def _update_rule_alerts_display(self, rows, rule_name):
        """Update the rule alerts display with the results"""
        try:
            # Populate tree using TreeViewManager
            gui.tree_manager.populate_tree(self.rule_alerts_tree, rows)
            self.update_output(f"Showing {len(rows)} alerts for rule: {rule_name}")
        except Exception as e:
            self.update_output(f"Error fetching alerts for rule {rule_name}: {e}")
    
    def apply_rule_filter(self, rule_filter):
        """Apply rule filter to alerts"""
        if not rule_filter:
            self.update_output("No filter entered")
            return
            
        # Clear existing items
        gui.tree_manager.clear_tree(self.alert_types_tree)
        
        # Queue the filtered query using analysis_manager
        gui.analysis_manager.queue_query(
            lambda: self._get_filtered_alerts_by_rule(rule_filter),
            self._update_alerts_by_type_display
        )
        
        self.update_output(f"Querying rules matching filter: {rule_filter}")
    
    def _get_filtered_alerts_by_rule(self, rule_filter):
        """Get alerts filtered by rule name pattern from analysis_1.db"""
        try:
            # Check if analysis_manager has this method already
            if hasattr(gui.analysis_manager, 'get_alerts_by_rule_type'):
                return gui.analysis_manager.get_alerts_by_rule_type(rule_filter=rule_filter)
            
            # Otherwise implement directly
            cursor = gui.analysis_manager.get_cursor()
            
            filter_pattern = f"%{rule_filter}%"
            cursor.execute("""
                SELECT rule_name, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM alerts 
                WHERE rule_name LIKE ?
                GROUP BY rule_name
                ORDER BY last_seen DESC
            """, (filter_pattern,))
            
            results = []
            for rule, count, timestamp in cursor.fetchall():
                # Format timestamp
                if isinstance(timestamp, (int, float)):
                    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
                else:
                    formatted_time = str(timestamp)
                
                results.append((rule, count, formatted_time))
                
            cursor.close()
            return results
        except Exception as e:
            gui.update_output(f"Error getting filtered alerts by rule: {e}")
            return []