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
        
        # Queue the alerts query
        gui.db_manager.queue_query(
            gui.db_manager.get_alerts_by_rule_type,
            callback=self._update_alerts_by_type_display
        )
        
        self.update_output("Alerts by type refresh queued")
    
    def _update_alerts_by_type_display(self, rows):
        """Update the alerts by type treeview with the results"""
        try:
            if not rows:
                self.update_output("No alerts found in database")
                return
            
            # Populate tree using TreeViewManager
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
        
        # Queue the query
        gui.db_manager.queue_query(
            gui.db_manager.get_rule_alerts,
            callback=lambda rows: self._update_rule_alerts_display(rows, rule_name),
            rule_name=rule_name
        )
    
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
        
        # Queue the filtered query
        gui.db_manager.queue_query(
            gui.db_manager.get_filtered_alerts_by_rule,
            callback=self._update_alerts_by_type_display,
            rule_filter=rule_filter
        )
        
        self.update_output(f"Querying rules matching filter: {rule_filter}")