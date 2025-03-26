# SubtabBase class is injected by the Loader

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
        
        # Queue the alerts query
        gui.db_manager.queue_query(
            gui.db_manager.get_alerts_by_ip,
            callback=self._update_alerts_display
        )
        
        self.update_output("Alerts refresh queued")
    
    def _update_alerts_display(self, rows):
        """Update the alerts treeview with the results"""
        try:
            # Populate tree using TreeViewManager
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
        
        # Queue the IP alerts query
        gui.db_manager.queue_query(
            gui.db_manager.get_ip_alerts,
            callback=lambda rows: self._update_ip_alerts_display(rows, ip),
            ip_address=ip
        )
    
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
        
        # Queue the filtered query
        gui.db_manager.queue_query(
            gui.db_manager.get_filtered_alerts_by_ip,
            callback=self._update_alerts_display,
            ip_filter=ip_filter
        )
        
        self.update_output(f"Querying alerts matching filter: {ip_filter}")