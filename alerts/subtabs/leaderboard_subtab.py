# SubtabBase class is injected by the Loader

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
        
        # Queue the leaderboard query
        gui.db_manager.queue_query(
            gui._get_leaderboard_data,
            callback=self._update_leaderboard_display
        )
        
        self.update_output("Refreshing threat leaderboard...")
    
    def _update_leaderboard_display(self, data):
        """Update the leaderboard display with the results"""
        try:
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
        
        # Queue the query for rule details by IP
        gui.db_manager.queue_query(
            gui._get_ip_rule_details,
            callback=lambda rows: self._update_leaderboard_details_display(rows, ip),
            ip_address=ip
        )
    
    def _update_leaderboard_details_display(self, rows, ip):
        """Update the leaderboard details display with rule information"""
        try:
            # Populate tree using TreeViewManager
            gui.tree_manager.populate_tree(self.leaderboard_details_tree, rows)
            self.update_output(f"Showing {len(rows)} rule types triggered by IP: {ip}")
        except Exception as e:
            self.update_output(f"Error fetching rule details for {ip}: {e}")