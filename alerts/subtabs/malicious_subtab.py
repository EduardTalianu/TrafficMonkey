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
        
        # Queue a query to get alert data
        gui.db_manager.queue_query(
            gui._get_malicious_ip_data,
            callback=self._update_malicious_display
        )
        
        self.update_output("Refreshing malicious IP list...")
    
    def _update_malicious_display(self, data):
        """Update the malicious IP display"""
        try:
            # Populate tree using TreeViewManager
            gui.tree_manager.populate_tree(self.malicious_tree, data)
            self.update_output(f"Found {len(data)} potentially malicious IPs from all alerts")
        except Exception as e:
            self.update_output(f"Error updating malicious IP display: {e}")