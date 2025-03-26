# SubtabBase class is injected by the Loader

class GeoLocationSubtab(SubtabBase):
    """Subtab that displays alerts with geo-location information"""
    
    def __init__(self):
        super().__init__(
            name="Geo Location",
            description="Displays alerts with geographical information"
        )
        self.geo_tree = None
        self.geo_details_tree = None
        self.selected_ip_var = None
    
    def create_ui(self):
        """Create UI components for Geo Location subtab"""
        # Control buttons frame
        gui.tab_factory.create_control_buttons(
            self.tab_frame,
            [
                {"text": "Refresh Geo Data", "command": self.refresh},
                {"text": "Show World Map", "command": self.show_map}
            ]
        )
        
        # Geo location treeview
        self.geo_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            self.tab_frame,
            columns=("ip", "country", "city", "alerts"),
            headings=["IP Address", "Country", "City", "Alert Count"],
            widths=[150, 100, 150, 80],
            height=10
        )
        
        # Create details frame
        details_frame = ttk.LabelFrame(self.tab_frame, text="Location Details")
        details_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.geo_details_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            details_frame,
            columns=("detail", "value"),
            headings=["Detail", "Value"],
            widths=[150, 300],
            height=10
        )
        
        # Selected IP frame
        info_frame = ttk.Frame(self.tab_frame)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.selected_ip_var = tk.StringVar()
        ttk.Label(info_frame, text="Selected IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(info_frame, textvariable=self.selected_ip_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        button_frame = ttk.Frame(info_frame)
        button_frame.grid(row=0, column=2, sticky="e", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Copy IP", 
                  command=lambda: gui.ip_manager.copy_ip_to_clipboard(self.selected_ip_var.get())
                 ).pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Mark as False Positive", 
                  command=lambda: gui.ip_manager.mark_as_false_positive(self.selected_ip_var.get())
                 ).pack(side="left", padx=5)
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)
        
        # Bind event to show details for selected IP
        self.geo_tree.bind("<<TreeviewSelect>>", self.show_location_details)
        
        # Create context menu
        gui.ip_manager.create_context_menu(
            self.geo_tree, 
            self.selected_ip_var, 
            lambda: self.show_location_details(None)
        )
    
    def refresh(self):
        """Refresh geo location data"""
        # Clear existing items
        gui.tree_manager.clear_tree(self.geo_tree)
        
        # In a real implementation, we would query an IP geolocation database
        # For this example, we'll use mock data
        mock_data = [
            ("192.168.1.1", "United States", "New York", 12),
            ("10.0.0.1", "Germany", "Berlin", 5),
            ("172.16.0.1", "Japan", "Tokyo", 8)
        ]
        
        # Populate tree with mock data
        gui.tree_manager.populate_tree(self.geo_tree, mock_data)
        self.update_output("Geo location data refreshed (mock data)")
    
    def show_location_details(self, event):
        """Show details for selected IP location"""
        # Clear existing items
        gui.tree_manager.clear_tree(self.geo_details_tree)
        
        # Get selected IP
        selected = self.geo_tree.selection()
        if not selected:
            return
            
        values = self.geo_tree.item(selected[0], "values")
        ip = values[0]
        country = values[1]
        city = values[2]
        
        self.selected_ip_var.set(ip)
        
        # Mock details data
        details = [
            ("IP", ip),
            ("Country", country),
            ("City", city),
            ("Region", "Example Region"),
            ("Latitude", "40.7128"),
            ("Longitude", "-74.0060"),
            ("ISP", "Example ISP"),
            ("Organization", "Example Org"),
            ("Timezone", "UTC-5")
        ]
        
        # Populate details tree
        gui.tree_manager.populate_tree(self.geo_details_tree, details)
        self.update_output(f"Showing location details for IP: {ip}")
    
    def show_map(self):
        """Show world map with alert locations"""
        self.update_output("World map feature would be displayed here")
        # In a real implementation, this would show a map visualization