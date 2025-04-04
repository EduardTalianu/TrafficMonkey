# SubtabBase class is injected by the Loader

class ConnectionGraphSubtab(SubtabBase):
    """Subtab that displays network connections as a visual graph"""
    
    def __init__(self):
        super().__init__(
            name="Connection Graph",
            description="Visualizes network connections between IPs as a graph"
        )
        self.connections_tree = None
        self.selected_ip_var = None
        # Mock data for demonstration
        self.connections = []
    
    def create_ui(self):
        """Create UI components for Connection Graph subtab"""
        # Control buttons frame
        gui.tab_factory.create_control_buttons(
            self.tab_frame,
            [
                {"text": "Refresh Connections", "command": self.refresh},
                {"text": "Generate Graph", "command": self.generate_graph}
            ]
        )
        
        # Settings frame
        settings_frame = ttk.LabelFrame(self.tab_frame, text="Graph Settings")
        settings_frame.pack(fill="x", padx=10, pady=5)
        
        # Graph options (using grid layout)
        self.show_alerts_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Show Alerts", 
                       variable=self.show_alerts_var).grid(row=0, column=0, padx=5, pady=5, sticky="w")
        
        self.group_by_subnet_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(settings_frame, text="Group by Subnet", 
                       variable=self.group_by_subnet_var).grid(row=0, column=1, padx=5, pady=5, sticky="w")
        
        self.show_traffic_volume_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Show Traffic Volume", 
                       variable=self.show_traffic_volume_var).grid(row=0, column=2, padx=5, pady=5, sticky="w")
        
        ttk.Label(settings_frame, text="Max Nodes:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.max_nodes_var = tk.IntVar(value=50)
        ttk.Entry(settings_frame, textvariable=self.max_nodes_var, width=8).grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        # Connections list frame
        connections_frame = ttk.LabelFrame(self.tab_frame, text="Top Connections")
        connections_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create connections treeview
        self.connections_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            connections_frame,
            columns=("src_ip", "dst_ip", "bytes", "packets", "alerts"),
            headings=["Source IP", "Destination IP", "Bytes", "Packets", "Alerts"],
            widths=[150, 150, 100, 80, 80],
            height=10
        )
        
        # Graph canvas frame (placeholder for the actual graph visualization)
        graph_frame = ttk.LabelFrame(self.tab_frame, text="Network Graph")
        graph_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Simple canvas as a placeholder for graph visualization
        self.graph_canvas = tk.Canvas(graph_frame, bg="white", height=200)
        self.graph_canvas.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add a placeholder message
        self.graph_canvas.create_text(
            self.graph_canvas.winfo_reqwidth() // 2, 
            100,
            text="Click 'Generate Graph' to visualize network connections",
            fill="gray"
        )
        
        # Selected IP frame
        info_frame = ttk.Frame(self.tab_frame)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.selected_ip_var = tk.StringVar()
        ttk.Label(info_frame, text="Selected IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(info_frame, textvariable=self.selected_ip_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        button_frame = ttk.Frame(info_frame)
        button_frame.grid(row=0, column=2, sticky="e", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Focus on IP", 
                  command=self.focus_on_ip).pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Copy IP", 
                  command=lambda: gui.ip_manager.copy_ip_to_clipboard(self.selected_ip_var.get())
                 ).pack(side="left", padx=5)
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)
        
        # Bind event to update selected IP
        self.connections_tree.bind("<<TreeviewSelect>>", self.update_selected_ip)
        
        # Create context menu
        gui.ip_manager.create_context_menu(
            self.connections_tree, 
            self.selected_ip_var
        )
    
    def refresh(self):
        """Refresh connection data"""
        # Clear existing items
        gui.tree_manager.clear_tree(self.connections_tree)
        
        # Queue the connections query using the database manager
        gui.db_manager.queue_query(
            gui.db_manager.get_top_connections,
            callback=self._update_connections_display,
            limit=self.max_nodes_var.get()
        )
        
        self.update_output("Connections refresh queued")
    
    def _update_connections_display(self, connections):
        """Update the connections display with the results using queue-based DB access"""
        try:
            # Store connections for later graph generation
            self.connections = connections
            
            # Format connections for display with additional alert info
            self._fetch_alert_counts_for_connections(connections)
            
        except Exception as e:
            self.update_output(f"Error updating connections display: {e}")

    def _fetch_alert_counts_for_connections(self, connections):
        """Fetch alert counts for each connection using the queue system"""
        # Prepare for batch processing
        connection_data = []
        
        # First format what we already have
        for i, (src_ip, dst_ip, total_bytes, packet_count, timestamp) in enumerate(connections):
            # Format bytes for display
            bytes_formatted = f"{total_bytes:,}" if total_bytes is not None else "0"
            
            # Store all data we need for later processing
            connection_data.append({
                'id': i,  # Use index as identifier for callback
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'bytes_formatted': bytes_formatted,
                'packet_count': packet_count
            })
        
        # Define query function to get alert counts
        def get_alert_counts(connection_data):
            results = []
            cursor = gui.db_manager.analysis_conn.cursor()
            
            # Process each connection
            for conn in connection_data:
                src_ip = conn['src_ip']
                dst_ip = conn['dst_ip']
                
                # Get alert count
                count = cursor.execute(
                    "SELECT COUNT(*) FROM alerts WHERE ip_address = ? OR ip_address = ?",
                    (src_ip, dst_ip)
                ).fetchone()[0]
                
                # Add to results with all data needed for display
                results.append((
                    conn['id'],
                    conn['src_ip'],
                    conn['dst_ip'],
                    conn['bytes_formatted'],
                    conn['packet_count'],
                    count
                ))
            
            cursor.close()
            return results
        
        # Queue the query with callback
        gui.db_manager.queue_query(
            get_alert_counts,
            callback=self._display_connections_with_alerts,
            connection_data=connection_data
        )
    

    def _display_connections_with_alerts(self, results):
        """Process query results and update the tree display"""
        try:
            # Sort results back to original order
            results.sort(key=lambda x: x[0])
            
            # Format data for tree display (removing the temporary ID)
            display_data = [(r[1], r[2], r[3], r[4], r[5]) for r in results]
            
            # Populate tree using TreeViewManager
            gui.tree_manager.populate_tree(self.connections_tree, display_data)
            self.update_output(f"Showing {len(display_data)} connections")
        except Exception as e:
            self.update_output(f"Error displaying connections: {e}")
            
    def update_selected_ip(self, event):
        """Update selected IP when a connection is selected"""
        selected = self.connections_tree.selection()
        if not selected:
            return
            
        # Get source IP as the default selected IP
        values = self.connections_tree.item(selected[0], "values")
        self.selected_ip_var.set(values[0])  # Source IP
    
    def focus_on_ip(self):
        """Center the graph on the selected IP"""
        selected_ip = self.selected_ip_var.get()
        if not selected_ip:
            return
            
        self.update_output(f"Focusing graph on IP: {selected_ip}")
        
        # This would actually adjust the graph visualization in a real implementation
        # For this example, we'll just show a message on the canvas
        self.graph_canvas.delete("all")  # Clear canvas
        self.graph_canvas.create_text(
            self.graph_canvas.winfo_reqwidth() // 2, 
            100,
            text=f"Graph focused on {selected_ip}",
            fill="blue"
        )
    
    def generate_graph(self):
        """Generate and display network connection graph"""
        if not self.connections:
            self.update_output("No connection data available. Run 'Refresh Connections' first.")
            return
        
        self.update_output("Generating network graph...")
        
        # Clear canvas
        self.graph_canvas.delete("all")
        
        # This is a very simple mock graph visualization
        # In a real implementation, we would use a proper graph visualization library
        
        # Create a dict to track node positions
        nodes = {}
        
        # Track connection lines
        lines = []
        
        # Simple layout algorithm - position nodes in a circle
        width = self.graph_canvas.winfo_width() or 400
        height = self.graph_canvas.winfo_height() or 200
        
        center_x = width // 2
        center_y = height // 2
        radius = min(width, height) // 3
        
        # First, collect all unique IPs
        all_ips = set()
        for src_ip, dst_ip, _, _, _ in self.connections:
            all_ips.add(src_ip)
            all_ips.add(dst_ip)
        
        # Limit to max nodes
        max_nodes = self.max_nodes_var.get()
        if len(all_ips) > max_nodes:
            all_ips = list(all_ips)[:max_nodes]
        
        # Position nodes in a circle
        import math
        angle_step = 2 * math.pi / len(all_ips)
        
        for i, ip in enumerate(all_ips):
            angle = i * angle_step
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            
            # Store node position
            nodes[ip] = (x, y)
            
            # Draw node
            node_id = self.graph_canvas.create_oval(x-5, y-5, x+5, y+5, fill="blue")
            self.graph_canvas.create_text(x, y-15, text=ip, font=("Arial", 8))
        
        # Draw connections
        for src_ip, dst_ip, bytes_total, _, _ in self.connections:
            if src_ip in nodes and dst_ip in nodes:
                src_x, src_y = nodes[src_ip]
                dst_x, dst_y = nodes[dst_ip]
                
                # Calculate line width based on bytes (thicker = more data)
                line_width = 1
                if bytes_total > 1000000:  # > 1MB
                    line_width = 3
                elif bytes_total > 100000:  # > 100KB
                    line_width = 2
                
                # Draw line
                line_id = self.graph_canvas.create_line(
                    src_x, src_y, dst_x, dst_y, 
                    arrow=tk.LAST, 
                    width=line_width,
                    fill="gray"
                )
                
                lines.append(line_id)
        
        self.update_output(f"Graph generated with {len(nodes)} nodes and {len(lines)} connections")