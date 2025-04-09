# SubtabBase class is injected by the Loader
import time
import math
import json
import tkinter as tk
from tkinter import ttk

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
        
        # Add option to highlight threats (new feature)
        self.highlight_threats_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(settings_frame, text="Highlight Threats", 
                       variable=self.highlight_threats_var).grid(row=0, column=3, padx=5, pady=5, sticky="w")
        
        ttk.Label(settings_frame, text="Max Nodes:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.max_nodes_var = tk.IntVar(value=50)
        ttk.Entry(settings_frame, textvariable=self.max_nodes_var, width=8).grid(row=1, column=1, padx=5, pady=5, sticky="w")
        
        # Connections list frame
        connections_frame = ttk.LabelFrame(self.tab_frame, text="Top Connections")
        connections_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Enhanced connections treeview with alert count and threat score
        self.connections_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            connections_frame,
            columns=("src_ip", "dst_ip", "bytes", "packets", "alerts", "threat_score"),
            headings=["Source IP", "Destination IP", "Bytes", "Packets", "Alerts", "Threat Score"],
            widths=[130, 130, 100, 80, 80, 100],
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
        
        # Add view threat intel button (new enhancement)
        ttk.Button(button_frame, text="View Threat Intel", 
                  command=self.view_threat_intel
                 ).pack(side="left", padx=5)
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)
        
        # Bind event to update selected IP
        self.connections_tree.bind("<<TreeviewSelect>>", self.update_selected_ip)
        
        # Create context menu
        self._create_context_menu()
    
    def _create_context_menu(self):
        """Create an enhanced context menu"""
        # Get parent window reference correctly
        parent_window = self.tab_frame.winfo_toplevel()
        
        menu = tk.Menu(parent_window, tearoff=0)
        menu.add_command(label="Focus on IP", 
                        command=self.focus_on_ip)
        menu.add_command(label="Copy IP", 
                        command=lambda: gui.ip_manager.copy_ip_to_clipboard(self.selected_ip_var.get()))
        menu.add_separator()
        menu.add_command(label="View Threat Intelligence", 
                        command=self.view_threat_intel)
        menu.add_command(label="Mark as False Positive", 
                        command=lambda: gui.ip_manager.mark_as_false_positive(self.selected_ip_var.get()))
        
        # Bind context menu
        def show_context_menu(event):
            # Update IP variable
            selected = self.connections_tree.selection()
            if selected:
                values = self.connections_tree.item(selected[0], "values")
                # Could be either source or destination IP based on click position
                x_click = event.x
                x_src = self.connections_tree.column("src_ip", "width") // 2
                x_dst = x_src + self.connections_tree.column("dst_ip", "width") // 2
                
                # Determine if click is closer to src or dst column
                ip = values[0] if x_click < x_src else values[1]
                self.selected_ip_var.set(ip)
                
                # Show menu
                menu.post(event.x_root, event.y_root)
        
        self.connections_tree.bind("<Button-3>", show_context_menu)

    def refresh(self):
        """Refresh connection data"""
        # Clear existing items
        gui.tree_manager.clear_tree(self.connections_tree)
        
        # Queue the connections query using the analysis manager instead of db_manager
        gui.analysis_manager.queue_query(
            self._get_top_connections,
            self._update_connections_display
        )
        
        self.update_output("Connections refresh queued")
    
    def _get_top_connections(self):
        """Get top connections from analysis_1.db with integrated analytics"""
        try:
            limit = self.max_nodes_var.get()
            cursor = gui.analysis_manager.get_cursor()
            
            # Enhanced query that joins connections with traffic patterns
            # Using LEFT JOIN to ensure we get connections even if there's no traffic pattern data
            cursor.execute("""
                SELECT 
                    c.src_ip, 
                    c.dst_ip, 
                    c.total_bytes, 
                    c.packet_count, 
                    c.timestamp,
                    t.classification,
                    t.periodic_score,
                    t.burst_score
                FROM connections c
                LEFT JOIN x_traffic_patterns t ON c.connection_key = t.connection_key
                ORDER BY c.total_bytes DESC
                LIMIT ?
            """, (limit,))
            
            results = cursor.fetchall()
            cursor.close()
            return results
        except Exception as e:
            gui.update_output(f"Error getting top connections: {e}")
            return []
    
    def _update_connections_display(self, connections):
        """Update the connections display with the results using queue-based DB access"""
        try:
            # Store enhanced connections for later graph generation
            self.connections = connections
            
            # Format connections for display with additional alert info and threat scores
            self._fetch_alert_counts_for_connections(connections)
            
        except Exception as e:
            self.update_output(f"Error updating connections display: {e}")

    def _fetch_alert_counts_for_connections(self, connections):
        """Fetch alert counts and threat scores for each connection using the queue system"""
        # Prepare for batch processing
        connection_data = []
        
        # First format what we already have
        for i, conn_data in enumerate(connections):
            # Extract basic connection data
            if len(conn_data) >= 8:  # Enhanced query with traffic pattern data
                src_ip, dst_ip, total_bytes, packet_count, timestamp, classification, periodic_score, burst_score = conn_data
            else:  # Basic connection data
                src_ip, dst_ip, total_bytes, packet_count, timestamp = conn_data[:5]
                classification, periodic_score, burst_score = None, None, None
            
            # Format bytes for display
            bytes_formatted = f"{total_bytes:,}" if total_bytes is not None else "0"
            
            # Store all data we need for later processing
            connection_data.append({
                'id': i,  # Use index as identifier for callback
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'bytes_formatted': bytes_formatted,
                'packet_count': packet_count,
                'classification': classification,
                'periodic_score': periodic_score,
                'burst_score': burst_score
            })
        
        # Queue the query using analysis_manager
        gui.analysis_manager.queue_query(
            lambda: self._get_enhanced_connection_data(connection_data),
            self._display_connections_with_enhancements
        )
    
    def _get_enhanced_connection_data(self, connection_data):
        """Get alert counts and threat scores for connections from analysis_1.db"""
        try:
            results = []
            cursor = gui.analysis_manager.get_cursor()
            
            # Process each connection
            for conn in connection_data:
                src_ip = conn['src_ip']
                dst_ip = conn['dst_ip']
                
                # Get alert count from x_alerts table (updated)
                alert_count = cursor.execute(
                    "SELECT COUNT(*) FROM x_alerts WHERE ip_address = ? OR ip_address = ?",
                    (src_ip, dst_ip)
                ).fetchone()[0]
                
                # Get threat scores from x_ip_threat_intel table (new)
                src_threat = cursor.execute(
                    "SELECT threat_score FROM x_ip_threat_intel WHERE ip_address = ?",
                    (src_ip,)
                ).fetchone()
                
                dst_threat = cursor.execute(
                    "SELECT threat_score FROM x_ip_threat_intel WHERE ip_address = ?",
                    (dst_ip,)
                ).fetchone()
                
                # Calculate combined threat score
                src_score = src_threat[0] if src_threat else 0
                dst_score = dst_threat[0] if dst_threat else 0
                combined_score = max(src_score, dst_score)  # Use the higher of the two scores
                
                # Add to results with all data needed for display
                results.append((
                    conn['id'],
                    conn['src_ip'],
                    conn['dst_ip'],
                    conn['bytes_formatted'],
                    conn['packet_count'],
                    alert_count,
                    f"{combined_score:.1f}" if combined_score > 0 else "0.0",
                    conn['classification'],
                    conn['periodic_score'],
                    conn['burst_score']
                ))
            
            cursor.close()
            return results
        except Exception as e:
            gui.update_output(f"Error getting enhanced connection data: {e}")
            return []

    def _display_connections_with_enhancements(self, results):
        """Process query results and update the tree display with enhanced data"""
        try:
            # Sort results back to original order
            results.sort(key=lambda x: x[0])
            
            # Format data for tree display (removing the temporary ID)
            display_data = [(r[1], r[2], r[3], r[4], r[5], r[6]) for r in results]
            
            # Store enhanced data for graph generation
            self.enhanced_connections = []
            for r in results:
                self.enhanced_connections.append({
                    'src_ip': r[1],
                    'dst_ip': r[2],
                    'bytes': r[3],
                    'packets': r[4],
                    'alerts': r[5],
                    'threat_score': float(r[6]) if r[6] and r[6] != "0.0" else 0,
                    'classification': r[7],
                    'periodic_score': r[8],
                    'burst_score': r[9]
                })
            
            # Populate tree using TreeViewManager
            gui.tree_manager.populate_tree(self.connections_tree, display_data)
            
            # Color rows based on threat score
            for i, item_id in enumerate(self.connections_tree.get_children()):
                values = self.connections_tree.item(item_id, "values")
                if len(values) >= 6:
                    try:
                        score = float(values[5])
                        
                        # Apply color based on threat score
                        if score > 6:
                            self.connections_tree.item(item_id, tags=("high_threat",))
                        elif score > 3:
                            self.connections_tree.item(item_id, tags=("medium_threat",))
                    except (ValueError, TypeError):
                        pass
            
            # Configure tag colors
            self.connections_tree.tag_configure("high_threat", background="#ffe6e6")  # Light red
            self.connections_tree.tag_configure("medium_threat", background="#fff6e6")  # Light orange
            
            self.update_output(f"Showing {len(display_data)} connections with enhanced data")
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
        
        # Regenerate graph with focus on this IP
        self.generate_graph(selected_ip)
    
    def view_threat_intel(self):
        """View detailed threat intelligence for the selected IP"""
        ip = self.selected_ip_var.get()
        if not ip:
            gui.update_output("No IP selected")
            return
        
        # Show a dialog with threat intelligence data
        try:
            # Check if MaliciousSubtab has view_threat_intel method we can reuse
            malicious_subtab = None
            for subtab in gui.subtab_loader.subtabs:
                if subtab.name == "Possible Malicious":
                    malicious_subtab = subtab
                    break
            
            if malicious_subtab and hasattr(malicious_subtab, 'view_threat_intel'):
                # Reuse MaliciousSubtab's implementation
                malicious_subtab.ip_var.set(ip)
                malicious_subtab.view_threat_intel()
            else:
                # Queue our own implementation - would need to be added
                gui.update_output("Direct threat intelligence view not implemented. Please use the Malicious tab.")
        except Exception as e:
            gui.update_output(f"Error accessing threat intelligence: {e}")
    
    def generate_graph(self, focus_ip=None):
        """Generate and display network connection graph"""
        if not hasattr(self, 'enhanced_connections') or not self.enhanced_connections:
            self.update_output("No connection data available. Run 'Refresh Connections' first.")
            return
        
        self.update_output("Generating network graph...")
        
        # Clear canvas
        self.graph_canvas.delete("all")
        
        # This is a very simple mock graph visualization
        # In a real implementation, we would use a proper graph visualization library
        
        # Create a dict to track node positions
        nodes = {}
        threat_scores = {}
        
        # Track connection lines
        lines = []
        
        # Simple layout algorithm - position nodes in a circle
        width = self.graph_canvas.winfo_width() or 400
        height = self.graph_canvas.winfo_height() or 200
        
        center_x = width // 2
        center_y = height // 2
        radius = min(width, height) // 3
        
        # First, collect all unique IPs and their threat scores
        all_ips = set()
        for conn in self.enhanced_connections:
            src_ip = conn['src_ip']
            dst_ip = conn['dst_ip']
            all_ips.add(src_ip)
            all_ips.add(dst_ip)
            
            # Track threat scores for coloring
            threat_score = conn['threat_score']
            if src_ip not in threat_scores or threat_score > threat_scores[src_ip]:
                threat_scores[src_ip] = threat_score
            if dst_ip not in threat_scores or threat_score > threat_scores[dst_ip]:
                threat_scores[dst_ip] = threat_score
        
        # If focusing on a specific IP, filter connections
        if focus_ip:
            # Keep only connections involving the focus IP
            filtered_ips = {focus_ip}
            for conn in self.enhanced_connections:
                if conn['src_ip'] == focus_ip:
                    filtered_ips.add(conn['dst_ip'])
                elif conn['dst_ip'] == focus_ip:
                    filtered_ips.add(conn['src_ip'])
            all_ips = filtered_ips
        
        # Limit to max nodes
        max_nodes = self.max_nodes_var.get()
        all_ips = list(all_ips)
        if len(all_ips) > max_nodes:
            # If focusing, make sure focus_ip stays
            if focus_ip:
                if focus_ip in all_ips:
                    all_ips.remove(focus_ip)
                    all_ips = all_ips[:max_nodes-1]
                    all_ips.append(focus_ip)
                else:
                    all_ips = all_ips[:max_nodes]
            else:
                all_ips = all_ips[:max_nodes]
        
        # Position nodes in a circle
        angle_step = 2 * math.pi / len(all_ips)
        
        # If focusing, position focus IP in the center
        if focus_ip and focus_ip in all_ips:
            nodes[focus_ip] = (center_x, center_y)
            all_ips.remove(focus_ip)  # Remove from the list to avoid duplicating
            angle_step = 2 * math.pi / max(1, len(all_ips))  # Recalculate angle step
        
        for i, ip in enumerate(all_ips):
            angle = i * angle_step
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            
            # Store node position
            nodes[ip] = (x, y)
            
            # Draw node with color based on threat score
            node_color = "blue"
            if ip in threat_scores:
                score = threat_scores[ip]
                if score > 6:
                    node_color = "red"
                elif score > 3:
                    node_color = "orange"
            
            # Draw node
            node_id = self.graph_canvas.create_oval(x-5, y-5, x+5, y+5, fill=node_color)
            self.graph_canvas.create_text(x, y-15, text=ip, font=("Arial", 8))
        
        # Add back the focus IP if it was processed separately
        if focus_ip and focus_ip not in nodes and focus_ip in all_ips:
            # This means we didn't handle it specially above
            nodes[focus_ip] = (center_x, center_y)
        
        # Draw connections (now using enhanced_connections)
        for conn in self.enhanced_connections:
            src_ip = conn['src_ip']
            dst_ip = conn['dst_ip']
            if src_ip in nodes and dst_ip in nodes:
                src_x, src_y = nodes[src_ip]
                dst_x, dst_y = nodes[dst_ip]
                
                # Calculate line width based on bytes (thicker = more data)
                try:
                    bytes_total = int(conn['bytes'].replace(',', ''))
                    line_width = 1
                    if bytes_total > 1000000:  # > 1MB
                        line_width = 3
                    elif bytes_total > 100000:  # > 100KB
                        line_width = 2
                except (ValueError, AttributeError):
                    line_width = 1
                
                # Select line color based on classification
                line_color = "gray"
                if conn.get('classification'):
                    if "malicious" in conn['classification'].lower():
                        line_color = "red"
                    elif "suspicious" in conn['classification'].lower():
                        line_color = "orange"
                    elif "periodic" in conn['classification'].lower() and conn.get('periodic_score', 0) > 0.7:
                        line_color = "purple"  # High periodic score may indicate beaconing
                
                # Draw line
                line_id = self.graph_canvas.create_line(
                    src_x, src_y, dst_x, dst_y, 
                    arrow=tk.LAST, 
                    width=line_width,
                    fill=line_color
                )
                
                # Optional tooltip-like label for connection details
                if self.show_traffic_volume_var.get():
                    # Calculate midpoint for label
                    mid_x = (src_x + dst_x) / 2
                    mid_y = (src_y + dst_y) / 2
                    
                    # Show traffic volume and alert count if enabled
                    label_text = f"{conn['bytes']}"
                    if conn['alerts'] > 0 and self.show_alerts_var.get():
                        label_text += f" ({conn['alerts']} alerts)"
                    
                    self.graph_canvas.create_text(
                        mid_x, mid_y - 10,
                        text=label_text,
                        font=("Arial", 7),
                        fill="dark gray"
                    )
                
                lines.append(line_id)
        
        # If focusing, add a title
        if focus_ip:
            title_y = 20
            self.graph_canvas.create_text(
                center_x, title_y,
                text=f"Network Connections for {focus_ip}",
                font=("Arial", 12, "bold"),
                fill="black"
            )
            
            # Add threat score if available
            if focus_ip in threat_scores and threat_scores[focus_ip] > 0:
                score = threat_scores[focus_ip]
                score_color = "green"
                if score > 3:
                    score_color = "orange"
                if score > 6:
                    score_color = "red"
                    
                self.graph_canvas.create_text(
                    center_x, title_y + 20,
                    text=f"Threat Score: {score:.1f}",
                    font=("Arial", 10),
                    fill=score_color
                )
        
        self.update_output(f"Graph generated with {len(nodes)} nodes and {len(lines)} connections")