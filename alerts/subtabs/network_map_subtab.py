# SubtabBase class is injected by the Loader
import tkinter as tk
from tkinter import ttk
import time
import math
import re
import random
import ipaddress
import json

class NetworkMapSubtab(SubtabBase):
    """Subtab that displays a network map using TTL and ARP data for accurate topology"""
    
    def __init__(self):
        super().__init__(
            name="Network Map",
            description="Visualizes the network topology using TTL and ARP data"
        )
        self.canvas = None
        self.controls_frame = None
        self.details_frame = None
        
        # Configuration options
        self.show_external = tk.BooleanVar(value=True)
        self.group_by_subnet = tk.BooleanVar(value=True)
        self.show_service_labels = tk.BooleanVar(value=True)
        self.show_threat_intel = tk.BooleanVar(value=True)
        self.node_spacing = tk.IntVar(value=150)
        
        # Data storage
        self.nodes = {}  # {node_id: {type, ip, name, x, y, ...}}
        self.edges = []  # [{source, target, protocol, volume, ...}]
        self.arp_relationships = {}  # {ip: [related_ips]}
        self.gateways = []  # List of identified gateway IPs
        self.selected_node = None
        self.last_refresh_time = 0
        self.refresh_interval = 15  # seconds
        
        # Visual elements
        self.node_radius = 20
        self.canvas_items = {}  # Store canvas item IDs for interaction
        self.colors = {
            "gateway": "#87CEEB",     # Sky Blue (for gateways/routers)
            "firewall": "#FF6347",    # Tomato Red (for firewalls)
            "vpn": "#9370DB",         # Medium Purple (for VPN endpoints)
            "border": "#4682B4",      # Steel Blue (for border routers)
            "lan": "#90EE90",         # Light Green (for LAN devices)
            "server": "#FFD700",      # Gold (for servers)
            "cloud": "#F0F8FF",       # Alice Blue (for cloud/external)
            "selected": "#00CED1",    # Dark Turquoise (for selected node)
            "background": "#FFFFFF",  # White (background)
            "threat": "#FF0000",      # Red (for threats)
            "warning": "#FFA500",     # Orange (for warnings)
        }
        
        # Statistics
        self.stats = {
            "lan_devices": 0,
            "wan_connections": 0,
            "gateways": 0,
            "firewalls": 0,
            "servers": 0,
            "threats": 0
        }
    
    def create_ui(self):
        """Create the network map UI components"""
        # Split the frame into controls (left) and map (right)
        main_frame = ttk.Frame(self.tab_frame)
        main_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Controls area (left side)
        self.controls_frame = ttk.Frame(main_frame, width=180)
        self.controls_frame.pack(side="left", fill="y", padx=5, pady=5)
        
        # Map area (right side)
        map_frame = ttk.Frame(main_frame)
        map_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)
        
        # Create controls
        self.create_control_panel()
        
        # Create map canvas
        self.create_map_canvas(map_frame)
        
        # Create details panel at bottom
        self.details_frame = ttk.LabelFrame(self.tab_frame, text="Device Details")
        self.details_frame.pack(fill="x", padx=10, pady=5)
        
        self.details_text = tk.Text(self.details_frame, height=5, wrap=tk.WORD)
        self.details_text.pack(fill="both", expand=True, padx=5, pady=5)
    
    def create_control_panel(self):
        """Create the controls for the network map"""
        # Title
        ttk.Label(self.controls_frame, text="Network Map Controls", 
                font=("TkDefaultFont", 10, "bold")).pack(anchor="w", padx=5, pady=5)
        
        # Refresh button
        ttk.Button(self.controls_frame, text="Refresh Map", 
                  command=self.refresh).pack(fill="x", padx=5, pady=5)
        
        # Stats frame
        stats_frame = ttk.LabelFrame(self.controls_frame, text="Network Statistics")
        stats_frame.pack(fill="x", padx=5, pady=5)
        
        self.stats_labels = {}
        for i, (stat_key, label_text) in enumerate([
            ("lan_devices", "LAN Devices:"),
            ("wan_connections", "WAN Connections:"),
            ("gateways", "Gateways/Routers:"),
            ("firewalls", "Firewalls:"),
            ("servers", "Servers:"),
            ("threats", "Threat Indicators:")
        ]):
            ttk.Label(stats_frame, text=label_text).grid(row=i, column=0, sticky="w", padx=5, pady=2)
            self.stats_labels[stat_key] = ttk.Label(stats_frame, text="0")
            self.stats_labels[stat_key].grid(row=i, column=1, sticky="e", padx=5, pady=2)
        
        # View options
        options_frame = ttk.LabelFrame(self.controls_frame, text="Display Options")
        options_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Checkbutton(options_frame, text="Show External Connections", 
                      variable=self.show_external,
                      command=self.refresh).pack(anchor="w", padx=5, pady=3)
        
        ttk.Checkbutton(options_frame, text="Group by Subnet", 
                      variable=self.group_by_subnet,
                      command=self.refresh).pack(anchor="w", padx=5, pady=3)
        
        ttk.Checkbutton(options_frame, text="Show Service Labels", 
                      variable=self.show_service_labels,
                      command=self.redraw_network).pack(anchor="w", padx=5, pady=3)
        
        ttk.Checkbutton(options_frame, text="Show Threat Intelligence", 
                      variable=self.show_threat_intel,
                      command=self.redraw_network).pack(anchor="w", padx=5, pady=3)
        
        ttk.Label(options_frame, text="Node Spacing:").pack(anchor="w", padx=5, pady=3)
        ttk.Scale(options_frame, from_=80, to=200, variable=self.node_spacing, 
                orient="horizontal", command=lambda s: self.redraw_network()).pack(fill="x", padx=5, pady=3)
        
        # Legend
        legend_frame = ttk.LabelFrame(self.controls_frame, text="Legend")
        legend_frame.pack(fill="x", padx=5, pady=5)
        
        # Create small canvas for legend
        legend_canvas = tk.Canvas(legend_frame, height=180, bg=self.colors["background"])
        legend_canvas.pack(fill="x", padx=5, pady=5)
        
        # Add legend items
        y_offset = 20
        for node_type in ["gateway", "border", "firewall", "vpn", "lan", "server", "cloud", "threat"]:
            # Draw colored circle
            legend_canvas.create_oval(10, y_offset-8, 26, y_offset+8, 
                                    fill=self.colors[node_type], outline="black")
            # Add label
            legend_canvas.create_text(35, y_offset, text=node_type.capitalize(), anchor="w")
            y_offset += 22
    
    def create_map_canvas(self, parent_frame):
        """Create the network map canvas with scrollbars"""
        # Frame for canvas and scrollbars
        canvas_frame = ttk.Frame(parent_frame)
        canvas_frame.pack(fill="both", expand=True)
        
        # Add scrollbars
        h_scrollbar = ttk.Scrollbar(canvas_frame, orient="horizontal")
        h_scrollbar.pack(side="bottom", fill="x")
        
        v_scrollbar = ttk.Scrollbar(canvas_frame)
        v_scrollbar.pack(side="right", fill="y")
        
        # Create canvas
        self.canvas = tk.Canvas(canvas_frame, bg=self.colors["background"],
                             xscrollcommand=h_scrollbar.set,
                             yscrollcommand=v_scrollbar.set)
        self.canvas.pack(fill="both", expand=True)
        
        # Configure scrollbars
        h_scrollbar.config(command=self.canvas.xview)
        v_scrollbar.config(command=self.canvas.yview)
        
        # Bind events
        self.canvas.bind("<ButtonPress-1>", self.on_canvas_click)
        self.canvas.bind("<ButtonPress-3>", self.on_canvas_right_click)
        self.canvas.bind("<B1-Motion>", self.on_canvas_drag)
        
        # Add zoom controls
        zoom_frame = ttk.Frame(parent_frame)
        zoom_frame.pack(fill="x", pady=5)
        
        ttk.Button(zoom_frame, text="Zoom In", 
                  command=lambda: self.zoom_canvas(1.2)).pack(side="left", padx=5)
        ttk.Button(zoom_frame, text="Zoom Out", 
                  command=lambda: self.zoom_canvas(0.8)).pack(side="left", padx=5)
        ttk.Button(zoom_frame, text="Reset View", 
                  command=self.reset_canvas_view).pack(side="left", padx=5)
        ttk.Button(zoom_frame, text="Export Map", 
                  command=self.export_map).pack(side="right", padx=5)
    
    def on_canvas_click(self, event):
        """Handle canvas click to select a node"""
        # Get canvas coordinates
        x = self.canvas.canvasx(event.x)
        y = self.canvas.canvasy(event.y)
        
        # Find closest item
        closest = self.canvas.find_closest(x, y)
        if closest:
            item_id = closest[0]
            if item_id in self.canvas_items:
                node_id = self.canvas_items[item_id]
                self.select_node(node_id)
            else:
                self.select_node(None)
        else:
            self.select_node(None)
    
    def on_canvas_right_click(self, event):
        """Handle right-click to show context menu"""
        # Get canvas coordinates
        x = self.canvas.canvasx(event.x)
        y = self.canvas.canvasy(event.y)
        
        # Find closest item
        closest = self.canvas.find_closest(x, y)
        if closest:
            item_id = closest[0]
            if item_id in self.canvas_items:
                node_id = self.canvas_items[item_id]
                self.select_node(node_id)
                
                # Create context menu
                node = self.nodes[node_id]
                menu = tk.Menu(self.canvas, tearoff=0)
                
                # Add menu items based on node type
                if "ip" in node:
                    menu.add_command(label=f"Copy IP: {node['ip']}", 
                                   command=lambda: gui.ip_manager.copy_ip_to_clipboard(node['ip']))
                
                if node["type"] in ["lan", "server"]:
                    menu.add_command(label="Show Connection Details", 
                                   command=lambda: self.show_connection_details(node_id))
                
                # Show ARP information if available
                if "ip" in node and node["ip"] in self.arp_relationships:
                    menu.add_command(label="Show ARP Relationships", 
                                   command=lambda: self.show_arp_details(node["ip"]))
                
                # Add threat intel options if available
                if "threat_score" in node and node["threat_score"] > 0:
                    menu.add_separator()
                    menu.add_command(label="Show Threat Details",
                                   command=lambda: self.show_threat_details(node["ip"]))
                    menu.add_command(label="Report False Positive",
                                   command=lambda: self.report_false_positive(node["ip"]))
                elif "ip" in node:
                    menu.add_separator()
                    menu.add_command(label="Check Threat Intelligence",
                                   command=lambda: self.check_threat_intel(node["ip"]))
                
                # Add other options
                menu.add_separator()
                menu.add_command(label="Center View on This Node", 
                               command=lambda: self.center_view_on_node(node_id))
                
                # Show menu at event position
                menu.post(event.x_root, event.y_root)
    
    def on_canvas_drag(self, event):
        """Handle dragging a node"""
        if self.selected_node:
            # Get canvas coordinates
            x = self.canvas.canvasx(event.x)
            y = self.canvas.canvasy(event.y)
            
            # Update node position
            if self.selected_node in self.nodes:
                self.nodes[self.selected_node]["x"] = x
                self.nodes[self.selected_node]["y"] = y
                self.redraw_network()
    
    def zoom_canvas(self, factor):
        """Zoom the canvas by scaling all items"""
        # Get canvas center
        center_x = self.canvas.winfo_width() / 2
        center_y = self.canvas.winfo_height() / 2
        
        # Scale everything from center
        self.canvas.scale("all", center_x, center_y, factor, factor)
        
        # Update scrollregion
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    
    def center_view_on_node(self, node_id):
        """Center the view on a specific node"""
        if node_id not in self.nodes:
            return
            
        node = self.nodes[node_id]
        x, y = node["x"], node["y"]
        
        # Get canvas dimensions
        canvas_width = self.canvas.winfo_width()
        canvas_height = self.canvas.winfo_height()
        
        # Calculate scroll position to center on node
        scroll_x = (x - canvas_width/2) / self.canvas.bbox("all")[2]
        scroll_y = (y - canvas_height/2) / self.canvas.bbox("all")[3]
        
        # Ensure scroll position is within bounds
        scroll_x = max(0, min(1, scroll_x))
        scroll_y = max(0, min(1, scroll_y))
        
        # Set scroll position
        self.canvas.xview_moveto(scroll_x)
        self.canvas.yview_moveto(scroll_y)
    
    def reset_canvas_view(self):
        """Reset view to show all content"""
        # Clear and redraw
        self.redraw_network()
        
        # Update scrollregion to show all content
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        
        # Reset view
        self.canvas.xview_moveto(0)
        self.canvas.yview_moveto(0)
    
    def refresh(self, ip_filter=None):
        """Refresh the network map with actual database queries"""
        # Clear existing data
        self.nodes = {}
        self.edges = []
        self.arp_relationships = {}
        self.gateways = []
        
        # Get network data from the database
        network_data = self.get_network_data()
        
        # Process the data to build topology
        if network_data:
            self.process_network_data(network_data)
        else:
            self.update_output("No network data available. Check database connection.")
        
        # Update statistics display
        self.update_statistics()
        
        # Redraw the network
        self.redraw_network()
        
        # Update the last refresh time
        self.last_refresh_time = time.time()
        
        self.update_output("Network map refreshed")

    
    def get_network_data(self):
        """Get required network data from the database, including TTL and ARP data"""
        try:
            # Get cursor from analysis_manager for analysis_1.db instead of db_manager for analysis.db
            cursor = gui.analysis_manager.get_cursor()
            
            # Get connections data with TTL values
            connections_query = """
                SELECT src_ip, dst_ip, src_port, dst_port, total_bytes, 
                    packet_count, protocol, ttl
                FROM connections
                ORDER BY total_bytes DESC
                LIMIT 1000
            """
            connections = cursor.execute(connections_query).fetchall()
            
            # Get ARP data for topology discovery
            arp_query = """
                SELECT src_ip, dst_ip, operation, timestamp
                FROM arp_data
                ORDER BY timestamp DESC
            """
            arp_data = cursor.execute(arp_query).fetchall()
            
            # Get DNS data for hostname resolution
            dns_query = """
                SELECT src_ip, query_domain
                FROM dns_queries
                WHERE timestamp > ?
                GROUP BY src_ip, query_domain
            """
            # Get DNS queries from the last 24 hours
            dns_data = cursor.execute(dns_query, (time.time() - 86400,)).fetchall()
            
            # Get HTTP data for service identification
            http_query = """
                SELECT connection_key, host
                FROM http_requests
                WHERE timestamp > ?
                GROUP BY connection_key, host
            """
            http_data = cursor.execute(http_query, (time.time() - 86400,)).fetchall()
            
            # Get threat intelligence data
            threat_intel_query = """
                SELECT ip_address, threat_score, threat_type, details, 
                    detection_method, protocol
                FROM x_ip_threat_intel
                WHERE threat_score > 0
            """
            try:
                threat_data = cursor.execute(threat_intel_query).fetchall()
            except Exception as e:
                self.update_output(f"Info: Threat intel not available: {e}")
                threat_data = []
            
            # Get geolocation data
            geo_query = """
                SELECT ip_address, country, region, city, 
                    latitude, longitude, asn_name
                FROM x_ip_geolocation
            """
            try:
                geo_data = cursor.execute(geo_query).fetchall()
            except Exception as e:
                self.update_output(f"Info: Geolocation data not available: {e}")
                geo_data = []
            
            # Get alerts related to network topology
            alerts_query = """
                SELECT ip_address, alert_message, rule_name, timestamp
                FROM x_alerts
                WHERE rule_name IN ('network_anomaly', 'network_topology')
                ORDER BY timestamp DESC
            """
            try:
                network_alerts = cursor.execute(alerts_query).fetchall()
            except Exception as e:
                self.update_output(f"Info: Alert data not available: {e}")
                network_alerts = []
            
            # Close the cursor
            cursor.close()
            
            return {
                "connections": connections,
                "arp_data": arp_data,
                "dns_data": dns_data,
                "http_data": http_data,
                "threat_data": threat_data,
                "geo_data": geo_data,
                "network_alerts": network_alerts
            }
        except Exception as e:
            self.update_output(f"Error fetching network data: {e}")
            return None
    
    def process_network_data(self, data):
        """Process network data including TTL and ARP to build accurate topology"""
        if not data:
            self.update_output("No network data available")
            return
        
        try:
            # Clear existing data
            self.nodes = {}
            self.edges = []
            self.arp_relationships = {}
            self.gateways = []
            
            # Reset statistics
            for stat in self.stats:
                self.stats[stat] = 0
            
            # Get network ranges
            local_ranges = self.get_local_network_ranges()
            
            # Process ARP data to build network relationships
            self.process_arp_data(data["arp_data"], local_ranges)
            
            # Identify gateways using TTL values and ARP patterns
            gateway_ips = self.identify_gateways_and_routers(
                data["connections"], 
                data["arp_data"],
                local_ranges
            )
            
            # Process geolocation data
            geo_lookup = {}
            if "geo_data" in data and data["geo_data"]:
                for geo_entry in data["geo_data"]:
                    if len(geo_entry) >= 3:
                        ip = geo_entry[0]
                        geo_lookup[ip] = {
                            "country": geo_entry[1],
                            "region": geo_entry[2],
                            "city": geo_entry[3] if len(geo_entry) > 3 else None,
                            "latitude": geo_entry[4] if len(geo_entry) > 4 else None,
                            "longitude": geo_entry[5] if len(geo_entry) > 5 else None,
                            "asn_name": geo_entry[6] if len(geo_entry) > 6 else None
                        }
            
            # Process threat intelligence data
            threat_lookup = {}
            if "threat_data" in data and data["threat_data"]:
                for threat_entry in data["threat_data"]:
                    if len(threat_entry) >= 3:
                        ip = threat_entry[0]
                        try:
                            details = json.loads(threat_entry[3]) if len(threat_entry) > 3 and threat_entry[3] else {}
                        except:
                            details = {}
                            
                        threat_lookup[ip] = {
                            "threat_score": threat_entry[1],
                            "threat_type": threat_entry[2],
                            "details": details,
                            "detection_method": threat_entry[4] if len(threat_entry) > 4 else None,
                            "protocol": threat_entry[5] if len(threat_entry) > 5 else None
                        }
                        
                        # Count threats for statistics
                        self.stats["threats"] += 1
            
            # Process connections to build topology
            self.build_network_topology(
                data["connections"], 
                data["dns_data"], 
                data["http_data"], 
                local_ranges, 
                gateway_ips,
                geo_lookup,
                threat_lookup
            )
            
            # Apply layout
            self.apply_hierarchical_layout()
            
            # Update statistics display
            self.update_statistics()
            
            # Draw the network
            self.redraw_network()
            
            self.update_output(f"Network map refreshed with {len(self.nodes)} devices and {len(self.edges)} connections")
        except Exception as e:
            self.update_output(f"Error processing network data: {e}")
            import traceback
            traceback.print_exc()

    def update_statistics(self):
        """Update the network statistics display"""
        # Count different node types
        self.stats = {
            "lan_devices": sum(1 for node in self.nodes.values() if node["type"] == "lan"),
            "wan_connections": sum(1 for edge in self.edges if edge.get("type") == "wan"),
            "gateways": sum(1 for node in self.nodes.values() if node["type"] in ["gateway", "border"]),
            "firewalls": sum(1 for node in self.nodes.values() if node["type"] == "firewall"),
            "servers": sum(1 for node in self.nodes.values() if node["type"] == "server"),
            "threats": sum(1 for node in self.nodes.values() if "threat_score" in node and node["threat_score"] > 50)
        }
        
        # Update the statistics labels if they exist
        if hasattr(self, 'stats_labels'):
            for stat_key, label in self.stats_labels.items():
                if stat_key in self.stats:
                    label.config(text=str(self.stats[stat_key]))

    def apply_hierarchical_layout(self):
        """Apply hierarchical layout like in the example image"""
        # Get canvas dimensions
        canvas_width = self.canvas.winfo_width() or 800
        canvas_height = self.canvas.winfo_height() or 600
        center_x = canvas_width / 2
        
        # Node spacing
        spacing = self.node_spacing.get()
        
        # Group nodes by type and parent
        node_groups = {
            "border": [],     # Border gateway
            "gateway": [],    # Additional gateways
            "firewall": [],   # Firewall
            "vpn": [],        # VPN tunnel
            "subnet": [],     # Subnet groups
            "lan": [],        # LAN devices not in subnets
            "server": [],     # Servers
            "cloud": []       # External/cloud
        }
        
        # Subnet children mapping
        subnet_children = {}
        
        for node_id, node in self.nodes.items():
            node_type = node["type"]
            
            # Special handling for subnets
            if node_type == "lan" and node_id.startswith("subnet_"):
                node_groups["subnet"].append(node_id)
                subnet_children[node_id] = []
            elif "parent" in node and node["parent"] in subnet_children:
                subnet_children[node["parent"]].append(node_id)
            elif node_type in node_groups:
                node_groups[node_type].append(node_id)
            else:
                node_groups["lan"].append(node_id)
        
        # Track current vertical position
        current_y = 60
        
        # 1. Place border gateway at top center
        border_id = None
        if node_groups["border"]:
            border_id = node_groups["border"][0]
            self.nodes[border_id]["x"] = center_x
            self.nodes[border_id]["y"] = current_y
        
        # 2. Place firewall below border
        firewall_y = None
        if node_groups["firewall"]:
            current_y += spacing
            firewall_id = node_groups["firewall"][0]
            self.nodes[firewall_id]["x"] = center_x
            self.nodes[firewall_id]["y"] = current_y
            firewall_y = current_y
        
        # 3. Place additional gateways to the sides of the border
        if node_groups["gateway"]:
            gateway_y = current_y
            gateway_count = len(node_groups["gateway"])
            gateway_width = gateway_count * spacing * 1.5
            gateway_start_x = center_x - gateway_width / 2 + spacing * 0.75
            
            for i, gateway_id in enumerate(node_groups["gateway"]):
                gateway_x = gateway_start_x + i * spacing * 1.5
                self.nodes[gateway_id]["x"] = gateway_x
                self.nodes[gateway_id]["y"] = gateway_y
        
        # 4. Place VPN tunnel to the right of firewall
        if node_groups["vpn"]:
            vpn_id = node_groups["vpn"][0]
            vpn_y = firewall_y if firewall_y else current_y
            self.nodes[vpn_id]["x"] = center_x + spacing * 2
            self.nodes[vpn_id]["y"] = vpn_y
        
        # 5. Place subnet nodes in a row
        current_y += spacing * 1.5
        subnet_count = len(node_groups["subnet"])
        if subnet_count > 0:
            subnet_width = subnet_count * spacing * 1.5
            subnet_start_x = center_x - subnet_width / 2 + spacing * 0.75
            
            for i, subnet_id in enumerate(node_groups["subnet"]):
                subnet_x = subnet_start_x + i * spacing * 1.5
                self.nodes[subnet_id]["x"] = subnet_x
                self.nodes[subnet_id]["y"] = current_y
                
                # Place subnet children in a cluster around the subnet
                self.place_subnet_children(subnet_id, subnet_children[subnet_id], subnet_x, current_y, spacing * 0.8)
        
        # 6. Place LAN devices in a row below
        current_y += spacing * 2
        lan_count = len(node_groups["lan"])
        if lan_count > 0:
            # Arrange in a balanced grid
            cols = min(max(int(math.sqrt(lan_count)), 1), 8)  # At most 8 columns
            rows = math.ceil(lan_count / cols)
            
            lan_width = cols * spacing * 1.5
            lan_start_x = center_x - lan_width / 2 + spacing * 0.75
            
            for i, node_id in enumerate(node_groups["lan"]):
                row = i // cols
                col = i % cols
                self.nodes[node_id]["x"] = lan_start_x + col * spacing * 1.5
                self.nodes[node_id]["y"] = current_y + row * spacing
        
        # 7. Place servers in a row below LAN devices
        current_y += (rows if lan_count > 0 else 0) * spacing + spacing * 1.5
        server_count = len(node_groups["server"])
        if server_count > 0:
            server_width = server_count * spacing * 1.5
            server_start_x = center_x - server_width / 2 + spacing * 0.75
            
            for i, node_id in enumerate(node_groups["server"]):
                self.nodes[node_id]["x"] = server_start_x + i * spacing * 1.5
                self.nodes[node_id]["y"] = current_y
        
        # 8. Place cloud/external nodes at the bottom
        current_y += spacing * 2
        cloud_count = len(node_groups["cloud"])
        if cloud_count > 0:
            # Use multiple rows if many cloud nodes
            cols = min(max(int(math.sqrt(cloud_count)), 1), 10)  # More columns for cloud
            rows = math.ceil(cloud_count / cols)
            
            cloud_width = cols * spacing * 1.2
            cloud_start_x = center_x - cloud_width / 2 + spacing * 0.6
            
            for i, node_id in enumerate(node_groups["cloud"]):
                row = i // cols
                col = i % cols
                self.nodes[node_id]["x"] = cloud_start_x + col * spacing * 1.2
                self.nodes[node_id]["y"] = current_y + row * spacing


    def place_subnet_children(self, subnet_id, children, subnet_x, subnet_y, radius):
        """Place children of a subnet in a cluster"""
        count = len(children)
        if count == 0:
            return
        
        # Place in a small circle around subnet
        angle_step = 2 * math.pi / count
        
        for i, node_id in enumerate(children):
            angle = i * angle_step
            self.nodes[node_id]["x"] = subnet_x + radius * math.cos(angle)
            self.nodes[node_id]["y"] = subnet_y + radius * math.sin(angle)

    def _position_subnet_children(self, subnet_id, children):
        """Position children of a subnet node in a nice arrangement"""
        if not children:
            return
            
        subnet = self.nodes[subnet_id]
        center_x, center_y = subnet["x"], subnet["y"]
        
        # Use a circle layout if fewer than 8 children
        if len(children) < 8:
            radius = max(self.node_spacing.get() * 0.7, 80)
            angle_step = 2 * math.pi / len(children)
            
            for i, child_id in enumerate(children):
                angle = i * angle_step
                self.nodes[child_id]["x"] = center_x + radius * math.cos(angle)
                self.nodes[child_id]["y"] = center_y + radius * math.sin(angle) + 50  # Offset to place below subnet node
        else:
            # Use a grid layout for many children
            rows = math.ceil(math.sqrt(len(children)))
            cols = math.ceil(len(children) / rows)
            
            # Calculate grid cell size
            cell_width = self.node_spacing.get() * 1.2
            cell_height = self.node_spacing.get() * 1.2
            
            # Calculate grid starting position (top-left corner)
            start_x = center_x - (cols * cell_width) / 2
            start_y = center_y + 50  # Offset to place below subnet node
            
            for i, child_id in enumerate(children):
                row = i // cols
                col = i % cols
                
                self.nodes[child_id]["x"] = start_x + col * cell_width + cell_width / 2
                self.nodes[child_id]["y"] = start_y + row * cell_height + cell_height / 2
    
    def _optimize_layout(self, iterations=10):
        """Apply force-directed layout to reduce overlapping with more effective forces"""
        # Minimum distance between nodes
        min_distance = self.node_radius * 2.5
        
        # Scale factor for repulsive forces (higher = stronger repulsion)
        repulsion_scale = 1.0
        
        # Scale for attractive forces (higher = stronger attraction)
        attraction_scale = 0.3
        
        for _ in range(iterations):
            # Calculate repulsive forces between all pairs of nodes
            movements = {node_id: {"dx": 0, "dy": 0} for node_id in self.nodes}
            
            # Apply repulsive forces
            for node1_id, node1 in self.nodes.items():
                for node2_id, node2 in self.nodes.items():
                    if node1_id == node2_id:
                        continue
                        
                    # Calculate distance and direction
                    dx = node1["x"] - node2["x"]
                    dy = node1["y"] - node2["y"]
                    distance = math.sqrt(dx*dx + dy*dy)
                    
                    # Apply stronger repulsion for closer nodes
                    if distance < min_distance:
                        # Inverse square repulsion
                        force = repulsion_scale * min_distance * min_distance / max(distance * distance, 0.1)
                        
                        # Normalize direction vector
                        if distance > 0:
                            dx = dx / distance
                            dy = dy / distance
                        else:
                            # Random direction if distance is zero
                            angle = random.uniform(0, 2 * math.pi)
                            dx = math.cos(angle)
                            dy = math.sin(angle)
                        
                        # Apply force
                        movements[node1_id]["dx"] += dx * force
                        movements[node1_id]["dy"] += dy * force
            
            # Apply attractive forces for connected nodes
            for edge in self.edges:
                if edge["source"] in self.nodes and edge["target"] in self.nodes:
                    source = self.nodes[edge["source"]]
                    target = self.nodes[edge["target"]]
                    
                    # Calculate distance and direction
                    dx = source["x"] - target["x"]
                    dy = source["y"] - target["y"]
                    distance = math.sqrt(dx*dx + dy*dy)
                    
                    # Only apply attraction if nodes are further apart than minimum distance
                    if distance > min_distance:
                        # Linear attraction
                        force = attraction_scale * (distance - min_distance) / 10
                        
                        # Normalize direction vector
                        if distance > 0:
                            dx = dx / distance
                            dy = dy / distance
                        else:
                            continue
                        
                        # Apply force (pull nodes toward each other)
                        movements[edge["source"]]["dx"] -= dx * force
                        movements[edge["source"]]["dy"] -= dy * force
                        movements[edge["target"]]["dx"] += dx * force
                        movements[edge["target"]]["dy"] += dy * force
            
            # Apply all calculated movements with damping
            damping = 0.8
            for node_id, move in movements.items():
                self.nodes[node_id]["x"] += move["dx"] * damping
                self.nodes[node_id]["y"] += move["dy"] * damping
            
            # Prevent nodes from moving outside canvas boundaries
            margin = self.node_radius * 2
            canvas_width = 2000  # Use larger virtual canvas
            canvas_height = 1500
            
            for node_id, node in self.nodes.items():
                node["x"] = max(margin, min(canvas_width - margin, node["x"]))
                node["y"] = max(margin, min(canvas_height - margin, node["y"]))


    def process_arp_data(self, arp_data, local_ranges):
        """Process ARP data to build network relationships"""
        if not arp_data:
            return
            
        # Track which IPs have ARP relationships
        for src_ip, dst_ip, operation, timestamp in arp_data:
            # Skip invalid data
            if not src_ip or not dst_ip:
                continue
                
            # Add to relationships dict
            if src_ip not in self.arp_relationships:
                self.arp_relationships[src_ip] = set()
                
            if dst_ip not in self.arp_relationships:
                self.arp_relationships[dst_ip] = set()
                
            # Add bidirectional relationship
            self.arp_relationships[src_ip].add(dst_ip)
            
            # For ARP replies (operation=2), add reverse relationship
            if operation == 2:
                self.arp_relationships[dst_ip].add(src_ip)
    
    def identify_gateways_and_routers(self, connections, arp_data, local_ranges):
        """Identify gateways using TTL values and ARP patterns"""
        # Gateway/router candidates
        gateway_candidates = {}
        
        # Check TTL values to identify likely routers
        # Typical default TTL values:
        # - Windows: 128
        # - Linux/Unix: 64
        # - Cisco routers: 255
        for conn in connections:
            if len(conn) < 8:
                continue  # Skip if TTL isn't included
                
            src_ip, dst_ip, _, _, _, _, _, ttl = conn
            
            # Skip invalid data
            if not src_ip or not dst_ip or ttl is None:
                continue
                
            # Check if source is local and destination is external
            src_is_local = self.is_local_ip(src_ip, local_ranges)
            dst_is_local = self.is_local_ip(dst_ip, local_ranges)
            
            if src_is_local and not dst_is_local:
                # Look for decremented TTL values that suggest a router
                # Typically routers decrement TTL by 1
                if ttl in [63, 127, 254]:  # One less than typical defaults
                    if src_ip not in gateway_candidates:
                        gateway_candidates[src_ip] = 0
                    gateway_candidates[src_ip] += 3  # Higher weight for TTL evidence
        
        # Analyze ARP data for gateway patterns
        if arp_data:
            arp_request_counts = {}  # Track how many ARP requests each IP receives
            
            for src_ip, dst_ip, operation, _ in arp_data:
                if not src_ip or not dst_ip:
                    continue
                    
                # Count ARP requests (operation=1)
                if operation == 1:
                    if dst_ip not in arp_request_counts:
                        arp_request_counts[dst_ip] = 0
                    arp_request_counts[dst_ip] += 1
            
            # IPs with many ARP requests are likely gateways
            for ip, count in arp_request_counts.items():
                if count >= 3:  # Threshold for considering a gateway
                    if ip not in gateway_candidates:
                        gateway_candidates[ip] = 0
                    gateway_candidates[ip] += count  # Weight by request count
        
        # Check for typical gateway addresses in each subnet
        for network in local_ranges:
            if network.version == 4:
                # First IP in subnet (typically .1)
                first_ip = str(network.network_address + 1)
                if first_ip in self.arp_relationships:
                    if first_ip not in gateway_candidates:
                        gateway_candidates[first_ip] = 0
                    gateway_candidates[first_ip] += 5  # High weight for .1 addresses
                
                # Last IP in subnet (typically .254)
                last_ip = str(network.broadcast_address - 1)
                if last_ip in self.arp_relationships:
                    if last_ip not in gateway_candidates:
                        gateway_candidates[last_ip] = 0
                    gateway_candidates[last_ip] += 3  # Medium weight for .254 addresses
        
        # Sort candidates by score
        gateway_ips = sorted(gateway_candidates.items(), key=lambda x: x[1], reverse=True)
        
        # Keep only the top candidates (limit to 3 gateways unless there's a clear winner)
        if gateway_ips:
            top_score = gateway_ips[0][1]
            clear_winners = [ip for ip, score in gateway_ips if score > top_score * 0.7]
            
            if len(clear_winners) <= 3:
                result = clear_winners
            else:
                result = [ip for ip, _ in gateway_ips[:3]]
                
            # Store the gateway IPs
            self.gateways = result
            
            self.update_output(f"Identified gateways: {', '.join(result)}")
            return result
        
        # If no gateways found, return empty list
        return []
    
    def get_local_network_ranges(self):
        """Determine local network address ranges"""
        local_ranges = []
        
        # Add common private IP ranges
        local_ranges.append(ipaddress.ip_network("10.0.0.0/8"))
        local_ranges.append(ipaddress.ip_network("172.16.0.0/12"))
        local_ranges.append(ipaddress.ip_network("192.168.0.0/16"))
        local_ranges.append(ipaddress.ip_network("127.0.0.0/8"))  # Localhost
        
        # Try to get interface IPs from GUI
        try:
            if hasattr(gui, 'capture_engine') and gui.capture_engine:
                for interface_info in gui.capture_engine.get_interfaces():
                    if len(interface_info) >= 3:
                        ip_addr = interface_info[2]
                        if ip_addr and ip_addr != "Unknown":
                            try:
                                # Create a subnet from interface IP
                                ip_obj = ipaddress.ip_address(ip_addr)
                                if ip_obj.version == 4:
                                    subnet_parts = ip_addr.split('.')
                                    if len(subnet_parts) == 4:
                                        subnet = f"{subnet_parts[0]}.{subnet_parts[1]}.{subnet_parts[2]}.0/24"
                                        local_ranges.append(ipaddress.ip_network(subnet, strict=False))
                            except ValueError:
                                pass
        except Exception as e:
            self.update_output(f"Warning: Could not determine local networks from interfaces: {e}")
        
        return local_ranges
    
    def is_local_ip(self, ip, local_ranges):
        """Check if an IP is in local ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return any(ip_obj in network for network in local_ranges)
        except ValueError:
            return False
    
    def build_network_topology(self, connections, dns_data, http_data, local_ranges, gateway_ips, 
                              geo_lookup=None, threat_lookup=None):
        """Build network topology using connections, TTL, and ARP data"""
        # Create hostname mappings
        hostname_map = {}
        for conn_key, hostname in http_data:
            parts = conn_key.split('->')
            if len(parts) == 2:
                ip = parts[1].split(':')[0]
                hostname_map[ip] = hostname
        
        # Process DNS data for IP to domain mapping
        dns_map = {}
        for src_ip, domain in dns_data:
            if domain:
                if src_ip not in dns_map:
                    dns_map[src_ip] = []
                if domain not in dns_map[src_ip]:
                    dns_map[src_ip].append(domain)
        
        # Find subnet groups if enabled
        subnet_groups = {}
        if self.group_by_subnet.get():
            for conn in connections:
                src_ip, dst_ip = conn[0], conn[1]
                
                # Skip invalid IPs
                if not src_ip or not dst_ip:
                    continue
                
                # Group local IPs by subnet
                for ip in [src_ip, dst_ip]:
                    if self.is_local_ip(ip, local_ranges) and ip not in gateway_ips:
                        try:
                            parts = ip.split('.')
                            if len(parts) == 4:
                                subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"
                                if subnet not in subnet_groups:
                                    subnet_groups[subnet] = []
                                if ip not in subnet_groups[subnet]:
                                    subnet_groups[subnet].append(ip)
                        except Exception:
                            pass
        
        # Create border gateway node - boundary between internal and external
        if gateway_ips:
            # Use the first gateway as the primary border gateway
            border_gateway = gateway_ips[0]
            
            self.nodes[border_gateway] = {
                "id": border_gateway,
                "type": "border",
                "ip": border_gateway,
                "name": "Border Gateway",
                "ttl": self.get_ttl_for_ip(connections, border_gateway),
                "x": 0,
                "y": 0
            }
            
            # Add geo data if available
            if geo_lookup and border_gateway in geo_lookup:
                self.nodes[border_gateway]["geo_data"] = geo_lookup[border_gateway]
            
            # Add threat data if available
            if threat_lookup and border_gateway in threat_lookup:
                self.nodes[border_gateway]["threat_score"] = threat_lookup[border_gateway]["threat_score"]
                self.nodes[border_gateway]["threat_type"] = threat_lookup[border_gateway]["threat_type"]
                self.nodes[border_gateway]["threat_details"] = threat_lookup[border_gateway]["details"]
            
            # Add other gateways if any
            for i, gateway in enumerate(gateway_ips[1:]):
                gateway_type = "gateway" if i == 0 else "gateway"
                self.nodes[gateway] = {
                    "id": gateway,
                    "type": gateway_type,
                    "ip": gateway,
                    "name": f"Gateway Router {i+1}",
                    "ttl": self.get_ttl_for_ip(connections, gateway),
                    "x": 0,
                    "y": 0
                }
                
                # Add geo data if available
                if geo_lookup and gateway in geo_lookup:
                    self.nodes[gateway]["geo_data"] = geo_lookup[gateway]
                
                # Add threat data if available
                if threat_lookup and gateway in threat_lookup:
                    self.nodes[gateway]["threat_score"] = threat_lookup[gateway]["threat_score"]
                    self.nodes[gateway]["threat_type"] = threat_lookup[gateway]["threat_type"]
                    self.nodes[gateway]["threat_details"] = threat_lookup[gateway]["details"]
                
                # Connect additional gateways to the border gateway
                self.edges.append({
                    "source": border_gateway,
                    "target": gateway,
                    "type": "network",
                    "is_gateway": True
                })
        else:
            # Create placeholder gateway if none detected
            self.nodes["border_gateway"] = {
                "id": "border_gateway",
                "type": "border",
                "name": "Border Gateway",
                "x": 0,
                "y": 0
            }
            border_gateway = "border_gateway"
        
        # Create subnet nodes
        if subnet_groups:
            for subnet, ips in subnet_groups.items():
                subnet_node_id = f"subnet_{subnet}"
                self.nodes[subnet_node_id] = {
                    "id": subnet_node_id,
                    "type": "lan",
                    "name": f"Network {subnet}.0/24",
                    "subnet": subnet,
                    "x": 0,
                    "y": 0
                }
                
                # Connect subnet to appropriate gateway
                # Find most appropriate gateway for this subnet
                subnet_gateway = self.find_subnet_gateway(subnet, gateway_ips, ips)
                if subnet_gateway:
                    self.edges.append({
                        "source": subnet_gateway,
                        "target": subnet_node_id,
                        "type": "network"
                    })
                else:
                    # Connect to border gateway if no specific gateway found
                    self.edges.append({
                        "source": border_gateway,
                        "target": subnet_node_id,
                        "type": "network"
                    })
        
        # Process firewall detection
        firewall_detected = False
        for conn in connections:
            if len(conn) < 7:
                continue
                
            src_ip, dst_ip, src_port, dst_port = conn[0], conn[1], conn[2], conn[3]
            
            # Look for common firewall evidence
            if src_port and dst_port:
                if dst_port in [80, 443] and self.is_local_ip(src_ip, local_ranges) and not self.is_local_ip(dst_ip, local_ranges):
                    firewall_detected = True
                    break
        
        # Add firewall node if detected
        if firewall_detected:
            self.nodes["firewall"] = {
                "id": "firewall",
                "type": "firewall",
                "name": "Firewall",
                "x": 0,
                "y": 0
            }
            
            # Connect firewall to border gateway
            self.edges.append({
                "source": border_gateway,
                "target": "firewall",
                "type": "network",
                "is_gateway": True
            })
        
        # Add VPN detection
        vpn_detected = False
        for conn in connections:
            if len(conn) < 4:
                continue
                
            src_ip, dst_ip, src_port, dst_port = conn[0], conn[1], conn[2], conn[3]
            
            # Look for VPN port usage
            if dst_port in [1194, 1723, 500, 4500]:
                vpn_detected = True
                
                # Add VPN tunnel node
                self.nodes["vpn_tunnel"] = {
                    "id": "vpn_tunnel",
                    "type": "vpn",
                    "name": "VPN Tunnel",
                    "x": 0,
                    "y": 0
                }
                
                # Connect to firewall if detected, otherwise border gateway
                vpn_source = "firewall" if "firewall" in self.nodes else border_gateway
                self.edges.append({
                    "source": vpn_source,
                    "target": "vpn_tunnel",
                    "type": "vpn"
                })
                
                break
        
        # Now add individual devices
        for conn in connections:
            if len(conn) < 7:
                continue
                
            src_ip, dst_ip, src_port, dst_port = conn[0], conn[1], conn[2], conn[3]
            
            # Skip invalid IPs
            if not src_ip or not dst_ip:
                continue
                
            src_is_local = self.is_local_ip(src_ip, local_ranges)
            dst_is_local = self.is_local_ip(dst_ip, local_ranges)
            
            # Skip non-local traffic if not showing external
            if not self.show_external.get() and not (src_is_local or dst_is_local):
                continue
                
            # Skip gateway IPs - already added
            if src_ip in gateway_ips or dst_ip in gateway_ips:
                continue
            
            # Process source node
            if src_ip not in self.nodes:
                # Check if it belongs to a subnet group
                src_subnet = None
                if self.group_by_subnet.get():
                    try:
                        parts = src_ip.split('.')
                        if len(parts) == 4:
                            src_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"
                    except:
                        pass
                
                if src_is_local and src_subnet and f"subnet_{src_subnet}" in self.nodes:
                    # Add to existing subnet
                    node_type = "server" if self.is_likely_server(src_ip, src_port, dns_map) else "lan"
                    
                    self.nodes[src_ip] = {
                        "id": src_ip,
                        "type": node_type,
                        "ip": src_ip,
                        "name": self.get_device_name(src_ip, hostname_map, dns_map),
                        "ttl": self.get_ttl_for_ip(connections, src_ip),
                        "parent": f"subnet_{src_subnet}",
                        "x": 0,
                        "y": 0
                    }
                    
                    # Add geo data if available
                    if geo_lookup and src_ip in geo_lookup:
                        self.nodes[src_ip]["geo_data"] = geo_lookup[src_ip]
                    
                    # Add threat data if available
                    if threat_lookup and src_ip in threat_lookup:
                        self.nodes[src_ip]["threat_score"] = threat_lookup[src_ip]["threat_score"]
                        self.nodes[src_ip]["threat_type"] = threat_lookup[src_ip]["threat_type"]
                        self.nodes[src_ip]["threat_details"] = threat_lookup[src_ip]["details"]
                    
                    # Connect to subnet
                    self.edges.append({
                        "source": f"subnet_{src_subnet}",
                        "target": src_ip,
                        "type": "lan"
                    })
                else:
                    # Add as standalone node
                    node_type = "lan" if src_is_local else "cloud"
                    
                    # Determine server type based on ports
                    if src_is_local and src_port:
                        if src_port in [80, 443, 25, 21, 22, 3306, 5432] or self.is_likely_server(src_ip, src_port, dns_map):
                            node_type = "server"
                    
                    self.nodes[src_ip] = {
                        "id": src_ip,
                        "type": node_type,
                        "ip": src_ip,
                        "name": self.get_device_name(src_ip, hostname_map, dns_map),
                        "ttl": self.get_ttl_for_ip(connections, src_ip),
                        "x": 0,
                        "y": 0
                    }
                    
                    # Add geo data if available
                    if geo_lookup and src_ip in geo_lookup:
                        self.nodes[src_ip]["geo_data"] = geo_lookup[src_ip]
                    
                    # Add threat data if available
                    if threat_lookup and src_ip in threat_lookup:
                        self.nodes[src_ip]["threat_score"] = threat_lookup[src_ip]["threat_score"]
                        self.nodes[src_ip]["threat_type"] = threat_lookup[src_ip]["threat_type"]
                        self.nodes[src_ip]["threat_details"] = threat_lookup[src_ip]["details"]
                    
                    # Connect to appropriate parent
                    if src_is_local:
                        if "firewall" in self.nodes:
                            self.edges.append({
                                "source": "firewall",
                                "target": src_ip,
                                "type": "network"
                            })
                        else:
                            # Find most appropriate gateway
                            gateway = self.find_best_gateway_for_ip(src_ip, gateway_ips)
                            self.edges.append({
                                "source": gateway if gateway else border_gateway,
                                "target": src_ip,
                                "type": "network"
                            })
            
            # Process destination node
            if dst_ip not in self.nodes:
                # Check if it belongs to a subnet group
                dst_subnet = None
                if self.group_by_subnet.get():
                    try:
                        parts = dst_ip.split('.')
                        if len(parts) == 4:
                            dst_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"
                    except:
                        pass
                
                if dst_is_local and dst_subnet and f"subnet_{dst_subnet}" in self.nodes:
                    # Add to existing subnet
                    node_type = "server" if self.is_likely_server(dst_ip, dst_port, dns_map) else "lan"
                    
                    self.nodes[dst_ip] = {
                        "id": dst_ip,
                        "type": node_type,
                        "ip": dst_ip,
                        "name": self.get_device_name(dst_ip, hostname_map, dns_map),
                        "ttl": self.get_ttl_for_ip(connections, dst_ip),
                        "parent": f"subnet_{dst_subnet}",
                        "x": 0,
                        "y": 0
                    }
                    
                    # Add geo data if available
                    if geo_lookup and dst_ip in geo_lookup:
                        self.nodes[dst_ip]["geo_data"] = geo_lookup[dst_ip]
                    
                    # Add threat data if available
                    if threat_lookup and dst_ip in threat_lookup:
                        self.nodes[dst_ip]["threat_score"] = threat_lookup[dst_ip]["threat_score"]
                        self.nodes[dst_ip]["threat_type"] = threat_lookup[dst_ip]["threat_type"]
                        self.nodes[dst_ip]["threat_details"] = threat_lookup[dst_ip]["details"]
                    
                    # Connect to subnet
                    self.edges.append({
                        "source": f"subnet_{dst_subnet}",
                        "target": dst_ip,
                        "type": "lan"
                    })
                else:
                    # Add as standalone node
                    node_type = "lan" if dst_is_local else "cloud"
                    
                    # Determine server type based on ports
                    if dst_port:
                        if dst_port in [80, 443, 25, 21, 22, 3306, 5432] or self.is_likely_server(dst_ip, dst_port, dns_map):
                            node_type = "server"
                    
                    # Mark as threat if it's in the threat_lookup
                    if threat_lookup and dst_ip in threat_lookup and threat_lookup[dst_ip]["threat_score"] > 70:
                        node_type = "threat" if not dst_is_local else node_type
                    
                    self.nodes[dst_ip] = {
                        "id": dst_ip,
                        "type": node_type,
                        "ip": dst_ip,
                        "name": self.get_device_name(dst_ip, hostname_map, dns_map),
                        "ttl": self.get_ttl_for_ip(connections, dst_ip),
                        "x": 0,
                        "y": 0
                    }
                    
                    # Add geo data if available
                    if geo_lookup and dst_ip in geo_lookup:
                        self.nodes[dst_ip]["geo_data"] = geo_lookup[dst_ip]
                    
                    # Add threat data if available
                    if threat_lookup and dst_ip in threat_lookup:
                        self.nodes[dst_ip]["threat_score"] = threat_lookup[dst_ip]["threat_score"]
                        self.nodes[dst_ip]["threat_type"] = threat_lookup[dst_ip]["threat_type"]
                        self.nodes[dst_ip]["threat_details"] = threat_lookup[dst_ip]["details"]
                    
                    # Connect external nodes to VPN if applicable
                    if not dst_is_local and "vpn_tunnel" in self.nodes:
                        if threat_lookup and dst_ip in threat_lookup and threat_lookup[dst_ip]["threat_score"] > 50:
                            # Always connect high-risk nodes through the VPN node for visual clarity
                            self.edges.append({
                                "source": "vpn_tunnel",
                                "target": dst_ip,
                                "type": "vpn"
                            })
                            continue
                        elif random.random() < 0.3:  # Only connect some external nodes to VPN
                            self.edges.append({
                                "source": "vpn_tunnel",
                                "target": dst_ip,
                                "type": "vpn"
                            })
                            continue
                    
                    # Connect to appropriate parent
                    if dst_is_local:
                        if "firewall" in self.nodes:
                            self.edges.append({
                                "source": "firewall",
                                "target": dst_ip,
                                "type": "network"
                            })
                        else:
                            # Find most appropriate gateway
                            gateway = self.find_best_gateway_for_ip(dst_ip, gateway_ips)
                            self.edges.append({
                                "source": gateway if gateway else border_gateway,
                                "target": dst_ip,
                                "type": "network"
                            })
                    else:
                        # External connections go through firewall if present
                        if "firewall" in self.nodes:
                            self.edges.append({
                                "source": "firewall",
                                "target": dst_ip,
                                "type": "wan"
                            })
                        else:
                            self.edges.append({
                                "source": border_gateway,
                                "target": dst_ip,
                                "type": "wan"
                            })
        
        # Add ARP-based connections for better accuracy within subnets
        for ip, related_ips in self.arp_relationships.items():
            if ip in self.nodes:
                for related_ip in related_ips:
                    if related_ip in self.nodes:
                        # Don't add duplicate edges
                        if not any((e["source"] == ip and e["target"] == related_ip) or 
                                  (e["source"] == related_ip and e["target"] == ip) for e in self.edges):
                            # Only connect within same subnet
                            if self.is_same_subnet(ip, related_ip):
                                self.edges.append({
                                    "source": ip,
                                    "target": related_ip,
                                    "type": "arp",
                                })
    
    def is_likely_server(self, ip, port, dns_map):
        """Check if an IP is likely a server based on port and DNS data"""
        # Check common server ports
        if port in [80, 443, 21, 22, 25, 3306, 5432, 8080, 8443, 27017]:
            return True
            
        # Check if it has DNS entries pointing to it
        for src_ip, domains in dns_map.items():
            for domain in domains:
                if domain and ('server' in domain.lower() or 
                              'service' in domain.lower() or 
                              'api' in domain.lower()):
                    return True
        
        return False
    
    def get_ttl_for_ip(self, connections, ip):
        """Get the TTL value for an IP from connections data"""
        for conn in connections:
            if len(conn) < 8:  # Make sure there's TTL data
                continue
                
            src_ip, _, _, _, _, _, _, ttl = conn
            if src_ip == ip and ttl is not None:
                return ttl
        return None
    
    def find_subnet_gateway(self, subnet, gateway_ips, subnet_ips):
        """Find the most appropriate gateway for a subnet"""
        # Check if any gateway IPs are in this subnet
        for gateway in gateway_ips:
            try:
                parts = gateway.split('.')
                if len(parts) == 4:
                    gateway_subnet = f"{parts[0]}.{parts[1]}.{parts[2]}"
                    if gateway_subnet == subnet:
                        return gateway
            except:
                continue
                
        # Check if any gateway has ARP relationships with subnet IPs
        for gateway in gateway_ips:
            if gateway in self.arp_relationships:
                for subnet_ip in subnet_ips:
                    if subnet_ip in self.arp_relationships[gateway]:
                        return gateway
                        
        # If no specific gateway found, return the first (main) gateway
        return gateway_ips[0] if gateway_ips else None
    
    def find_best_gateway_for_ip(self, ip, gateway_ips):
        """Find the most appropriate gateway for an IP based on ARP relationships"""
        if not gateway_ips:
            return None
            
        # Check direct ARP relationships first
        for gateway in gateway_ips:
            if gateway in self.arp_relationships and ip in self.arp_relationships[gateway]:
                return gateway
                
        # Check subnet match
        try:
            ip_parts = ip.split('.')
            if len(ip_parts) == 4:
                ip_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}"
                
                for gateway in gateway_ips:
                    gateway_parts = gateway.split('.')
                    if len(gateway_parts) == 4:
                        gateway_subnet = f"{gateway_parts[0]}.{gateway_parts[1]}.{gateway_parts[2]}"
                        if gateway_subnet == ip_subnet:
                            return gateway
        except:
            pass
            
        # Default to first gateway
        return gateway_ips[0]
    
    def is_same_subnet(self, ip1, ip2):
        """Check if two IPs are in the same subnet (based on first 3 octets)"""
        try:
            ip1_parts = ip1.split('.')
            ip2_parts = ip2.split('.')
            
            if len(ip1_parts) == 4 and len(ip2_parts) == 4:
                return ip1_parts[0] == ip2_parts[0] and \
                       ip1_parts[1] == ip2_parts[1] and \
                       ip1_parts[2] == ip2_parts[2]
        except:
            pass
            
        return False
    
    def get_device_name(self, ip, hostname_map, dns_map):
        """Get a friendly name for a device using hostname data and ports"""
        # First check for hostname from HTTP
        if ip in hostname_map:
            return hostname_map[ip]
        
        # Then check DNS data
        if ip in dns_map and dns_map[ip]:
            # Use first part of first domain name
            domain_parts = dns_map[ip][0].split('.')
            if domain_parts:
                return domain_parts[0]
        
        # Check if this is a gateway
        if ip in self.gateways:
            return f"Gateway {ip}"
        
        # Use IP with subnet context
        try:
            parts = ip.split('.')
            if len(parts) == 4:
                # Identify special IPs by last octet
                last_octet = int(parts[3])
                if last_octet == 1:
                    return f"Router {ip}"
                elif last_octet == 2:
                    return f"DNS {ip}"
                elif last_octet in [100, 200, 254]:
                    return f"Server {ip}"
                else:
                    return f"Host {ip}"
        except:
            pass
            
        return f"Device {ip}"
    
    def draw_node(self, node):
        """Draw a node on the canvas with improved visuals"""
        node_type = node["type"]
        x, y = node["x"], node["y"]
        radius = self.node_radius
        
        # Special size adjustments
        if node_type in ["border", "gateway"]:
            radius = radius * 1.2
        elif node_type == "firewall":
            radius = radius * 1.1
        elif node_type == "subnet":
            radius = radius * 1.3
        
        # Get color
        color = self.colors.get(node_type, self.colors["lan"])
        
        # If selected, use selected color
        if node["id"] == self.selected_node:
            color = self.colors["selected"]
                
        # If the node has a high threat score, override with threat color
        if "threat_score" in node and node["threat_score"] > 70:
            color = self.colors["threat"]
        elif "threat_score" in node and node["threat_score"] > 30:
            color = self.colors["warning"]
        
        # Draw main shape (specific shapes for different types)
        if node_type == "firewall":
            # Firewall shape (rectangle)
            item_id = self.canvas.create_rectangle(
                x - radius, y - radius * 0.8,
                x + radius, y + radius * 0.8,
                fill=color, outline="black", width=2
            )
        elif node_type == "subnet":
            # Subnet shape (rounded rectangle)
            item_id = self.canvas.create_rectangle(
                x - radius * 1.2, y - radius * 0.6,
                x + radius * 1.2, y + radius * 0.6,
                fill=color, outline="black", width=2,
                tags="subnet"
            )
        elif node_type == "cloud":
            # Cloud shape (oval)
            item_id = self.canvas.create_oval(
                x - radius * 1.2, y - radius * 0.7,
                x + radius * 1.2, y + radius * 0.7,
                fill=color, outline="black", width=2
            )
        else:
            # Regular nodes (circle)
            item_id = self.canvas.create_oval(
                x - radius, y - radius,
                x + radius, y + radius,
                fill=color, outline="black", width=2
            )
        
        # Store the node id in our mapping
        self.canvas_items[item_id] = node["id"]
        
        # Add label
        label = node.get("name", node["id"])
        if node_type == "subnet":
            # For subnets, put label inside
            self.canvas.create_text(
                x, y,
                text=label,
                font=("TkDefaultFont", 8),
                fill="black"
            )
        else:
            # For other nodes, put label below
            self.canvas.create_text(
                x, y + radius + 10,
                text=label,
                font=("TkDefaultFont", 8),
                fill="black"
            )
        
        # Add ASN group label for external nodes
        if node_type == "cloud" and "asn_group" in node:
            self.canvas.create_text(
                x, y - radius - 25,
                text=node["asn_group"],
                font=("TkDefaultFont", 7, "bold"),
                fill="darkblue"
            )
        
        # Add threat indicator if available and enabled
        if self.show_threat_intel.get() and "threat_score" in node and node["threat_score"] > 0:
            threat_color = "red" if node["threat_score"] > 70 else "orange"
            threat_text = f"Risk: {int(node['threat_score'])}%"
            
            # Draw threat score as small text above the node
            self.canvas.create_text(
                x, y - radius - 15,
                text=threat_text,
                font=("TkDefaultFont", 7, "bold"),
                fill=threat_color
            )
            
            # Add an exclamation mark inside high-risk nodes
            if node["threat_score"] > 70:
                self.canvas.create_text(
                    x, y,
                    text="!",
                    font=("TkDefaultFont", 14, "bold"),
                    fill="white"
                )
        
        # Add geo information if available and enabled
        if self.show_service_labels.get() and "geo_data" in node and node["geo_data"].get("country"):
            # Format the geolocation display
            geo_display = []
            if node["geo_data"].get("country"):
                geo_display.append(node["geo_data"]["country"])
            if node["geo_data"].get("city"):
                geo_display.append(node["geo_data"]["city"])
            
            if geo_display:
                self.canvas.create_text(
                    x, y - radius - 25,
                    text="/".join(geo_display),
                    font=("TkDefaultFont", 7),
                    fill="darkblue"
                )
        
        # Add IP address for some nodes (if showing service labels)
        if self.show_service_labels.get() and "ip" in node and node_type not in ["gateway", "firewall", "vpn", "subnet"]:
            ip_text = node["ip"]
            if "ttl" in node and node["ttl"] is not None:
                ip_text += f" (TTL: {node['ttl']})"
                
            self.canvas.create_text(
                x, y - radius - 10,
                text=ip_text,
                font=("TkDefaultFont", 7),
                fill="gray"
            )
        
        # Add icon or text indicator to help identify the node type
        if node_type == "border":
            self.canvas.create_text(x, y, text="B", font=("TkDefaultFont", 12, "bold"), fill="white")
        elif node_type == "gateway":
            self.canvas.create_text(x, y, text="G", font=("TkDefaultFont", 12, "bold"), fill="white")
        elif node_type == "firewall":
            self.canvas.create_text(x, y, text="FW", font=("TkDefaultFont", 10, "bold"), fill="white")
        elif node_type == "vpn":
            self.canvas.create_text(x, y, text="VPN", font=("TkDefaultFont", 9, "bold"), fill="white")
        elif node_type == "server":
            self.canvas.create_text(x, y, text="S", font=("TkDefaultFont", 10, "bold"), fill="white")
        elif node_type == "threat" and not "threat_score" in node:
            self.canvas.create_text(x, y, text="!", font=("TkDefaultFont", 12, "bold"), fill="white")

    def select_node(self, node_id):
        """Select a node and display its details"""
        self.selected_node = node_id
        self.details_text.delete(1.0, tk.END)
        
        if node_id and node_id in self.nodes:
            node = self.nodes[node_id]
            
            # Build details text
            details = f"Type: {node['type'].capitalize()}\n"
            details += f"Name: {node.get('name', 'Unknown')}\n"
            
            if "ip" in node:
                details += f"IP Address: {node['ip']}\n"
                
                # Show TTL if available
                if "ttl" in node and node["ttl"] is not None:
                    details += f"TTL: {node['ttl']}\n"
                
                # Show ARP relationships if any
                if node["ip"] in self.arp_relationships:
                    arp_count = len(self.arp_relationships[node["ip"]])
                    details += f"ARP relationships: {arp_count}\n"
                    
                # Show geolocation if available
                if "geo_data" in node and node["geo_data"]:
                    geo = node["geo_data"]
                    geo_details = []
                    if geo.get("country"):
                        geo_details.append(f"Country: {geo['country']}")
                    if geo.get("region") and geo.get("city"):
                        geo_details.append(f"Location: {geo['city']}, {geo['region']}")
                    elif geo.get("city"):
                        geo_details.append(f"City: {geo['city']}")
                    if geo.get("asn_name"):
                        geo_details.append(f"Network: {geo['asn_name']}")
                    
                    if geo_details:
                        details += "\nGeolocation:\n"
                        details += "\n".join(f"  {item}" for item in geo_details)
                
                # Show threat intel if available
                if "threat_score" in node and node["threat_score"] > 0:
                    details += f"\nThreat Score: {node['threat_score']}%\n"
                    if "threat_type" in node and node["threat_type"]:
                        details += f"Threat Type: {node['threat_type']}\n"
                    
                    if "threat_details" in node and node["threat_details"]:
                        details += "Threat Details:\n"
                        for key, value in node["threat_details"].items():
                            if isinstance(value, dict):
                                details += f"  {key}:\n"
                                for k, v in value.items():
                                    details += f"    {k}: {v}\n"
                            else:
                                details += f"  {key}: {value}\n"
            
            # Count connections
            incoming = []
            outgoing = []
            
            for edge in self.edges:
                if edge["source"] == node_id and edge["target"] in self.nodes:
                    target = self.nodes[edge["target"]]
                    outgoing.append(f"{target.get('name', target['id'])} ({edge.get('type', 'network')})")
                elif edge["target"] == node_id and edge["source"] in self.nodes:
                    source = self.nodes[edge["source"]]
                    incoming.append(f"{source.get('name', source['id'])} ({edge.get('type', 'network')})")
            
            if incoming:
                details += f"\nIncoming connections from ({len(incoming)}):\n"
                details += ", ".join(incoming[:5])
                if len(incoming) > 5:
                    details += f", ... and {len(incoming) - 5} more"
            
            if outgoing:
                details += f"\n\nOutgoing connections to ({len(outgoing)}):\n"
                details += ", ".join(outgoing[:5])
                if len(outgoing) > 5:
                    details += f", ... and {len(outgoing) - 5} more"
            
            self.details_text.insert(tk.END, details)
        
        # Redraw to update selection
        self.redraw_network()
    
    def show_threat_details(self, ip_address):
        """Show detailed threat information for an IP address"""
        if not hasattr(gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        # Create dialog
        dialog = tk.Toplevel(self.tab_frame)
        dialog.title(f"Threat Details: {ip_address}")
        dialog.geometry("600x400")
        dialog.transient(self.tab_frame)
        dialog.grab_set()
        
        # Add header
        ttk.Label(dialog, text=f"Threat Intelligence Data for {ip_address}", 
                font=("TkDefaultFont", 11, "bold")).pack(pady=10)
        
        # Create content frame
        content_frame = ttk.Frame(dialog)
        content_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create scrollable text widget
        text_widget = tk.Text(content_frame, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(content_frame, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side="right", fill="y")
        text_widget.pack(side="left", fill="both", expand=True)
        
        # Insert loading message
        text_widget.insert(tk.END, "Loading threat intelligence data...")
        
        # Queue the threat intel lookup using analysis_manager
        gui.analysis_manager.queue_query(
            lambda: self._get_detailed_threat_intel(ip_address),
            lambda data: self._display_threat_intel(text_widget, ip_address, data)
        )
        
        # Add buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", pady=10)
        
        ttk.Button(btn_frame, text="Report False Positive", 
                  command=lambda: self.report_false_positive(ip_address, dialog)).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Close", 
                  command=dialog.destroy).pack(side="right", padx=10)
    
    def _get_detailed_threat_intel(self, ip_address):
        """Get detailed threat intelligence data for an IP from analysis_1.db"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            
            # Get threat intel data
            cursor.execute("""
                SELECT threat_score, threat_type, confidence, source, 
                       details, detection_method, protocol, 
                       first_seen, last_seen, alert_count,
                       destination_ip, destination_port
                FROM x_ip_threat_intel
                WHERE ip_address = ?
            """, (ip_address,))
            
            threat_data = cursor.fetchone()
            
            # Get related alerts
            cursor.execute("""
                SELECT alert_message, rule_name, timestamp
                FROM x_alerts
                WHERE ip_address = ?
                ORDER BY timestamp DESC
                LIMIT 10
            """, (ip_address,))
            
            alerts = cursor.fetchall()
            
            # Get geo data if available
            try:
                cursor.execute("""
                    SELECT country, region, city, latitude, longitude, asn, asn_name
                    FROM x_ip_geolocation
                    WHERE ip_address = ?
                """, (ip_address,))
                geo_data = cursor.fetchone()
            except:
                geo_data = None
            
            # Get traffic pattern data if available
            try:
                cursor.execute("""
                    SELECT connection_key, avg_packet_size, periodic_score, burst_score, 
                           classification, session_count
                    FROM x_traffic_patterns
                    WHERE connection_key LIKE ? OR connection_key LIKE ?
                    LIMIT 5
                """, (f"{ip_address}:%->%", f"%->{ip_address}:%"))
                traffic_patterns = cursor.fetchall()
            except:
                traffic_patterns = []
            
            cursor.close()
            
            return {
                "threat_data": threat_data,
                "alerts": alerts,
                "geo_data": geo_data,
                "traffic_patterns": traffic_patterns
            }
        except Exception as e:
            self.update_output(f"Error getting threat intel: {e}")
            return {
                "error": str(e)
            }
    
    def _display_threat_intel(self, text_widget, ip_address, data):
        """Display threat intelligence data in the details dialog"""
        # Clear the widget
        text_widget.delete(1.0, tk.END)
        
        # Check for errors
        if "error" in data:
            text_widget.insert(tk.END, f"Error retrieving threat data: {data['error']}\n")
            return
        
        # Display threat data
        threat_data = data.get("threat_data")
        if threat_data:
            text_widget.insert(tk.END, "THREAT INTELLIGENCE SUMMARY\n", "section")
            text_widget.insert(tk.END, f"IP Address: {ip_address}\n")
            
            if len(threat_data) >= 3:
                text_widget.insert(tk.END, f"Threat Score: {threat_data[0]}%\n")
                text_widget.insert(tk.END, f"Threat Type: {threat_data[1] or 'Unknown'}\n")
                text_widget.insert(tk.END, f"Confidence: {threat_data[2] * 100 if threat_data[2] is not None else 'N/A'}%\n")
                
                if len(threat_data) >= 4:
                    text_widget.insert(tk.END, f"Source: {threat_data[3] or 'Internal detection'}\n")
                
                # Parse and display details JSON
                if len(threat_data) >= 5 and threat_data[4]:
                    text_widget.insert(tk.END, "\nDETAILED THREAT INFORMATION\n", "section")
                    try:
                        details = json.loads(threat_data[4])
                        for key, value in details.items():
                            if isinstance(value, dict):
                                text_widget.insert(tk.END, f"{key}:\n", "subsection")
                                for k, v in value.items():
                                    text_widget.insert(tk.END, f"  {k}: {v}\n")
                            else:
                                text_widget.insert(tk.END, f"{key}: {value}\n")
                    except:
                        text_widget.insert(tk.END, f"Details: {threat_data[4]}\n")
                
                # Additional metadata if available
                if len(threat_data) >= 9:
                    text_widget.insert(tk.END, "\nTHREAT TIMELINE\n", "section")
                    if threat_data[7]:  # first_seen
                        first_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(threat_data[7]))
                        text_widget.insert(tk.END, f"First Detected: {first_seen}\n")
                    if threat_data[8]:  # last_seen
                        last_seen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(threat_data[8]))
                        text_widget.insert(tk.END, f"Last Updated: {last_seen}\n")
                    if len(threat_data) >= 10 and threat_data[9]:  # alert_count
                        text_widget.insert(tk.END, f"Total Alerts: {threat_data[9]}\n")
                        
                # Show connection details if available
                if len(threat_data) >= 12:
                    if threat_data[10] or threat_data[11]:  # destination_ip, destination_port
                        text_widget.insert(tk.END, "\nCONNECTION DETAILS\n", "section")
                        if threat_data[10]:  # destination_ip
                            text_widget.insert(tk.END, f"Destination IP: {threat_data[10]}\n")
                        if threat_data[11]:  # destination_port
                            text_widget.insert(tk.END, f"Destination Port: {threat_data[11]}\n")
                        if threat_data[6]:  # protocol
                            text_widget.insert(tk.END, f"Protocol: {threat_data[6]}\n")
        else:
            text_widget.insert(tk.END, "No threat intelligence data available for this IP address.\n")
        
        # Display related alerts
        alerts = data.get("alerts", [])
        if alerts:
            text_widget.insert(tk.END, "\nRELATED ALERTS\n", "section")
            for alert in alerts:
                if len(alert) >= 3:
                    alert_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(alert[2]))
                    text_widget.insert(tk.END, f"[{alert_time}] {alert[0]}\n")
        
        # Display geolocation data
        geo_data = data.get("geo_data")
        if geo_data:
            text_widget.insert(tk.END, "\nGEOLOCATION DATA\n", "section")
            if len(geo_data) >= 3:
                if geo_data[0]:  # country
                    text_widget.insert(tk.END, f"Country: {geo_data[0]}\n")
                if geo_data[1] and geo_data[2]:  # region, city
                    text_widget.insert(tk.END, f"Location: {geo_data[2]}, {geo_data[1]}\n")
                elif geo_data[2]:  # city only
                    text_widget.insert(tk.END, f"City: {geo_data[2]}\n")
                
                # Coordinates
                if len(geo_data) >= 5 and geo_data[3] and geo_data[4]:
                    text_widget.insert(tk.END, f"Coordinates: {geo_data[3]}, {geo_data[4]}\n")
                
                # ASN info
                if len(geo_data) >= 7 and geo_data[6]:
                    text_widget.insert(tk.END, f"Network: {geo_data[6]}\n")
                    if geo_data[5]:
                        text_widget.insert(tk.END, f"ASN: {geo_data[5]}\n")
        
        # Display traffic pattern data
        patterns = data.get("traffic_patterns", [])
        if patterns:
            text_widget.insert(tk.END, "\nTRAFFIC PATTERN ANALYSIS\n", "section")
            for pattern in patterns:
                if len(pattern) >= 6:
                    text_widget.insert(tk.END, f"Connection: {pattern[0]}\n", "subsection")
                    text_widget.insert(tk.END, f"  Average Packet Size: {pattern[1]} bytes\n")
                    text_widget.insert(tk.END, f"  Periodicity Score: {pattern[2]:.2f}\n")
                    text_widget.insert(tk.END, f"  Burst Score: {pattern[3]:.2f}\n")
                    if pattern[4]:  # classification
                        text_widget.insert(tk.END, f"  Classification: {pattern[4]}\n")
                    text_widget.insert(tk.END, f"  Session Count: {pattern[5]}\n")
        
        # Configure tags for formatting
        text_widget.tag_configure("section", font=("TkDefaultFont", 10, "bold"))
        text_widget.tag_configure("subsection", font=("TkDefaultFont", 9, "bold"))
    
    def report_false_positive(self, ip_address, dialog=None):
        """Report an IP address as a false positive in the threat intel"""
        if not hasattr(gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        # Confirm with the user
        confirm = tk.messagebox.askyesno(
            "Confirm False Positive",
            f"Are you sure you want to report {ip_address} as a false positive?\n\n"
            "This will adjust the threat score and add a note to the threat intel database.",
            parent=dialog if dialog else self.tab_frame
        )
        
        if not confirm:
            return
            
        # Queue the update using analysis_manager
        gui.analysis_manager.queue_query(
            lambda: self._update_threat_intel_false_positive(ip_address),
            lambda result: self._handle_false_positive_result(result, ip_address, dialog)
        )
    
    def _update_threat_intel_false_positive(self, ip_address):
        """Update the threat intel database to mark an IP as a false positive"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            
            # Check if IP exists in the threat intel database
            cursor.execute("SELECT threat_score, details FROM x_ip_threat_intel WHERE ip_address = ?", (ip_address,))
            existing = cursor.fetchone()
            
            if existing:
                # Parse existing details or create new
                try:
                    details = json.loads(existing[1]) if existing[1] else {}
                except:
                    details = {}
                
                # Add false positive report
                if "false_positive_reports" not in details:
                    details["false_positive_reports"] = []
                
                details["false_positive_reports"].append({
                    "timestamp": time.time(),
                    "prev_score": existing[0],
                    "source": "user_report"
                })
                
                # Lower the threat score
                new_score = max(10, existing[0] * 0.5)  # Reduce by 50% but not below 10
                
                # Update the database
                cursor.execute("""
                    UPDATE x_ip_threat_intel
                    SET threat_score = ?, 
                        confidence = confidence * 0.5,
                        details = ?
                    WHERE ip_address = ?
                """, (new_score, json.dumps(details), ip_address))
                
                # Add note to alerts
                cursor.execute("""
                    INSERT INTO x_alerts (ip_address, alert_message, rule_name, timestamp)
                    VALUES (?, ?, ?, ?)
                """, (
                    ip_address,
                    f"IP reported as false positive by user. Threat score reduced from {existing[0]} to {new_score}.",
                    "false_positive_report",
                    time.time()
                ))
                
                gui.analysis_manager.analysis1_conn.commit()
                cursor.close()
                return True
            else:
                cursor.close()
                return False
        except Exception as e:
            self.update_output(f"Error updating threat intel: {e}")
            return False
    
    def _handle_false_positive_result(self, success, ip_address, dialog):
        """Handle the result of the false positive report"""
        if success:
            self.update_output(f"IP {ip_address} marked as false positive. Threat score reduced.")
            if dialog:
                tk.messagebox.showinfo(
                    "False Positive Reported",
                    f"The threat score for {ip_address} has been reduced. This information has been saved to the threat intelligence database.",
                    parent=dialog
                )
            
            # Refresh the network map to show the updated threat scores
            self.refresh()
        else:
            self.update_output(f"Could not mark {ip_address} as false positive. IP not found in threat database.")
            if dialog:
                tk.messagebox.showerror(
                    "Error Reporting False Positive",
                    f"Could not mark {ip_address} as false positive. The IP address was not found in the threat database.",
                    parent=dialog
                )
    
    def check_threat_intel(self, ip_address):
        """Manually check for threat intelligence on an IP address"""
        if not hasattr(gui, 'analysis_manager'):
            self.update_output("Analysis manager not available")
            return
            
        # Show scanning dialog
        dialog = tk.Toplevel(self.tab_frame)
        dialog.title(f"Checking Threat Intel: {ip_address}")
        dialog.geometry("400x200")
        dialog.transient(self.tab_frame)
        dialog.grab_set()
        
        # Add header
        ttk.Label(dialog, text=f"Checking threat intelligence for {ip_address}", 
                font=("TkDefaultFont", 11, "bold")).pack(pady=10)
        
        # Add progress bar
        progress = ttk.Progressbar(dialog, mode="indeterminate")
        progress.pack(fill="x", padx=20, pady=10)
        progress.start()
        
        # Add status label
        status_label = ttk.Label(dialog, text="Scanning for threat intelligence data...")
        status_label.pack(pady=10)
        
        # Queue the threat check using analysis_manager
        gui.analysis_manager.queue_query(
            lambda: self._perform_threat_check(ip_address),
            lambda result: self._handle_threat_check_result(result, ip_address, dialog, status_label, progress)
        )
    
    def _perform_threat_check(self, ip_address):
        """Perform a threat intelligence check on an IP address"""
        try:
            # First check if we already have threat intel
            cursor = gui.analysis_manager.get_cursor()
            
            cursor.execute("SELECT threat_score FROM x_ip_threat_intel WHERE ip_address = ?", (ip_address,))
            existing = cursor.fetchone()
            
            if existing and existing[0] > 0:
                cursor.close()
                return {"status": "existing", "score": existing[0]}
            
            # Simulate a basic threat check
            # In a real implementation, this would call into actual threat intelligence services
            time.sleep(2)  # Simulate API call delay
            
            # Generate a random score for demonstration
            # In reality, this would be based on actual threat intel data sources
            is_threat = random.random() < 0.3  # 30% chance of being a threat
            
            if is_threat:
                threat_score = random.randint(30, 90)
                threat_type = random.choice(["malware", "scanner", "spam", "botnet", "proxy"])
                
                # Create threat details
                threat_details = {
                    "detected_by": "network_map_scan",
                    "scan_time": time.time(),
                    "detection_method": "manual_check",
                    "threat_indicators": {
                        "suspicious_behavior": random.random() > 0.5,
                        "connection_anomalies": random.random() > 0.7
                    }
                }
                
                # Update threat intelligence database
                threat_data = {
                    'score': threat_score,
                    'type': threat_type,
                    'confidence': 0.8,
                    'source': 'manual_check',
                    'details': threat_details,
                    'detection_method': 'user_initiated_scan'
                }
                
                # Use analysis_manager to update threat intel
                if hasattr(gui.analysis_manager, 'update_threat_intel'):
                    gui.analysis_manager.update_threat_intel(ip_address, threat_data)
                else:
                    # Fallback direct database update
                    cursor.execute("""
                        INSERT OR REPLACE INTO x_ip_threat_intel
                        (ip_address, threat_score, threat_type, confidence, source, 
                         details, detection_method, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        ip_address,
                        threat_score,
                        threat_type,
                        0.8,
                        'manual_check',
                        json.dumps(threat_details),
                        'user_initiated_scan',
                        time.time(),
                        time.time()
                    ))
                    gui.analysis_manager.analysis1_conn.commit()
                
                cursor.close()
                return {"status": "threat", "score": threat_score, "type": threat_type}
            else:
                # No threat found
                # Still record in database but with zero score
                cursor.execute("""
                    INSERT OR REPLACE INTO x_ip_threat_intel
                    (ip_address, threat_score, threat_type, confidence, source,
                     detection_method, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ip_address,
                    0,
                    'clean',
                    1.0,
                    'manual_check',
                    'user_initiated_scan',
                    time.time(),
                    time.time()
                ))
                gui.analysis_manager.analysis1_conn.commit()
                
                cursor.close()
                return {"status": "clean"}
        except Exception as e:
            self.update_output(f"Error performing threat check: {e}")
            return {"status": "error", "message": str(e)}
    
    def _handle_threat_check_result(self, result, ip_address, dialog, status_label, progress):
        """Handle the result of the threat intelligence check"""
        # Stop the progress bar
        progress.stop()
        
        if result["status"] == "error":
            status_label.config(text=f"Error checking threat intelligence: {result.get('message', 'Unknown error')}")
            return
            
        elif result["status"] == "existing":
            score = result.get("score", 0)
            status_label.config(text=f"Existing threat intelligence found. Threat score: {score}%")
            
            # Change dialog buttons
            btn_frame = ttk.Frame(dialog)
            btn_frame.pack(fill="x", pady=10)
            
            ttk.Button(btn_frame, text="View Details", 
                      command=lambda: [dialog.destroy(), self.show_threat_details(ip_address)]).pack(side="left", padx=10)
            ttk.Button(btn_frame, text="Close", 
                      command=dialog.destroy).pack(side="right", padx=10)
            
        elif result["status"] == "threat":
            score = result.get("score", 0)
            threat_type = result.get("type", "unknown")
            
            status_label.config(text=f"Threat detected! Score: {score}%, Type: {threat_type}")
            
            # Change dialog appearance for threat
            dialog.configure(background="#ffebee")  # Light red background
            
            # Add warning icon (text-based for portability)
            warning_label = ttk.Label(dialog, text="⚠️", font=("TkDefaultFont", 24))
            warning_label.pack(pady=5)
            
            # Change dialog buttons
            btn_frame = ttk.Frame(dialog)
            btn_frame.pack(fill="x", pady=10)
            
            ttk.Button(btn_frame, text="View Details", 
                      command=lambda: [dialog.destroy(), self.show_threat_details(ip_address)]).pack(side="left", padx=10)
            ttk.Button(btn_frame, text="Close", 
                      command=dialog.destroy).pack(side="right", padx=10)
            
            # Refresh the network map to show the updated threat
            self.refresh()
            
        else:  # clean
            status_label.config(text="No threats detected for this IP address.")
            
            # Change dialog appearance for clean
            dialog.configure(background="#e8f5e9")  # Light green background
            
            # Add checkmark icon (text-based for portability)
            checkmark_label = ttk.Label(dialog, text="✅", font=("TkDefaultFont", 24))
            checkmark_label.pack(pady=5)
            
            # Change dialog buttons
            btn_frame = ttk.Frame(dialog)
            btn_frame.pack(fill="x", pady=10)
            
            ttk.Button(btn_frame, text="Close", 
                      command=dialog.destroy).pack(side="right", padx=10)
    
    def add_network_insight(self, ip_address, insight_type, details=None):
        """Add a network insight to the analysis system"""
        if not hasattr(gui, 'analysis_manager'):
            return False
            
        details = details or {}
        
        # Determine the appropriate analytics data to store
        if insight_type == "isolated_host":
            # Add alert for isolated host with no expected connections
            gui.analysis_manager.add_alert(
                ip_address,
                f"Isolated host detected: {details.get('reason', 'No expected connections')}",
                "network_anomaly"
            )
        elif insight_type == "unexpected_gateway":
            # Add alert for unexpected gateway/router
            gui.analysis_manager.add_alert(
                ip_address,
                f"Unexpected gateway or router detected: {details.get('reason', 'Not in expected gateway list')}",
                "network_topology"
            )
        elif insight_type == "subnet_anomaly":
            # Update threat intel for subnet anomaly
            threat_data = {
                'score': 40,
                'type': 'network_anomaly',
                'confidence': 0.7,
                'source': 'network_map',
                'details': details,
                'detection_method': 'topology_analysis'
            }
            gui.analysis_manager.update_threat_intel(ip_address, threat_data)
        
        return True

    def export_as_json(self):
        """Export the network map data as JSON with enhanced analytics data"""
        try:
            import os
            import json
            
            # Generate filename with timestamp
            filename = f"network_map_{time.strftime('%Y%m%d_%H%M%S')}.json"
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            filepath = os.path.join(desktop_path, filename)
            
            # Prepare data for export
            export_data = {
                "nodes": {},
                "edges": [],
                "gateways": self.gateways,
                "arp_relationships": {ip: list(relations) for ip, relations in self.arp_relationships.items()},
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                "stats": self.stats,
                "analytics": {
                    "threat_detected": sum(1 for node in self.nodes.values() if "threat_score" in node and node["threat_score"] > 0),
                    "geo_locations": sum(1 for node in self.nodes.values() if "geo_data" in node),
                    "servers_detected": sum(1 for node in self.nodes.values() if node["type"] == "server"),
                    "total_bytes": sum(edge.get("bytes", 0) for edge in self.edges)
                }
            }
            
            # Convert nodes to serializable format with analytics data
            for node_id, node in self.nodes.items():
                export_node = {
                    "id": node["id"],
                    "type": node["type"],
                    "name": node.get("name", "Unknown"),
                    "ip": node.get("ip", None),
                    "ttl": node.get("ttl", None),
                    "x": node["x"],
                    "y": node["y"]
                }
                
                # Add threat intel if available
                if "threat_score" in node:
                    export_node["threat_score"] = node["threat_score"]
                    export_node["threat_type"] = node.get("threat_type")
                
                # Add geo data if available
                if "geo_data" in node:
                    export_node["geo_data"] = node["geo_data"]
                
                export_data["nodes"][node_id] = export_node
            
            # Convert edges to serializable format
            for edge in self.edges:
                export_data["edges"].append({
                    "source": edge["source"],
                    "target": edge["target"],
                    "type": edge.get("type", "network"),
                    "is_gateway": edge.get("is_gateway", False),
                    "bytes": edge.get("bytes", 0)
                })
            
            # Write to file
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.update_output(f"Map data exported to {filepath}")
            messagebox.showinfo("Export Successful", f"Map data exported to {filepath}")
        except Exception as e:
            self.update_output(f"Error exporting JSON: {e}")
            raise
    
    def export_map(self):
        """Export the network map to a file"""
        # Call the existing export_as_json method
        self.export_as_json()


    def redraw_network(self, *args):
        """Redraw the network graph on the canvas"""
        if not self.canvas:
            return

        # Clear the canvas
        self.canvas.delete("all")
        self.canvas_items = {} # Clear item mapping

        if not self.nodes:
            self.canvas.create_text(
                self.canvas.winfo_width() // 2 if self.canvas.winfo_width() > 1 else 200,
                self.canvas.winfo_height() // 2 if self.canvas.winfo_height() > 1 else 100,
                text="No network data loaded. Click 'Refresh Map'.",
                fill="gray"
            )
            self.canvas.configure(scrollregion=(0, 0, 400, 200))
            return

        # Draw edges first (so they are below nodes)
        for edge in self.edges:
            source_id = edge["source"]
            target_id = edge["target"]

            if source_id in self.nodes and target_id in self.nodes:
                source_node = self.nodes[source_id]
                target_node = self.nodes[target_id]

                src_x, src_y = source_node["x"], source_node["y"]
                dst_x, dst_y = target_node["x"], target_node["y"]

                # Determine line color and width based on edge type/data
                line_color = "gray"
                line_width = 1
                edge_type = edge.get("type", "network")

                if edge_type == "wan":
                    line_color = "lightblue"
                    line_width = 2
                elif edge_type == "vpn":
                    line_color = "purple"
                    line_width = 2
                elif edge_type == "arp":
                    line_color = "lightgray"
                    line_width = 1
                elif edge.get("is_gateway"):
                     line_color = "darkblue"
                     line_width = 3

                # Draw the line
                self.canvas.create_line(
                    src_x, src_y, dst_x, dst_y,
                    fill=line_color, width=line_width, tags="edge"
                )

        # Draw nodes
        for node_id, node in self.nodes.items():
            self.draw_node(node) # draw_node already exists and handles colors/selection

        # Update scroll region after drawing
        try:
            bbox = self.canvas.bbox("all")
            if bbox:
                # Add some padding to the bounding box
                padded_bbox = (bbox[0] - 50, bbox[1] - 50, bbox[2] + 50, bbox[3] + 50)
                self.canvas.configure(scrollregion=padded_bbox)
            else:
                 self.canvas.configure(scrollregion=(0, 0, 400, 200))
        except Exception as e:
            self.update_output(f"Error setting scrollregion: {e}")
            self.canvas.configure(scrollregion=(0, 0, 1000, 800)) # Default fallback

        self.update_output("Network map redrawn.")