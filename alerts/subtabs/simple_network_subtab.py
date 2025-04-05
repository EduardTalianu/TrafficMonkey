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
        }
        
        # Statistics
        self.stats = {
            "lan_devices": 0,
            "wan_connections": 0,
            "gateways": 0,
            "firewalls": 0,
            "servers": 0
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
            ("servers", "Servers:")
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
        
        ttk.Label(options_frame, text="Node Spacing:").pack(anchor="w", padx=5, pady=3)
        ttk.Scale(options_frame, from_=80, to=200, variable=self.node_spacing, 
                orient="horizontal", command=lambda s: self.redraw_network()).pack(fill="x", padx=5, pady=3)
        
        # Legend
        legend_frame = ttk.LabelFrame(self.controls_frame, text="Legend")
        legend_frame.pack(fill="x", padx=5, pady=5)
        
        # Create small canvas for legend
        legend_canvas = tk.Canvas(legend_frame, height=160, bg=self.colors["background"])
        legend_canvas.pack(fill="x", padx=5, pady=5)
        
        # Add legend items
        y_offset = 20
        for node_type in ["gateway", "border", "firewall", "vpn", "lan", "server", "cloud"]:
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
    
    def refresh(self):
        """Refresh the network map data and visualization"""
        # Check refresh interval
        current_time = time.time()
        if (current_time - self.last_refresh_time) < self.refresh_interval and self.nodes:
            self.update_output(f"Network map will refresh in {int(self.refresh_interval - (current_time - self.last_refresh_time))} seconds")
            return
        
        self.last_refresh_time = current_time
        self.update_output("Refreshing network map...")
        
        # Queue database query
        gui.db_manager.queue_query(
            self.get_network_data,
            callback=self.process_network_data
        )
    
    def get_network_data(self):
        """Get required network data from the database, including TTL and ARP data"""
        try:
            # Create a cursor for querying
            cursor = gui.db_manager.analysis_conn.cursor()
            
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
            
            # Close the cursor
            cursor.close()
            
            return {
                "connections": connections,
                "arp_data": arp_data,
                "dns_data": dns_data,
                "http_data": http_data
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
            
            # Process connections to build topology
            self.build_network_topology(
                data["connections"], 
                data["dns_data"], 
                data["http_data"], 
                local_ranges, 
                gateway_ips
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
    
    def build_network_topology(self, connections, dns_data, http_data, local_ranges, gateway_ips):
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
                    self.nodes[src_ip] = {
                        "id": src_ip,
                        "type": "lan",
                        "ip": src_ip,
                        "name": self.get_device_name(src_ip, hostname_map, dns_map),
                        "ttl": self.get_ttl_for_ip(connections, src_ip),
                        "parent": f"subnet_{src_subnet}",
                        "x": 0,
                        "y": 0
                    }
                    
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
                        if src_port in [80, 443, 25, 21, 22, 3306, 5432]:
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
                    self.nodes[dst_ip] = {
                        "id": dst_ip,
                        "type": "lan",
                        "ip": dst_ip,
                        "name": self.get_device_name(dst_ip, hostname_map, dns_map),
                        "ttl": self.get_ttl_for_ip(connections, dst_ip),
                        "parent": f"subnet_{dst_subnet}",
                        "x": 0,
                        "y": 0
                    }
                    
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
                        if dst_port in [80, 443, 25, 21, 22, 3306, 5432]:
                            node_type = "server"
                    
                    self.nodes[dst_ip] = {
                        "id": dst_ip,
                        "type": node_type,
                        "ip": dst_ip,
                        "name": self.get_device_name(dst_ip, hostname_map, dns_map),
                        "ttl": self.get_ttl_for_ip(connections, dst_ip),
                        "x": 0,
                        "y": 0
                    }
                    
                    # Connect external nodes to VPN if applicable
                    if not dst_is_local and "vpn_tunnel" in self.nodes:
                        if random.random() < 0.3:  # Only connect some external nodes to VPN
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
    
    def update_statistics(self):
        """Update network statistics"""
        # Reset statistics
        self.stats = {
            "lan_devices": 0,
            "wan_connections": 0,
            "gateways": 0,
            "firewalls": 0,
            "servers": 0
        }
        
        # Count devices by type
        for node in self.nodes.values():
            node_type = node["type"]
            if node_type in ["lan"]:
                self.stats["lan_devices"] += 1
            elif node_type in ["border", "gateway"]:
                self.stats["gateways"] += 1
            elif node_type == "firewall":
                self.stats["firewalls"] += 1
            elif node_type == "server":
                self.stats["servers"] += 1
            elif node_type == "cloud":
                self.stats["wan_connections"] += 1
        
        # Update labels
        for stat_key, value in self.stats.items():
            if stat_key in self.stats_labels:
                self.stats_labels[stat_key].config(text=str(value))
    
    def redraw_network(self):
        """Redraw the entire network visualization"""
        # Clear the canvas
        self.canvas.delete("all")
        self.canvas_items = {}
        
        # Draw the edges first (so they're behind nodes)
        for edge in self.edges:
            self.draw_edge(edge)
        
        # Draw the nodes
        for node_id, node in self.nodes.items():
            self.draw_node(node)
        
        # Update scrollregion
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))
    
    def draw_node(self, node):
        """Draw a node on the canvas"""
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
    
    def draw_edge(self, edge):
        """Draw an edge between nodes"""
        source_id = edge["source"]
        target_id = edge["target"]
        edge_type = edge.get("type", "network")
        
        # Make sure both nodes exist
        if source_id not in self.nodes or target_id not in self.nodes:
            return
        
        source = self.nodes[source_id]
        target = self.nodes[target_id]
        
        # Get coordinates
        x1, y1 = source["x"], source["y"]
        x2, y2 = target["x"], target["y"]
        
        # Choose line appearance based on edge type
        if edge_type == "network":
            width = 2
            color = "#4472C4"  # Blue
            dash = None
        elif edge_type == "lan":
            width = 1
            color = "#70AD47"  # Green
            dash = None
        elif edge_type == "wan":
            width = 1
            color = "#ED7D31"  # Orange
            dash = None
        elif edge_type == "vpn":
            width = 1
            color = "#7030A0"  # Purple
            dash = (5, 2)
        elif edge_type == "arp":
            width = 1
            color = "#A5A5A5"  # Gray
            dash = (2, 2)
        else:  # direct
            width = 1
            color = "#A5A5A5"  # Gray
            dash = None
            
        # Wider lines for gateway connections
        if edge.get("is_gateway", False):
            width = 3
        
        # Adjust line ending to stop at node boundaries
        # Get node radius based on type
        radius1 = self.node_radius
        if source["type"] in ["border", "gateway"]:
            radius1 *= 1.2
        elif source["type"] == "firewall":
            radius1 *= 1.1
        elif source["type"] == "subnet":
            radius1 *= 1.3
        
        radius2 = self.node_radius
        if target["type"] in ["border", "gateway"]:
            radius2 *= 1.2
        elif target["type"] == "firewall":
            radius2 *= 1.1
        elif target["type"] == "subnet":
            radius2 *= 1.3
        
        # Calculate unit vector along the line
        dx = x2 - x1
        dy = y2 - y1
        length = math.sqrt(dx*dx + dy*dy)
        if length < 1:  # Avoid division by zero
            return
        
        dx, dy = dx/length, dy/length
        
        # Calculate start and end points
        start_x = x1 + dx * radius1
        start_y = y1 + dy * radius1
        end_x = x2 - dx * radius2
        end_y = y2 - dy * radius2
        
        # Draw the line
        self.canvas.create_line(
            start_x, start_y, end_x, end_y,
            fill=color, width=width,
            dash=dash,
            arrow="last", arrowshape=(8, 10, 3)
        )
    
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
    
    def show_connection_details(self, node_id):
        """Show detailed connection information for a node"""
        if node_id not in self.nodes:
            return
        
        node = self.nodes[node_id]
        
        # Create dialog
        dialog = tk.Toplevel(self.tab_frame)
        dialog.title(f"Connections: {node.get('name', node_id)}")
        dialog.geometry("500x400")
        dialog.transient(self.tab_frame)
        dialog.grab_set()
        
        # Add header
        ttk.Label(dialog, text=f"Connection Details for {node.get('name', node_id)}", 
                font=("TkDefaultFont", 11, "bold")).pack(pady=10)
        
        if "ip" in node:
            ttk.Label(dialog, text=f"IP: {node['ip']}").pack(pady=3)
            
            # Show TTL if available
            if "ttl" in node and node["ttl"] is not None:
                ttk.Label(dialog, text=f"TTL: {node['ttl']}").pack(pady=3)
        
        # Create notebook for incoming/outgoing
        conn_notebook = ttk.Notebook(dialog)
        conn_notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Incoming tab
        incoming_frame = ttk.Frame(conn_notebook)
        conn_notebook.add(incoming_frame, text="Incoming")
        
        incoming_tree = ttk.Treeview(incoming_frame, columns=("source", "type"))
        incoming_tree.heading("source", text="Source")
        incoming_tree.heading("type", text="Type")
        incoming_tree.column("#0", width=0, stretch=tk.NO)
        incoming_tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Outgoing tab
        outgoing_frame = ttk.Frame(conn_notebook)
        conn_notebook.add(outgoing_frame, text="Outgoing")
        
        outgoing_tree = ttk.Treeview(outgoing_frame, columns=("target", "type"))
        outgoing_tree.heading("target", text="Target")
        outgoing_tree.heading("type", text="Type")
        outgoing_tree.column("#0", width=0, stretch=tk.NO)
        outgoing_tree.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Populate data
        for edge in self.edges:
            if edge["target"] == node_id and edge["source"] in self.nodes:
                source = self.nodes[edge["source"]]
                incoming_tree.insert("", "end", values=(
                    source.get("name", source["id"]),
                    edge.get("type", "network")
                ))
            
            if edge["source"] == node_id and edge["target"] in self.nodes:
                target = self.nodes[edge["target"]]
                outgoing_tree.insert("", "end", values=(
                    target.get("name", target["id"]),
                    edge.get("type", "network")
                ))
        
        # Add close button
        ttk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=10)
    
    def show_arp_details(self, ip):
        """Show ARP relationship details for an IP"""
        if ip not in self.arp_relationships:
            return
            
        related_ips = self.arp_relationships[ip]
        
        # Create dialog
        dialog = tk.Toplevel(self.tab_frame)
        dialog.title(f"ARP Relationships: {ip}")
        dialog.geometry("400x300")
        dialog.transient(self.tab_frame)
        dialog.grab_set()
        
        # Add header
        ttk.Label(dialog, text=f"ARP Relationships for {ip}", 
                font=("TkDefaultFont", 11, "bold")).pack(pady=10)
        
        # Create treeview
        tree_frame = ttk.Frame(dialog)
        tree_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        tree = ttk.Treeview(tree_frame, columns=("ip", "name", "type"))
        tree.heading("ip", text="IP Address")
        tree.heading("name", text="Device Name")
        tree.heading("type", text="Type")
        tree.column("#0", width=0, stretch=tk.NO)
        tree.column("ip", width=150)
        tree.column("name", width=150)
        tree.column("type", width=80)
        tree.pack(fill="both", expand=True)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
        scrollbar.pack(side="right", fill="y")
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Populate data
        for related_ip in related_ips:
            name = "Unknown"
            node_type = "Unknown"
            
            # Get info if this IP is in our nodes
            if related_ip in self.nodes:
                node = self.nodes[related_ip]
                name = node.get("name", "Unknown")
                node_type = node["type"].capitalize()
                
            tree.insert("", "end", values=(related_ip, name, node_type))
        
        # Add buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", pady=10)
        
        ttk.Button(btn_frame, text="Copy Selected IP", 
                  command=lambda: self.copy_selected_arp_ip(tree)).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Close", 
                  command=dialog.destroy).pack(side="right", padx=10)
    
    def copy_selected_arp_ip(self, tree):
        """Copy selected IP from ARP relationships dialog"""
        selected = tree.selection()
        if selected:
            ip = tree.item(selected[0], "values")[0]
            gui.ip_manager.copy_ip_to_clipboard(ip)
    
    def export_map(self):
        """Export the network map as an image or JSON data"""
        # Create dialog
        dialog = tk.Toplevel(self.tab_frame)
        dialog.title("Export Network Map")
        dialog.geometry("300x160")
        dialog.transient(self.tab_frame)
        dialog.grab_set()
        
        # Add header
        ttk.Label(dialog, text="Export Options", 
                font=("TkDefaultFont", 11, "bold")).pack(pady=10)
        
        # Export format options
        export_format = tk.StringVar(value="png")
        ttk.Radiobutton(dialog, text="PNG Image", 
                      variable=export_format, value="png").pack(anchor="w", padx=20, pady=3)
        ttk.Radiobutton(dialog, text="JSON Data", 
                      variable=export_format, value="json").pack(anchor="w", padx=20, pady=3)
        
        # Add buttons
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", pady=10)
        
        ttk.Button(btn_frame, text="Export", 
                  command=lambda: self.do_export(export_format.get(), dialog)).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Cancel", 
                  command=dialog.destroy).pack(side="right", padx=10)
    
    def do_export(self, format_type, dialog):
        """Perform the export operation"""
        try:
            if format_type == "png":
                self.export_as_png()
            else:
                self.export_as_json()
                
            dialog.destroy()
        except Exception as e:
            self.update_output(f"Export error: {e}")
            messagebox.showerror("Export Error", str(e), parent=dialog)
    
    def export_as_png(self):
        """Export the network map as a PNG image"""
        try:
            from PIL import ImageGrab
            import os
            
            # Generate filename with timestamp
            filename = f"network_map_{time.strftime('%Y%m%d_%H%M%S')}.png"
            desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
            filepath = os.path.join(desktop_path, filename)
            
            # Get canvas bounds
            bbox = self.canvas.bbox("all")
            if not bbox:
                raise ValueError("No content to export")
                
            # Add margin
            x1, y1, x2, y2 = bbox
            margin = 20
            x1 -= margin
            y1 -= margin
            x2 += margin
            y2 += margin
            
            # Take screenshot
            screenshot_bbox = (
                self.canvas.winfo_rootx() + x1,
                self.canvas.winfo_rooty() + y1,
                self.canvas.winfo_rootx() + x2,
                self.canvas.winfo_rooty() + y2
            )
            
            image = ImageGrab.grab(bbox=screenshot_bbox)
            image.save(filepath)
            
            self.update_output(f"Map exported to {filepath}")
            messagebox.showinfo("Export Successful", f"Map exported to {filepath}")
        except ImportError:
            self.update_output("PIL/Pillow library required for image export")
            raise ValueError("PIL/Pillow library required for image export")
        except Exception as e:
            self.update_output(f"Error exporting image: {e}")
            raise
    
    def export_as_json(self):
        """Export the network map data as JSON"""
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
                "stats": self.stats
            }
            
            # Convert nodes to serializable format
            for node_id, node in self.nodes.items():
                export_data["nodes"][node_id] = {
                    "id": node["id"],
                    "type": node["type"],
                    "name": node.get("name", "Unknown"),
                    "ip": node.get("ip", None),
                    "ttl": node.get("ttl", None),
                    "x": node["x"],
                    "y": node["y"]
                }
            
            # Convert edges to serializable format
            for edge in self.edges:
                export_data["edges"].append({
                    "source": edge["source"],
                    "target": edge["target"],
                    "type": edge.get("type", "network"),
                    "is_gateway": edge.get("is_gateway", False)
                })
            
            # Write to file
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.update_output(f"Map data exported to {filepath}")
            messagebox.showinfo("Export Successful", f"Map data exported to {filepath}")
        except Exception as e:
            self.update_output(f"Error exporting JSON: {e}")
            raise
    
    def on_tab_selected(self):
        """Called when this tab is selected"""
        # Refresh if needed
        current_time = time.time()
        if (current_time - self.last_refresh_time) > self.refresh_interval or not self.nodes:
            self.refresh()