import subprocess
import socket
import re
import os
import json
import time
import threading
import logging
import random
from collections import deque, defaultdict

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('traffic_capture')

class TrafficCaptureEngine:
    """Handles traffic capture and processing logic"""
    
    def __init__(self, gui):
        """Initialize the traffic capture engine"""
        self.gui = gui  # Reference to the GUI to update status and logs
        self.running = False
        self.capture_thread = None
        self.tshark_process = None
        self.packet_queue = deque()
        self.alerts_by_ip = defaultdict(set)
        self.packet_batch_count = 0
        self.packet_count = 0
        
        # Use the database manager from the GUI
        self.db_manager = gui.db_manager
    
    def get_interfaces(self):
        """Get network interfaces using tshark directly"""
        interfaces = []
        try:
            cmd = ["tshark", "-D"]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='replace')
            
            for line in output.splitlines():
                if not line.strip():
                    continue
                    
                # Parse tshark interface line which has format: NUMBER. NAME (DESCRIPTION)
                match = re.match(r'(\d+)\.\s+(.+?)(?:\s+\((.+)\))?$', line)
                if match:
                    idx, iface_id, desc = match.groups()
                    desc = desc or iface_id  # Use ID as description if none provided
                    
                    # Get IP address if possible
                    ip_addr = self.get_interface_ip(iface_id)
                    
                    # Add to interfaces list (name, id, ip, description)
                    # name and description are for display, id is for tshark
                    interfaces.append((desc, iface_id, ip_addr, desc))
                    
            return interfaces
        except subprocess.CalledProcessError as e:
            self.gui.update_output(f"Error getting tshark interfaces: {e.output.decode('utf-8', errors='replace')}")
            return []
        except Exception as e:
            self.gui.update_output(f"Error listing interfaces: {e}")
            return []

    def get_interface_ip(self, interface_id):
        """Try to get the IP address for an interface"""
        try:
            # Check for an IPv4 address at the end of the interface name
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', interface_id)
            if ip_match:
                return ip_match.group(1)
            
            # Try to get IP using socket if possible
            try:
                # This method only works for named interfaces, not for interface IDs
                # that are numeric or GUIDs
                if not re.match(r'^\d+$', interface_id) and not re.match(r'^{.*}$', interface_id):
                    # Remove any trailing numbers that might be part of the tshark interface name
                    clean_name = re.sub(r'\d+$', '', interface_id)
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    # Try to get the IP of this interface by connecting to a dummy address
                    s.connect(('10.254.254.254', 1))
                    ip = s.getsockname()[0]
                    s.close()
                    return ip
            except:
                pass
                
            # For Windows adapters with GUIDs, we can't easily determine the IP
            # A more robust approach would use ipconfig or equivalent
            return "Unknown"
        except Exception:
            return "Unknown"
    
    def start_capture(self, interface, batch_size, sliding_window_size):
        """Start capturing packets on the specified interface"""
        if self.running:
            return
        
        self.running = True
        self.batch_size = batch_size
        self.sliding_window_size = sliding_window_size
        self.packet_count = 0
        self.packet_batch_count = 0
        self.capture_thread = threading.Thread(target=self.capture_packets, 
                                              args=(interface,), 
                                              daemon=True)
        self.capture_thread.start()
    
    def stop_capture(self):
        """Stop the packet capture"""
        self.running = False
        if self.tshark_process:
            try:
                self.tshark_process.terminate()
                self.tshark_process = None
            except Exception as e:
                self.gui.update_output(f"Error stopping tshark: {e}")
        
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
            self.capture_thread = None
    
    def capture_packets(self, interface):
        """Capture packets with streaming JSON parser"""
        try:
            self.gui.update_output(f"Capturing on interface: {interface}")
            
            # Construct tshark command with JSON output
            cmd = [
                "tshark",
                "-i", interface,
                "-T", "json",
                "-f", "ip or icmp or udp port 53",  # Capture IP, ICMP, and DNS traffic
                "-Y", "ip or icmp or dns",          # Display filter for the same
                "-l"  # Line-buffered output
            ]
            
            self.gui.update_output(f"Running command: {' '.join(cmd)}")
            
            # Start tshark process - use binary mode instead of text mode
            self.tshark_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                #bufsize=1  # Line buffered
                # Remove text=True parameter
            )
            
            buffer = ""  # Buffer to accumulate JSON output
            last_buffer_log_time = time.time()
            
            # Process each line from tshark
            for binary_line in iter(self.tshark_process.stdout.readline, b''):
                if not self.running:
                    break
                    
                # Decode with error handling
                line = binary_line.decode('utf-8', errors='replace').strip()
                if not line:
                    continue
                
                # Add line to buffer
                buffer += line
                
                # Log buffer size occasionally (not more than once every 30 seconds)
                current_time = time.time()
                if current_time - last_buffer_log_time > 30:
                    self.gui.update_output(f"Buffer size: {len(buffer)} chars")
                    last_buffer_log_time = current_time
                
                # Extract complete JSON objects from the buffer
                objs = self.extract_json_objects(buffer)
                if objs:
                    # Only log this for large batches (more than 10 objects)
                    if len(objs) > 10:
                        self.gui.update_output(f"Found {len(objs)} complete JSON objects")
                    
                    for obj_str in objs:
                        try:
                            packet_data = json.loads(obj_str)
                            self.process_packet_json(packet_data)
                            self.packet_count += 1
                            self.packet_batch_count += 1
                        except json.JSONDecodeError as e:
                            self.gui.update_output(f"JSON Decode Error: {e}")
                    
                    # Remove parsed objects from buffer - find last closing brace
                    last_obj_end = buffer.rfind(objs[-1]) + len(objs[-1])
                    buffer = buffer[last_obj_end:]
                    
                    # Commit database changes in batches
                    if self.packet_batch_count >= self.batch_size:
                        self.db_manager.commit_capture()
                        self.packet_batch_count = 0
                        
                        # Periodically analyze traffic and update UI
                        self.gui.analyze_traffic()
                        self.gui.update_output(f"Processed {self.packet_count} packets total")
                        self.gui.master.after(0, lambda pc=self.packet_count: self.gui.status_var.set(f"Captured: {pc} packets"))
                
                # Prevent buffer from growing too large (10MB limit)
                if len(buffer) > 10_000_000:
                    self.gui.update_output("Buffer exceeded 10MB limit, resetting...")
                    buffer = ""
            
            # Check for any errors from tshark
            if self.tshark_process:
                errors = self.tshark_process.stderr.read()
                if errors:
                    self.gui.update_output(f"Tshark errors: {errors.decode('utf-8', errors='replace')}")
        
        except PermissionError:
            self.gui.update_output("Permission denied. Run with elevated privileges.")
        except Exception as e:
            self.gui.update_output(f"Capture error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.gui.update_output("Capture stopped")
            self.gui.master.after(0, lambda: self.gui.status_var.set("Ready"))
            if self.tshark_process:
                self.tshark_process.terminate()
                self.tshark_process = None
    
    def extract_json_objects(self, s):
        """
        Extracts complete JSON object strings from a string 's' by scanning for balanced curly braces.
        Returns a list of JSON object strings.
        This version is more robust against malformed JSON.
        """
        objects = []
        start_indices = []
        bracket_counts = []
        
        for i, char in enumerate(s):
            if char == '{':
                if not start_indices:  # This is the start of a new object
                    start_indices.append(i)
                    bracket_counts.append(1)
                else:
                    # Increment the current bracket count
                    bracket_counts[-1] += 1
            elif char == '}':
                if start_indices:  # Only process if we're tracking an object
                    bracket_counts[-1] -= 1
                    
                    # Check if we've closed the current object
                    if bracket_counts[-1] == 0:
                        start = start_indices.pop()
                        bracket_counts.pop()
                        
                        # Extract the JSON object
                        json_obj = s[start:i+1]
                        
                        # Validate it's actually parseable JSON before adding
                        try:
                            json.loads(json_obj)
                            objects.append(json_obj)
                        except json.JSONDecodeError:
                            self.gui.update_output(f"Skipping malformed JSON object: {json_obj[:50]}...")
        
        return objects
    
    def process_packet_json(self, packet_data):
        """Process a packet with robust error handling and protocol-specific extraction"""
        try:
            # Verify we have a dictionary
            if not isinstance(packet_data, dict):
                self.gui.update_output(f"Skipping packet: not a valid dict: {type(packet_data)}")
                return
                
            # Extract source and destination IPs from packet
            source = packet_data.get("_source", {})
            if not source:
                self.gui.update_output("Skipping packet: No _source in packet_data")
                return
                
            layers = source.get("layers", {})
            if not layers or not isinstance(layers, dict):
                self.gui.update_output("Skipping packet: No valid layers in packet_data._source")
                return
            
            # Get IP info if available
            if "ip" not in layers:
                # This is probably not an IP packet - could be ARP, etc.
                # Handle non-IP protocols if needed
                return
                
            ip_layer = layers["ip"]
            if not isinstance(ip_layer, dict):
                self.gui.update_output(f"Skipping packet: IP layer is not a dict: {type(ip_layer)}")
                return
                
            src_ip = ip_layer.get("ip.src")
            if not src_ip:
                self.gui.update_output("Skipping packet: No source IP in packet")
                return
                
            dst_ip = ip_layer.get("ip.dst")
            if not dst_ip:
                self.gui.update_output("Skipping packet: No destination IP in packet")
                return
            
            # Extract port information if available (TCP or UDP)
            src_port = None
            dst_port = None
            
            # Check for TCP layer
            if "tcp" in layers and isinstance(layers["tcp"], dict):
                tcp_layer = layers["tcp"]
                try:
                    src_port = int(tcp_layer.get("tcp.srcport", 0))
                    dst_port = int(tcp_layer.get("tcp.dstport", 0))
                    
                    # For port scan detection
                    self._update_port_scan_data(src_ip, dst_ip, dst_port)
                except (ValueError, TypeError):
                    self.gui.update_output("Warning: Could not convert TCP port to integer")
            
            # Check for UDP layer if TCP not found
            elif "udp" in layers and isinstance(layers["udp"], dict):
                udp_layer = layers["udp"]
                try:
                    src_port = int(udp_layer.get("udp.srcport", 0))
                    dst_port = int(udp_layer.get("udp.dstport", 0))
                    
                    # For port scan detection
                    self._update_port_scan_data(src_ip, dst_ip, dst_port)
                    
                    # Process DNS over UDP (port 53)
                    if dst_port == 53 or src_port == 53:
                        self._process_dns_packet(layers, src_ip, dst_ip)
                except (ValueError, TypeError):
                    self.gui.update_output("Warning: Could not convert UDP port to integer")
            
            # Check for ICMP
            elif "icmp" in layers:
                self._process_icmp_packet(layers, src_ip, dst_ip)
            
            # Get frame info
            frame = layers.get("frame", {})
            if not frame:
                self.gui.update_output("Warning: No frame info in packet, using default length 0")
                length = 0
            else:
                try:
                    length = int(frame.get("frame.len", 0))
                except (ValueError, TypeError):
                    self.gui.update_output(f"Error converting frame.len to int: {frame.get('frame.len')}")
                    length = 0
            
            # Skip processing if the IP is in the false positives list
            if src_ip in self.gui.false_positives or dst_ip in self.gui.false_positives:
                return
            
            # Create a connection key that includes ports if available
            if src_port and dst_port:
                connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            else:
                connection_key = f"{src_ip}->{dst_ip}"
            
            # Check for RDP connection (port 3389)
            is_rdp = 0
            if dst_port == 3389:
                is_rdp = 1
                self.gui.update_output(f"Detected RDP connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
            
            # Use database manager to add packet
            return self.db_manager.add_packet(
                connection_key, src_ip, dst_ip, src_port, dst_port, length, is_rdp
            )
                    
        except Exception as e:
            self.gui.update_output(f"Error processing packet: {e}")
            return False

    def _update_port_scan_data(self, src_ip, dst_ip, dst_port):
        """Update port scan detection data"""
        if not dst_port:
            return
            
        # Use database manager to store port scan data
        self.db_manager.add_port_scan_data(src_ip, dst_ip, dst_port)

    def _process_dns_packet(self, layers, src_ip, dst_ip):
        """Extract and store DNS query information"""
        try:
            if "dns" not in layers:
                return
                
            dns_layer = layers["dns"]
            if not isinstance(dns_layer, dict):
                return
                
            # Extract DNS query name
            query_name = dns_layer.get("dns.qry.name")
            if not query_name:
                return
                
            # Extract query type
            query_type = dns_layer.get("dns.qry.type")
            if not query_type:
                query_type = "unknown"
                
            # Store DNS query using database manager
            self.db_manager.add_dns_query(src_ip, query_name, query_type)
            
            # Periodically log DNS activity
            if random.random() < 0.01:  # Log approximately 1% of DNS queries
                self.gui.update_output(f"DNS Query: {src_ip} -> {query_name} (Type: {query_type})")
                
        except Exception as e:
            self.gui.update_output(f"Error processing DNS packet: {e}")

    def _process_icmp_packet(self, layers, src_ip, dst_ip):
        """Extract and store ICMP packet information"""
        try:
            if "icmp" not in layers:
                return
                
            icmp_layer = layers["icmp"]
            if not isinstance(icmp_layer, dict):
                return
                
            # Extract ICMP type
            icmp_type = None
            try:
                icmp_type = int(icmp_layer.get("icmp.type", 0))
            except (ValueError, TypeError):
                icmp_type = 0
                
            # Store ICMP packet using database manager
            self.db_manager.add_icmp_packet(src_ip, dst_ip, icmp_type)
            
            # Check for ICMP floods using the analysis database and queue system
            def check_icmp_flood():
                try:
                    current_time = time.time()
                    count = self.db_manager.analysis_cursor.execute("""
                        SELECT COUNT(*) FROM icmp_packets 
                        WHERE src_ip = ? AND dst_ip = ? AND timestamp > ?
                    """, (src_ip, dst_ip, current_time - 10)).fetchone()[0]  # Last 10 seconds
                    
                    if count > 10:  # Log if more than 10 ICMP packets in 10 seconds
                        self.gui.update_output(f"High ICMP traffic: {src_ip} sent {count} ICMP packets to {dst_ip} in the last 10 seconds")
                except Exception as e:
                    self.gui.update_output(f"Error checking ICMP flood: {e}")
            
            # Queue the ICMP flood check
            self.db_manager.queue_query(check_icmp_flood)
                
        except Exception as e:
            self.gui.update_output(f"Error processing ICMP packet: {e}")
            
    def add_alert(self, ip_address, alert_message, rule_name):
        """Add an alert through the database manager's queue"""
        # Store in in-memory collection first
        if alert_message not in self.alerts_by_ip[ip_address]:
            self.alerts_by_ip[ip_address].add(alert_message)
            
            # Queue the alert for processing
            return self.db_manager.queue_alert(ip_address, alert_message, rule_name)
        return False