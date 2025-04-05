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
import capture_fields

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
        self.packet_sample_count = 0  # For debug packet sampling
        
        # Use the database manager from the GUI
        self.db_manager = gui.db_manager
        
        # Create logs directory if it doesn't exist
        self.logs_dir = os.path.join(gui.app_root, "logs", "packets")
        os.makedirs(self.logs_dir, exist_ok=True)
        self.gui.update_output(f"Packet samples will be saved to {self.logs_dir}")
    
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
        self.packet_sample_count = 0
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
    
    def save_packet_sample(self, packet_data, packet_type="unknown"):
        """Save a sample packet to the logs folder for debugging"""
        try:
            # Only save up to 20 samples to avoid filling disk
            if self.packet_sample_count >= 20:
                return
                
            self.packet_sample_count += 1
            timestamp = int(time.time())
            filename = f"packet_{packet_type}_{timestamp}_{self.packet_sample_count}.json"
            filepath = os.path.join(self.logs_dir, filename)
            
            with open(filepath, 'w') as f:
                json.dump(packet_data, f, indent=2)
                
            self.gui.update_output(f"Saved {packet_type} packet sample to {filename}")
        except Exception as e:
            self.gui.update_output(f"Error saving packet sample: {e}")
    
    def capture_packets(self, interface):
        """Capture packets with streaming EK format parser using dynamic field definitions"""
        try:
            self.gui.update_output(f"Capturing on interface: {interface}")
            
            # Build tshark command dynamically from field definitions
            cmd = [
                "tshark",
                "-i", interface,
                "-T", "ek",  # Elasticsearch Kibana format
            ]
            
            # Add all fields from configuration
            for field in capture_fields.get_tshark_fields():
                cmd.extend(["-e", field])
            
            # Add filters
            cmd.extend([
                "-f", "tcp or udp or icmp",  # Capture filter
                "-Y", "http or tls or ssl or http2 or dns or icmp",  # Display filter
                "-l"  # Line-buffered output
            ])
            
            self.gui.update_output(f"Running command: {' '.join(cmd)}")
            
            # Start tshark process - use binary mode instead of text mode
            self.tshark_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            buffer = ""  # Buffer to accumulate EK output
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
                buffer += line + "\n"  # Add newline to keep lines separated
                
                # Log buffer size occasionally (not more than once every 30 seconds)
                current_time = time.time()
                if current_time - last_buffer_log_time > 30:
                    self.gui.update_output(f"Buffer size: {len(buffer)} chars")
                    last_buffer_log_time = current_time
                
                # Extract complete JSON objects from the buffer
                packet_objects = self.extract_ek_objects(buffer)
                if packet_objects:
                    # Only log this for large batches (more than 10 objects)
                    if len(packet_objects) > 10:
                        self.gui.update_output(f"Found {len(packet_objects)} complete JSON objects")
                    
                    # Process each packet JSON object
                    for packet_json in packet_objects:
                        try:
                            packet_data = json.loads(packet_json)
                            # Save a sample of each packet type
                            if random.random() < 0.05 and self.packet_sample_count < 20:
                                # Determine packet type for better sample naming
                                packet_type = self.determine_packet_type(packet_data)
                                self.save_packet_sample(packet_data, packet_type)
                                
                            self.process_packet_ek(packet_data)
                            self.packet_count += 1
                            self.packet_batch_count += 1
                        except json.JSONDecodeError as e:
                            self.gui.update_output(f"JSON Decode Error: {e}")
                    
                    # Remove processed content from buffer
                    # Keep only the last 1000 characters to handle any incomplete objects
                    buffer = buffer[-1000:] if len(buffer) > 1000 else buffer
                    
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
    
    def determine_packet_type(self, packet_data):
        """Determine packet type for logging purposes"""
        if not packet_data or "layers" not in packet_data:
            return "unknown"
            
        layers = packet_data.get("layers", {})
        
        if "dns_qry_name" in layers:
            return "dns"
        elif "http_host" in layers or "http_request_method" in layers:
            return "http"
        elif "tls_handshake_type" in layers:
            return "tls"
        elif "icmp_type" in layers:
            return "icmp"
        elif "tcp_srcport" in layers:
            return "tcp"
        elif "udp_srcport" in layers:
            return "udp"
        
        return "unknown"
    
    def extract_ek_objects(self, buffer):
        """
        Extract data objects from tshark -T ek output format
        Returns a list of complete JSON data objects (without index lines)
        """
        objects = []
        lines = buffer.strip().split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            if not line:
                i += 1
                continue
            
            # Check if this appears to be an index line (first line of a pair)
            if line.startswith('{"index"'):
                # The next line should be the data line
                if i + 1 < len(lines) and lines[i + 1].strip():
                    data_line = lines[i + 1].strip()
                    try:
                        # Validate it's valid JSON before adding
                        json.loads(data_line)
                        objects.append(data_line)
                        # Move past this pair
                        i += 2
                    except json.JSONDecodeError:
                        # If we can't parse the data line, just move forward one line
                        self.gui.update_output(f"Skipping malformed EK data line: {data_line[:50]}...")
                        i += 1
                else:
                    # Incomplete pair, just move forward
                    i += 1
            else:
                # If this isn't an index line, try parsing it anyway in case it's a data line
                try:
                    json.loads(line)
                    objects.append(line)
                except json.JSONDecodeError:
                    pass
                i += 1
        
        return objects
    
    def get_array_value(self, array_field):
        """
        Extract first value from an array field, which is the typical structure in EK format.
        Returns None if the field is not an array or is empty.
        """
        if isinstance(array_field, list) and array_field:
            return array_field[0]
        return None
    
    def get_layer_value(self, layers, field_name):
        """
        Get a value from the layers object, handling the EK array format.
        Returns the first value from the array if present, otherwise None.
        """
        if field_name in layers:
            return self.get_array_value(layers[field_name])
        return None
    
    def process_packet_ek(self, packet_data):
        """Process a packet in Elasticsearch Kibana format using field definitions"""
        try:
            # Get the layers
            layers = packet_data.get("layers", {})
            if not layers:
                return False
            
            # Extract IP addresses (supporting both IPv4 and IPv6) using field definitions
            src_ip = None
            dst_ip = None
            
            # Try IPv4 fields first
            src_ip_field = capture_fields.get_field_by_tshark_name("ip.src")
            dst_ip_field = capture_fields.get_field_by_tshark_name("ip.dst")
            
            if src_ip_field:
                layer_name = src_ip_field["tshark_field"].replace(".", "_")
                src_ip = self.get_layer_value(layers, layer_name)
                
            if dst_ip_field:
                layer_name = dst_ip_field["tshark_field"].replace(".", "_")
                dst_ip = self.get_layer_value(layers, layer_name)
            
            # If not found, try IPv6 fields
            if not src_ip:
                src_ipv6_field = capture_fields.get_field_by_tshark_name("ipv6.src")
                if src_ipv6_field:
                    layer_name = src_ipv6_field["tshark_field"].replace(".", "_")
                    src_ip = self.get_layer_value(layers, layer_name)
                    
            if not dst_ip:
                dst_ipv6_field = capture_fields.get_field_by_tshark_name("ipv6.dst")
                if dst_ipv6_field:
                    layer_name = dst_ipv6_field["tshark_field"].replace(".", "_")
                    dst_ip = self.get_layer_value(layers, layer_name)
            
            # Basic data validation - we need IPs to proceed
            if not src_ip or not dst_ip:
                # Don't log this too frequently
                if random.random() < 0.05:
                    self.gui.update_output(f"Missing IP addresses in packet - src:{src_ip}, dst:{dst_ip}")
                return False
            
            # Extract port and length information
            src_port, dst_port = self._extract_ports(layers)
            length = self._extract_length(layers)
            
            # Skip processing if the IP is in the false positives list
            if src_ip in self.gui.false_positives or dst_ip in self.gui.false_positives:
                return False
            
            # Create a connection key that includes ports if available
            if src_port is not None and dst_port is not None:
                connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            else:
                connection_key = f"{src_ip}->{dst_ip}"
            
            # Check for RDP connection (port 3389)
            is_rdp = 0
            if dst_port == 3389:
                is_rdp = 1
                self.gui.update_output(f"Detected RDP connection from {src_ip}:{src_port} to {dst_ip}:{dst_port}")
            
            # Process specific protocol data if present
            protocol_detected = False
            
            # Check for protocol fields using categories
            for category in ["dns", "http", "tls", "icmp"]:
                fields = capture_fields.get_fields_by_category(category)
                layer_names = [f["tshark_field"].replace(".", "_") for f in fields]
                
                if any(name in layers for name in layer_names):
                    # Call the appropriate protocol handler
                    if category == "dns" and self._has_dns_data(layers):
                        self._process_dns_packet_ek(layers, src_ip, dst_ip)
                        protocol_detected = True
                    elif category == "http" and self._has_http_data(layers):
                        self._process_http_packet_ek(layers, src_ip, dst_ip, src_port, dst_port)
                        protocol_detected = True
                    elif category == "tls" and self._has_tls_data(layers):
                        self._process_tls_packet_ek(layers, src_ip, dst_ip, src_port, dst_port)
                        protocol_detected = True
                    elif category == "icmp" and "icmp_type" in layers:
                        self._process_icmp_packet_ek(layers, src_ip, dst_ip)
                        protocol_detected = True
            
            # Port scan detection
            if dst_port:
                self._update_port_scan_data(src_ip, dst_ip, dst_port)
            
            # Protocol detection based on ports if not already detected
            if not protocol_detected:
                # Check standard ports
                if dst_port == 80:
                    self.db_manager.add_app_protocol(connection_key, "HTTP", detection_method="port-based")
                elif dst_port == 443:
                    self.db_manager.add_app_protocol(connection_key, "HTTPS", detection_method="port-based")
                elif dst_port == 53 or src_port == 53:
                    self.db_manager.add_app_protocol(connection_key, "DNS", detection_method="port-based")
                else:
                    # Try other protocol detection
                    self._detect_application_protocol(src_ip, dst_ip, src_port, dst_port, layers, 
                                                    is_tcp=(src_port is not None and "tcp_srcport" in layers))
            
            # Use database manager to add packet
            return self.db_manager.add_packet(
                connection_key, src_ip, dst_ip, src_port, dst_port, length, is_rdp
            )
                    
        except Exception as e:
            self.gui.update_output(f"Error processing packet: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _has_dns_data(self, layers):
        """Check if layers contain DNS query data"""
        return "dns_qry_name" in layers
    
    def _has_http_data(self, layers):
        """Check if layers contain HTTP data"""
        return any(key in layers for key in ["http_host", "http_request_method", "http_request_uri", "http_response_code"])
    
    def _has_tls_data(self, layers):
        """Check if layers contain TLS data"""
        return any(key in layers for key in ["tls_handshake_type", "tls_handshake_version"])
    
    def _extract_ports(self, layers):
        """Extract source and destination ports from packet layers"""
        src_port = None
        dst_port = None
        
        # Try TCP ports first
        tcp_src_field = capture_fields.get_field_by_tshark_name("tcp.srcport")
        if tcp_src_field:
            layer_name = tcp_src_field["tshark_field"].replace(".", "_")
            tcp_src = self.get_layer_value(layers, layer_name)
            if tcp_src:
                try:
                    src_port = int(tcp_src)
                except (ValueError, TypeError):
                    pass
        
        tcp_dst_field = capture_fields.get_field_by_tshark_name("tcp.dstport")
        if tcp_dst_field:
            layer_name = tcp_dst_field["tshark_field"].replace(".", "_")
            tcp_dst = self.get_layer_value(layers, layer_name)
            if tcp_dst:
                try:
                    dst_port = int(tcp_dst)
                except (ValueError, TypeError):
                    pass
        
        # If not found, try UDP ports
        if src_port is None:
            udp_src_field = capture_fields.get_field_by_tshark_name("udp.srcport")
            if udp_src_field:
                layer_name = udp_src_field["tshark_field"].replace(".", "_")
                udp_src = self.get_layer_value(layers, layer_name)
                if udp_src:
                    try:
                        src_port = int(udp_src)
                    except (ValueError, TypeError):
                        pass
        
        if dst_port is None:
            udp_dst_field = capture_fields.get_field_by_tshark_name("udp.dstport")
            if udp_dst_field:
                layer_name = udp_dst_field["tshark_field"].replace(".", "_")
                udp_dst = self.get_layer_value(layers, layer_name)
                if udp_dst:
                    try:
                        dst_port = int(udp_dst)
                    except (ValueError, TypeError):
                        pass
                        
        return src_port, dst_port
    
    def _extract_length(self, layers):
        """Extract frame length from packet layers"""
        length = 0
        frame_len_field = capture_fields.get_field_by_tshark_name("frame.len")
        if frame_len_field:
            layer_name = frame_len_field["tshark_field"].replace(".", "_")
            frame_len = self.get_layer_value(layers, layer_name)
            if frame_len:
                try:
                    length = int(frame_len)
                except (ValueError, TypeError):
                    pass
        return length

    def _update_port_scan_data(self, src_ip, dst_ip, dst_port):
        """Update port scan detection data"""
        if not dst_port:
            return
            
        # Use database manager to store port scan data
        self.db_manager.add_port_scan_data(src_ip, dst_ip, dst_port)

    def _process_dns_packet_ek(self, layers, src_ip, dst_ip):
        """Extract and store DNS query information from EK format"""
        try:
            # Extract query name directly from layers
            query_name = self.get_layer_value(layers, "dns_qry_name")
            
            # Extract query type
            query_type_raw = self.get_layer_value(layers, "dns_qry_type")
            query_type = query_type_raw or "unknown"
            
            # If we don't have a query name, can't process this DNS packet
            if not query_name:
                return False
                
            # Store DNS query using database manager
            self.db_manager.add_dns_query(src_ip, query_name, query_type)
            
            # Periodically log DNS activity
            if random.random() < 0.01:  # Log approximately 1% of DNS queries
                self.gui.update_output(f"DNS Query: {src_ip} -> {query_name} (Type: {query_type})")
            
            return True
                
        except Exception as e:
            self.gui.update_output(f"Error processing DNS packet: {e}")
            return False

    def _process_icmp_packet_ek(self, layers, src_ip, dst_ip):
        """Extract and store ICMP packet information from EK format"""
        try:
            # Extract ICMP type directly from layers
            icmp_type_raw = self.get_layer_value(layers, "icmp_type")
            
            # Parse ICMP type
            icmp_type = 0
            if icmp_type_raw is not None:
                try:
                    icmp_type = int(icmp_type_raw)
                except (ValueError, TypeError):
                    icmp_type = 0
                
            # Store ICMP packet using database manager
            self.db_manager.add_icmp_packet(src_ip, dst_ip, icmp_type)
            
            # Check for ICMP floods using the analysis database and queue system
            def check_icmp_flood():
                try:
                    cursor = self.db_manager.get_cursor_for_rules()
                    current_time = time.time()
                    count = cursor.execute("""
                        SELECT COUNT(*) FROM icmp_packets 
                        WHERE src_ip = ? AND dst_ip = ? AND timestamp > ?
                    """, (src_ip, dst_ip, current_time - 10)).fetchone()[0]  # Last 10 seconds
                    
                    cursor.close()  # Make sure to close the cursor
                    
                    if count > 10:  # Log if more than 10 ICMP packets in 10 seconds
                        self.gui.update_output(f"High ICMP traffic: {src_ip} sent {count} ICMP packets to {dst_ip} in the last 10 seconds")
                except Exception as e:
                    self.gui.update_output(f"Error checking ICMP flood: {e}")
            
            # Queue the ICMP flood check
            self.db_manager.queue_query(check_icmp_flood)
            
            return True
                
        except Exception as e:
            self.gui.update_output(f"Error processing ICMP packet: {e}")
            return False
            
    def add_alert(self, ip_address, alert_message, rule_name):
        """Add an alert through the database manager's queue"""
        # Store in in-memory collection first
        if alert_message not in self.alerts_by_ip[ip_address]:
            self.alerts_by_ip[ip_address].add(alert_message)
            
            # Queue the alert for processing
            return self.db_manager.queue_alert(ip_address, alert_message, rule_name)
        return False
    
    def _process_http_packet_ek(self, layers, src_ip, dst_ip, src_port, dst_port):
        """Extract and store HTTP packet information from EK format"""
        try:
            # Create connection key
            connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            
            # Record application protocol
            self.db_manager.add_app_protocol(connection_key, "HTTP", detection_method="direct")
            
            # Extract HTTP fields directly from layers
            method = self.get_layer_value(layers, "http_request_method")
            uri = self.get_layer_value(layers, "http_request_uri")
            host = self.get_layer_value(layers, "http_host")
            user_agent = self.get_layer_value(layers, "http_user_agent")
            status_code_raw = self.get_layer_value(layers, "http_response_code")
            server = self.get_layer_value(layers, "http_server")
            content_type = self.get_layer_value(layers, "http_content_type")
            content_length_raw = self.get_layer_value(layers, "http_content_length")
            
            # Parse content length if present
            content_length = 0
            if content_length_raw:
                try:
                    content_length = int(content_length_raw)
                except (ValueError, TypeError):
                    content_length = 0
            
            # Determine if this is a request or response
            is_request = method is not None or uri is not None or host is not None
            is_response = status_code_raw is not None
            
            # Process as a request
            if is_request:
                return self._process_http_request(
                    connection_key, 
                    method or "GET",  # Default method
                    host or dst_ip,   # Use destination IP if host not available
                    uri or "/",       # Default URI
                    user_agent or "", 
                    content_type or "",
                    content_length
                )
            # Process as a response
            elif is_response:
                # Try to find the corresponding request
                cursor = self.db_manager.get_cursor_for_rules()
                cursor.execute("""
                    SELECT id FROM http_requests 
                    WHERE connection_key = ? 
                    ORDER BY timestamp DESC LIMIT 1
                """, (connection_key,))
                
                result = cursor.fetchone()
                cursor.close()
                
                if result:
                    request_id = result[0]
                    
                    # Parse status code
                    status_code = 0
                    if status_code_raw:
                        try:
                            status_code = int(status_code_raw)
                        except (ValueError, TypeError):
                            status_code = 0
                    
                    # Create headers dictionary
                    headers = {}
                    if server:
                        headers["Server"] = server
                    if content_type:
                        headers["Content-Type"] = content_type
                    if content_length > 0:
                        headers["Content-Length"] = str(content_length)
                    
                    # Convert headers to JSON
                    headers_json = json.dumps(headers)
                    
                    # Store the response
                    return self.db_manager.add_http_response(
                        request_id,
                        status_code,
                        content_type or "",
                        content_length,
                        server or "",
                        headers_json
                    )
            
            # If it has host information but doesn't clearly fit request/response pattern
            if host:
                # Create minimal request
                headers = {"Host": host}
                if user_agent:
                    headers["User-Agent"] = user_agent
                
                headers_json = json.dumps(headers)
                
                # Store minimal HTTP request
                self.db_manager.add_http_request(
                    connection_key, 
                    "GET",         # Assumed method
                    host,
                    "/",           # Assumed path
                    "HTTP/1.1",    # Assumed version
                    user_agent or "",
                    "",            # No referer
                    content_type or "",
                    headers_json,
                    content_length
                )
                return True
            
            return False
            
        except Exception as e:
            self.gui.update_output(f"Error processing HTTP packet: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _process_http_request(self, connection_key, method, host, uri, user_agent, content_type, content_length):
        """Process HTTP request with simplified field extraction"""
        try:
            # Create headers dictionary
            headers = {"Host": host}
            
            if user_agent:
                headers["User-Agent"] = user_agent
                
            if content_type:
                headers["Content-Type"] = content_type
                
            if content_length > 0:
                headers["Content-Length"] = str(content_length)
            
            # Convert headers to JSON
            headers_json = json.dumps(headers)
            
            # Store in database
            request_id = self.db_manager.add_http_request(
                connection_key,
                method,
                host,
                uri,
                "HTTP/1.1",    # Assumed version
                user_agent or "",
                "",            # No referer in EK format
                content_type or "",
                headers_json,
                content_length
            )
            
            # Log a small percentage of HTTP requests for monitoring
            if random.random() < 0.05:  # Log roughly 5% of requests
                self.gui.update_output(f"HTTP: {method} {host}{uri}")
            
            return request_id is not None
            
        except Exception as e:
            self.gui.update_output(f"Error processing HTTP request: {e}")
            return False

    def _process_tls_packet_ek(self, layers, src_ip, dst_ip, src_port, dst_port):
        """Extract and store TLS/SSL packet information from EK format"""
        try:
            # Create connection key
            connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            
            # Record application protocol
            self.db_manager.add_app_protocol(connection_key, "TLS/SSL", detection_method="direct")
            
            # Extract TLS fields directly from layers
            tls_version = self.get_layer_value(layers, "tls_handshake_version")
            cipher_suite = self.get_layer_value(layers, "tls_handshake_ciphersuite")
            server_name = self.get_layer_value(layers, "tls_handshake_extensions_server_name")
            
            # Set default values if needed
            if not tls_version:
                if dst_port == 443:
                    tls_version = "TLSv1.2 (assumed)"
                else:
                    tls_version = "Unknown"
            
            if not cipher_suite:
                cipher_suite = "Unknown"
            
            # If no server name available, use destination IP
            if not server_name:
                server_name = dst_ip
            
            # We don't attempt to calculate JA3/JA3S fingerprints here
            ja3_fingerprint = ""
            ja3s_fingerprint = ""
            cert_issuer = ""
            cert_subject = ""
            cert_valid_from = ""
            cert_valid_to = ""
            cert_serial = ""
            
            # Store in database
            success = self.db_manager.add_tls_connection(
                connection_key, tls_version, cipher_suite, server_name, 
                ja3_fingerprint, ja3s_fingerprint, cert_issuer, cert_subject,
                cert_valid_from, cert_valid_to, cert_serial
            )
            
            # Log success or failure
            if success:
                self.gui.update_output(f"Stored TLS connection: {server_name} ({tls_version})")
                
                # Trigger a refresh of the TLS tab if it's currently visible
                if hasattr(self.gui, 'subtabs') and self.gui.subtabs:
                    for subtab in self.gui.subtabs:
                        if hasattr(subtab, 'name') and subtab.name == "HTTP/TLS Monitor":
                            self.gui.master.after(5000, subtab.refresh_tls_connections)
                            break
            else:
                self.gui.update_output(f"Failed to store TLS connection for {connection_key}")
                
            return success
            
        except Exception as e:
            self.gui.update_output(f"Error processing TLS packet: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _detect_application_protocol(self, src_ip, dst_ip, src_port, dst_port, layers, is_tcp=True):
        """Detect application protocol based on port numbers and packet content"""
        try:
            # Create connection key
            connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            
            # Common protocol port mappings
            tcp_port_protocols = {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                80: "HTTP",
                110: "POP3",
                119: "NNTP",
                143: "IMAP",
                443: "HTTPS",
                465: "SMTPS",
                993: "IMAPS",
                995: "POP3S",
                1433: "MSSQL",
                1521: "Oracle",
                3306: "MySQL",
                3389: "RDP",
                5432: "PostgreSQL",
                5900: "VNC",
                6379: "Redis",
                8080: "HTTP-ALT",
                8443: "HTTPS-ALT",
                9418: "Git",
                27017: "MongoDB"
            }
            
            udp_port_protocols = {
                53: "DNS",
                67: "DHCP",
                69: "TFTP",
                123: "NTP",
                161: "SNMP",
                500: "IPsec",
                514: "Syslog",
                1900: "SSDP",
                5353: "mDNS"
            }
            
            protocol = None
            port_map = tcp_port_protocols if is_tcp else udp_port_protocols
            
            # Check destination port
            if dst_port in port_map:
                protocol = port_map[dst_port]
            # Check source port (less reliable but still useful)
            elif src_port in port_map:
                protocol = port_map[src_port]
            
            # If we detected a protocol, store it
            if protocol:
                return self.db_manager.add_app_protocol(
                    connection_key, protocol, detection_method="port-based"
                )
            
            return False
        except Exception as e:
            self.gui.update_output(f"Error detecting application protocol: {e}")
            return False