# Rule class is injected by the RuleLoader
import logging
from collections import defaultdict
import time
import json

class NetworkTopologyMapperRule(Rule):
    """Rule that builds a map of internal network topology from traffic patterns"""
    def __init__(self):
        super().__init__(
            name="Internal Network Topology Mapper",
            description="Maps internal network topology by analyzing traffic patterns"
        )
        # Store subnet information
        self.subnets = defaultdict(set)
        # Store router/gateway information
        self.potential_gateways = defaultdict(int)
        # Store device information
        self.devices = defaultdict(dict)
        # Last analysis time
        self.last_analysis_time = 0
        # Analysis interval in seconds
        self.analysis_interval = 300  # 5 minutes
        # Track already reported networks
        self.reported_networks = set()
        # Track interesting devices for red team reports
        self.reported_devices = set()
    
    def analyze(self, db_cursor):
        alerts = []
        
        current_time = time.time()
        if current_time - self.last_analysis_time < self.analysis_interval:
            return []
            
        self.last_analysis_time = current_time
        
        try:
            # Get all connections to map the network
            db_cursor.execute("""
                SELECT src_ip, dst_ip, src_port, dst_port, protocol, total_bytes
                FROM connections
                ORDER BY timestamp DESC
                LIMIT 10000
            """)
            
            # Process connections
            for row in db_cursor.fetchall():
                src_ip, dst_ip, src_port, dst_port, protocol, total_bytes = row
                
                # Skip non-internal IPs
                if not self._is_internal_ip(src_ip) and not self._is_internal_ip(dst_ip):
                    continue
                
                # Extract subnet information
                src_subnet = self._get_subnet(src_ip)
                dst_subnet = self._get_subnet(dst_ip)
                
                if src_subnet:
                    self.subnets[src_subnet].add(src_ip)
                if dst_subnet:
                    self.subnets[dst_subnet].add(dst_ip)
                
                # Identify potential gateways (devices that communicate across subnets)
                if src_subnet and dst_subnet and src_subnet != dst_subnet:
                    self.potential_gateways[src_ip] += 1
                    self.potential_gateways[dst_ip] += 1
                
                # Collect device information
                if self._is_internal_ip(src_ip):
                    if src_ip not in self.devices:
                        self.devices[src_ip] = {
                            "ports_used": set(),
                            "protocols": set(),
                            "connections": 0,
                            "data_transferred": 0
                        }
                    
                    self.devices[src_ip]["ports_used"].add(src_port)
                    if protocol:
                        self.devices[src_ip]["protocols"].add(protocol)
                    self.devices[src_ip]["connections"] += 1
                    self.devices[src_ip]["data_transferred"] += total_bytes
            
            # Get DNS information to identify hostnames
            db_cursor.execute("""
                SELECT query_domain, a_record
                FROM dns_queries
                WHERE a_record IS NOT NULL
                ORDER BY timestamp DESC
            """)
            
            dns_records = {}
            for row in db_cursor.fetchall():
                query_domain, a_record = row
                if a_record and self._is_internal_ip(a_record):
                    dns_records[a_record] = query_domain
            
            # Add hostname information to devices
            for ip, hostname in dns_records.items():
                if ip in self.devices:
                    self.devices[ip]["hostname"] = hostname
            
            # Generate reports on the network topology
            for subnet, ips in self.subnets.items():
                # Skip if we've already reported this subnet
                if subnet in self.reported_networks:
                    continue
                
                self.reported_networks.add(subnet)
                
                # Find likely gateway for this subnet
                likely_gateway = None
                max_score = 0
                for ip in ips:
                    if self.potential_gateways[ip] > max_score:
                        max_score = self.potential_gateways[ip]
                        likely_gateway = ip
                
                # Create basic topology report
                devices_count = len(ips)
                gateway_info = f"Likely gateway: {likely_gateway}" if likely_gateway else "Gateway not identified"
                
                alert_msg = f"Network topology: Subnet {subnet} contains {devices_count} devices. {gateway_info}"
                alerts.append(alert_msg)
                
                # Create detailed subnet information for database storage
                subnet_details = {
                    "subnet": subnet,
                    "device_count": devices_count,
                    "gateway": likely_gateway,
                    "devices": []
                }
                
                # Add information about the most interesting devices (gateways, servers)
                interesting_devices = []
                for ip in ips:
                    if ip in self.devices:
                        device_info = self.devices[ip].copy()
                        # Convert sets to lists for JSON serialization
                        device_info["ports_used"] = list(device_info.get("ports_used", []))
                        device_info["protocols"] = list(device_info.get("protocols", []))
                        
                        device_info["ip"] = ip
                        device_info["gateway_score"] = self.potential_gateways[ip]
                        
                        # Identify if this is likely a server
                        is_server = False
                        for port in device_info["ports_used"]:
                            if isinstance(port, int) and port < 1024:
                                is_server = True
                                break
                        
                        device_info["likely_server"] = is_server
                        interesting_devices.append(device_info)
                
                # Sort by gateway score (highest first)
                interesting_devices.sort(key=lambda x: x["gateway_score"], reverse=True)
                
                # Add the most interesting devices to the subnet details
                subnet_details["devices"] = interesting_devices[:10]  # Top 10 most interesting
                
                # Store subnet details in the database
                self._store_network_map(subnet, subnet_details)
                
                # Add to red findings - Map interesting network topologies
                self._add_subnet_to_red_findings(subnet, subnet_details)
                
                # Report interesting devices individually
                for device in interesting_devices:
                    if device["gateway_score"] > 5 or device["likely_server"]:
                        # Check if we've already reported this device
                        device_ip = device["ip"]
                        if device_ip not in self.reported_devices:
                            self.reported_devices.add(device_ip)
                            self._add_device_to_red_findings(device)
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Network Topology Mapper: {e}"
            logging.error(error_msg)
            return [error_msg]
    
    def _add_subnet_to_red_findings(self, subnet, subnet_details):
        """Add subnet information to red team findings"""
        try:
            # Only add significant subnets with multiple devices
            if subnet_details["device_count"] < 3:
                return
                
            # Create description
            description = f"Network subnet {subnet} identified with {subnet_details['device_count']} devices"
            
            # Create detailed information
            details = {
                "subnet": subnet,
                "device_count": subnet_details["device_count"],
                "gateway": subnet_details.get("gateway", "Unknown"),
                "networks_connected": [],
                "key_systems": []
            }
            
            # Add info about connected networks
            connected_subnets = set()
            for device in subnet_details.get("devices", []):
                # Use the device's IP to get the subnet
                device_ip = device.get("ip")
                if device_ip and self.potential_gateways.get(device_ip, 0) > 0:
                    # This device connects to other subnets, find which ones
                    for other_subnet, other_ips in self.subnets.items():
                        if other_subnet != subnet and device_ip not in other_ips:
                            # Check if this device communicates with any IP in the other subnet
                            communicates = False
                            for other_ip in other_ips:
                                # Simple check - if both are gateways, they probably communicate
                                if self.potential_gateways.get(other_ip, 0) > 0:
                                    communicates = True
                                    break
                                    
                            if communicates:
                                connected_subnets.add(other_subnet)
            
            details["networks_connected"] = list(connected_subnets)
            
            # Add info about key systems
            for device in subnet_details.get("devices", [])[:5]:  # Top 5 most interesting
                if device.get("likely_server") or device.get("gateway_score", 0) > 3:
                    key_system = {
                        "ip": device.get("ip", ""),
                        "hostname": device.get("hostname", "Unknown"),
                        "role": "Gateway" if device.get("gateway_score", 0) > 3 else "Server",
                        "protocols": device.get("protocols", [])
                    }
                    details["key_systems"].append(key_system)
            
            # Determine severity - network mapping itself is not a vulnerability
            severity = "low"
            
            # Calculate value of this subnet for red teaming
            if subnet_details.get("gateway") and len(details["networks_connected"]) > 1:
                # This subnet connects to multiple other networks - higher value target
                severity = "medium"
                
            # Create remediation guidance
            remediation = "Network segmentation via VLANs, subnets, and firewall rules to limit lateral movement. Implement principle of least privilege for network access."
            
            # Add to red findings
            if hasattr(self, 'analysis_manager') and self.analysis_manager and hasattr(self.analysis_manager, 'red_report_manager'):
                self.analysis_manager.red_report_manager.add_red_finding(
                    src_ip="N/A",  # No specific source IP for network mapping
                    dst_ip=subnet.split('/')[0],  # Use subnet as destination
                    rule_name=self.name,
                    description=description,
                    severity=severity,
                    details=details,
                    remediation=remediation
                )
            else:
                logging.warning("Cannot add red finding: red_report_manager not available")
            
        except Exception as e:
            logging.error(f"Error adding subnet to red findings: {e}")
    
    def _add_device_to_red_findings(self, device):
        """Add interesting device information to red team findings"""
        try:
            device_ip = device.get("ip")
            hostname = device.get("hostname", "Unknown")
            ports_used = device.get("ports_used", [])
            
            # Determine device role
            role = "Unknown"
            if device.get("gateway_score", 0) > 5:
                role = "Gateway/Router"
            elif device.get("likely_server"):
                role = "Server"
                
                # Try to determine server type based on ports
                server_ports = {
                    80: "Web Server",
                    443: "Web Server (HTTPS)",
                    21: "FTP Server",
                    22: "SSH Server",
                    23: "Telnet Server",
                    25: "SMTP Server",
                    53: "DNS Server",
                    445: "File Server (SMB)",
                    3389: "RDP Server",
                    3306: "MySQL Database",
                    1433: "MSSQL Database",
                    5432: "PostgreSQL Database",
                    27017: "MongoDB Database"
                }
                
                for port in ports_used:
                    if port in server_ports:
                        role = server_ports[port]
                        break
            
            # Create description
            display_name = hostname if hostname != "Unknown" else device_ip
            description = f"Key network device identified: {display_name} ({role})"
            
            # Create detailed information
            details = {
                "ip": device_ip,
                "hostname": hostname,
                "role": role,
                "gateway_score": device.get("gateway_score", 0),
                "likely_server": device.get("likely_server", False),
                "ports_used": sorted(ports_used),
                "protocols": device.get("protocols", []),
                "connections": device.get("connections", 0),
                "data_transferred": device.get("data_transferred", 0),
                "subnet": self._get_subnet(device_ip)
            }
            
            # Determine severity based on role and importance
            severity = "low"
            if role in ["Gateway/Router", "Domain Controller", "LDAP Server", "DNS Server"]:
                severity = "medium"  # Infrastructure servers are higher value targets
            
            # Special consideration for devices with large connection counts
            if device.get("connections", 0) > 1000:
                severity = "medium"  # High-traffic nodes are important
                
            # Create remediation guidance based on role
            if role == "Gateway/Router":
                remediation = "Ensure router has strong access controls, updated firmware, and properly configured ACLs. Monitor for unauthorized access attempts."
            elif "Server" in role:
                remediation = "Implement host-based firewall rules to limit access to necessary services only. Ensure server is patched and running minimal required services."
            else:
                remediation = "Review network access control for this device. Implement monitoring for unusual connection patterns."
            
            # Add to red findings
            if hasattr(self, 'analysis_manager') and self.analysis_manager and hasattr(self.analysis_manager, 'red_report_manager'):
                self.analysis_manager.red_report_manager.add_red_finding(
                    src_ip="N/A",  # No specific source IP for device discovery
                    dst_ip=device_ip,
                    rule_name=self.name,
                    description=description,
                    severity=severity,
                    details=details,
                    remediation=remediation
                )
            else:
                logging.warning("Cannot add red finding: red_report_manager not available")
            
        except Exception as e:
            logging.error(f"Error adding device to red findings: {e}")
    
    def _is_internal_ip(self, ip):
        """Check if an IP address is internal/private"""
        if not ip:
            return False
            
        # Check RFC1918 private ranges
        if ip.startswith('10.') or ip.startswith('192.168.'):
            return True
        if ip.startswith('172.'):
            parts = ip.split('.')
            if len(parts) > 1:
                second_octet = int(parts[1])
                if 16 <= second_octet <= 31:
                    return True
        
        # Check localhost
        if ip.startswith('127.'):
            return True
            
        # Check link-local
        if ip.startswith('169.254.'):
            return True
            
        return False
    
    def _get_subnet(self, ip):
        """Extract the subnet from an IP address (simple /24 assumption)"""
        if not ip or not self._is_internal_ip(ip):
            return None
            
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            
        return None
    
    def _store_network_map(self, subnet, subnet_details):
        """Store the network map in the database for later exploitation"""
        try:
            # If we have an analysis_manager, store data in x_ip_threat_intel
            if hasattr(self, 'analysis_manager') and self.analysis_manager:
                # Create a dummy IP for the subnet (for storage purposes)
                subnet_ip = subnet.split('/')[0]
                
                # Create threat intel entry for this subnet
                threat_data = {
                    "score": 0,  # Not a threat, just information
                    "type": "network_topology",
                    "confidence": 0.9,
                    "source": self.name,
                    "details": subnet_details,
                    "protocol": "NETWORK",
                    "detection_method": "traffic_analysis"
                }
                
                # Store in the threat_intel table
                self.analysis_manager.update_threat_intel(subnet_ip, threat_data)
                
                # If gateway is identified, add it to the database too
                if subnet_details["gateway"]:
                    gateway_ip = subnet_details["gateway"]
                    
                    # Create threat intel entry for this gateway
                    gateway_data = {
                        "score": 0,  # Not a threat, just information
                        "type": "network_gateway",
                        "confidence": 0.8,
                        "source": self.name,
                        "details": {
                            "subnet": subnet,
                            "gateway_score": self.potential_gateways[gateway_ip],
                            "device_info": self.devices.get(gateway_ip, {})
                        },
                        "protocol": "NETWORK",
                        "detection_method": "traffic_analysis"
                    }
                    
                    # Store in the threat_intel table
                    self.analysis_manager.update_threat_intel(gateway_ip, gateway_data)
        except Exception as e:
            logging.error(f"Error storing network map: {e}")
    
    def get_params(self):
        return {
            "analysis_interval": {
                "type": "int",
                "default": 300,
                "current": self.analysis_interval,
                "description": "Interval between analyses (seconds)"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "analysis_interval":
            self.analysis_interval = int(value)
            return True
        return False