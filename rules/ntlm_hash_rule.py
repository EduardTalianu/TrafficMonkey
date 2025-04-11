# Rule class is injected by the RuleLoader
import re
import base64
import logging

class NTLMHashCollectorRule(Rule):
    """Rule to detect and extract NTLM authentication hashes for offline cracking"""
    def __init__(self):
        super().__init__(
            name="NTLM Hash Collector",
            description="Detects and extracts NTLM authentication hashes for offline analysis"
        )
        self.detected_hashes = set()  # Track already detected hashes
    
    def analyze(self, db_cursor):
        alerts = []
        try:
            # Query for HTTP headers containing NTLM authentication
            db_cursor.execute("""
                SELECT h.connection_key, header_value, h.header_name, r.host, r.uri
                FROM http_headers h
                LEFT JOIN http_requests r ON h.request_id = r.id
                WHERE h.header_name = 'Authorization' AND h.header_value LIKE 'NTLM %'
            """)
            
            for row in db_cursor.fetchall():
                connection_key, auth_header, header_name, host, uri = row
                
                # Skip if we've already detected this NTLM auth header
                if auth_header in self.detected_hashes:
                    continue
                    
                self.detected_hashes.add(auth_header)
                
                # Extract the base64 encoded NTLM message
                ntlm_b64 = auth_header.split(' ')[1]
                
                try:
                    # Decode the base64 data
                    ntlm_data = base64.b64decode(ntlm_b64)
                    
                    # Check NTLM message type
                    if len(ntlm_data) > 8:
                        # Extract NTLM message type (byte offset 8)
                        ntlm_type = ntlm_data[8]
                        
                        # Extract source and destination IPs from connection key
                        src_ip = connection_key.split('->')[0].split(':')[0]
                        dst_ip = connection_key.split('->')[1].split(':')[0]
                        
                        if ntlm_type == 1:
                            # Type 1: NTLM Negotiate message
                            alert_msg = f"NTLM authentication negotiation detected from {src_ip} to {dst_ip}"
                            alerts.append(alert_msg)
                            
                        elif ntlm_type == 2:
                            # Type 2: NTLM Challenge message from server
                            
                            # Try to extract the challenge value
                            if len(ntlm_data) > 24:
                                challenge = ntlm_data[24:32].hex()
                                alert_msg = f"NTLM Challenge from {dst_ip} to {src_ip}: Challenge={challenge}"
                                alerts.append(alert_msg)
                            else:
                                alert_msg = f"NTLM Challenge from {dst_ip} to {src_ip} (malformed)"
                                alerts.append(alert_msg)
                                
                        elif ntlm_type == 3:
                            # Type 3: NTLM Response message with hash
                            
                            # Format NTLM hash for potential offline cracking
                            ntlm_hash = ntlm_b64  # Base64 representation of the full Type 3 message
                            
                            # Extract username if possible (this is a simplification, real parsing is more complex)
                            username = "unknown"
                            try:
                                # Look for a domain and username in ASCII
                                ascii_data = ntlm_data.decode('ascii', errors='ignore')
                                username_match = re.search(r'([a-zA-Z0-9\.-_]+\\[a-zA-Z0-9\.-_]+)', ascii_data)
                                if username_match:
                                    username = username_match.group(1)
                            except:
                                pass
                            
                            alert_msg = f"NTLM Authentication hash captured from {src_ip} ({username}) to {dst_ip}"
                            alerts.append(alert_msg)
                            
                            # Add detailed alert with actual hash data for potential offline use
                            detailed_msg = f"NTLM Auth hash ({username}): {ntlm_hash[:20]}... (Base64 Type 3 message)"
                            self.add_alert(src_ip, detailed_msg)
                            
                            # Add to red findings
                            self._add_ntlm_hash_to_red_findings(
                                src_ip, 
                                dst_ip, 
                                username, 
                                ntlm_hash, 
                                "HTTP", 
                                connection_key,
                                host=host,
                                uri=uri
                            )
                            
                except Exception as e:
                    logging.error(f"Error processing NTLM data: {e}")
            
            # Also look in other protocols like SMB
            db_cursor.execute("""
                SELECT connection_key, protocol, c.src_ip, c.dst_ip
                FROM connections c
                WHERE protocol = 'SMB' OR dst_port = 445 OR dst_port = 139
            """)
            
            for row in db_cursor.fetchall():
                connection_key, protocol, src_ip, dst_ip = row
                
                # Create a unique key for this SMB connection
                smb_key = f"SMB:{connection_key}"
                if smb_key in self.detected_hashes:
                    continue
                
                self.detected_hashes.add(smb_key)
                
                alert_msg = f"NTLM authentication likely occurred in SMB connection from {src_ip} to {dst_ip}"
                alerts.append(alert_msg)
                
                # Add detailed alert about potential credential capture
                self.add_alert(src_ip, f"Potential NTLM credentials used in SMB connection to {dst_ip}")
                
                # Add to red findings
                self._add_ntlm_hash_to_red_findings(
                    src_ip, 
                    dst_ip, 
                    "unknown", 
                    None, 
                    "SMB", 
                    connection_key,
                    host=None,
                    uri=None,
                    hash_captured=False
                )
            
            # Prevent the detected set from growing too large
            if len(self.detected_hashes) > 1000:
                # Clear out half the old entries
                self.detected_hashes = set(list(self.detected_hashes)[-500:])
            
            return alerts
            
        except Exception as e:
            alerts.append(f"Error in NTLM Hash Collector: {e}")
            return alerts
    
    def _add_ntlm_hash_to_red_findings(self, src_ip, dst_ip, username, ntlm_hash, protocol, connection_key, host=None, uri=None, hash_captured=True):
        """Add detected NTLM hash to red team findings"""
        try:
            # Create appropriate description
            if hash_captured:
                description = f"NTLM authentication hash captured: {username} from {src_ip} to {dst_ip}"
                severity = "high"
            else:
                description = f"NTLM authentication detected: {src_ip} to {dst_ip} via {protocol}"
                severity = "medium"
            
            # Create detailed information
            details = {
                "username": username,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol,
                "hash_captured": hash_captured
            }
            
            # Add protocol-specific details
            if protocol == "HTTP" and host:
                details["host"] = host
                details["uri"] = uri
                details["target"] = f"{host}{uri if uri else ''}"
            
            # Add hash information if captured (first 20 chars only for security)
            if hash_captured and ntlm_hash:
                details["hash_type"] = "NTLMv2" if len(ntlm_hash) > 100 else "NTLMv1"
                details["hash_sample"] = ntlm_hash[:20] + "..." if ntlm_hash else "Unknown"
            
            # Add attack techniques information
            details["techniques"] = ["NTLM Relay", "Pass-the-Hash"]
            if hash_captured:
                details["techniques"].append("Offline Password Cracking")
            
            # Create remediation guidance
            if hash_captured:
                remediation = (
                    "NTLM authentication hashes have been captured and could be used for offline cracking or Pass-the-Hash attacks.\n\n"
                    "Recommended actions:\n"
                    "1. Transition from NTLM to Kerberos authentication where possible\n"
                    "2. Implement SMB signing to prevent NTLM relay attacks\n"
                    "3. Enable Extended Protection for Authentication (EPA) for web applications\n"
                    "4. Implement Network Level Authentication (NLA) for RDP\n"
                    "5. Consider changing the password for the affected user account\n"
                    "6. Monitor for lateral movement using these credentials"
                )
            else:
                remediation = (
                    "NTLM authentication was detected but hashes were not captured in this instance.\n\n"
                    "Recommended actions:\n"
                    "1. Transition from NTLM to Kerberos authentication where possible\n"
                    "2. Implement SMB signing to prevent NTLM relay attacks\n"
                    "3. Review services using NTLM authentication and update configuration\n"
                    "4. Consider using more secure authentication mechanisms"
                )
            
            # Add to red findings directly
            self.add_red_finding(
                src_ip=src_ip,
                dst_ip=dst_ip,
                description=description,
                severity=severity,
                details=details,
                connection_key=connection_key,
                remediation=remediation
            )
            
        except Exception as e:
            logging.error(f"Error adding NTLM hash to red findings: {e}")
    
    def get_params(self):
        # No configurable parameters for this rule
        return {}