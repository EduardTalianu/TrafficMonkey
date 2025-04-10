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
                SELECT connection_key, header_value 
                FROM http_headers 
                WHERE header_name = 'Authorization' AND header_value LIKE 'NTLM %'
            """)
            
            for row in db_cursor.fetchall():
                connection_key, auth_header = row
                
                # Skip if we've already detected this NTLM auth header
                if auth_header in self.detected_hashes:
                    continue
                    
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
                            self.detected_hashes.add(auth_header)
                            alert_msg = f"NTLM authentication negotiation detected from {src_ip} to {dst_ip}"
                            alerts.append(alert_msg)
                            
                        elif ntlm_type == 2:
                            # Type 2: NTLM Challenge message from server
                            self.detected_hashes.add(auth_header)
                            
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
                            self.detected_hashes.add(auth_header)
                            
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
                            
                except Exception as e:
                    logging.error(f"Error processing NTLM data: {e}")
            
            # Also look in other protocols like SMB
            db_cursor.execute("""
                SELECT connection_key, protocol 
                FROM connections 
                WHERE protocol = 'SMB' OR dst_port = 445 OR dst_port = 139
            """)
            
            for row in db_cursor.fetchall():
                connection_key, protocol = row
                
                # Create a unique key for this SMB connection
                smb_key = f"SMB:{connection_key}"
                if smb_key in self.detected_hashes:
                    continue
                
                self.detected_hashes.add(smb_key)
                
                # Extract source and destination IPs from connection key
                src_ip = connection_key.split('->')[0].split(':')[0]
                dst_ip = connection_key.split('->')[1].split(':')[0]
                
                alert_msg = f"NTLM authentication likely occurred in SMB connection from {src_ip} to {dst_ip}"
                alerts.append(alert_msg)
                
                # Add detailed alert about potential credential capture
                self.add_alert(src_ip, f"Potential NTLM credentials used in SMB connection to {dst_ip}")
            
            # Prevent the detected set from growing too large
            if len(self.detected_hashes) > 1000:
                # Clear out half the old entries
                self.detected_hashes = set(list(self.detected_hashes)[-500:])
            
            return alerts
            
        except Exception as e:
            alerts.append(f"Error in NTLM Hash Collector: {e}")
            return alerts
    
    def get_params(self):
        # No configurable parameters for this rule
        return {}