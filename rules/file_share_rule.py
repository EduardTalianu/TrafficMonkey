# Rule class is injected by the RuleLoader
import logging
import time

class InsecureFileShareDetectorRule(Rule):
    """Rule that identifies insecure file shares and weak file permissions"""
    def __init__(self):
        super().__init__(
            name="Insecure File Share Detector",
            description="Identifies accessible SMB shares and potential file permission weaknesses"
        )
        # Track detected shares
        self.detected_shares = set()
        
        # Track users with access to shares
        self.share_access = {}
        
        # Track file operations that might indicate weak permissions
        self.interesting_files = set()
        
        # Last analysis time
        self.last_analysis_time = 0
        # Analysis interval in seconds
        self.analysis_interval = 600  # 10 minutes
    
    def analyze(self, db_cursor):
        alerts = []
        
        current_time = time.time()
        if current_time - self.last_analysis_time < self.analysis_interval:
            return []
            
        self.last_analysis_time = current_time
        
        try:
            # Look for SMB authentication sessions
            db_cursor.execute("""
                SELECT sa.connection_key, sa.domain, sa.account, sa.share_name,
                       c.src_ip, c.dst_ip, c.dst_port
                FROM smb_auth sa
                JOIN connections c ON sa.connection_key = c.connection_key
                ORDER BY sa.timestamp DESC
            """)
            
            for row in db_cursor.fetchall():
                connection_key, domain, account, share_name, src_ip, dst_ip, dst_port = row
                
                # Skip if no share name
                if not share_name:
                    continue
                
                # Create a unique key for this share
                share_key = f"{dst_ip}:{share_name}"
                
                # Track user access to shares
                if share_key not in self.share_access:
                    self.share_access[share_key] = set()
                
                user_key = f"{domain}\\{account}" if domain else account
                self.share_access[share_key].add(user_key)
                
                # Skip if already detected
                if share_key in self.detected_shares:
                    continue
                    
                self.detected_shares.add(share_key)
                
                # Alert on detected share
                alert_msg = f"SMB share detected: \\\\{dst_ip}\\{share_name} - Account: {user_key}"
                alerts.append(alert_msg)
                
                # Add detailed alert
                detailed_msg = f"SMB share access: {user_key} connected to \\\\{dst_ip}\\{share_name}"
                self.add_alert(dst_ip, detailed_msg)
                
                # Store for later exploitation
                self._store_share_info(dst_ip, share_name, domain, account)
                
                # Add to red findings
                self._add_share_to_red_findings(
                    src_ip, 
                    dst_ip, 
                    share_name, 
                    domain, 
                    account, 
                    connection_key
                )
            
            # Look for file operations that might indicate writable shares
            db_cursor.execute("""
                SELECT sf.connection_key, sf.filename, sf.operation, sf.size,
                       c.src_ip, c.dst_ip
                FROM smb_files sf
                JOIN connections c ON sf.connection_key = c.connection_key
                ORDER BY sf.timestamp DESC
                LIMIT 1000
            """)
            
            for row in db_cursor.fetchall():
                connection_key, filename, operation, size, src_ip, dst_ip = row
                
                # Skip if no filename or operation
                if not filename or not operation:
                    continue
                
                # Focus on write operations
                if operation.upper() in ['WRITE', 'CREATE', 'MKDIR', 'RMDIR', 'DELETE', 'RENAME']:
                    # Create a unique key for this file operation
                    file_key = f"{dst_ip}:{filename}:{operation}"
                    
                    # Skip if already detected
                    if file_key in self.interesting_files:
                        continue
                        
                    self.interesting_files.add(file_key)
                    
                    # Alert on writable access
                    alert_msg = f"Writable SMB access detected: {src_ip} performed {operation} on {filename} at {dst_ip}"
                    alerts.append(alert_msg)
                    
                    # Add detailed alert
                    detailed_msg = f"Write access to SMB share: {src_ip} {operation} {filename} on {dst_ip}"
                    self.add_alert(dst_ip, detailed_msg)
                    
                    # Store information about writable share
                    self._store_file_access(dst_ip, filename, operation, src_ip)
                    
                    # Add to red findings
                    self._add_writable_share_to_red_findings(
                        src_ip, 
                        dst_ip, 
                        filename, 
                        operation, 
                        size, 
                        connection_key
                    )
            
            # Prevent the sets from growing too large
            if len(self.detected_shares) > 500:
                self.detected_shares = set(list(self.detected_shares)[-250:])
            
            if len(self.interesting_files) > 1000:
                self.interesting_files = set(list(self.interesting_files)[-500:])
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Insecure File Share Detector: {e}"
            logging.error(error_msg)
            return [error_msg]
    
    def _add_share_to_red_findings(self, src_ip, dst_ip, share_name, domain, account, connection_key):
        """Add detected SMB share to red team findings"""
        try:
            # Format user account
            user_account = f"{domain}\\{account}" if domain else account
            
            # Create suitable description
            description = f"SMB share access: \\\\{dst_ip}\\{share_name}"
            
            # Determine severity based on share name
            severity = "medium"
            common_admin_shares = ["ADMIN$", "C$", "IPC$"]
            if share_name in common_admin_shares:
                severity = "high"  # Administrative shares are high risk
            elif share_name.lower() in ["users", "public", "shared", "documents", "data"]:
                severity = "medium"  # Common user data shares are medium risk
            
            # Create detailed information
            details = {
                "share_name": share_name,
                "host": dst_ip,
                "account": user_account,
                "access_type": "SMB",
                "technique": "Network Share Discovery (MITRE ATT&CK T1135)"
            }
            
            # Add information about account and share type
            if share_name in common_admin_shares:
                details["share_type"] = "Administrative"
                details["risk"] = "Administrative shares can provide system-level access"
            else:
                details["share_type"] = "User"
                details["risk"] = "User shares may contain sensitive data and can be used for lateral movement"
            
            # Add users with access if known
            if f"{dst_ip}:{share_name}" in self.share_access:
                details["users_with_access"] = list(self.share_access[f"{dst_ip}:{share_name}"])
            
            # Create remediation guidance
            if share_name in common_admin_shares:
                remediation = (
                    f"Administrative share \\\\{dst_ip}\\{share_name} is accessible by {user_account}.\n\n"
                    "Recommended actions:\n"
                    "1. Restrict administrative share access to only necessary administrator accounts\n"
                    "2. Implement network segmentation to limit access to administrative shares\n"
                    "3. Ensure SMB signing is enabled to prevent NTLM relay attacks\n"
                    "4. Monitor access to administrative shares for suspicious activity\n"
                    "5. Consider disabling administrative shares if not needed"
                )
            else:
                remediation = (
                    f"SMB share \\\\{dst_ip}\\{share_name} is accessible by {user_account}.\n\n"
                    "Recommended actions:\n"
                    "1. Review share permissions to ensure only necessary users have access\n"
                    "2. Implement least privilege principle for share access\n"
                    "3. Enable access auditing for sensitive shares\n"
                    "4. Ensure SMB signing is enabled to prevent NTLM relay attacks\n"
                    "5. Consider moving to a more secure file sharing solution if needed"
                )
            
            # Add to red findings
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
            logging.error(f"Error adding share to red findings: {e}")
    
    def _add_writable_share_to_red_findings(self, src_ip, dst_ip, filename, operation, size, connection_key):
        """Add writable SMB share to red team findings"""
        try:
            # Create suitable description
            description = f"Writable SMB share detected on {dst_ip}"
            
            # Determine severity based on operation
            severity = "high"  # Writable shares are generally high risk
            
            # Try to determine file type from name
            file_type = "Unknown"
            if "." in filename:
                extension = filename.split(".")[-1].lower()
                if extension in ["exe", "dll", "bat", "cmd", "ps1", "vbs", "js"]:
                    file_type = "Executable"
                    severity = "critical"  # Writing executables is critical risk
                elif extension in ["doc", "docx", "xls", "xlsx", "pdf", "txt"]:
                    file_type = "Document"
                elif extension in ["zip", "tar", "gz", "rar"]:
                    file_type = "Archive"
                elif extension in ["jpg", "png", "gif", "bmp"]:
                    file_type = "Image"
                    severity = "medium"  # Images are lower risk
                elif extension in ["conf", "config", "ini", "xml", "json"]:
                    file_type = "Configuration"
                    severity = "high"  # Config files are high risk
            
            # Create detailed information
            details = {
                "filename": filename,
                "operation": operation,
                "file_size": size,
                "file_type": file_type,
                "source_ip": src_ip,
                "technique": "Data Staged (MITRE ATT&CK T1074)"
            }
            
            # Add operation-specific details
            if operation.upper() == 'WRITE' or operation.upper() == 'CREATE':
                details["attack_vector"] = "File creation can be used for persistence or code execution"
                details["potential_attacks"] = [
                    "Malicious file upload for later execution",
                    "WebShell placement",
                    "Persistence mechanism installation",
                    "Configuration file modification"
                ]
            elif operation.upper() == 'DELETE' or operation.upper() == 'RMDIR':
                details["attack_vector"] = "File deletion can be used for anti-forensics or sabotage"
                details["potential_attacks"] = [
                    "Log deletion or modification",
                    "Evidence removal",
                    "Critical file deletion"
                ]
                
            # Create remediation guidance
            remediation = (
                f"Writable SMB share detected - {src_ip} performed {operation} operation on {filename}.\n\n"
                "Recommended actions:\n"
                "1. Review shared folder permissions and implement least privilege\n"
                "2. Use read-only permissions where write access is not required\n"
                "3. Implement file auditing to track file modifications\n"
                "4. Consider restricting executable file types on shares\n"
                "5. Implement integrity monitoring for critical files\n"
                "6. Regularly scan shared folders for malicious content"
            )
            
            # Add to red findings
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
            logging.error(f"Error adding writable share to red findings: {e}")
    
    def _store_share_info(self, ip, share_name, domain, account):
        """Store share information in the database for later exploitation"""
        try:
            # If we have an analysis_manager, store data in x_ip_threat_intel
            if hasattr(self, 'analysis_manager') and self.analysis_manager:
                # Create threat intel entry for this share
                user_key = f"{domain}\\{account}" if domain else account
                
                threat_data = {
                    "score": 5.0,  # Medium score for file share
                    "type": "smb_share",
                    "confidence": 0.9,
                    "source": self.name,
                    "details": {
                        "share_name": share_name,
                        "accessed_by": user_key,
                        "discovery_time": time.time(),
                        "users_with_access": list(self.share_access.get(f"{ip}:{share_name}", []))
                    },
                    "protocol": "SMB",
                    "destination_port": 445,
                    "detection_method": "smb_traffic_analysis"
                }
                
                # Store in the threat_intel table
                self.analysis_manager.update_threat_intel(ip, threat_data)
        except Exception as e:
            logging.error(f"Error storing share information: {e}")
    
    def _store_file_access(self, ip, filename, operation, src_ip):
        """Store file access information in the database for later exploitation"""
        try:
            # If we have an analysis_manager, store data in x_ip_threat_intel
            if hasattr(self, 'analysis_manager') and self.analysis_manager:
                # Create threat intel entry for this file access
                threat_data = {
                    "score": 7.0,  # Higher score for writable access
                    "type": "writable_share",
                    "confidence": 0.8,
                    "source": self.name,
                    "details": {
                        "filename": filename,
                        "operation": operation,
                        "accessed_by": src_ip,
                        "discovery_time": time.time()
                    },
                    "protocol": "SMB",
                    "destination_port": 445,
                    "detection_method": "smb_traffic_analysis"
                }
                
                # Store in the threat_intel table
                self.analysis_manager.update_threat_intel(ip, threat_data)
        except Exception as e:
            logging.error(f"Error storing file access information: {e}")
    
    def get_params(self):
        return {
            "analysis_interval": {
                "type": "int",
                "default": 600,
                "current": self.analysis_interval,
                "description": "Interval between analyses (seconds)"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "analysis_interval":
            self.analysis_interval = int(value)
            return True
        return False