# Rule class is injected by the RuleLoader
import logging
import re

class SensitiveFileDetectorRule(Rule):
    """Rule to detect sensitive files being transferred over the network"""
    def __init__(self):
        super().__init__(
            name="Sensitive File Detector",
            description="Detects sensitive files being transferred over HTTP or SMB"
        )
        
        # Define sensitive file extensions
        self.sensitive_extensions = [
            # Config files
            ".config", ".conf", ".ini", ".env", ".properties", ".yml", ".yaml", ".json", ".xml",
            # Credential files
            ".key", ".pem", ".cer", ".crt", ".p12", ".pfx", ".jks", ".keystore", ".htpasswd",
            # Backup files
            ".bak", ".backup", ".old", ".tmp", ".temp", ".swp", ".save",
            # Database files
            ".db", ".sqlite", ".mdb", ".accdb", ".sql", ".dump",
            # Document files
            ".docx", ".xlsx", ".pdf", ".pptx", ".csv", ".txt",
            # Code files (sensitive)
            ".ps1", ".bat", ".sh", ".py", ".js", ".php"
        ]
        
        # Define sensitive file regexes
        self.sensitive_file_patterns = [
            r"password.*\.txt",
            r"secret.*\.",
            r"backup.*\.",
            r"config.*\.",
            r".*\.env",
            r".*\.git/.*",
            r".*\.ssh/.*",
            r".*\.aws/.*",
            r"wp-config\.php",
            r"hibernate\.cfg\.xml",
            r"web\.config",
            r"\.htaccess",
            r".*\.pem",
            r".*\.ppk"
        ]
        
        # Track detected sensitive files to avoid duplicates
        self.detected_files = set()
        
    def analyze(self, db_cursor):
        alerts = []
        try:
            # Query for SMB file access
            db_cursor.execute("""
                SELECT connection_key, filename, size, operation
                FROM smb_files
                WHERE filename IS NOT NULL
            """)
            
            for row in db_cursor.fetchall():
                connection_key, filename, size, operation = row
                
                # Create a unique key for this file detection
                detection_key = f"SMB:{connection_key}:{filename}"
                if detection_key in self.detected_files:
                    continue
                
                # Check if this is a sensitive file
                is_sensitive = False
                reason = ""
                
                # Check extensions
                filename_lower = filename.lower()
                for ext in self.sensitive_extensions:
                    if filename_lower.endswith(ext):
                        is_sensitive = True
                        reason = f"Sensitive extension: {ext}"
                        break
                
                # Check patterns if not already identified
                if not is_sensitive:
                    for pattern in self.sensitive_file_patterns:
                        if re.match(pattern, filename_lower, re.IGNORECASE):
                            is_sensitive = True
                            reason = f"Sensitive pattern: {pattern}"
                            break
                
                if is_sensitive:
                    self.detected_files.add(detection_key)
                    
                    # Extract source and destination IPs from connection key
                    src_ip = connection_key.split('->')[0].split(':')[0]
                    dst_ip = connection_key.split('->')[1].split(':')[0]
                    
                    # Determine risk level
                    risk_level = "Medium"
                    if any(kw in filename_lower for kw in ["password", "secret", "key", "token", "credential"]):
                        risk_level = "High"
                    elif any(ext in filename_lower for ext in [".key", ".pem", ".pfx", ".env"]):
                        risk_level = "High"
                    
                    alert_msg = f"Sensitive file detected over SMB from {src_ip} to {dst_ip}: {filename} ({reason}) [Risk: {risk_level}]"
                    alerts.append(alert_msg)
                    
                    # Add to alerts database
                    self.add_alert(dst_ip, alert_msg)
            
            # Query for HTTP requests with URI
            db_cursor.execute("""
                SELECT connection_key, method, host, uri
                FROM http_requests
                WHERE uri IS NOT NULL
            """)
            
            for row in db_cursor.fetchall():
                connection_key, method, host, uri = row
                
                # Skip if this is not a GET request (most likely to be a file download)
                if method != "GET" and method != "POST":
                    continue
                
                # Get the filename from the URI
                filename = uri.split('/')[-1]
                if '?' in filename:
                    filename = filename.split('?')[0]
                
                # Skip if no filename or empty
                if not filename:
                    continue
                
                # Create a unique key for this file detection
                detection_key = f"HTTP:{connection_key}:{filename}"
                if detection_key in self.detected_files:
                    continue
                
                # Check if this is a sensitive file
                is_sensitive = False
                reason = ""
                
                # Check extensions
                filename_lower = filename.lower()
                for ext in self.sensitive_extensions:
                    if filename_lower.endswith(ext):
                        is_sensitive = True
                        reason = f"Sensitive extension: {ext}"
                        break
                
                # Check patterns if not already identified
                if not is_sensitive:
                    for pattern in self.sensitive_file_patterns:
                        if re.match(pattern, filename_lower, re.IGNORECASE):
                            is_sensitive = True
                            reason = f"Sensitive pattern: {pattern}"
                            break
                
                if is_sensitive:
                    self.detected_files.add(detection_key)
                    
                    # Extract source and destination IPs from connection key
                    src_ip = connection_key.split('->')[0].split(':')[0]
                    dst_ip = connection_key.split('->')[1].split(':')[0]
                    
                    # Determine risk level
                    risk_level = "Medium"
                    if any(kw in filename_lower for kw in ["password", "secret", "key", "token", "credential"]):
                        risk_level = "High"
                    elif any(ext in filename_lower for ext in [".key", ".pem", ".pfx", ".env"]):
                        risk_level = "High"
                    
                    alert_msg = f"Sensitive file detected over HTTP from {src_ip} to {dst_ip} ({host}): {filename} ({reason}) [Risk: {risk_level}]"
                    alerts.append(alert_msg)
                    
                    # Add to alerts database
                    self.add_alert(dst_ip, alert_msg)
            
            # Prevent the detected set from growing too large
            if len(self.detected_files) > 1000:
                # Clear out half the old entries
                self.detected_files = set(list(self.detected_files)[-500:])
            
            return alerts
            
        except Exception as e:
            alerts.append(f"Error in Sensitive File Detector: {e}")
            logging.error(f"Error in Sensitive File Detector: {e}")
            return alerts
    
    def get_params(self):
        return {
            "sensitive_extensions": {
                "type": "str",
                "default": ", ".join(self.sensitive_extensions[:10]) + "...",  # First 10 for brevity
                "current": ", ".join(self.sensitive_extensions[:10]) + "...",
                "description": "Comma-separated list of sensitive file extensions"
            },
            "sensitive_file_patterns": {
                "type": "str",
                "default": ", ".join(self.sensitive_file_patterns[:5]) + "...",  # First 5 for brevity
                "current": ", ".join(self.sensitive_file_patterns[:5]) + "...",
                "description": "Comma-separated list of sensitive file patterns"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "sensitive_extensions":
            self.sensitive_extensions = [e.strip() for e in value.split(",")]
            return True
        elif param_name == "sensitive_file_patterns":
            self.sensitive_file_patterns = [p.strip() for p in value.split(",")]
            return True
        return False