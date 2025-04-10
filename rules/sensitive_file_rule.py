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
        
        # Define specific high-risk files and their severity
        self.high_risk_files = {
            # Critical files
            "id_rsa": "critical",
            "id_dsa": "critical",
            "config.php": "high",
            "wp-config.php": "critical",
            ".env": "critical",
            ".htpasswd": "critical",
            "credentials.xml": "critical",
            "password.txt": "critical",
            "database.yml": "critical",
            # High severity files
            "web.config": "high",
            ".aws/credentials": "critical",
            ".ssh/config": "high",
            "settings.xml": "high",
            "hibernate.cfg.xml": "high",
            "application.properties": "high",
            "application.yml": "high",
            "settings.json": "high"
        }
        
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
                    
                    # Add to red findings
                    self._add_sensitive_file_to_red_findings(
                        src_ip, 
                        dst_ip, 
                        filename, 
                        "SMB", 
                        reason, 
                        connection_key, 
                        file_size=size, 
                        operation=operation
                    )
            
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
                    
                    # Add to red findings
                    self._add_sensitive_file_to_red_findings(
                        src_ip, 
                        dst_ip, 
                        filename, 
                        "HTTP", 
                        reason, 
                        connection_key, 
                        method=method, 
                        host=host, 
                        uri=uri
                    )
            
            # Prevent the detected set from growing too large
            if len(self.detected_files) > 1000:
                # Clear out half the old entries
                self.detected_files = set(list(self.detected_files)[-500:])
            
            return alerts
            
        except Exception as e:
            alerts.append(f"Error in Sensitive File Detector: {e}")
            logging.error(f"Error in Sensitive File Detector: {e}")
            return alerts
    
    def _add_sensitive_file_to_red_findings(self, src_ip, dst_ip, filename, protocol, reason, connection_key, **kwargs):
        """Add detected sensitive file to red team findings"""
        try:
            # Determine severity based on filename and extension
            filename_lower = filename.lower()
            basename = filename_lower.split('/')[-1]
            
            # Check for known high-risk files first
            for high_risk_file, severity in self.high_risk_files.items():
                if basename.endswith(high_risk_file) or high_risk_file in basename:
                    risk_severity = severity
                    break
            else:
                # Default severity assessment
                risk_severity = "medium"
                
                # Check for high-risk indicators
                if any(kw in filename_lower for kw in ["password", "secret", "key", "token", "credential", "admin"]):
                    risk_severity = "high"
                
                # Check for critical file extensions
                critical_extensions = [".pem", ".key", ".pkcs12", ".p12", ".pfx", ".keystore", ".env", ".htpasswd"]
                high_extensions = [".conf", ".config", ".yml", ".yaml", ".properties", ".ini", ".bak", ".sql", ".db"]
                
                for ext in critical_extensions:
                    if filename_lower.endswith(ext):
                        risk_severity = "critical"
                        break
                
                if risk_severity != "critical":  # Only check high extensions if not already critical
                    for ext in high_extensions:
                        if filename_lower.endswith(ext):
                            risk_severity = "high"
                            break
            
            # Create appropriate description
            if protocol == "SMB":
                operation = kwargs.get("operation", "access")
                description = f"Sensitive file {operation} over SMB: {filename}"
            else:  # HTTP
                host = kwargs.get("host", dst_ip)
                method = kwargs.get("method", "GET")
                description = f"Sensitive file accessed over HTTP: {host}{kwargs.get('uri', '')}"
            
            # Create details dictionary with all relevant information
            details = {
                "filename": filename,
                "protocol": protocol,
                "detection_reason": reason,
                "severity": risk_severity
            }
            
            # Add protocol-specific details
            if protocol == "SMB":
                details.update({
                    "operation": kwargs.get("operation", "unknown"),
                    "file_size": kwargs.get("file_size", "unknown")
                })
            else:  # HTTP
                details.update({
                    "host": kwargs.get("host", dst_ip),
                    "uri": kwargs.get("uri", ""),
                    "method": kwargs.get("method", "GET"),
                    "is_encrypted": False if kwargs.get("host", "").startswith("http://") else True
                })
            
            # Create recommendations based on file type
            if ".key" in filename_lower or ".pem" in filename_lower or "id_rsa" in filename_lower:
                remediation = "Immediately rotate this cryptographic key. Private keys should never be transmitted over the network, especially unencrypted protocols."
            elif ".env" in filename_lower or "config" in filename_lower:
                remediation = "Review and secure this configuration file. Configuration files often contain sensitive information like database credentials and API keys. Use environment variables or secret management systems instead."
            elif ".bak" in filename_lower or ".backup" in filename_lower:
                remediation = "Remove backup files from public-facing servers. Backup files may contain sensitive information or configuration data not intended for public access."
            elif ".sql" in filename_lower or ".db" in filename_lower:
                remediation = "Secure database files and ensure they are not accessible via web servers. Database files may contain sensitive information like user accounts and personal data."
            else:
                remediation = "Review access controls for sensitive files. Implement proper authentication and authorization for file access. Consider encrypting sensitive data both in transit and at rest."
            
            # Add to red findings
            self.add_red_finding(
                src_ip=src_ip,
                dst_ip=dst_ip,
                description=description,
                severity=risk_severity,
                details=details,
                connection_key=connection_key,
                remediation=remediation
            )
            
        except Exception as e:
            logging.error(f"Error adding sensitive file to red findings: {e}")
    
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