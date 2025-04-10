# Rule class is injected by the RuleLoader
import logging
from collections import defaultdict
import time
import re

class PrivilegeEscalationDetectorRule(Rule):
    """Rule that identifies privilege escalation opportunities in network traffic"""
    def __init__(self):
        super().__init__(
            name="Privilege Escalation Detector",
            description="Identifies privilege escalation opportunities from network traffic"
        )
        # Track administrative sessions
        self.admin_sessions = set()
        # Track detected vulnerabilities
        self.detected_vulns = set()
        # Track vulnerable software versions
        self.vulnerable_software = {
            # Format: "software_name": {"version": "CVE/vulnerability description"}
            "Apache": {
                "2.4.49": "CVE-2021-41773 - Path Traversal/RCE",
                "2.4.50": "CVE-2021-42013 - Path Traversal/RCE"
            },
            "Tomcat": {
                "9.0.0": "Multiple RCE vulnerabilities",
                "8.5.": "Potential vulnerabilities if unpatched"
            },
            "JBoss": {
                "": "Potential for default credentials"
            },
            "Jenkins": {
                "": "Common privilege escalation target"
            },
            "WebLogic": {
                "": "History of critical RCE vulnerabilities"
            }
        }
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
            # Look for administrative sessions (RDP, SSH, admin panels)
            db_cursor.execute("""
                SELECT c.connection_key, c.src_ip, c.dst_ip, c.dst_port
                FROM connections c
                WHERE c.dst_port IN (22, 3389, 5985, 5986)
                ORDER BY c.timestamp DESC
                LIMIT 1000
            """)
            
            for row in db_cursor.fetchall():
                connection_key, src_ip, dst_ip, dst_port = row
                
                # Create a unique key for this admin session
                admin_key = f"{src_ip}->{dst_ip}:{dst_port}"
                
                # Skip if already detected
                if admin_key in self.admin_sessions:
                    continue
                
                self.admin_sessions.add(admin_key)
                
                # Determine protocol
                protocol = "Unknown"
                if dst_port == 22:
                    protocol = "SSH"
                elif dst_port == 3389:
                    protocol = "RDP"
                elif dst_port in [5985, 5986]:
                    protocol = "WinRM"
                
                alert_msg = f"Administrative access channel detected: {protocol} from {src_ip} to {dst_ip}"
                alerts.append(alert_msg)
                
                # Store for later use
                self._store_admin_access(src_ip, dst_ip, protocol)
                
                # Add to red findings
                self._add_admin_session_to_red_findings(src_ip, dst_ip, protocol, dst_port, connection_key)
            
            # Look for vulnerable web server versions
            db_cursor.execute("""
                SELECT res.server, r.host, c.dst_ip, c.dst_port, c.connection_key
                FROM http_responses res
                JOIN http_requests r ON res.http_request_id = r.id
                JOIN connections c ON r.connection_key = c.connection_key
                WHERE res.server IS NOT NULL
                GROUP BY res.server, c.dst_ip
            """)
            
            for row in db_cursor.fetchall():
                server, host, dst_ip, dst_port, connection_key = row
                
                # Skip if no server header
                if not server:
                    continue
                
                # Check against vulnerable software list
                for software_name, versions in self.vulnerable_software.items():
                    if software_name.lower() in server.lower():
                        # Check if this is a vulnerable version
                        for version_prefix, vulnerability in versions.items():
                            # Empty prefix means any version
                            if not version_prefix or version_prefix in server:
                                # Create a unique key
                                vuln_key = f"{software_name}:{dst_ip}:{server}"
                                
                                # Skip if already detected
                                if vuln_key in self.detected_vulns:
                                    continue
                                
                                self.detected_vulns.add(vuln_key)
                                
                                alert_msg = f"Potential privilege escalation target: {software_name} on {host or dst_ip}:{dst_port} - {server} - {vulnerability}"
                                alerts.append(alert_msg)
                                
                                # Add detailed alert
                                self.add_alert(dst_ip, f"Privilege escalation opportunity: {software_name} ({server}) - {vulnerability}")
                                
                                # Store vulnerability information
                                self._store_vulnerability(dst_ip, software_name, server, vulnerability)
                                
                                # Add to red findings
                                self._add_vulnerability_to_red_findings(
                                    dst_ip, 
                                    software_name, 
                                    server, 
                                    vulnerability, 
                                    host, 
                                    dst_port, 
                                    connection_key
                                )
            
            # Look for web applications commonly used for privilege escalation
            db_cursor.execute("""
                SELECT c.dst_ip, r.host, r.uri, c.dst_port, c.connection_key
                FROM http_requests r
                JOIN connections c ON r.connection_key = c.connection_key
                WHERE r.uri LIKE '/admin%' OR r.uri LIKE '/manager%' 
                   OR r.uri LIKE '/console%' OR r.uri LIKE '/wp-admin%'
                   OR r.uri LIKE '/phpmyadmin%' OR r.uri LIKE '/jenkins%'
                GROUP BY c.dst_ip, r.uri
            """)
            
            for row in db_cursor.fetchall():
                dst_ip, host, uri, dst_port, connection_key = row
                
                # Extract application type
                app_type = "Unknown"
                if "/admin" in uri:
                    app_type = "Admin Panel"
                elif "/manager" in uri:
                    app_type = "Tomcat Manager"
                elif "/console" in uri:
                    app_type = "Web Console"
                elif "/wp-admin" in uri:
                    app_type = "WordPress Admin"
                elif "/phpmyadmin" in uri:
                    app_type = "phpMyAdmin"
                elif "/jenkins" in uri:
                    app_type = "Jenkins"
                
                # Create a unique key
                app_key = f"{app_type}:{dst_ip}:{uri}"
                
                # Skip if already detected
                if app_key in self.detected_vulns:
                    continue
                
                self.detected_vulns.add(app_key)
                
                alert_msg = f"Potential privilege escalation target: {app_type} on {host or dst_ip}:{dst_port}{uri}"
                alerts.append(alert_msg)
                
                # Add detailed alert
                self.add_alert(dst_ip, f"Privilege escalation opportunity: {app_type} accessible at http{'s' if dst_port == 443 else ''}://{host or dst_ip}:{dst_port}{uri}")
                
                # Store application information
                self._store_vulnerability(dst_ip, app_type, uri, "Administrative interface accessible over network")
                
                # Add to red findings
                self._add_admin_interface_to_red_findings(
                    dst_ip, 
                    app_type, 
                    uri, 
                    host, 
                    dst_port, 
                    connection_key
                )
            
            # Prevent the detected sets from growing too large
            if len(self.admin_sessions) > 1000:
                self.admin_sessions = set(list(self.admin_sessions)[-500:])
            
            if len(self.detected_vulns) > 1000:
                self.detected_vulns = set(list(self.detected_vulns)[-500:])
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Privilege Escalation Detector: {e}"
            logging.error(error_msg)
            return [error_msg]
    
    def _add_admin_session_to_red_findings(self, src_ip, dst_ip, protocol, dst_port, connection_key):
        """Add administrative session to red team findings"""
        try:
            # Create suitable description
            description = f"Administrative access channel: {protocol} from {src_ip} to {dst_ip}"
            
            # Determine severity - admin channels are a medium risk as they're expected but useful for lateral movement
            severity = "medium"
            
            # Create detailed information
            details = {
                "protocol": protocol,
                "port": dst_port,
                "client": src_ip,
                "server": dst_ip,
                "admin_channel_type": protocol,
                "relevance": "Administrative channels can be used for privilege escalation and lateral movement"
            }
            
            # Add protocol-specific details
            if protocol == "RDP":
                details["techniques"] = ["Credential Theft", "Keystroke Logging", "Session Hijacking"]
                details["tools"] = ["mimikatz", "xfreerdp"]
            elif protocol == "SSH":
                details["techniques"] = ["Credential Theft", "Key Theft", "Agent Forwarding Abuse"]
                details["tools"] = ["sshuttle", "ssh proxying"]
            elif protocol == "WinRM":
                details["techniques"] = ["PowerShell Remoting", "Lateral Movement"]
                details["tools"] = ["PowerShell Empire", "Evil-WinRM"]
            
            # Create remediation guidance
            remediation = (
                f"Administrative {protocol} access should be restricted to necessary users only.\n\n"
                "Recommended actions:\n"
                "1. Implement network segmentation to limit administrative access channels\n"
                "2. Use jump hosts/bastion hosts for administrative access\n"
                "3. Implement multi-factor authentication for administrative protocols\n"
                "4. Enable detailed logging for administrative sessions\n"
                "5. Consider using Just-In-Time (JIT) access for administrative privileges"
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
            logging.error(f"Error adding admin session to red findings: {e}")
    
    def _add_vulnerability_to_red_findings(self, dst_ip, software_name, server, vulnerability, host, dst_port, connection_key):
        """Add vulnerable software to red team findings"""
        try:
            # Create suitable description
            description = f"Privilege escalation target: {software_name} on {host or dst_ip}"
            
            # Determine severity based on vulnerability
            severity = "high"  # Most server vulnerabilities with RCE potential are high
            if "critical" in vulnerability.lower() or "RCE" in vulnerability:
                severity = "critical"
            
            # Create detailed information
            details = {
                "software": software_name,
                "version": server,
                "vulnerability": vulnerability,
                "host": host or dst_ip,
                "port": dst_port,
                "target": f"http{'s' if dst_port == 443 else ''}://{host or dst_ip}:{dst_port}"
            }
            
            # Extract CVE if present
            cve_match = re.search(r'CVE-\d+-\d+', vulnerability)
            if cve_match:
                details["cve"] = cve_match.group(0)
            
            # Add software-specific exploitation details
            if software_name == "Apache":
                if "2.4.49" in server or "2.4.50" in server:
                    details["exploitation"] = "Path traversal to RCE via CGI-bin"
                    details["tools"] = ["curl", "Metasploit"]
            elif software_name == "Tomcat":
                details["exploitation"] = "Default credentials, Manager app deployment"
                details["tools"] = ["tomcat-mgr-deploy", "Metasploit"]
            elif software_name == "JBoss":
                details["exploitation"] = "JMX Console, Admin Console, default credentials"
                details["tools"] = ["JexBoss", "Metasploit"]
            elif software_name == "Jenkins":
                details["exploitation"] = "Script Console, Groovy execution"
                details["tools"] = ["Jenkins-attack", "Script Console"]
            
            # Create remediation guidance
            remediation = (
                f"The {software_name} server {server} may be vulnerable to {vulnerability}.\n\n"
                "Recommended actions:\n"
                "1. Update the software to the latest patched version\n"
                "2. Apply security patches for the specific vulnerability\n"
                "3. Implement network access controls to limit exposure\n"
                "4. Use Web Application Firewall rules to block exploitation attempts\n"
                "5. Review configuration for hardening opportunities\n"
                "6. Monitor logs for exploitation attempts"
            )
            
            # Add to red findings
            self.add_red_finding(
                src_ip="N/A",  # No specific source for this finding
                dst_ip=dst_ip,
                description=description,
                severity=severity,
                details=details,
                connection_key=connection_key,
                remediation=remediation
            )
            
        except Exception as e:
            logging.error(f"Error adding vulnerability to red findings: {e}")
    
    def _add_admin_interface_to_red_findings(self, dst_ip, app_type, uri, host, dst_port, connection_key):
        """Add administrative interface to red team findings"""
        try:
            # Create suitable description
            description = f"Administrative interface exposed: {app_type} on {host or dst_ip}"
            
            # Determine severity based on interface type
            severity = "medium"
            if app_type in ["phpMyAdmin", "Jenkins", "Tomcat Manager"]:
                severity = "high"  # These are commonly exploited
            
            # Create detailed information
            details = {
                "interface_type": app_type,
                "uri": uri,
                "host": host or dst_ip,
                "port": dst_port,
                "target": f"http{'s' if dst_port == 443 else ''}://{host or dst_ip}:{dst_port}{uri}"
            }
            
            # Add interface-specific attack vectors
            attack_vectors = []
            default_creds = []
            
            if app_type == "phpMyAdmin":
                attack_vectors = ["SQL Injection", "File Write via SQL", "RCE via plugins"]
                details["exploitation"] = "Database access, potential for file system access and RCE"
            elif app_type == "Jenkins":
                attack_vectors = ["Script Console", "Build execution", "Plugin vulnerabilities"]
                details["exploitation"] = "Execute commands via Groovy scripts or builds"
                default_creds = ["admin:password", "admin:admin"]
            elif app_type == "Tomcat Manager":
                attack_vectors = ["WAR deployment", "Default credentials"]
                details["exploitation"] = "Deploy malicious WAR files for RCE"
                default_creds = ["tomcat:tomcat", "admin:admin", "admin:password"]
            elif app_type == "WordPress Admin":
                attack_vectors = ["Plugin vulnerabilities", "Theme editor", "Brute force"]
                details["exploitation"] = "Edit themes for code execution, exploit plugins"
            
            if attack_vectors:
                details["attack_vectors"] = attack_vectors
            if default_creds:
                details["default_credentials"] = default_creds
            
            # Create remediation guidance
            remediation = (
                f"The {app_type} administrative interface is exposed and could be used for privilege escalation.\n\n"
                "Recommended actions:\n"
                "1. Restrict access to administrative interfaces with IP filtering\n"
                "2. Use strong, unique credentials and disable default accounts\n"
                "3. Implement multi-factor authentication if available\n"
                "4. Consider using a VPN or bastion host for administrative access\n"
                f"5. Regularly update {app_type} to patch security vulnerabilities\n"
                "6. Consider moving administrative interfaces to non-standard ports\n"
                "7. Implement strict session timeout policies"
            )
            
            # Add to red findings
            self.add_red_finding(
                src_ip="N/A",  # No specific source for this finding
                dst_ip=dst_ip,
                description=description,
                severity=severity,
                details=details,
                connection_key=connection_key,
                remediation=remediation
            )
            
        except Exception as e:
            logging.error(f"Error adding admin interface to red findings: {e}")
    
    def _store_admin_access(self, src_ip, dst_ip, protocol):
        """Store administrative access information in database"""
        try:
            # If we have an analysis_manager, store data in x_ip_threat_intel
            if hasattr(self, 'analysis_manager') and self.analysis_manager:
                # Create threat intel entry for the destination (admin accessed machine)
                threat_data = {
                    "score": 0,  # Not a threat, just information
                    "type": "admin_access",
                    "confidence": 0.8,
                    "source": self.name,
                    "details": {
                        "admin_client": src_ip,
                        "access_protocol": protocol,
                        "discovery_time": time.time()
                    },
                    "protocol": protocol,
                    "destination_ip": dst_ip,
                    "detection_method": "traffic_analysis"
                }
                
                # Store in the threat_intel table
                self.analysis_manager.update_threat_intel(dst_ip, threat_data)
        except Exception as e:
            logging.error(f"Error storing admin access information: {e}")
    
    def _store_vulnerability(self, ip, software, version, vulnerability):
        """Store vulnerability information in database"""
        try:
            # If we have an analysis_manager, store data in x_ip_threat_intel
            if hasattr(self, 'analysis_manager') and self.analysis_manager:
                # Create threat intel entry for the vulnerability
                threat_data = {
                    "score": 7.5,  # Default high score for potential privesc
                    "type": "privilege_escalation",
                    "confidence": 0.7,
                    "source": self.name,
                    "details": {
                        "software": software,
                        "version": version,
                        "vulnerability": vulnerability,
                        "discovery_time": time.time()
                    },
                    "detection_method": "version_analysis"
                }
                
                # Store in the threat_intel table
                self.analysis_manager.update_threat_intel(ip, threat_data)
        except Exception as e:
            logging.error(f"Error storing vulnerability information: {e}")
    
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