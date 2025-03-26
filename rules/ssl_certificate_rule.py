# Rule class is injected by the RuleLoader
import time
import re
import logging
from datetime import datetime

class SSLCertificateRule(Rule):
    """Rule that validates SSL/TLS certificates in captured traffic"""
    def __init__(self):
        super().__init__("SSL Certificate Validation", "Detects expired, self-signed, or suspicious SSL/TLS certificates")
        self.check_interval = 3600  # Run this rule every hour (3600 seconds)
        self.last_check_time = 0
        self.certificate_cache = {}  # Cache for certificate validation
        self.alert_on_self_signed = True  # Whether to alert on self-signed certificates
        self.alert_on_expired = True  # Whether to alert on expired certificates
        self.alert_on_weak_crypto = True  # Whether to alert on weak crypto algorithms
        self.alert_on_wildcard = False  # Whether to alert on wildcard certificates
    
    def analyze(self, db_cursor):
        alerts = []
        current_time = time.time()
        
        # Only run this rule periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Check if ssl_certificates table exists
            db_cursor.execute("""
                SELECT name FROM sqlite_master 
                WHERE type='table' AND name='ssl_certificates'
            """)
            
            if not db_cursor.fetchone():
                return []  # Skip rule if table doesn't exist
            
            # Query for TLS traffic from connections (assuming ports 443, 8443 are HTTPS)
            db_cursor.execute("""
                SELECT src_ip, dst_ip, dst_port, connection_key
                FROM connections
                WHERE (dst_port = 443 OR dst_port = 8443 OR dst_port = 465 OR dst_port = 993 OR dst_port = 995)
                AND timestamp > datetime('now', '-1 day')
            """)
            
            # Store results locally
            tls_connections = []
            for row in db_cursor.fetchall():
                tls_connections.append(row)
            
            # Look for certificates in previously analyzed connections
            for src_ip, dst_ip, dst_port, connection_key in tls_connections:
                # Skip if we've analyzed this connection already and cached the result
                if connection_key in self.certificate_cache:
                    continue
                
                # Look up any certificate info we've extracted
                db_cursor.execute("""
                    SELECT subject, issuer, not_before, not_after, is_self_signed, signature_algorithm, subject_alt_names
                    FROM ssl_certificates
                    WHERE connection_key = ?
                """, (connection_key,))
                
                cert_result = db_cursor.fetchone()
                
                if cert_result:
                    subject, issuer, not_before, not_after, is_self_signed, signature_algorithm, subject_alt_names = cert_result
                    
                    # Parse certificate fields for validation
                    try:
                        # Check for self-signed certificates
                        if is_self_signed and self.alert_on_self_signed:
                            alerts.append(f"Self-signed certificate detected: {src_ip} -> {dst_ip}:{dst_port} (Subject: {subject})")
                        
                        # Check for expired certificates
                        if self.alert_on_expired and not_after:
                            try:
                                # Parse expiration date (assuming ISO format)
                                expiry_date = datetime.fromisoformat(not_after.replace('Z', '+00:00'))
                                if expiry_date < datetime.now():
                                    alerts.append(f"Expired certificate detected: {src_ip} -> {dst_ip}:{dst_port} (Expired: {not_after})")
                            except ValueError:
                                # If date parsing fails, skip the expiry check
                                pass
                        
                        # Check for weak signature algorithms
                        if self.alert_on_weak_crypto and signature_algorithm:
                            weak_algorithms = ["md5", "sha1", "md2", "md4"]
                            for weak_algo in weak_algorithms:
                                if weak_algo.lower() in signature_algorithm.lower():
                                    alerts.append(f"Weak certificate signature algorithm detected: {src_ip} -> {dst_ip}:{dst_port} ({signature_algorithm})")
                                    break
                        
                        # Check for wildcard certificates
                        if self.alert_on_wildcard and subject_alt_names:
                            if '*.' in subject_alt_names or '*.' in subject:
                                alerts.append(f"Wildcard certificate detected: {src_ip} -> {dst_ip}:{dst_port} (Subject: {subject})")
                        
                        # Cache this certificate
                        self.certificate_cache[connection_key] = {
                            'subject': subject,
                            'validated': True,
                            'timestamp': time.time()
                        }
                    except Exception as e:
                        logging.error(f"Error parsing certificate data: {e}")
                        # Skip cert if parsing fails
                        continue
            
            # Clean up old entries from the certificate cache
            current_cache_size = len(self.certificate_cache)
            if current_cache_size > 1000:
                # Remove entries older than 24 hours
                old_entries = []
                for key, value in self.certificate_cache.items():
                    if time.time() - value.get('timestamp', 0) > 86400:
                        old_entries.append(key)
                
                for key in old_entries:
                    self.certificate_cache.pop(key, None)
            
            return alerts
        except Exception as e:
            error_msg = f"Error in SSL Certificate rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def get_params(self):
        return {
            "alert_on_self_signed": {
                "type": "bool",
                "default": True,
                "current": self.alert_on_self_signed,
                "description": "Alert on self-signed certificates"
            },
            "alert_on_expired": {
                "type": "bool",
                "default": True,
                "current": self.alert_on_expired,
                "description": "Alert on expired certificates"
            },
            "alert_on_weak_crypto": {
                "type": "bool",
                "default": True,
                "current": self.alert_on_weak_crypto,
                "description": "Alert on weak cryptographic algorithms"
            },
            "alert_on_wildcard": {
                "type": "bool",
                "default": False,
                "current": self.alert_on_wildcard,
                "description": "Alert on wildcard certificates (may cause false positives)"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "alert_on_self_signed":
            self.alert_on_self_signed = bool(value)
            return True
        elif param_name == "alert_on_expired":
            self.alert_on_expired = bool(value)
            return True
        elif param_name == "alert_on_weak_crypto":
            self.alert_on_weak_crypto = bool(value)
            return True
        elif param_name == "alert_on_wildcard":
            self.alert_on_wildcard = bool(value)
            return True
        return False