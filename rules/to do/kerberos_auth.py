# Rule class is injected by the RuleLoader
import logging
from collections import defaultdict
import time

class KerberosAnalyzerRule(Rule):
    """Rule that analyzes Kerberos authentication traffic for exploitation opportunities"""
    def __init__(self):
        super().__init__(
            name="Kerberos Authentication Analyzer",
            description="Identifies Kerberos authentication patterns and potential ticket extraction opportunities"
        )
        # Track Kerberos servers (KDCs)
        self.kdc_servers = set()
        # Track service principals
        self.service_principals = defaultdict(set)
        # Track users with Kerberos authentication
        self.kerberos_users = set()
        # Last analysis time
        self.last_analysis_time = 0
        # Analysis interval in seconds
        self.analysis_interval = 900  # 15 minutes
        # Track already reported information
        self.reported_items = set()
    
    def analyze(self, db_cursor):
        alerts = []
        
        current_time = time.time()
        if current_time - self.last_analysis_time < self.analysis_interval:
            return []
            
        self.last_analysis_time = current_time
        
        try:
            # Get Kerberos traffic (port 88)
            db_cursor.execute("""
                SELECT c.src_ip, c.dst_ip, c.connection_key, c.total_bytes
                FROM connections c
                WHERE c.dst_port = 88 
                ORDER BY c.timestamp DESC
                LIMIT 5000
            """)
            
            # Process Kerberos connections
            for row in db_cursor.fetchall():
                src_ip, dst_ip, connection_key, total_bytes = row
                
                # Skip already analyzed connections
                conn_key = f"Kerberos:{connection_key}"
                if conn_key in self.reported_items:
                    continue
                
                self.reported_items.add(conn_key)
                
                # Add to KDC servers list (destination is likely a KDC)
                self.kdc_servers.add(dst_ip)
                
                # Add to Kerberos users list (source is likely a user)
                self.kerberos_users.add(src_ip)
                
                # Look for large responses that might contain Kerberos tickets (TGTs/TGSs)
                if total_bytes and total_bytes > 1500:  # Arbitrary threshold for ticket responses
                    alert_msg = f"Potential Kerberos ticket response from {dst_ip} to {src_ip} ({total_bytes} bytes)"
                    alerts.append(alert_msg)
                    
                    # Add detailed alert with recommendation
                    if total_bytes > 4000:  # Larger tickets might be more interesting
                        detailed_msg = f"Large Kerberos ticket data from {dst_ip} to {src_ip} ({total_bytes} bytes) - Potential for ticket extraction"
                        self.add_alert(dst_ip, detailed_msg)
            
            # Try to get DNS queries for Kerberos service principal names (SPNs)
            db_cursor.execute("""
                SELECT dns.src_ip, dns.query_domain, dns.a_record
                FROM dns_queries dns
                WHERE dns.query_domain LIKE '%._tcp.%' OR dns.query_domain LIKE '%.kerberos.%'
                ORDER BY dns.timestamp DESC
            """)
            
            for row in db_cursor.fetchall():
                src_ip, query_domain, a_record = row
                
                # Skip already analyzed SPNs
                spn_key = f"SPN:{query_domain}"
                if spn_key in self.reported_items:
                    continue
                
                self.reported_items.add(spn_key)
                
                # Extract service type from SPN query
                service_type = "unknown"
                if "._tcp." in query_domain:
                    service_type = query_domain.split("._tcp.")[0].strip('_')
                    
                # Add to SPN collection
                if a_record:
                    self.service_principals[service_type].add(a_record)
                
                # Alert on interesting service types
                if service_type in ["kerberos", "ldap", "cifs", "http", "mssql", "sip"]:
                    alert_msg = f"Kerberos service principal detected: {service_type} on {a_record or 'unknown'} (queried by {src_ip})"
                    alerts.append(alert_msg)
                    
                    if service_type in ["mssql", "http", "cifs"]:
                        # These are common targets for Kerberoasting
                        detailed_msg = f"Potential Kerberoasting target: {service_type} SPN on {a_record or 'unknown'}"
                        self.add_alert(src_ip, detailed_msg)
            
            # Generate summary of Kerberos infrastructure
            if self.kdc_servers and not self.reported_items.intersection(["KDC_Summary"]):
                self.reported_items.add("KDC_Summary")
                
                kdcs = ", ".join(list(self.kdc_servers)[:5])
                kdc_count = len(self.kdc_servers)
                user_count = len(self.kerberos_users)
                
                summary_msg = f"Kerberos infrastructure: {kdc_count} KDCs detected (including {kdcs}), {user_count} clients observed"
                alerts.append(summary_msg)
                
                # Store detailed information in database
                self._store_kerberos_info()
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in Kerberos Authentication Analyzer: {e}"
            logging.error(error_msg)
            return [error_msg]
    
    def _store_kerberos_info(self):
        """Store Kerberos information in the database for later exploitation"""
        try:
            # If we have an analysis_manager, store data in x_ip_threat_intel
            if hasattr(self, 'analysis_manager') and self.analysis_manager:
                # Store information about each KDC
                for kdc_ip in self.kdc_servers:
                    # Create threat intel entry for this KDC
                    threat_data = {
                        "score": 0,  # Not a threat, just information
                        "type": "kerberos_service",
                        "confidence": 0.9,
                        "source": self.name,
                        "details": {
                            "service_role": "KDC",
                            "kerberos_clients": list(self.kerberos_users)[:20],  # Limit to 20 clients
                            "client_count": len(self.kerberos_users),
                            "discovery_time": time.time()
                        },
                        "protocol": "Kerberos",
                        "destination_port": 88,
                        "detection_method": "traffic_analysis"
                    }
                    
                    # Store in the threat_intel table
                    self.analysis_manager.update_threat_intel(kdc_ip, threat_data)
                
                # Store information about service principals (potential Kerberoasting targets)
                for service_type, ips in self.service_principals.items():
                    for ip in ips:
                        spn_data = {
                            "score": 0,  # Not a threat, just information
                            "type": "service_principal",
                            "confidence": 0.8,
                            "source": self.name,
                            "details": {
                                "service_type": service_type,
                                "spn_detected": True,
                                "kerberoasting_candidate": service_type in ["mssql", "http", "cifs"],
                                "discovery_time": time.time()
                            },
                            "protocol": "Kerberos",
                            "detection_method": "dns_analysis"
                        }
                        
                        # Store in the threat_intel table
                        self.analysis_manager.update_threat_intel(ip, spn_data)
        except Exception as e:
            logging.error(f"Error storing Kerberos information: {e}")
    
    def get_params(self):
        return {
            "analysis_interval": {
                "type": "int",
                "default": 900,
                "current": self.analysis_interval,
                "description": "Interval between analyses (seconds)"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "analysis_interval":
            self.analysis_interval = int(value)
            return True
        return False