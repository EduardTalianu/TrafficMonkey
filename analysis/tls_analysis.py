# tls_analysis.py - Enhanced TLS/SSL traffic analysis
import time
import logging
import socket
import json
import re
from collections import defaultdict
import math

logger = logging.getLogger('tls_analysis')

class TLSAnalyzer(AnalysisBase):
    """Advanced TLS/SSL traffic analyzer with certificate and cipher analysis"""
    
    def __init__(self):
        super().__init__(
            name="TLS Traffic Analysis",
            description="Analyzes TLS/SSL connections, certificates, and cryptographic properties"
        )
        # TLS version metadata
        self.tls_versions = {
            "0x0300": {"name": "SSLv3", "security_level": 0, "year": 1996},
            "0x0301": {"name": "TLSv1.0", "security_level": 1, "year": 1999},
            "0x0302": {"name": "TLSv1.1", "security_level": 2, "year": 2006},
            "0x0303": {"name": "TLSv1.2", "security_level": 3, "year": 2008},
            "0x0304": {"name": "TLSv1.3", "security_level": 4, "year": 2018}
        }
        
        # Weak ciphers (partial list)
        self.weak_ciphers = [
            "NULL", "EXPORT", "DES", "RC4", "MD5", "anon", 
            "CBC", "DHE_EXPORT", "DH_EXPORT", "IDEA"
        ]
        
        # Strong ciphers (partial list)
        self.strong_ciphers = [
            "ECDHE", "TLS_AES", "GCM", "CHACHA20", "POLY1305", 
            "SHA256", "SHA384", "ECDSA", "X25519"
        ]
        
        # Common SSL/TLS ports for categorization
        self.usual_tls_ports = {443, 8443, 636, 465, 563, 614, 993, 995}
        
        # Analysis intervals
        self.last_dns_resolve_time = 0
        self.dns_resolve_interval = 1800  # 30 minutes
        
        # Server name indicators for special domains
        self.financial_domains = {"bank", "finance", "pay", "credit", "loan", "invest"}
        self.health_domains = {"health", "medical", "patient", "doctor", "hospital", "clinic"}
        self.government_domains = {"gov", "government", "admin", "federal", "state", "county", "city"}
    
    def initialize(self):
        # Create or update required tables with enhanced schema
        cursor = self.analysis_manager.get_cursor()
        try:
            # TLS analysis results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tls_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_key TEXT UNIQUE,
                    server_name TEXT,
                    suspicious_score REAL DEFAULT 0,
                    cipher_issues BOOLEAN DEFAULT 0,
                    version_issues BOOLEAN DEFAULT 0,
                    port_issues BOOLEAN DEFAULT 0,
                    first_seen REAL,
                    last_seen REAL,
                    detection_details TEXT,
                    client_random TEXT,
                    cipher_suite TEXT,
                    tls_version TEXT,
                    security_level INTEGER DEFAULT 0,
                    pfs_enabled BOOLEAN DEFAULT 0,
                    key_exchange TEXT,
                    tls_extensions TEXT,
                    domain_risk_level TEXT
                )
            """)
            
            # Certificate analysis table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tls_certificate_analysis (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_key TEXT,
                    server_name TEXT,
                    subject_cn TEXT,
                    issuer_cn TEXT,
                    valid_from REAL,
                    valid_to REAL,
                    key_type TEXT,
                    key_size INTEGER,
                    signature_algorithm TEXT,
                    is_expired BOOLEAN DEFAULT 0,
                    is_self_signed BOOLEAN DEFAULT 0,
                    is_wildcard BOOLEAN DEFAULT 0,
                    san_entries TEXT,
                    domain_match BOOLEAN DEFAULT 1,
                    security_score REAL DEFAULT 0,
                    ocsp_stapling BOOLEAN DEFAULT 0,
                    first_seen REAL,
                    last_seen REAL,
                    UNIQUE(server_name, subject_cn, issuer_cn)
                )
            """)
            
            # JA3 fingerprint table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tls_ja3_fingerprints (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ja3_hash TEXT,
                    ja3_string TEXT,
                    count INTEGER DEFAULT 1,
                    first_seen REAL,
                    last_seen REAL,
                    client_ips TEXT,
                    destinations TEXT,
                    is_known BOOLEAN DEFAULT 0,
                    category TEXT,
                    description TEXT,
                    UNIQUE(ja3_hash)
                )
            """)
            
            # Server analysis table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS tls_server_analysis (
                    server_name TEXT PRIMARY KEY,
                    supported_protocols TEXT,
                    preferred_cipher TEXT,
                    certificate_count INTEGER DEFAULT 1,
                    uses_sni BOOLEAN DEFAULT 1,
                    supports_alpn BOOLEAN DEFAULT 0,
                    alpn_protocols TEXT,
                    handshake_errors INTEGER DEFAULT 0,
                    first_seen REAL,
                    last_seen REAL,
                    security_score REAL DEFAULT 0
                )
            """)
            
            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_analysis_server ON tls_analysis(server_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_analysis_score ON tls_analysis(suspicious_score DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_analysis_security ON tls_analysis(security_level)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_cert_server ON tls_certificate_analysis(server_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_cert_issuer ON tls_certificate_analysis(issuer_cn)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_cert_score ON tls_certificate_analysis(security_score)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_ja3_hash ON tls_ja3_fingerprints(ja3_hash)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_ja3_known ON tls_ja3_fingerprints(is_known)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_server_name ON tls_server_analysis(server_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_tls_server_score ON tls_server_analysis(security_score)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("TLS analysis tables initialized with enhanced schema")
        except Exception as e:
            logger.error(f"Error initializing TLS analysis tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process a TLS packet for enhanced analysis"""
        # Get the layers
        layers = packet_data.get("layers", {})
        if not layers:
            return False
        
        # Check if this is a TLS packet
        if not self.analysis_manager._has_tls_data(layers):
            return False
        
        try:
            # Extract TLS data
            src_ip = self.analysis_manager._get_layer_value(layers, "ip_src") or self.analysis_manager._get_layer_value(layers, "ipv6_src")
            dst_ip = self.analysis_manager._get_layer_value(layers, "ip_dst") or self.analysis_manager._get_layer_value(layers, "ipv6_dst")
            
            if not src_ip or not dst_ip:
                return False
                
            src_port, dst_port = self.analysis_manager._extract_ports(layers)
            
            # Create connection key
            if src_port and dst_port:
                connection_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            else:
                connection_key = f"{src_ip}->{dst_ip}"
            
            # Extract TLS fields
            tls_version = self.analysis_manager._get_layer_value(layers, "tls_handshake_version")
            cipher_suite = self.analysis_manager._get_layer_value(layers, "tls_handshake_ciphersuite")
            server_name = self.analysis_manager._get_layer_value(layers, "tls_handshake_extensions_server_name")
            client_random = self.analysis_manager._get_layer_value(layers, "tls_handshake_random")
            ja3_fingerprint = self.analysis_manager._get_layer_value(layers, "tls_handshake_ja3")
            ja3s_fingerprint = self.analysis_manager._get_layer_value(layers, "tls_handshake_ja3s")
            
            # Extract certificate data if present
            cert_issuer = self.analysis_manager._get_layer_value(layers, "tls_handshake_certificate_issuer")
            cert_subject = self.analysis_manager._get_layer_value(layers, "tls_handshake_certificate_subject")
            cert_valid_from = self.analysis_manager._get_layer_value(layers, "tls_handshake_certificate_validity_notbefore")
            cert_valid_to = self.analysis_manager._get_layer_value(layers, "tls_handshake_certificate_validity_notafter")
            cert_serial = self.analysis_manager._get_layer_value(layers, "tls_handshake_certificate_serialnumber")
            cert_sig_algo = self.analysis_manager._get_layer_value(layers, "tls_handshake_certificate_signaturealgorithm")
            cert_key_type = self.analysis_manager._get_layer_value(layers, "tls_handshake_certificate_keytype")
            cert_key_size = self.analysis_manager._get_layer_value(layers, "tls_handshake_certificate_keysize")
            cert_san = self.analysis_manager._get_layer_value(layers, "tls_handshake_certificate_san")
            
            # Extract TLS extensions
            tls_extensions = {}
            for key, value in layers.items():
                if key.startswith("tls_handshake_extension_"):
                    extension_name = key.replace("tls_handshake_extension_", "")
                    tls_extensions[extension_name] = self.analysis_manager._get_layer_value(layers, key)
            
            # Set defaults if needed
            if not tls_version:
                if dst_port == 443:
                    tls_version = "0x0303"  # Assume TLSv1.2 for HTTPS traffic
                else:
                    tls_version = "Unknown"
            
            if not server_name:
                server_name = dst_ip
            
            # Analyze the TLS connection
            self._analyze_tls_connection(
                connection_key, src_ip, dst_ip, src_port, dst_port,
                tls_version, cipher_suite, server_name, client_random,
                ja3_fingerprint, ja3s_fingerprint, tls_extensions
            )
            
            # If certificate data is present, analyze it separately
            if cert_subject and cert_issuer:
                self._analyze_certificate(
                    connection_key, server_name, cert_subject, cert_issuer,
                    cert_valid_from, cert_valid_to, cert_serial, cert_sig_algo,
                    cert_key_type, cert_key_size, cert_san
                )
            
            # Analyze JA3 fingerprints if present
            if ja3_fingerprint:
                self._analyze_ja3_fingerprint(
                    connection_key, src_ip, dst_ip, server_name, ja3_fingerprint
                )
            
            return True
        except Exception as e:
            logger.error(f"Error analyzing TLS packet: {e}")
            return False
    
    def _analyze_tls_connection(self, connection_key, src_ip, dst_ip, src_port, dst_port,
                              tls_version, cipher_suite, server_name, client_random,
                              ja3_fingerprint, ja3s_fingerprint, tls_extensions):
        """Analyze TLS connection for security issues and metrics"""
        current_time = time.time()
        
        # Calculate suspicious score and security metrics
        suspicious_score = 0
        cipher_issues = False
        version_issues = False
        port_issues = False
        detection_details = {}
        
        # Determine security level based on TLS version
        security_level = 0
        version_info = self.tls_versions.get(tls_version, None)
        if version_info:
            security_level = version_info["security_level"]
        elif isinstance(tls_version, str) and "TLS" in tls_version:
            # Try to parse other TLS version formats
            if "1.3" in tls_version:
                security_level = 4
            elif "1.2" in tls_version:
                security_level = 3
            elif "1.1" in tls_version:
                security_level = 2
            elif "1.0" in tls_version:
                security_level = 1
            else:
                security_level = 0
        
        # Check for unusual port (not in standard SSL/TLS ports)
        if dst_port and dst_port not in self.usual_tls_ports:
            suspicious_score += 2
            port_issues = True
            detection_details["unusual_port"] = dst_port
        
        # Check for outdated/insecure TLS version
        if security_level < 3:  # Anything below TLS 1.2 is considered outdated
            suspicious_score += 3
            version_issues = True
            detection_details["outdated_tls"] = tls_version
            
            # Extra penalty for very old versions
            if security_level < 2:  # SSLv3 or TLS 1.0
                suspicious_score += 2
                detection_details["obsolete_tls"] = True
        
        # Analyze cipher suite
        pfs_enabled = False
        key_exchange = "unknown"
        
        if cipher_suite:
            # Check for weak cipher components
            for weak_cipher in self.weak_ciphers:
                if weak_cipher in cipher_suite:
                    suspicious_score += 2
                    cipher_issues = True
                    detection_details.setdefault("weak_ciphers", []).append(weak_cipher)
            
            # Check for strong cipher components
            strong_count = 0
            for strong_cipher in self.strong_ciphers:
                if strong_cipher in cipher_suite:
                    strong_count += 1
            
            # Credit for good ciphers (reduce suspicion)
            if strong_count > 0:
                suspicious_score = max(0, suspicious_score - strong_count)
            
            # Detect Perfect Forward Secrecy
            if "DHE" in cipher_suite or "ECDHE" in cipher_suite:
                pfs_enabled = True
            
            # Extract key exchange method
            if "ECDHE" in cipher_suite:
                key_exchange = "ECDHE"
            elif "DHE" in cipher_suite or "EDH" in cipher_suite:
                key_exchange = "DHE"
            elif "ECDH" in cipher_suite:
                key_exchange = "ECDH"
            elif "DH" in cipher_suite:
                key_exchange = "DH"
            elif "RSA" in cipher_suite:
                key_exchange = "RSA"
        
        # Analyze TLS extensions
        extension_json = json.dumps(tls_extensions) if tls_extensions else "{}"
        
        # Calculate domain risk level
        domain_risk = self._calculate_domain_risk(server_name)
        
        # Store analysis results
        cursor = self.analysis_manager.get_cursor()
        
        try:
            # Check if connection exists in analysis
            cursor.execute("SELECT first_seen FROM tls_analysis WHERE connection_key = ?", (connection_key,))
            result = cursor.fetchone()
            
            if result:
                # Update existing connection
                cursor.execute("""
                    UPDATE tls_analysis
                    SET server_name = ?,
                        suspicious_score = ?,
                        cipher_issues = ?,
                        version_issues = ?,
                        port_issues = ?,
                        last_seen = ?,
                        detection_details = ?,
                        client_random = ?,
                        cipher_suite = ?,
                        tls_version = ?,
                        security_level = ?,
                        pfs_enabled = ?,
                        key_exchange = ?,
                        tls_extensions = ?,
                        domain_risk_level = ?
                    WHERE connection_key = ?
                """, (
                    server_name,
                    suspicious_score,
                    cipher_issues,
                    version_issues,
                    port_issues,
                    current_time,
                    json.dumps(detection_details),
                    client_random,
                    cipher_suite,
                    tls_version,
                    security_level,
                    pfs_enabled,
                    key_exchange,
                    extension_json,
                    domain_risk,
                    connection_key
                ))
            else:
                # Insert new connection analysis
                cursor.execute("""
                    INSERT INTO tls_analysis
                    (connection_key, server_name, suspicious_score, cipher_issues, 
                     version_issues, port_issues, first_seen, last_seen, detection_details,
                     client_random, cipher_suite, tls_version, security_level,
                     pfs_enabled, key_exchange, tls_extensions, domain_risk_level)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    connection_key,
                    server_name,
                    suspicious_score,
                    cipher_issues,
                    version_issues,
                    port_issues,
                    current_time,
                    current_time,
                    json.dumps(detection_details),
                    client_random,
                    cipher_suite,
                    tls_version,
                    security_level,
                    pfs_enabled,
                    key_exchange,
                    extension_json,
                    domain_risk
                ))
            
            # Also update server analysis
            self._update_server_analysis(cursor, server_name, tls_version, cipher_suite, tls_extensions, current_time)
            
            self.analysis_manager.analysis1_conn.commit()
        finally:
            cursor.close()
    
    def _analyze_certificate(self, connection_key, server_name, cert_subject, cert_issuer,
                           cert_valid_from, cert_valid_to, cert_serial, cert_sig_algo,
                           cert_key_type, cert_key_size, cert_san):
        """Analyze TLS certificate for security and validity metrics"""
        current_time = time.time()
        
        # Parse certificate validity dates
        try:
            # Handle different date formats
            valid_from_ts = self._parse_cert_date(cert_valid_from)
            valid_to_ts = self._parse_cert_date(cert_valid_to)
        except (ValueError, TypeError):
            # If parsing fails, use current time as fallback
            valid_from_ts = current_time - 86400 * 30  # Assume 30 days old
            valid_to_ts = current_time + 86400 * 90    # Assume 90 days validity
        
        # Parse CN from subject/issuer DNs
        subject_cn = self._extract_cn(cert_subject) or server_name
        issuer_cn = self._extract_cn(cert_issuer) or "Unknown"
        
        # Check for self-signed certificate
        is_self_signed = subject_cn == issuer_cn
        
        # Check if certificate is expired
        is_expired = valid_to_ts < current_time
        
        # Check for wildcard certificate
        is_wildcard = '*' in subject_cn
        
        # Parse SAN entries
        san_entries = []
        if cert_san:
            sans = cert_san.split(',')
            san_entries = [san.strip() for san in sans]
        
        # Check domain match
        domain_match = False
        if server_name:
            # Direct match
            if server_name == subject_cn:
                domain_match = True
            # Wildcard match
            elif subject_cn.startswith('*.') and server_name.endswith(subject_cn[2:]):
                domain_match = True
            # SAN match
            elif san_entries:
                for san in san_entries:
                    if san == server_name:
                        domain_match = True
                        break
                    if san.startswith('*.') and server_name.endswith(san[2:]):
                        domain_match = True
                        break
        
        # Parse key size as integer
        if cert_key_size and isinstance(cert_key_size, str):
            try:
                key_size = int(cert_key_size)
            except ValueError:
                key_size = 0
        else:
            key_size = cert_key_size or 0
        
        # Calculate security score for certificate (0-10)
        security_score = 5  # Start with neutral score
        
        # Adjust score based on certificate properties
        if is_expired:
            security_score -= 3
        if is_self_signed:
            security_score -= 3
        
        # Key type and size
        if cert_key_type == "RSA" and key_size >= 2048:
            security_score += 1
        elif cert_key_type == "RSA" and key_size < 2048:
            security_score -= 2
        elif cert_key_type == "ECC":
            security_score += 2
        
        # Signature algorithm
        if cert_sig_algo:
            if "sha256" in cert_sig_algo.lower() or "sha384" in cert_sig_algo.lower():
                security_score += 1
            elif "sha1" in cert_sig_algo.lower() or "md5" in cert_sig_algo.lower():
                security_score -= 2
        
        # Domain match
        if not domain_match:
            security_score -= 2
        
        # Certificate validity period
        validity_period = valid_to_ts - valid_from_ts
        if validity_period > 86400 * 365 * 2:  # More than 2 years
            security_score -= 1  # Long-lived certificates are less secure
        
        # Cap the score
        security_score = max(0, min(10, security_score))
        
        # Store certificate analysis
        cursor = self.analysis_manager.get_cursor()
        
        try:
            # Check if we've already analyzed this certificate
            cursor.execute("""
                SELECT id FROM tls_certificate_analysis
                WHERE server_name = ? AND subject_cn = ? AND issuer_cn = ?
            """, (server_name, subject_cn, issuer_cn))
            
            result = cursor.fetchone()
            
            san_entries_json = json.dumps(san_entries) if san_entries else "[]"
            
            if result:
                # Update existing certificate analysis
                cert_id = result[0]
                cursor.execute("""
                    UPDATE tls_certificate_analysis
                    SET connection_key = ?,
                        valid_from = ?,
                        valid_to = ?,
                        key_type = ?,
                        key_size = ?,
                        signature_algorithm = ?,
                        is_expired = ?,
                        is_self_signed = ?,
                        is_wildcard = ?,
                        san_entries = ?,
                        domain_match = ?,
                        security_score = ?,
                        last_seen = ?
                    WHERE id = ?
                """, (
                    connection_key,
                    valid_from_ts,
                    valid_to_ts,
                    cert_key_type,
                    key_size,
                    cert_sig_algo,
                    is_expired,
                    is_self_signed,
                    is_wildcard,
                    san_entries_json,
                    domain_match,
                    security_score,
                    current_time,
                    cert_id
                ))
            else:
                # Insert new certificate analysis
                cursor.execute("""
                    INSERT INTO tls_certificate_analysis
                    (connection_key, server_name, subject_cn, issuer_cn, valid_from, valid_to,
                     key_type, key_size, signature_algorithm, is_expired, is_self_signed,
                     is_wildcard, san_entries, domain_match, security_score, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    connection_key,
                    server_name,
                    subject_cn,
                    issuer_cn,
                    valid_from_ts,
                    valid_to_ts,
                    cert_key_type,
                    key_size,
                    cert_sig_algo,
                    is_expired,
                    is_self_signed,
                    is_wildcard,
                    san_entries_json,
                    domain_match,
                    security_score,
                    current_time,
                    current_time
                ))
            
            self.analysis_manager.analysis1_conn.commit()
        finally:
            cursor.close()
    
    def _analyze_ja3_fingerprint(self, connection_key, client_ip, dst_ip, server_name, ja3_hash):
        """Analyze JA3 client fingerprint for client profiling"""
        current_time = time.time()
        cursor = self.analysis_manager.get_cursor()
        
        try:
            # Check if fingerprint exists
            cursor.execute("SELECT count, client_ips, destinations FROM tls_ja3_fingerprints WHERE ja3_hash = ?", (ja3_hash,))
            result = cursor.fetchone()
            
            if result:
                # Update existing JA3 fingerprint
                count, client_ips_json, destinations_json = result
                
                # Parse existing IPs and destinations
                client_ips = json.loads(client_ips_json) if client_ips_json else []
                destinations = json.loads(destinations_json) if destinations_json else []
                
                # Add new IPs and destinations
                if client_ip not in client_ips:
                    client_ips.append(client_ip)
                    
                destination = f"{dst_ip}:{server_name}"
                if destination not in destinations:
                    destinations.append(destination)
                
                # Limit lists to prevent excessive growth
                if len(client_ips) > 100:
                    client_ips = client_ips[-100:]
                if len(destinations) > 100:
                    destinations = destinations[-100:]
                
                cursor.execute("""
                    UPDATE tls_ja3_fingerprints
                    SET count = count + 1,
                        last_seen = ?,
                        client_ips = ?,
                        destinations = ?
                    WHERE ja3_hash = ?
                """, (
                    current_time,
                    json.dumps(client_ips),
                    json.dumps(destinations),
                    ja3_hash
                ))
            else:
                # Insert new JA3 fingerprint
                cursor.execute("""
                    INSERT INTO tls_ja3_fingerprints
                    (ja3_hash, count, first_seen, last_seen, client_ips, destinations)
                    VALUES (?, 1, ?, ?, ?, ?)
                """, (
                    ja3_hash,
                    current_time,
                    current_time,
                    json.dumps([client_ip]),
                    json.dumps([f"{dst_ip}:{server_name}"])
                ))
            
            self.analysis_manager.analysis1_conn.commit()
        finally:
            cursor.close()
    
    def _update_server_analysis(self, cursor, server_name, tls_version, cipher_suite, tls_extensions, current_time):
        """Update TLS server behavior analysis"""
        try:
            # Check if server exists
            cursor.execute("SELECT supported_protocols, preferred_cipher FROM tls_server_analysis WHERE server_name = ?", (server_name,))
            result = cursor.fetchone()
            
            # Parse TLS extensions
            alpn_protocols = []
            supports_alpn = False
            
            if tls_extensions and isinstance(tls_extensions, dict) and 'alpn' in tls_extensions:
                supports_alpn = True
                alpn_value = tls_extensions['alpn']
                if alpn_value:
                    alpn_protocols = [p.strip() for p in alpn_value.split(',')]
            
            # Get TLS version name
            version_name = "Unknown"
            if tls_version in self.tls_versions:
                version_name = self.tls_versions[tls_version]["name"]
            elif isinstance(tls_version, str):
                if "1.3" in tls_version:
                    version_name = "TLSv1.3"
                elif "1.2" in tls_version:
                    version_name = "TLSv1.2"
                elif "1.1" in tls_version:
                    version_name = "TLSv1.1"
                elif "1.0" in tls_version:
                    version_name = "TLSv1.0"
                elif "SSL" in tls_version:
                    version_name = "SSLv3"
            
            if result:
                # Update existing server analysis
                protocols_json, preferred_cipher = result
                
                # Parse existing protocols
                protocols = json.loads(protocols_json) if protocols_json else []
                
                # Add new protocol if not already present
                if version_name not in protocols:
                    protocols.append(version_name)
                
                # Calculate security score
                security_score = self._calculate_server_security_score(
                    protocols, cipher_suite, supports_alpn
                )
                
                cursor.execute("""
                    UPDATE tls_server_analysis
                    SET supported_protocols = ?,
                        preferred_cipher = ?,
                        supports_alpn = ?,
                        alpn_protocols = ?,
                        last_seen = ?,
                        security_score = ?
                    WHERE server_name = ?
                """, (
                    json.dumps(protocols),
                    cipher_suite or preferred_cipher,  # Keep existing if new is None
                    supports_alpn,
                    json.dumps(alpn_protocols),
                    current_time,
                    security_score,
                    server_name
                ))
            else:
                # Insert new server analysis
                security_score = self._calculate_server_security_score(
                    [version_name], cipher_suite, supports_alpn
                )
                
                cursor.execute("""
                    INSERT INTO tls_server_analysis
                    (server_name, supported_protocols, preferred_cipher, uses_sni,
                     supports_alpn, alpn_protocols, first_seen, last_seen, security_score)
                    VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?)
                """, (
                    server_name,
                    json.dumps([version_name]),
                    cipher_suite,
                    supports_alpn,
                    json.dumps(alpn_protocols),
                    current_time,
                    current_time,
                    security_score
                ))
        except Exception as e:
            logger.error(f"Error updating server analysis for {server_name}: {e}")
    
    def _calculate_domain_risk(self, server_name):
        """Calculate domain risk level based on name characteristics"""
        if not server_name or self.analysis_manager._is_ip_address(server_name):
            return "medium"  # IP addresses default to medium risk
        
        # Extract domain parts
        domain_parts = server_name.lower().split('.')
        
        # Check for high-value domains
        if len(domain_parts) >= 2:
            tld = domain_parts[-1]
            domain = domain_parts[-2]
            
            # Check special categories
            if any(keyword in domain for keyword in self.financial_domains) or tld == 'bank':
                return "high"
            
            if any(keyword in domain for keyword in self.health_domains):
                return "high"
            
            if any(keyword in domain for keyword in self.government_domains) or tld == 'gov':
                return "high"
            
            # Check for common TLDs
            if tld in ('com', 'org', 'net', 'edu', 'gov', 'mil'):
                return "medium"
                
            # Check for country TLDs
            if len(tld) == 2:  # Country code TLDs
                return "medium"
        
        # Default risk level
        return "low"
    
    def _calculate_server_security_score(self, protocols, cipher_suite, supports_alpn):
        """Calculate server security score based on protocols and features"""
        score = 5  # Start with neutral score
        
        # Evaluate protocols
        if protocols:
            # Bonus for supporting TLS 1.3
            if "TLSv1.3" in protocols:
                score += 2
            # Bonus for supporting TLS 1.2
            elif "TLSv1.2" in protocols:
                score += 1
            
            # Penalty for supporting old protocols
            if "SSLv3" in protocols:
                score -= 2
            if "TLSv1.0" in protocols:
                score -= 1
        
        # Evaluate cipher suite
        if cipher_suite:
            # Bonus for strong ciphers
            strong_count = 0
            for strong_cipher in self.strong_ciphers:
                if strong_cipher in cipher_suite:
                    strong_count += 1
            
            score += min(2, strong_count)  # Max +2 for strong ciphers
            
            # Penalty for weak ciphers
            weak_count = 0
            for weak_cipher in self.weak_ciphers:
                if weak_cipher in cipher_suite:
                    weak_count += 1
            
            score -= min(3, weak_count)  # Max -3 for weak ciphers
        
        # Bonus for ALPN support (modern feature)
        if supports_alpn:
            score += 1
        
        # Cap the score
        return max(0, min(10, score))
    
    def _parse_cert_date(self, date_str):
        """Parse certificate date string to timestamp"""
        if not date_str:
            return time.time()
            
        # Common date formats in certificates
        formats = [
            "%b %d %H:%M:%S %Y GMT",  # Jun 11 11:05:33 2023 GMT
            "%Y-%m-%d %H:%M:%S",      # 2023-06-11 11:05:33
            "%Y%m%d%H%M%SZ",          # 20230611110533Z
            "%Y-%m-%dT%H:%M:%SZ"      # 2023-06-11T11:05:33Z
        ]
        
        for fmt in formats:
            try:
                return time.mktime(time.strptime(date_str, fmt))
            except ValueError:
                continue
                
        # If all parsing attempts fail, return current time
        return time.time()
    
    def _extract_cn(self, dn_string):
        """Extract Common Name (CN) from a Distinguished Name (DN) string"""
        if not dn_string:
            return None
            
        # Look for CN= pattern in the DN
        cn_match = re.search(r'CN=([^,]+)', dn_string)
        if cn_match:
            return cn_match.group(1).strip()
            
        return None
    
    def run_periodic_analysis(self):
        """Run periodic TLS analysis, including domain name resolution and certificate checks"""
        current_time = time.time()
        
        try:
            # Resolve domain names
            if current_time - self.last_dns_resolve_time >= self.dns_resolve_interval:
                self.last_dns_resolve_time = current_time
                self._resolve_domain_names()
            
            # Check for soon-to-expire certificates
            self._check_certificate_expiration()
            
            # Analyze server security metrics
            self._analyze_server_security()
            
            # Analyze unusual JA3 fingerprints
            self._analyze_unusual_fingerprints()
            
            return True
        except Exception as e:
            logger.error(f"Error in TLS periodic analysis: {e}")
            return False
    
    def _resolve_domain_names(self):
        """Resolve IP addresses to domain names for TLS connections"""
        try:
            cursor = self.analysis_manager.get_cursor()
            
            # Get all TLS connections with server names that look like IP addresses
            cursor.execute("""
                SELECT id, server_name, connection_key
                FROM tls_analysis
                WHERE server_name LIKE '%\\.%\\.%\\.%' 
                OR server_name IS NULL
                LIMIT 100
            """)
            
            rows = cursor.fetchall()
            updates = 0
            
            for row in rows:
                tls_id, server_name, connection_key = row
                
                # Extract destination IP from connection key
                try:
                    dst_ip = connection_key.split('->')[1].split(':')[0]
                except IndexError:
                    continue
                    
                # Skip if we already have a non-IP server name
                if server_name and not self.analysis_manager._is_ip_address(server_name):
                    continue
                    
                # Try reverse DNS lookup
                try:
                    hostname, _, _ = socket.gethostbyaddr(dst_ip)
                    if hostname and hostname != dst_ip and not self.analysis_manager._is_ip_address(hostname):
                        # Update the server name in the database
                        cursor.execute("""
                            UPDATE tls_analysis
                            SET server_name = ?
                            WHERE id = ?