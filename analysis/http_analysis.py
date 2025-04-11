# x_http_analysis.py - Enhanced HTTP traffic analysis with advanced metrics
import time
import logging
import json
import re
import math
from collections import defaultdict, Counter
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger('http_analysis')

class HTTPAnalyzer(AnalysisBase):
    """Advanced HTTP traffic analyzer with behavior profiling and anomaly detection"""
    
    def __init__(self):
        super().__init__(
            name="HTTP Traffic Analysis",
            description="Advanced HTTP traffic analysis with behavior profiling"
        )
        # Suspicious patterns in URLs (with explanatory comments)
        self.suspicious_url_patterns = [
            (r'(?i)(?:\.\.\/|\.\.\\)', 'directory_traversal'),                  # Directory traversal
            (r'(?i)(?:\/etc\/passwd|c:\\windows)', 'system_file_access'),       # Common file access attempts
            (r'(?i)(?:\'|\%27).+(?:\'|\%27)', 'sql_injection_quotes'),          # SQL injection with quotes
            (r'(?i)(?:<script>|<\/script>)', 'xss_script_tag'),                 # XSS script tags
            (r'(?i)(?:eval\(|\balert\(|\bprompt\()', 'javascript_injection'),   # JavaScript injection
            (r'(?i)(?:exec\(|system\(|passthru\()', 'command_injection'),       # PHP command injection
            (r'(?i)(?:cmd\.exe|\/bin\/bash|\/bin\/sh)', 'command_execution'),   # Command execution
            (r'(?i)(?:\bor\b|\band\b).*?(?:--|#)', 'sql_injection_operators'),  # SQL injection keywords
            (r'(?i)(?:base64_decode|eval\(base64_)', 'encoded_payload'),        # Encoded attacks
            (r'(?i)(?:select.+from|union\s+select)', 'sql_select'),             # SQL SELECT statements
            (r'(?i)(?:drop\s+table|alter\s+table|create\s+table)', 'sql_ddl'),  # SQL DDL statements
            (r'(?i)(?:concat\(|group_concat|substr\()', 'sql_functions'),       # SQL functions
            (r'(?i)(?:sleep\(|benchmark\(|pg_sleep)', 'time_based_injection'),  # Time-based SQL injection
            (r'(?i)(?:onload=|onerror=|onclick=)', 'event_handler_xss'),        # Event handler XSS
            (r'(?i)(?:document\.cookie|document\.location)', 'cookie_stealing'), # Cookie stealing
            (r'(?i)(?:\/admin\/|\/administrator\/)', 'admin_access'),           # Admin page access
            (r'(?i)(?:\?|\&)(?:password|passwd|pwd)=', 'password_in_url'),      # Password in URL
            (r'(?i)(?:\.php\.suspected|\.\w+\.suspected)', 'file_extension_bypass'), # Extension bypass
            (r'(?i)(?:\\x[0-9a-f]{2}|%[0-9a-f]{2}){4,}', 'hex_encoding'),      # Hex encoding
            (r'(?i)(?:\/\.git\/|\/\.svn\/|\/\.htaccess)', 'metadata_access')    # Metadata file access
        ]
        
        # Suspicious user agent patterns
        self.suspicious_user_agents = [
            (r'(?i)(?:sqlmap|acunetix|nikto|nessus|nmap)', 'scanner'),          # Known scanner tools
            (r'(?i)(?:burpsuite|owasp|zap|gobuster|dirbuster)', 'pentest_tool'),# Pentesting tools
            (r'(?i)(?:metasploit|python-requests|curl|wget)', 'scripted_client'),# Scripted/automation clients
            (r'(?i)(?:zgrab|masscan|hydra|brutus)', 'scanner_aggressive'),      # Aggressive scanning tools
            (r'(?i)(?:\\x[0-9a-f]{2}|%[0-9a-f]{2}){4,}', 'encoded_ua'),        # Encoded user agent
            (r'(?i)(?:webshell|backdoor|reverse_shell)', 'malicious'),          # Explicitly malicious
            (r'(?i)(?:netsparker|qualys|rapid7)', 'commercial_scanner'),        # Commercial scanners
            (r'(?i)(?:semrush|ahrefs|moz)', 'seo_crawler')                      # SEO crawlers
        ]
        
        # Suspicious header patterns
        self.suspicious_headers = [
            (r'(?i)(?:Content-Type:\s*application\/x-www-form-urlencoded.*?SELECT)', 'sql_in_content'),
            (r'(?i)(?:X-Forwarded-For:\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s*,\s*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 'ip_spoofing'),
            (r'(?i)(?:Authorization:\s*Basic\s*[A-Za-z0-9+/]{30,})', 'base64_auth')
        ]
        
        # IP address pattern
        self.ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
        
        # Analysis periods
        self.last_report_time = 0
        self.report_interval = 1800  # 30 minutes
        
        # HTTP client behavioral profiles
        self.client_profiles = {}  # {client_ip: {profile_data}}
        
        # Host path maps for structure analysis
        self.host_paths = defaultdict(set)  # {host: {paths}}
        
        # Fingerprinting maps
        self.tech_fingerprints = {
            'php': [r'\.php$', r'PHPSESSID', r'X-Powered-By: PHP'],
            'asp': [r'\.asp$', r'\.aspx$', r'X-AspNet-Version', r'ASP.NET'],
            'jsp': [r'\.jsp$', r'\.do$', r'JSESSIONID'],
            'nodejs': [r'node/', r'Express'],
            'wordpress': [r'/wp-content/', r'/wp-includes/', r'/wp-admin/'],
            'drupal': [r'/sites/default/', r'/sites/all/', r'Drupal'],
            'joomla': [r'/administrator/', r'/components/', r'Joomla'],
            'jquery': [r'jquery', r'jQuery'],
            'bootstrap': [r'bootstrap', r'Bootstrap'],
            'react': [r'react', r'React', r'reactjs'],
            'angular': [r'angular', r'Angular', r'ng-'],
            'vue': [r'vue', r'Vue', r'vuejs']
        }
    
    def initialize(self):
        # Create or update required tables
        cursor = self.analysis_manager.get_cursor()
        try:
            # HTTP analysis results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS x_http_analysis(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    connection_key TEXT,
                    host TEXT,
                    uri TEXT,
                    method TEXT,
                    suspicious_score REAL DEFAULT 0,
                    user_agent TEXT,
                    detected_patterns TEXT,
                    first_seen REAL,
                    last_seen REAL,
                    request_count INTEGER DEFAULT 1,
                    status_codes TEXT,
                    attack_type TEXT,
                    attack_confidence REAL DEFAULT 0,
                    response_time_avg REAL DEFAULT 0,
                    response_size_avg REAL DEFAULT 0,
                    parameters TEXT,
                    has_credentials BOOLEAN DEFAULT 0
                )
            """)
            
            # HTTP client behavior profiles
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS x_http_client_profiles (
                    client_ip TEXT PRIMARY KEY,
                    first_seen REAL,
                    last_seen REAL,
                    requests_count INTEGER DEFAULT 0,
                    unique_hosts INTEGER DEFAULT 0,
                    unique_paths INTEGER DEFAULT 0,
                    user_agents TEXT,
                    methods_used TEXT,
                    status_codes_received TEXT,
                    average_request_interval REAL,
                    path_depth_avg REAL,
                    parameter_use_ratio REAL,
                    error_ratio REAL,
                    suspicious_score REAL DEFAULT 0,
                    profile_type TEXT,
                    session_entropy REAL DEFAULT 0,
                    automated_score REAL DEFAULT 0
                )
            """)
            
            # HTTP host technology fingerprints
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS x_http_host_technologies (
                    host TEXT PRIMARY KEY,
                    first_seen REAL,
                    last_seen REAL,
                    technologies TEXT,
                    server_headers TEXT,
                    cms_version TEXT,
                    framework_version TEXT,
                    response_headers TEXT,
                    security_headers TEXT,
                    security_score REAL DEFAULT 0
                )
            """)
            
            # HTTP parameter analysis
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS x_http_parameter_analysis(
                    parameter_name TEXT,
                    host TEXT,
                    data_type TEXT,
                    min_length INTEGER,
                    max_length INTEGER,
                    avg_length REAL,
                    unique_values INTEGER,
                    entropy REAL,
                    is_pii BOOLEAN DEFAULT 0,
                    is_sensitive BOOLEAN DEFAULT 0,
                    first_seen REAL,
                    last_seen REAL,
                    PRIMARY KEY (parameter_name, host)
                )
            """)
            
            # Create indices
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_analysis_host ON x_http_analysis(host)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_analysis_score ON x_http_analysis(suspicious_score DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_analysis_attack ON x_http_analysis(attack_type)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_client_score ON x_http_client_profiles(suspicious_score DESC)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_client_auto ON x_http_client_profiles(automated_score DESC)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_host_tech ON http_host_technologies(host)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_host_security ON http_host_technologies(security_score)")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_http_param_sensitive ON http_parameter_analysis(is_sensitive)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("HTTP analysis tables initialized with enhanced schema")
        except Exception as e:
            logger.error(f"Error initializing HTTP analysis tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process an HTTP packet for advanced analysis"""
        # Get the layers
        layers = packet_data.get("layers", {})
        if not layers:
            return False
        
        # Check if this is an HTTP packet
        if not self.analysis_manager._has_http_data(layers):
            return False
        
        try:
            # Extract HTTP data
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
            
            # Extract HTTP fields for request analysis
            method = self.analysis_manager._get_layer_value(layers, "http_request_method")
            uri = self.analysis_manager._get_layer_value(layers, "http_request_uri")
            host = self.analysis_manager._get_layer_value(layers, "http_host")
            user_agent = self.analysis_manager._get_layer_value(layers, "http_user_agent")
            referer = self.analysis_manager._get_layer_value(layers, "http_referer")
            content_type = self.analysis_manager._get_layer_value(layers, "http_content_type")
            
            # Extract headers for additional analysis
            headers = {}
            for key in layers.keys():
                if key.startswith("http_") and "_line" not in key and key not in [
                    "http_request_method", "http_request_uri", "http_host", 
                    "http_user_agent", "http_referer", "http_content_type"
                ]:
                    header_name = key[5:].replace("_", "-")  # Convert http_accept_language to Accept-Language
                    headers[header_name] = self.analysis_manager._get_layer_value(layers, key)
            
            # Process request data
            if method and uri:
                self._analyze_http_request(
                    connection_key, src_ip, dst_ip, method, uri, host or dst_ip, 
                    user_agent, referer, content_type, headers
                )
            
            # Process response data
            status_code_raw = self.analysis_manager._get_layer_value(layers, "http_response_code")
            server_header = self.analysis_manager._get_layer_value(layers, "http_server")
            
            if status_code_raw:
                try:
                    status_code = int(status_code_raw)
                    self._analyze_http_response(
                        connection_key, src_ip, dst_ip, status_code, 
                        server_header, host or dst_ip, uri, headers
                    )
                except (ValueError, TypeError):
                    pass
            
            return True
        except Exception as e:
            logger.error(f"Error analyzing HTTP packet: {e}")
            return False
    
    def _analyze_http_request(self, connection_key, src_ip, dst_ip, method, uri, host, 
                              user_agent, referer, content_type, headers):
        """Enhanced analysis of HTTP requests with pattern detection and behavioral profiling"""
        current_time = time.time()
        
        # Parse URL components
        parsed_uri = urlparse(uri)
        path = parsed_uri.path or "/"
        query = parsed_uri.query
        
        # Extract parameters from query string
        parameters = {}
        if query:
            try:
                parameters = parse_qs(query)
            except Exception:
                pass
        
        # Track host path structure for site mapping
        self.host_paths[host].add(path)
        
        # Calculate path depth
        path_depth = path.count('/')
        
        # Check for suspicious URL patterns
        suspicious_score = 0
        detected_patterns = []
        
        for pattern, pattern_name in self.suspicious_url_patterns:
            if re.search(pattern, uri):
                suspicious_score += 3
                detected_patterns.append(pattern_name)
        
        # Check for suspicious user agent
        user_agent_type = "normal"
        if user_agent:
            for pattern, ua_type in self.suspicious_user_agents:
                if re.search(pattern, user_agent):
                    suspicious_score += 2
                    detected_patterns.append(f"ua_{ua_type}")
                    user_agent_type = ua_type
        
        # Check for suspicious headers
        for pattern, header_type in self.suspicious_headers:
            for header_name, header_value in headers.items():
                if header_value and re.search(pattern, f"{header_name}: {header_value}"):
                    suspicious_score += 2
                    detected_patterns.append(f"header_{header_type}")
        
        # Check for IP address in host header (unusual)
        if host and re.search(self.ip_pattern, host):
            suspicious_score += 1
            detected_patterns.append("ip_as_host")
        
        # Check for unusual HTTP methods
        if method not in ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"]:
            suspicious_score += 2
            detected_patterns.append(f"unusual_method_{method}")
        
        # Check for authentication or credentials in URL
        has_credentials = False
        if "Authorization" in headers or re.search(r'(?i)(?:\?|\&)(?:password|passwd|pwd|token|apikey)=', uri):
            has_credentials = True
            
        # Determine attack type and confidence
        attack_type = None
        attack_confidence = 0
        
        # Categorize attack types
        attack_categories = {
            'sql_injection': ['sql_injection_quotes', 'sql_injection_operators', 'sql_select', 'sql_functions', 'time_based_injection'],
            'xss': ['xss_script_tag', 'event_handler_xss', 'javascript_injection'],
            'file_inclusion': ['directory_traversal', 'system_file_access', 'file_extension_bypass'],
            'command_injection': ['command_injection', 'command_execution'],
            'scanning': ['scanner', 'pentest_tool', 'scripted_client', 'scanner_aggressive', 'commercial_scanner'],
            'information_disclosure': ['metadata_access', 'admin_access'],
            'authentication_attack': ['password_in_url'],
            'encoding_evasion': ['hex_encoding', 'encoded_payload', 'encoded_ua']
        }
        
        # Count pattern matches by category
        category_counts = defaultdict(int)
        for pattern in detected_patterns:
            for category, patterns in attack_categories.items():
                if any(pattern.startswith(p) or pattern == p for p in patterns):
                    category_counts[category] += 1
        
        # Determine primary attack type
        if category_counts:
            attack_type = max(category_counts.items(), key=lambda x: x[1])[0]
            # Calculate confidence based on number of matches in category
            attack_confidence = min(1.0, category_counts[attack_type] / 3)  # Scale to max 1.0
        
        # Store analysis results
        cursor = self.analysis_manager.get_cursor()
        
        try:
            # Check if we've seen this request before
            cursor.execute("""
                SELECT id, suspicious_score, request_count, status_codes, 
                       response_time_avg, response_size_avg
                FROM x_http_analysis
                WHERE host = ? AND uri = ? AND method = ?
            """, (host, uri, method))
            
            result = cursor.fetchone()
            
            # Prepare patterns JSON
            patterns_json = json.dumps(detected_patterns)
            parameters_json = json.dumps({k: len(v) for k, v in parameters.items()}) if parameters else "{}"
            
            if result:
                # Update existing record
                record_id, old_score, request_count, status_codes_json, resp_time_avg, resp_size_avg = result
                
                # Use the higher score
                final_score = max(suspicious_score, old_score)
                
                # Convert status codes JSON
                status_codes = json.loads(status_codes_json) if status_codes_json else {}
                
                cursor.execute("""
                    UPDATE x_http_analysis
                    SET last_seen = ?,
                        request_count = request_count + 1,
                        suspicious_score = ?,
                        user_agent = ?,
                        detected_patterns = ?,
                        attack_type = ?,
                        attack_confidence = ?,
                        parameters = ?,
                        has_credentials = ?
                    WHERE id = ?
                """, (
                    current_time, final_score, user_agent or "", patterns_json,
                    attack_type, attack_confidence, parameters_json, 
                    1 if has_credentials else 0, record_id
                ))
            else:
                # Insert new record
                cursor.execute("""
                    INSERT INTO x_http_analysis
                    (connection_key, host, uri, method, suspicious_score, user_agent, 
                     detected_patterns, first_seen, last_seen, parameters, 
                     attack_type, attack_confidence, has_credentials)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    connection_key, host, uri, method, suspicious_score, 
                    user_agent or "", patterns_json, current_time, current_time,
                    parameters_json, attack_type, attack_confidence,
                    1 if has_credentials else 0
                ))
            
            # Update client profile
            self._update_client_profile(
                cursor, src_ip, host, method, path, path_depth, 
                user_agent, user_agent_type, parameters, current_time
            )
            
            # Analyze any parameters
            if parameters:
                self._analyze_parameters(cursor, host, parameters, current_time)
            
            self.analysis_manager.analysis1_conn.commit()
        finally:
            cursor.close()
    
    def _analyze_http_response(self, connection_key, src_ip, dst_ip, status_code, 
                               server_header, host, uri, headers):
        """Analyze HTTP response data to enhance request analysis and profile hosts"""
        current_time = time.time()
        cursor = self.analysis_manager.get_cursor()
        
        try:
            # Update status code in the x_http_analysistable
            cursor.execute("""
                SELECT id, status_codes FROM x_http_analysis
                WHERE connection_key = ? OR (host = ? AND uri = ?)
                ORDER BY last_seen DESC LIMIT 1
            """, (connection_key, host, uri or "/"))
            
            result = cursor.fetchone()
            
            if result:
                record_id, status_codes_json = result
                
                # Parse existing status codes or create new dictionary
                status_codes = {}
                if status_codes_json:
                    try:
                        status_codes = json.loads(status_codes_json)
                    except json.JSONDecodeError:
                        status_codes = {}
                
                # Convert status code to string for JSON key
                status_str = str(status_code)
                
                # Update status code count
                if status_str in status_codes:
                    status_codes[status_str] += 1
                else:
                    status_codes[status_str] = 1
                
                # Update record
                cursor.execute("""
                    UPDATE x_http_analysis
                    SET status_codes = ?
                    WHERE id = ?
                """, (json.dumps(status_codes), record_id))
            
            # Update host technologies profile
            self._analyze_host_technologies(cursor, host, server_header, headers, current_time)
            
            # Update client profile with response data
            if src_ip:
                cursor.execute("""
                    SELECT client_ip, status_codes_received FROM x_http_client_profiles
                    WHERE client_ip = ?
                """, (src_ip,))
                
                client_result = cursor.fetchone()
                
                if client_result:
                    client_ip, status_codes_json = client_result
                    
                    # Parse existing status codes or create new dictionary
                    status_codes = {}
                    if status_codes_json:
                        try:
                            status_codes = json.loads(status_codes_json)
                        except json.JSONDecodeError:
                            status_codes = {}
                    
                    # Update status code count
                    status_str = str(status_code)
                    if status_str in status_codes:
                        status_codes[status_str] += 1
                    else:
                        status_codes[status_str] = 1
                    
                    # Calculate error ratio
                    total_responses = sum(status_codes.values())
                    error_responses = sum(status_codes.get(str(c), 0) for c in range(400, 600))
                    error_ratio = error_responses / total_responses if total_responses > 0 else 0
                    
                    # Update client profile
                    cursor.execute("""
                        UPDATE x_http_client_profiles
                        SET status_codes_received = ?,
                            error_ratio = ?,
                            last_seen = ?
                        WHERE client_ip = ?
                    """, (json.dumps(status_codes), error_ratio, current_time, src_ip))
            
            self.analysis_manager.analysis1_conn.commit()
        except Exception as e:
            logger.error(f"Error analyzing HTTP response: {e}")
        finally:
            cursor.close()
    
    def _update_client_profile(self, cursor, client_ip, host, method, path, path_depth, 
                               user_agent, user_agent_type, parameters, timestamp):
        """Update HTTP client behavioral profile"""
        try:
            # Check if client exists in profiles
            cursor.execute("""
                SELECT requests_count, unique_hosts, unique_paths, user_agents, 
                       methods_used, path_depth_avg, parameter_use_ratio,
                       first_seen, last_seen, automated_score
                FROM x_http_client_profiles
                WHERE client_ip = ?
            """, (client_ip,))
            
            result = cursor.fetchone()
            
            # Track method usage
            has_parameters = 1 if parameters else 0
            
            if result:
                (requests_count, unique_hosts, unique_paths, user_agents_json, 
                 methods_json, path_depth_avg, parameter_use_ratio, 
                 first_seen, last_seen, automated_score) = result
                
                # Parse JSON data
                user_agents_dict = json.loads(user_agents_json) if user_agents_json else {}
                methods_dict = json.loads(methods_json) if methods_json else {}
                
                # Update counters
                requests_count += 1
                
                # Update unique hosts set
                cursor.execute("""
                    SELECT COUNT(*) FROM (
                        SELECT DISTINCT host FROM x_http_analysis
                        WHERE connection_key LIKE ? || '%'
                    )
                """, (client_ip,))
                unique_hosts = cursor.fetchone()[0] or 1
                
                # Update unique paths set
                cursor.execute("""
                    SELECT COUNT(*) FROM (
                        SELECT DISTINCT uri FROM x_http_analysis
                        WHERE connection_key LIKE ? || '%'
                    )
                """, (client_ip,))
                unique_paths = cursor.fetchone()[0] or 1
                
                # Update user agent tracking
                if user_agent:
                    ua_key = user_agent_type
                    if ua_key in user_agents_dict:
                        user_agents_dict[ua_key] += 1
                    else:
                        user_agents_dict[ua_key] = 1
                
                # Update methods tracking
                if method in methods_dict:
                    methods_dict[method] += 1
                else:
                    methods_dict[method] = 1
                
                # Update path depth average
                path_depth_avg = ((path_depth_avg * (requests_count - 1)) + path_depth) / requests_count
                
                # Update parameter use ratio
                total_params = parameter_use_ratio * (requests_count - 1) + has_parameters
                parameter_use_ratio = total_params / requests_count
                
                # Calculate request interval
                avg_interval = 0
                if last_seen and last_seen != timestamp:
                    interval = timestamp - last_seen
                    
                    # Get previous average interval
                    cursor.execute("""
                        SELECT average_request_interval FROM x_http_client_profiles
                        WHERE client_ip = ?
                    """, (client_ip,))
                    prev_avg = cursor.fetchone()[0] or 0
                    
                    # Calculate new average (weighted to recent)
                    if prev_avg > 0:
                        avg_interval = (prev_avg * 0.8) + (interval * 0.2)
                    else:
                        avg_interval = interval
                
                # Determine if the client is likely automated
                automated_score = self._calculate_automated_score(
                    requests_count, unique_paths, path_depth_avg, parameter_use_ratio,
                    avg_interval, user_agents_dict, methods_dict
                )
                
                # Calculate session entropy
                session_entropy = self._calculate_session_entropy(cursor, client_ip)
                
                # Determine profile type
                profile_type = self._determine_profile_type(
                    automated_score, user_agents_dict, methods_dict, unique_paths
                )
                
                # Calculate new suspicious score
                suspicious_score = self._calculate_client_suspicious_score(
                    automated_score, user_agents_dict, methods_dict, profile_type,
                    parameter_use_ratio, session_entropy
                )
                
                # Update client profile
                cursor.execute("""
                    UPDATE x_http_client_profiles
                    SET requests_count = ?,
                        unique_hosts = ?,
                        unique_paths = ?,
                        user_agents = ?,
                        methods_used = ?,
                        last_seen = ?,
                        average_request_interval = ?,
                        path_depth_avg = ?,
                        parameter_use_ratio = ?,
                        automated_score = ?,
                        session_entropy = ?,
                        profile_type = ?,
                        suspicious_score = ?
                    WHERE client_ip = ?
                """, (
                    requests_count, unique_hosts, unique_paths, 
                    json.dumps(user_agents_dict), json.dumps(methods_dict),
                    timestamp, avg_interval, path_depth_avg, parameter_use_ratio,
                    automated_score, session_entropy, profile_type, suspicious_score, client_ip
                ))
            else:
                # Create new client profile
                user_agents_dict = {user_agent_type: 1} if user_agent else {"unknown": 1}
                methods_dict = {method: 1}
                
                # Initialize with conservative values
                automated_score = 0.1
                profile_type = "new"
                suspicious_score = 0.1
                session_entropy = 0
                
                cursor.execute("""
                    INSERT INTO x_http_client_profiles
                    (client_ip, first_seen, last_seen, requests_count, unique_hosts,
                     unique_paths, user_agents, methods_used, average_request_interval,
                     path_depth_avg, parameter_use_ratio, automated_score,
                     session_entropy, profile_type, suspicious_score)
                    VALUES (?, ?, ?, 1, 1, 1, ?, ?, 0, ?, ?, ?, ?, ?, ?)
                """, (
                    client_ip, timestamp, timestamp, 
                    json.dumps(user_agents_dict), json.dumps(methods_dict),
                    path_depth, has_parameters, automated_score,
                    session_entropy, profile_type, suspicious_score
                ))
        except Exception as e:
            logger.error(f"Error updating client profile for {client_ip}: {e}")
    
    def _analyze_parameters(self, cursor, host, parameters, timestamp):
        """Analyze HTTP query parameters to detect sensitive data and patterns"""
        try:
            for param_name, values in parameters.items():
                if not values:
                    continue # Calculate statistics for this parameter
                lengths = [len(v) for v in values if v]
                if not lengths:
                    continue
                    
                min_length = min(lengths)
                max_length = max(lengths)
                avg_length = sum(lengths) / len(lengths)
                
                # Calculate unique values ratio
                unique_values = len(set(values))
                
                # Determine data type
                data_type = self._detect_parameter_type(values[0])
                
                # Calculate entropy of values
                entropy = self._calculate_parameter_entropy(values)
                
                # Check if parameter might contain PII
                is_pii = self._detect_pii_parameter(param_name, values[0])
                
                # Check if parameter might be sensitive
                is_sensitive = self._detect_sensitive_parameter(param_name, values[0])
                
                # Check if parameter exists
                cursor.execute("""
                    SELECT parameter_name, data_type, min_length, max_length, avg_length, unique_values
                    FROM http_parameter_analysis
                    WHERE parameter_name = ? AND host = ?
                """, (param_name, host))
                
                result = cursor.fetchone()
                
                if result:
                    # Update existing parameter
                    _, old_data_type, old_min, old_max, old_avg, old_unique = result
                    
                    # Update with new extremes
                    new_min = min(min_length, old_min)
                    new_max = max(max_length, old_max)
                    
                    # Weighted average for avg_length
                    cursor.execute("""
                        SELECT COUNT(*) FROM x_http_analysis
                        WHERE host = ? AND parameters LIKE ?
                    """, (host, f'%"{param_name}"%'))
                    
                    param_count = cursor.fetchone()[0] or 1
                    new_avg = ((old_avg * (param_count - 1)) + avg_length) / param_count
                    
                    cursor.execute("""
                        UPDATE http_parameter_analysis
                        SET min_length = ?,
                            max_length = ?,
                            avg_length = ?,
                            unique_values = ?,
                            entropy = ?,
                            is_pii = ?,
                            is_sensitive = ?,
                            last_seen = ?
                        WHERE parameter_name = ? AND host = ?
                    """, (
                        new_min, new_max, new_avg, unique_values + old_unique,
                        entropy, 1 if is_pii else 0, 1 if is_sensitive else 0,
                        timestamp, param_name, host
                    ))
                else:
                    # Insert new parameter
                    cursor.execute("""
                        INSERT INTO http_parameter_analysis
                        (parameter_name, host, data_type, min_length, max_length, 
                         avg_length, unique_values, entropy, is_pii, is_sensitive, 
                         first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        param_name, host, data_type, min_length, max_length,
                        avg_length, unique_values, entropy, 
                        1 if is_pii else 0, 1 if is_sensitive else 0, 
                        timestamp, timestamp
                    ))
        except Exception as e:
            logger.error(f"Error analyzing parameters for host {host}: {e}")
    
    def _analyze_host_technologies(self, cursor, host, server_header, headers, timestamp):
        """Analyze and fingerprint technologies used by the host"""
        try:
            # Check if host exists
            cursor.execute("""
                SELECT technologies, server_headers, security_headers
                FROM http_host_technologies
                WHERE host = ?
            """, (host,))
            
            result = cursor.fetchone()
            
            # Detect technologies from headers
            technologies = set()
            if server_header:
                for tech, patterns in self.tech_fingerprints.items():
                    if any(re.search(pattern, server_header, re.IGNORECASE) for pattern in patterns):
                        technologies.add(tech)
            
            # Look for technology indicators in headers
            for header_name, header_value in headers.items():
                if not header_value:
                    continue
                for tech, patterns in self.tech_fingerprints.items():
                    if any(re.search(pattern, header_value, re.IGNORECASE) for pattern in patterns):
                        technologies.add(tech)
            
            # Check for security headers
            security_headers = {
                'Strict-Transport-Security': False,
                'Content-Security-Policy': False,
                'X-Content-Type-Options': False,
                'X-Frame-Options': False,
                'X-XSS-Protection': False,
                'Referrer-Policy': False,
                'Permissions-Policy': False
            }
            
            for header in security_headers.keys():
                if header in headers:
                    security_headers[header] = True
            
            # Calculate security score (0-10)
            security_score = sum(1.4 for h, present in security_headers.items() if present)
            
            if result:
                # Update existing host profile
                existing_tech_json, existing_server_headers_json, existing_security_headers_json = result
                
                # Merge technologies
                existing_tech = json.loads(existing_tech_json) if existing_tech_json else []
                merged_tech = list(set(existing_tech + list(technologies)))
                
                # Update server headers
                existing_server_headers = json.loads(existing_server_headers_json) if existing_server_headers_json else {}
                if server_header and server_header not in existing_server_headers.values():
                    existing_server_headers[str(timestamp)] = server_header
                
                # Limit to last 10 server headers
                if len(existing_server_headers) > 10:
                    existing_server_headers = dict(sorted(existing_server_headers.items(), reverse=True)[:10])
                
                # Update security headers status
                existing_security_headers = json.loads(existing_security_headers_json) if existing_security_headers_json else {}
                for header, present in security_headers.items():
                    if present:
                        existing_security_headers[header] = True
                
                cursor.execute("""
                    UPDATE http_host_technologies
                    SET technologies = ?,
                        server_headers = ?,
                        security_headers = ?,
                        security_score = ?,
                        last_seen = ?
                    WHERE host = ?
                """, (
                    json.dumps(merged_tech),
                    json.dumps(existing_server_headers),
                    json.dumps(existing_security_headers),
                    security_score,
                    timestamp,
                    host
                ))
            else:
                # Create new host profile
                cursor.execute("""
                    INSERT INTO http_host_technologies
                    (host, first_seen, last_seen, technologies, server_headers,
                     security_headers, security_score)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    host,
                    timestamp,
                    timestamp,
                    json.dumps(list(technologies)),
                    json.dumps({str(timestamp): server_header}) if server_header else "{}",
                    json.dumps({h: present for h, present in security_headers.items() if present}),
                    security_score
                ))
        except Exception as e:
            logger.error(f"Error analyzing host technologies for {host}: {e}")
    
    def _detect_parameter_type(self, value):
        """Detect data type of parameter value"""
        if not value:
            return "empty"
            
        # Check if it's a numeric value
        try:
            int(value)
            return "integer"
        except ValueError:
            try:
                float(value)
                return "float"
            except ValueError:
                pass
        
        # Check for boolean values
        if value.lower() in ('true', 'false', '1', '0', 'yes', 'no'):
            return "boolean"
            
        # Check for date format
        if re.match(r'^\d{4}-\d{2}-\d{2}', value):
            return "date"
            
        # Check for emails
        if '@' in value and '.' in value.split('@')[1]:
            return "email"
            
        # Check for URLs
        if value.startswith(('http://', 'https://')):
            return "url"
            
        # Check for UUIDs
        if re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', value, re.I):
            return "uuid"
            
        # Check for JSON
        if (value.startswith('{') and value.endswith('}')) or (value.startswith('[') and value.endswith(']')):
            try:
                json.loads(value)
                return "json"
            except:
                pass
                
        # Check for base64
        if re.match(r'^[A-Za-z0-9+/]+={0,2}$', value) and len(value) % 4 == 0:
            return "base64"
            
        # Default to string
        return "string"
    
    def _calculate_parameter_entropy(self, values):
        """Calculate Shannon entropy of parameter values"""
        # Concatenate all values for analysis
        combined = ''.join(str(v) for v in values)
        if not combined:
            return 0
            
        # Count frequencies
        freq = {}
        for char in combined:
            if char in freq:
                freq[char] += 1
            else:
                freq[char] = 1
                
        # Calculate entropy
        entropy = 0
        for count in freq.values():
            probability = count / len(combined)
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def _detect_pii_parameter(self, param_name, value):
        """Detect if parameter might contain personally identifiable information"""
        pii_indicators = [
            'email', 'mail', 'address', 'name', 'firstname', 'lastname', 'fullname',
            'phone', 'mobile', 'ssn', 'social', 'dob', 'birth', 'gender', 'zip',
            'postal', 'passport', 'license', 'credential', 'user', 'username'
        ]
        
        # Check parameter name
        if any(indicator in param_name.lower() for indicator in pii_indicators):
            return True
            
        # Check if value looks like an email
        if '@' in value and '.' in value.split('@')[1]:
            return True
            
        # Check for phone number pattern
        if re.search(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', value):
            return True
            
        # Check for social security number pattern (US)
        if re.search(r'\b\d{3}[-]?\d{2}[-]?\d{4}\b', value):
            return True
            
        return False
    
    def _detect_sensitive_parameter(self, param_name, value):
        """Detect if parameter might contain sensitive information"""
        sensitive_indicators = [
            'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
            'auth', 'credential', 'hash', 'private', 'security', 'signature',
            'access_token', 'refresh_token', 'session'
        ]
        
        # Check parameter name
        return any(indicator in param_name.lower() for indicator in sensitive_indicators)
    
    def _calculate_automated_score(self, requests_count, unique_paths, path_depth_avg, 
                                 parameter_use_ratio, avg_interval, user_agents_dict, methods_dict):
        """Calculate a score representing how likely the client is automated (0-10)"""
        if requests_count < 5:
            return 0  # Not enough data
            
        score = 0
        
        # Regular users typically visit relatively few unique paths
        paths_ratio = min(1.0, unique_paths / requests_count)
        if paths_ratio < 0.1:  # Less than 10% of requests go to unique paths
            score += 2
        elif paths_ratio < 0.3:
            score += 1
            
        # Check for regular intervals between requests
        if avg_interval > 0:
            # Very consistent timing suggests automation
            if avg_interval < 1.0:  # Less than 1 second between requests
                score += 3
            elif avg_interval < 5.0:  # Less than 5 seconds between requests
                score += 2
            elif avg_interval < 10.0:  # Less than 10 seconds between requests
                score += 1
                
        # Check user agent diversity (automated tools often use few user agents)
        if len(user_agents_dict) == 1 and requests_count > 10:
            score += 1
            
        # Check for scripted client user agents
        for ua_type, count in user_agents_dict.items():
            if ua_type in ('scanner', 'pentest_tool', 'scripted_client', 'scanner_aggressive'):
                score += 2
                
        # Check method diversity (automated tools often use consistent methods)
        if len(methods_dict) == 1 and requests_count > 10:
            score += 1
            
        # Cap the score at 10
        return min(10, score)
    
    def _calculate_session_entropy(self, cursor, client_ip):
        """Calculate entropy of client's session (measuring randomness/uniqueness of behavior)"""
        try:
            # Get unique paths visited by this client
            cursor.execute("""
                SELECT uri FROM x_http_analysis
                WHERE connection_key LIKE ? || '%'
                ORDER BY last_seen DESC
                LIMIT 50
            """, (client_ip,))
            
            paths = [row[0] for row in cursor.fetchall()]
            
            if not paths:
                return 0
                
            # Calculate path transitions
            transitions = []
            for i in range(1, len(paths)):
                transitions.append(f"{paths[i-1]}->{paths[i]}")
                
            # Count transition frequencies
            freq = {}
            for transition in transitions:
                if transition in freq:
                    freq[transition] += 1
                else:
                    freq[transition] = 1
                    
            # Calculate entropy
            entropy = 0
            total_transitions = len(transitions)
            if total_transitions == 0:
                return 0
                
            for count in freq.values():
                probability = count / total_transitions
                entropy -= probability * math.log2(probability)
                
            # Normalize to 0-10 scale
            # A completely random browsing pattern would have high entropy
            # A very predictable pattern would have low entropy
            return min(10, entropy * 2)
        except Exception as e:
            logger.error(f"Error calculating session entropy for {client_ip}: {e}")
            return 0
    
    def _determine_profile_type(self, automated_score, user_agents_dict, methods_dict, unique_paths):
        """Determine the type of client profile based on behavior"""
        # Check for known scanners/tools
        for ua_type in user_agents_dict.keys():
            if ua_type in ('scanner', 'scanner_aggressive', 'commercial_scanner'):
                return 'scanner'
            elif ua_type in ('pentest_tool'):
                return 'penetration_test'
            elif ua_type in ('seo_crawler'):
                return 'crawler'
                
        # Check for other automated behavior
        if automated_score > 7:
            if 'GET' in methods_dict and len(methods_dict) == 1:
                return 'crawler'
            else:
                return 'automated'
                
        # Check for API client
        if 'POST' in methods_dict and methods_dict.get('GET', 0) < methods_dict['POST'] and unique_paths < 5:
            return 'api_client'
            
        # Normal browsing behavior
        if automated_score < 3 and unique_paths > 5:
            return 'browser'
            
        # Default
        return 'mixed'
    
    def _calculate_client_suspicious_score(self, automated_score, user_agents_dict, 
                                         methods_dict, profile_type, parameter_use_ratio, 
                                         session_entropy):
        """Calculate a suspiciousness score for the client (0-10)"""
        score = 0
        
        # Known scanners/tools are automatically suspicious
        for ua_type, count in user_agents_dict.items():
            if ua_type in ('scanner', 'scanner_aggressive', 'pentest_tool'):
                score += 3
            elif ua_type in ('scripted_client'):
                score += 1
                
        # Highly automated behavior is somewhat suspicious
        if automated_score > 8:
            score += 2
        elif automated_score > 5:
            score += 1
            
        # Unusual profile types
        if profile_type in ('scanner', 'penetration_test'):
            score += 3
        elif profile_type in ('automated'):
            score += 1
            
        # Unusual method distributions
        if 'POST' in methods_dict and 'GET' not in methods_dict and sum(methods_dict.values()) > 10:
            score += 1
        if 'OPTIONS' in methods_dict and methods_dict['OPTIONS'] > 5:
            score += 1
        if any(m in methods_dict for m in ('PUT', 'DELETE')) and sum(methods_dict.values()) > 10:
            score += 1
            
        # Low entropy can indicate scripted behavior
        if session_entropy < 2 and automated_score > 5:
            score += 1
            
        # Cap the score at 10
        return min(10, score)
    
    def run_periodic_analysis(self):
        """Run periodic analysis on HTTP traffic"""
        current_time = time.time()
        if current_time - self.last_report_time < self.report_interval:
            return False  # Not time for a report yet
        
        self.last_report_time = current_time
        
        try:
            cursor = self.analysis_manager.get_cursor()
            
            # Analyze host paths to detect site structure
            self._analyze_host_structures(cursor)
            
            # Analyze suspicious HTTP requests
            self._analyze_suspicious_requests(cursor)
            
            # Analyze client behaviors
            self._analyze_client_behaviors(cursor)
            
            # Analyze parameters for sensitive data
            self._analyze_sensitive_parameters(cursor)
            
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error in HTTP periodic analysis: {e}")
            return False
    
    def _analyze_host_structures(self, cursor):
        """Analyze host path structures to detect site organization"""
        try:
            # Get hosts with significant traffic
            cursor.execute("""
                SELECT host, COUNT(*) as request_count
                FROM x_http_analysis
                GROUP BY host
                HAVING request_count > 10
                ORDER BY request_count DESC
                LIMIT 20
            """)
            
            hosts = cursor.fetchall()
            
            for host, request_count in hosts:
                # Get paths for this host
                cursor.execute("""
                    SELECT uri, COUNT(*) as count
                    FROM x_http_analysis
                    WHERE host = ?
                    GROUP BY uri
                    ORDER BY count DESC
                    LIMIT 100
                """, (host,))
                
                paths = [row[0] for row in cursor.fetchall()]
                
                if not paths:
                    continue
                    
                # Group paths by directory structure
                path_tree = {}
                
                for path in paths:
                    parts = path.strip('/').split('/')
                    current = path_tree
                    
                    for part in parts:
                        if not part:
                            continue
                        if part not in current:
                            current[part] = {}
                        current = current[part]
                
                # Count entry points (top-level directories)
                entry_points = len(path_tree)
                
                # Calculate average path depth
                depths = [len(p.strip('/').split('/')) for p in paths]
                avg_depth = sum(depths) / len(depths) if depths else 0
                
                logger.info(f"Host {host} structure: {entry_points} entry points, {len(paths)} paths, avg depth: {avg_depth:.1f}")
                
                # Detect if site might have an API
                api_paths = [p for p in paths if '/api/' in p or p.startswith('/api')]
                if api_paths:
                    logger.info(f"Host {host} has API endpoints: {len(api_paths)} paths detected")
        except Exception as e:
            logger.error(f"Error analyzing host structures: {e}")
    
    def _analyze_suspicious_requests(self, cursor):
        """Analyze suspicious HTTP requests for attack patterns"""
        try:
            # Get top suspicious requests
            cursor.execute("""
                SELECT host, uri, method, suspicious_score, detected_patterns, attack_type, request_count
                FROM x_http_analysis
                WHERE suspicious_score > 3
                ORDER BY suspicious_score DESC, request_count DESC
                LIMIT 50
            """)
            
            suspicious_requests = cursor.fetchall()
            
            if suspicious_requests:
                logger.info(f"Found {len(suspicious_requests)} suspicious HTTP requests")
                
                # Group by attack type
                attack_types = defaultdict(int)
                attack_hosts = defaultdict(set)
                
                for host, uri, method, score, patterns_json, attack_type, count in suspicious_requests:
                    if attack_type:
                        attack_types[attack_type] += 1
                        attack_hosts[attack_type].add(host)
                
                # Log summary
                for attack_type, count in attack_types.items():
                    targets = len(attack_hosts[attack_type])
                    logger.info(f"Attack type: {attack_type}, Count: {count}, Unique targets: {targets}")
        except Exception as e:
            logger.error(f"Error analyzing suspicious requests: {e}")
    
    def _analyze_client_behaviors(self, cursor):
        """Analyze HTTP client behaviors for anomalies"""
        try:
            # Get clients with high automated scores
            cursor.execute("""
                SELECT client_ip, automated_score, suspicious_score, profile_type, 
                       requests_count, unique_hosts, unique_paths, session_entropy
                FROM x_http_client_profiles
                WHERE automated_score > 7 OR suspicious_score > 5
                ORDER BY suspicious_score DESC
                LIMIT 20
            """)
            
            automated_clients = cursor.fetchall()
            
            if automated_clients:
                logger.info(f"Found {len(automated_clients)} potentially automated HTTP clients")
                
                for (client_ip, automated_score, suspicious_score, profile_type, 
                    requests, hosts, paths, entropy) in automated_clients:
                    logger.info(f"Client {client_ip}: {profile_type}, automation={automated_score:.1f}, " +
                                f"suspicious={suspicious_score:.1f}, requests={requests}, targets={hosts}")
        except Exception as e:
            logger.error(f"Error analyzing client behaviors: {e}")
    
    def _analyze_sensitive_parameters(self, cursor):
        """Analyze HTTP parameters for sensitive data"""
        try:
            # Find sensitive parameters
            cursor.execute("""
                SELECT parameter_name, host, data_type, avg_length, entropy, is_pii
                FROM http_parameter_analysis
                WHERE is_sensitive = 1 OR is_pii = 1
                ORDER BY entropy DESC
                LIMIT 30
            """)
            
            sensitive_params = cursor.fetchall()
            
            if sensitive_params:
                logger.info(f"Found {len(sensitive_params)} sensitive HTTP parameters")
                
                for param, host, data_type, avg_length, entropy, is_pii in sensitive_params:
                    type_str = "PII" if is_pii else "Sensitive"
                    logger.info(f"{type_str} parameter '{param}' on {host}: type={data_type}, " +
                                f"length={avg_length:.1f}, entropy={entropy:.2f}")
        except Exception as e:
            logger.error(f"Error analyzing sensitive parameters: {e}")