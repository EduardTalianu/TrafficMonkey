# Rule class is injected by the RuleLoader
import requests
import time
import os
import ipaddress
import json
import logging
import re
import hashlib
import threading

class VirusTotalRule(Rule):
    """Rule that checks IPs and URLs against VirusTotal API"""
    def __init__(self):
        super().__init__("VirusTotal Security Check", "Checks IPs and URLs against VirusTotal API to detect malicious connections")
        self.min_detections = 1
        self.cache_duration = 86400  # Cache results for 24 hours (in seconds)
        self.check_interval = 10     # Check at most one resource every 10 seconds to respect API limits
        self.max_checks_per_run = 5  # Maximum number of resources to check per rule run
        self.check_urls = True       # Whether to extract and check URLs from connection data
        
        # To prevent database recursion errors
        self.pending_updates = []
        self.pending_alerts = []
        
        # Store reference to analysis_manager (will be set later when analysis_manager is available)
        self.analysis_manager = None
        
        # Set up cache file path in db directory
        try:
            # Try to locate the db directory from the app_root in the GUI
            if 'gui' in globals() and hasattr(globals()['gui'], 'app_root'):
                app_root = globals()['gui'].app_root
                self.cache_file = os.path.join(app_root, "db", "vt_cache.json")
            else:
                # Fallback: Search for common parent directories
                current_dir = os.getcwd()
                if os.path.exists(os.path.join(current_dir, "db")):
                    self.cache_file = os.path.join(current_dir, "db", "vt_cache.json")
                elif os.path.exists(os.path.join(current_dir, "..", "db")):
                    self.cache_file = os.path.join(current_dir, "..", "db", "vt_cache.json")
                else:
                    # Last resort: just use the current directory
                    self.cache_file = "vt_cache.json"
            
            # Create the db directory if it doesn't exist
            cache_dir = os.path.dirname(self.cache_file)
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir, exist_ok=True)
                
            logging.info(f"Using VirusTotal cache file at: {self.cache_file}")
        except Exception as e:
            logging.error(f"Error setting VirusTotal cache file path: {e}")
            self.cache_file = "vt_cache.json"
        
        # Set up false positives file path in db directory
        try:
            # Try to locate the db directory from the app_root in the GUI
            if 'gui' in globals() and hasattr(globals()['gui'], 'app_root'):
                app_root = globals()['gui'].app_root
                self.false_positives_file = os.path.join(app_root, "db", "false_positives.txt")
            else:
                # Fallback: Search for common parent directories
                current_dir = os.getcwd()
                if os.path.exists(os.path.join(current_dir, "db")):
                    self.false_positives_file = os.path.join(current_dir, "db", "false_positives.txt")
                elif os.path.exists(os.path.join(current_dir, "..", "db")):
                    self.false_positives_file = os.path.join(current_dir, "..", "db", "false_positives.txt")
                else:
                    # Last resort: just use the current directory
                    self.false_positives_file = "false_positives.txt"
            
            # Create the db directory if it doesn't exist
            fp_dir = os.path.dirname(self.false_positives_file)
            if not os.path.exists(fp_dir):
                os.makedirs(fp_dir, exist_ok=True)
                
            logging.info(f"Using false positives file at: {self.false_positives_file}")
        except Exception as e:
            logging.error(f"Error setting false positives file path: {e}")
            self.false_positives_file = "false_positives.txt"
        
        self.false_positives = self.load_false_positives()
        
        self.ip_cache = {}
        self.url_cache = {}
        self.last_check_time = 0
        
        # Load cache if it exists
        self.load_cache()
        
        # Define configurable parameters
        self.configurable_params = {
            "min_detections": {
                "description": "Minimum number of VirusTotal detections to be considered malicious",
                "type": "int",
                "default": 1,
                "current": self.min_detections
            },
            "cache_duration": {
                "description": "How long to cache results (in seconds)",
                "type": "int",
                "default": 86400,
                "current": self.cache_duration
            },
            "check_interval": {
                "description": "Minimum seconds between API checks (to respect rate limits)",
                "type": "int",
                "default": 10, 
                "current": self.check_interval
            },
            "max_checks_per_run": {
                "description": "Maximum number of resources to check in a single run",
                "type": "int",
                "default": 5,
                "current": self.max_checks_per_run
            },
            "check_urls": {
                "description": "Whether to extract and check URLs from connection data",
                "type": "bool",
                "default": True,
                "current": self.check_urls
            }
        }
    
    def load_false_positives(self):
        """Load false positives list from file"""
        false_positives = set()
        try:
            # Create directory if it doesn't exist
            fp_dir = os.path.dirname(self.false_positives_file)
            if not os.path.exists(fp_dir):
                os.makedirs(fp_dir, exist_ok=True)
                
            if os.path.exists(self.false_positives_file):
                with open(self.false_positives_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            false_positives.add(line)
                logging.info(f"Loaded {len(false_positives)} false positives from {self.false_positives_file}")
            return false_positives
        except Exception as e:
            logging.error(f"Error loading false positives: {e}")
            return false_positives
    
    def load_cache(self):
        """Load cached results"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    cache_data = json.load(f)
                    self.ip_cache = cache_data.get('ips', {})
                    self.url_cache = cache_data.get('urls', {})
                logging.info(f"Loaded {len(self.ip_cache)} IP and {len(self.url_cache)} URL results from VirusTotal cache")
            else:
                self.ip_cache = {}
                self.url_cache = {}
        except Exception as e:
            logging.error(f"Error loading VirusTotal cache: {e}")
            self.ip_cache = {}
            self.url_cache = {}
    
    def save_cache(self):
        """Save cache to disk"""
        try:
            # Make sure the directory exists
            cache_dir = os.path.dirname(self.cache_file)
            if not os.path.exists(cache_dir):
                os.makedirs(cache_dir, exist_ok=True)
                
            combined_cache = {
                'ips': self.ip_cache,
                'urls': self.url_cache
            }
            with open(self.cache_file, 'w') as f:
                json.dump(combined_cache, f, indent=2)
            return True
        except Exception as e:
            logging.error(f"Error saving VirusTotal cache: {e}")
            return False
    
    def is_valid_public_ip(self, ip):
        """Check if IP is a valid public IP address"""
        try:
            # Skip empty or invalid IPs
            if not ip or not isinstance(ip, str):
                return False
                
            # Remove port if present
            if ":" in ip:
                ip = ip.split(":")[0]
                
            ip_obj = ipaddress.ip_address(ip)
            return (not ip_obj.is_private and
                    not ip_obj.is_loopback and
                    not ip_obj.is_link_local and
                    not ip_obj.is_multicast and
                    not ip_obj.is_reserved)
        except ValueError:
            return False
    
    def extract_urls_from_packet(self, connection_data):
        """
        Extract potential URLs from connection data
        In a real implementation, this would analyze HTTP traffic if available
        """
        urls = []
        # This is a simplified example - in a real implementation,
        # you would look at actual HTTP traffic data
        if connection_data and isinstance(connection_data, dict):
            # Check if we have any HTTP data
            http_data = connection_data.get('http', '')
            if http_data:
                # Extract URLs from HTTP data
                url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
                matches = url_pattern.findall(str(http_data))
                urls.extend(matches)
        
        return urls
    
    def check_ip(self, ip, api_key):
        """Check an IP address against VirusTotal API"""
        if not api_key:
            logging.warning("No VirusTotal API key provided")
            return None
        
        # Extract the IP part if it contains port information
        clean_ip = ip.split(':')[0] if ':' in ip else ip
        
        # Check if IP is in false positives list
        if clean_ip in self.false_positives:
            logging.info(f"Skipping IP {clean_ip} as it's in the false positives list")
            return {
                'timestamp': time.time(),
                'malicious_count': 0,
                'suspicious_count': 0,
                'total_detections': 0,
                'is_malicious': False,
                'status': 'False Positive'
            }
        
        # Check if we've recently checked this IP
        if clean_ip in self.ip_cache:
            cache_entry = self.ip_cache[clean_ip]
            cache_time = cache_entry.get('timestamp', 0)
            if time.time() - cache_time < self.cache_duration:
                return cache_entry
        
        # Respect API rate limits
        current_time = time.time()
        if current_time - self.last_check_time < self.check_interval:
            return None
        
        self.last_check_time = current_time
        
        # Make the API request
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{clean_ip}"
        headers = {
            "x-apikey": api_key
        }
        
        try:
            logging.info(f"Checking IP {clean_ip} with VirusTotal API")
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                
                # Extract the last analysis stats
                last_analysis = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious_count = last_analysis.get('malicious', 0)
                suspicious_count = last_analysis.get('suspicious', 0)
                
                # Create a cache entry
                entry = {
                    'timestamp': time.time(),
                    'malicious_count': malicious_count,
                    'suspicious_count': suspicious_count,
                    'total_detections': malicious_count + suspicious_count,
                    'is_malicious': (malicious_count + suspicious_count) >= self.min_detections,
                    'status': 'Malicious' if (malicious_count + suspicious_count) >= self.min_detections else 'Clean'
                }
                
                # Update cache
                self.ip_cache[clean_ip] = entry
                self.save_cache()
                
                return entry
                
            elif response.status_code == 404:
                # IP not found in VirusTotal
                entry = {
                    'timestamp': time.time(),
                    'malicious_count': 0,
                    'suspicious_count': 0,
                    'total_detections': 0,
                    'is_malicious': False,
                    'status': 'Unknown'
                }
                self.ip_cache[clean_ip] = entry
                self.save_cache()
                
                return entry
                
            else:
                logging.error(f"VirusTotal API error for IP {clean_ip}: {response.status_code}")
                return None
                
        except Exception as e:
            logging.error(f"Error checking IP {clean_ip} with VirusTotal: {e}")
            return None
    
    def check_url(self, url, api_key):
        """Check a URL against VirusTotal API"""
        if not api_key or not url:
            return None
            
        # Normalize the URL
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        
        # Extract domain from URL to check against false positives
        domain_match = re.search(r'https?://([^:/]+)', url)
        if domain_match:
            domain = domain_match.group(1)
            # Check if domain is in false positives
            if domain in self.false_positives:
                logging.info(f"Skipping URL {url} as domain {domain} is in false positives list")
                return {
                    'timestamp': time.time(),
                    'malicious_count': 0,
                    'suspicious_count': 0,
                    'total_detections': 0,
                    'is_malicious': False,
                    'status': 'False Positive'
                }
            
        # Use URL as cache key
        if url in self.url_cache:
            cache_entry = self.url_cache[url]
            cache_time = cache_entry.get('timestamp', 0)
            if time.time() - cache_time < self.cache_duration:
                return cache_entry
                
        # Respect API rate limits
        current_time = time.time()
        if current_time - self.last_check_time < self.check_interval:
            return None
            
        self.last_check_time = current_time
        
        try:
            # For URLs, we need to use a different endpoint
            # First, get URL ID by hash
            url_id = hashlib.sha256(url.encode()).hexdigest()
            
            api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
            headers = {
                "x-apikey": api_key
            }
            
            logging.info(f"Checking URL {url} with VirusTotal API")
            response = requests.get(api_url, headers=headers)
            
            if response.status_code == 200:
                result = response.json()
                
                # Extract the last analysis stats
                last_analysis = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious_count = last_analysis.get('malicious', 0)
                suspicious_count = last_analysis.get('suspicious', 0)
                
                # Create a cache entry
                entry = {
                    'timestamp': time.time(),
                    'malicious_count': malicious_count,
                    'suspicious_count': suspicious_count,
                    'total_detections': malicious_count + suspicious_count,
                    'is_malicious': (malicious_count + suspicious_count) >= self.min_detections,
                    'status': 'Malicious' if (malicious_count + suspicious_count) >= self.min_detections else 'Clean'
                }
                
                # Update cache
                self.url_cache[url] = entry
                self.save_cache()
                
                return entry
                
            elif response.status_code == 404:
                # If URL not found, we can try to submit it
                logging.info(f"URL {url} not found in VirusTotal, submitting for analysis")
                
                # Submit URL for analysis
                submit_url = "https://www.virustotal.com/api/v3/urls"
                data = {"url": url}
                response = requests.post(submit_url, headers=headers, data=data)
                
                if response.status_code == 200:
                    # Successfully submitted, but no result yet
                    entry = {
                        'timestamp': time.time(),
                        'malicious_count': 0,
                        'suspicious_count': 0,
                        'total_detections': 0,
                        'is_malicious': False,
                        'status': 'Submitted'
                    }
                    self.url_cache[url] = entry
                    self.save_cache()
                    return entry
                else:
                    logging.error(f"Error submitting URL {url} to VirusTotal: {response.status_code}")
                    return None
            else:
                logging.error(f"VirusTotal API error for URL {url}: {response.status_code}")
                return None
                
        except Exception as e:
            logging.error(f"Error checking URL {url} with VirusTotal: {e}")
            return None
    
    def add_pending_alert(self, ip, message, rule_name):
        """Add an alert to the pending list"""
        self.pending_alerts.append((ip, message, rule_name))
    
    def process_pending_alerts(self):
        """Process all pending alerts using the new x_alerts table"""
        for ip, msg, rule_name in self.pending_alerts:
            try:
                # Use analysis_manager to add alert to x_alerts table in analysis_1.db
                self.db_manager.analysis_manager.add_alert(ip, msg, rule_name)
            except Exception as e:
                logging.error(f"Error adding alert to x_alerts table: {e}")
        
        # Clear the list after processing
        self.pending_alerts = []
    
    def analyze(self, db_cursor):
        # Ensure analysis_manager is linked
        if not self.analysis_manager and hasattr(self.db_manager, 'analysis_manager'):
            self.analysis_manager = self.db_manager.analysis_manager
        
        # Return early if analysis_manager is not available
        if not self.analysis_manager:
            logging.error("Cannot run VirusTotal rule: analysis_manager not available")
            return ["ERROR: VirusTotal rule requires analysis_manager"]
        
        # Clear pending alerts from previous runs
        self.pending_alerts = []
        
        # Store alerts to be returned
        alerts = []
        
        # Refresh false positives list before running analysis
        self.false_positives = self.load_false_positives()
        
        try:
            # First, look for any connections already marked as malicious in threat intel table
            # Get a cursor for analysis_1.db
            analysis1_cursor = self.analysis_manager.get_cursor()
            
            # Query x_ip_threat_intel table for malicious IPs
            analysis1_cursor.execute("""
                SELECT ip_address, threat_score, threat_type 
                FROM x_ip_threat_intel 
                WHERE threat_type = 'malware' AND source = 'VirusTotal'
            """)
            
            vt_alerts = analysis1_cursor.fetchall()
            
            for ip_address, threat_score, threat_type in vt_alerts:
                # Check if IP is in false positives list
                if ip_address in self.false_positives:
                    # Update threat intel in analysis_1.db to mark as false positive
                    self.analysis_manager.update_threat_intel(ip_address, {
                        "score": 0,
                        "type": "clean",
                        "confidence": 1.0,
                        "source": "VirusTotal",
                        "details": {"status": "False Positive"}
                    })
                    continue  # Skip creating an alert
                
                # Create alert message
                alert_msg = f"Malicious IP detected: {ip_address} (VirusTotal score: {threat_score})"
                
                # Add to pending alerts
                self.add_pending_alert(ip_address, alert_msg, self.name)
                
                # Add to immediate alerts list
                alerts.append(f"ALERT: {alert_msg}")
            
            # Get API key from environment
            api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
            if not api_key:
                # Add a warning alert
                default_ip = vt_alerts[0][0] if vt_alerts else "0.0.0.0"
                self.add_pending_alert(default_ip, "No VirusTotal API key set in environment variable VIRUSTOTAL_API_KEY", self.name)
                alerts.append("WARNING: No VirusTotal API key set in environment variable VIRUSTOTAL_API_KEY")
                
                # Process all pending alerts
                self.process_pending_alerts()
                
                return alerts
            
            # Look for new connections that haven't been checked
            # Query from analysis.db (read-only)
            db_cursor.execute("""
                SELECT connection_key, src_ip, dst_ip 
                FROM connections 
                WHERE total_bytes > 1000
                LIMIT 100
            """)
            
            # Store the results to process after closing the cursor
            unchecked_connections = []
            for row in db_cursor.fetchall():
                unchecked_connections.append(row)
            
            # Now check if these connections have been analyzed in the threat intel table
            # Get all IPs that have already been checked
            analysis1_cursor.execute("SELECT ip_address FROM x_ip_threat_intel WHERE source = 'VirusTotal'")
            checked_ips = {row[0] for row in analysis1_cursor.fetchall()}
            
            # Check a limited number of resources per run to respect API limits
            checks_performed = 0
            # Keep track of checked IPs for informational messages
            newly_checked_ips = set()
            
            # Process connections outside of cursor context
            for connection_key, src_ip, dst_ip in unchecked_connections:
                # Extract the IP part if it contains port information
                dst_ip_clean = dst_ip.split(':')[0] if ':' in dst_ip else dst_ip
                
                # Skip if not a valid public IP
                if not self.is_valid_public_ip(dst_ip_clean):
                    continue
                
                # Skip if IP is in false positives list
                if dst_ip_clean in self.false_positives:
                    continue
                
                # Skip if we've already checked this IP
                if dst_ip_clean in checked_ips:
                    continue
                
                # Check if we've reached our limit for this run
                if checks_performed >= self.max_checks_per_run:
                    break
                    
                # Check the IP
                result = self.check_ip(dst_ip_clean, api_key)
                checks_performed += 1
                newly_checked_ips.add(dst_ip_clean)
                
                if result:
                    # Store the result in x_ip_threat_intel table
                    if result['is_malicious']:
                        # Create threat intelligence data
                        threat_data = {
                            "score": result['total_detections'],
                            "type": "malware",
                            "confidence": 0.8,
                            "source": "VirusTotal",
                            "first_seen": time.time(),
                            "details": {
                                "malicious_count": result['malicious_count'],
                                "suspicious_count": result['suspicious_count'],
                                "status": result['status']
                            }
                        }
                    else:
                        # Create clean intel data
                        threat_data = {
                            "score": 0,
                            "type": "clean",
                            "confidence": 0.8,
                            "source": "VirusTotal",
                            "first_seen": time.time(),
                            "details": {
                                "malicious_count": result['malicious_count'],
                                "suspicious_count": result['suspicious_count'],
                                "status": result['status']
                            }
                        }
                    
                    # Store in x_ip_threat_intel table
                    self.analysis_manager.update_threat_intel(dst_ip_clean, threat_data)
                    
                    if result['is_malicious']:
                        # Create alert message
                        alert_msg = f"Malicious IP detected in connection from {src_ip} to {dst_ip} (VirusTotal detections: {result['total_detections']})"
                        
                        # Add to pending alerts
                        self.add_pending_alert(dst_ip_clean, alert_msg, self.name)
                        
                        # Add to immediate alerts list
                        alerts.append(f"ALERT: {alert_msg}")
                
                # If URL checking is enabled, check URLs from the connection data
                if self.check_urls and checks_performed < self.max_checks_per_run:
                    # This is where you would extract URLs from packet data if available
                    # For demo purposes, we'll just check if the destination looks like a hostname
                    if not re.match(r'^\d+\.\d+\.\d+\.\d+', dst_ip):
                        potential_url = dst_ip.split(':')[0] if ':' in dst_ip else dst_ip
                        
                        # Check if domain is in false positives list
                        if potential_url in self.false_positives:
                            continue
                        
                        # Check if we still have API quota
                        if checks_performed >= self.max_checks_per_run:
                            break
                            
                        url_result = self.check_url(potential_url, api_key)
                        checks_performed += 1
                        
                        if url_result and url_result['is_malicious']:
                            # Store URL threat intel
                            threat_data = {
                                "score": url_result['total_detections'],
                                "type": "malicious_url",
                                "confidence": 0.8,
                                "source": "VirusTotal",
                                "first_seen": time.time(),
                                "details": {
                                    "malicious_count": url_result['malicious_count'],
                                    "suspicious_count": url_result['suspicious_count'],
                                    "status": url_result['status'],
                                    "url": potential_url
                                }
                            }
                            
                            # We'll use the domain/hostname as the key in threat intel
                            self.analysis_manager.update_threat_intel(potential_url, threat_data)
                            
                            # Create alert message
                            alert_msg = f"Malicious URL detected in connection from {src_ip} to {potential_url} (VirusTotal detections: {url_result['total_detections']})"
                            
                            # Add to pending alerts
                            self.add_pending_alert(potential_url, alert_msg, self.name)
                            
                            # Add to immediate alerts list
                            alerts.append(f"ALERT: {alert_msg}")
            
            if checks_performed > 0:
                # Use the most recently checked IP for info messages
                info_ip = next(iter(newly_checked_ips)) if newly_checked_ips else "127.0.0.1"
                
                info_msg = f"Checked {checks_performed} resources with VirusTotal API"
                alerts.append(f"INFO: {info_msg}")
                
                cache_msg = f"VirusTotal cache has {len(self.ip_cache)} IPs and {len(self.url_cache)} URLs"
                alerts.append(f"INFO: {cache_msg}")
                
                fp_msg = f"Using {len(self.false_positives)} IP addresses in false positives list"
                alerts.append(f"INFO: {fp_msg}")
                
                # Add to pending alerts instead of queuing directly
                self.add_pending_alert(info_ip, info_msg, self.name)
                self.add_pending_alert(info_ip, cache_msg, self.name)
                self.add_pending_alert(info_ip, fp_msg, self.name)
        
        except Exception as e:
            logging.error(f"Error in VirusTotal rule: {e}")
            import traceback
            traceback.print_exc()
            
            # Add error to alerts
            alerts.append(f"ERROR: VirusTotal rule error: {e}")
        
        finally:
            # Process all pending alerts
            self.process_pending_alerts()
            
        return alerts
    
    def update_param(self, param_name, value):
        """Update a configurable parameter"""
        if param_name in self.configurable_params:
            if param_name == "min_detections":
                self.min_detections = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
            elif param_name == "cache_duration":
                self.cache_duration = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
            elif param_name == "check_interval":
                self.check_interval = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
            elif param_name == "max_checks_per_run":
                self.max_checks_per_run = int(value)
                self.configurable_params[param_name]["current"] = int(value)
                return True
            elif param_name == "check_urls":
                self.check_urls = bool(value)
                self.configurable_params[param_name]["current"] = bool(value)
                return True
        return False
    
    def get_params(self):
        """Get configurable parameters"""
        return self.configurable_params
    
    def add_alert(self, ip_address, alert_message):
        """Use the analysis_manager to add an alert to the x_alerts table"""
        if self.analysis_manager:
            return self.analysis_manager.add_alert(ip_address, alert_message, self.name)
        else:
            # Fall back to pending alerts if analysis_manager not available
            self.add_pending_alert(ip_address, alert_message, self.name)
            return True
        
    def _add_threat_intel(self, ip_address, result):
        """Add threat intelligence data to analysis_1.db with extended columns"""
        if not self.analysis_manager:
            return False
            
        try:
            # Determine if URL or IP detection
            is_url = 'url' in str(result.get('status', '')).lower() or len(ip_address.split('.')) != 4
            
            # Create threat intelligence data
            threat_data = {
                "score": result.get('total_detections', 0),
                "type": "malware" if result.get('is_malicious', False) else "clean",
                "confidence": 0.8 if result.get('is_malicious', False) else 0.5,
                "source": "VirusTotal",
                "first_seen": time.time(),
                "details": {
                    "malicious_count": result.get('malicious_count', 0),
                    "suspicious_count": result.get('suspicious_count', 0),
                    "status": result.get('status', 'Unknown')
                },
                # Extended columns
                "protocol": "HTTP" if is_url else "IP",
                "detection_method": "virustotal_api",
                "encoding_type": None
            }
            
            # Update threat intelligence in analysis_1.db
            return self.analysis_manager.update_threat_intel(ip_address, threat_data)
        except Exception as e:
            logging.error(f"Error adding threat intelligence data: {e}")
            return False