# Rule class is injected by the RuleLoader
import requests
import time
import os
import ipaddress
import json
import logging
import re
import hashlib

class VirusTotalRule(Rule):
    """Rule that checks IPs and URLs against VirusTotal API"""
    def __init__(self):
        super().__init__("VirusTotal Security Check", "Checks IPs and URLs against VirusTotal API to detect malicious connections")
        self.min_detections = 1
        self.cache_duration = 86400  # Cache results for 24 hours (in seconds)
        self.check_interval = 10     # Check at most one resource every 10 seconds to respect API limits
        self.max_checks_per_run = 5  # Maximum number of resources to check per rule run
        self.check_urls = True       # Whether to extract and check URLs from connection data
        
        # Store cache in the current directory
        self.cache_file = "vt_cache.json"
        
        # Find the rules directory and false positives file without using __file__
        # This will work with the exec() loading mechanism
        try:
            import os
            # Try to locate the root directory from the app_root in the GUI
            # First, check if we're running in the context of the GUI
            if 'gui' in globals() and hasattr(globals()['gui'], 'app_root'):
                app_root = globals()['gui'].app_root
                self.false_positives_file = os.path.join(app_root, "rules", "false_positives.txt")
            else:
                # Fallback: Search for common parent directories
                current_dir = os.getcwd()
                if os.path.exists(os.path.join(current_dir, "rules", "false_positives.txt")):
                    self.false_positives_file = os.path.join(current_dir, "rules", "false_positives.txt")
                elif os.path.exists(os.path.join(current_dir, "..", "rules", "false_positives.txt")):
                    self.false_positives_file = os.path.join(current_dir, "..", "rules", "false_positives.txt")
                else:
                    # Last resort: just use a relative path
                    self.false_positives_file = os.path.join("rules", "false_positives.txt")
            
            logging.info(f"Using false positives file at: {self.false_positives_file}")
        except Exception as e:
            logging.error(f"Error locating false positives file: {e}")
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
    
    def analyze(self, db_cursor):
        alerts = []
        
        # Refresh false positives list before running analysis
        self.false_positives = self.load_false_positives()
        
        # First, look for any connections already marked as malicious
        db_cursor.execute("SELECT src_ip, dst_ip, connection_key, vt_result FROM connections WHERE vt_result = 'Malicious'")
        vt_alerts = db_cursor.fetchall()
        
        for src_ip, dst_ip, connection_key, vt_result in vt_alerts:
            # Check if destination IP is in false positives list
            dst_ip_clean = dst_ip.split(':')[0] if ':' in dst_ip else dst_ip
            
            if dst_ip_clean in self.false_positives:
                # Update the database to mark this as false positive
                try:
                    db_cursor.execute(
                        "UPDATE connections SET vt_result = ? WHERE connection_key = ?",
                        ('False Positive', connection_key)
                    )
                    db_cursor.connection.commit()
                except Exception as e:
                    logging.error(f"Database error updating false positive status: {e}")
                
                continue  # Skip creating an alert
                
            alerts.append(f"ALERT: Malicious connection from {src_ip} to {dst_ip} (VirusTotal: {vt_result})")
        
        # Get API key from environment
        api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            alerts.append("WARNING: No VirusTotal API key set in environment variable VIRUSTOTAL_API_KEY")
            return alerts
        
        # Look for new connections that haven't been checked
        db_cursor.execute("""
            SELECT connection_key, src_ip, dst_ip 
            FROM connections 
            WHERE (vt_result IS NULL OR vt_result = 'unknown')
            AND total_bytes > 1000
            LIMIT 100
        """)
        
        unchecked = db_cursor.fetchall()
        
        # Check a limited number of resources per run to respect API limits
        checks_performed = 0
        
        for connection_key, src_ip, dst_ip in unchecked:
            # Extract the IP part if it contains port information
            dst_ip_clean = dst_ip.split(':')[0] if ':' in dst_ip else dst_ip
            
            # Skip if not a valid public IP
            if not self.is_valid_public_ip(dst_ip_clean):
                continue
            
            # Skip if IP is in false positives list
            if dst_ip_clean in self.false_positives:
                # Update the database to mark this as false positive
                try:
                    db_cursor.execute(
                        "UPDATE connections SET vt_result = ? WHERE connection_key = ?",
                        ('False Positive', connection_key)
                    )
                    db_cursor.connection.commit()
                    logging.info(f"Marked connection {connection_key} as false positive")
                except Exception as e:
                    logging.error(f"Database error updating false positive status: {e}")
                continue
            
            # Check if we've reached our limit for this run
            if checks_performed >= self.max_checks_per_run:
                break
                
            # Check the IP
            result = self.check_ip(dst_ip_clean, api_key)
            checks_performed += 1
            
            if result:
                # Update the database with the result
                try:
                    db_cursor.execute(
                        "UPDATE connections SET vt_result = ? WHERE connection_key = ?",
                        (result['status'], connection_key)
                    )
                    db_cursor.connection.commit()
                    
                    if result['is_malicious']:
                        alerts.append(f"ALERT: Malicious IP detected in connection from {src_ip} to {dst_ip} (VirusTotal detections: {result['total_detections']})")
                        
                except Exception as e:
                    logging.error(f"Database error updating VirusTotal result: {e}")
            
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
                        alerts.append(f"ALERT: Malicious URL detected in connection from {src_ip} to {potential_url} (VirusTotal detections: {url_result['total_detections']})")
        
        if checks_performed > 0:
            alerts.append(f"INFO: Checked {checks_performed} resources with VirusTotal API")
            alerts.append(f"INFO: VirusTotal cache has {len(self.ip_cache)} IPs and {len(self.url_cache)} URLs")
            alerts.append(f"INFO: Using {len(self.false_positives)} IP addresses in false positives list")
            
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