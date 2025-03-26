# Rule class is injected by the RuleLoader
import os
import time
import json
import urllib.request
import ipaddress
import logging

class GeolocationRule(Rule):
    """Rule that detects connections from high-risk countries or regions"""
    def __init__(self):
        super().__init__("Geolocation-based Detection", "Flags connections from high-risk countries or regions")
        
        # Configure high-risk countries (using ISO country codes)
        self.high_risk_countries = [
            "RU", "CN", "IR", "KP", "SY"  # Russia, China, Iran, North Korea, Syria
        ]
        
        self.alert_on_all_foreign = False  # Whether to alert on all non-local countries
        self.check_interval = 3600  # Run this rule every hour (3600 seconds)
        self.last_check_time = 0
        self.geo_cache = {}  # Cache for IP geolocation lookups
        self.cache_duration = 86400 * 7  # Cache IP geo results for 7 days
        self.min_bytes = 5000  # Minimum bytes for a significant connection
        self.cache_file = self._get_cache_path()
        
        # Load cached geolocation data
        self._load_cache()
    
    def _get_cache_path(self):
        """Determine the path for the geolocation cache file"""
        try:
            # Try to locate the db directory from the app_root in the GUI
            if hasattr(self, 'db_manager') and hasattr(self.db_manager, 'app_root'):
                app_root = self.db_manager.app_root
                cache_file = os.path.join(app_root, "db", "geo_cache.json")
            else:
                # Fallback: Search for common parent directories
                current_dir = os.getcwd()
                if os.path.exists(os.path.join(current_dir, "db")):
                    cache_file = os.path.join(current_dir, "db", "geo_cache.json")
                elif os.path.exists(os.path.join(current_dir, "..", "db")):
                    cache_file = os.path.join(current_dir, "..", "db", "geo_cache.json")
                else:
                    # Last resort: just use the current directory
                    cache_file = "geo_cache.json"
            
            # Ensure the directory exists
            os.makedirs(os.path.dirname(cache_file), exist_ok=True)
            return cache_file
            
        except Exception as e:
            logging.error(f"Error determining geo cache path: {e}")
            return "geo_cache.json"
    
    def _load_cache(self):
        """Load geolocation cache from disk"""
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r') as f:
                    self.geo_cache = json.load(f)
                logging.info(f"Loaded {len(self.geo_cache)} IP geolocations from cache")
        except Exception as e:
            logging.error(f"Error loading geo cache: {e}")
            self.geo_cache = {}
    
    def _save_cache(self):
        """Save geolocation cache to disk"""
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.geo_cache, f)
            logging.info(f"Saved {len(self.geo_cache)} IP geolocations to cache")
        except Exception as e:
            logging.error(f"Error saving geo cache: {e}")
    
    def is_private_ip(self, ip):
        """Check if an IP address is a private/local address"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False
    
    def get_ip_geolocation(self, ip):
        """Lookup geolocation for an IP address"""
        # Skip private IPs
        if self.is_private_ip(ip):
            return {
                "country_code": "LOCAL",
                "country_name": "Local Network",
                "timestamp": time.time()
            }
        
        # Check cache first
        if ip in self.geo_cache:
            cache_entry = self.geo_cache[ip]
            cache_time = cache_entry.get("timestamp", 0)
            
            # Return from cache if not expired
            if time.time() - cache_time < self.cache_duration:
                return cache_entry
        
        # Use a free geolocation API (IP-API)
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode"
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            response = urllib.request.urlopen(req, timeout=5)
            data = json.loads(response.read().decode())
            
            if data.get("status") == "success":
                result = {
                    "country_code": data.get("countryCode", "XX"),
                    "country_name": data.get("country", "Unknown"),
                    "timestamp": time.time()
                }
                
                # Update cache
                self.geo_cache[ip] = result
                self._save_cache()
                
                return result
            else:
                # API error, return unknown
                return {
                    "country_code": "XX",
                    "country_name": "Unknown",
                    "timestamp": time.time()
                }
        except Exception as e:
            logging.error(f"Error looking up IP geolocation for {ip}: {e}")
            # Error in lookup, return unknown
            return {
                "country_code": "XX",
                "country_name": "Unknown",
                "timestamp": time.time()
            }
    
    def analyze(self, db_cursor):
        alerts = []
        current_time = time.time()
        
        # Only run this rule periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Get recent connections with significant data
            db_cursor.execute("""
                SELECT src_ip, dst_ip, total_bytes
                FROM connections
                WHERE total_bytes > ?
                AND timestamp > datetime('now', '-1 day')
                ORDER BY timestamp DESC
                LIMIT 100
            """, (self.min_bytes,))
            
            # Store results locally
            connections = []
            for row in db_cursor.fetchall():
                connections.append(row)
            
            # Keep track of what we've alerted on to avoid duplicates
            alerted_ips = set()
            
            for src_ip, dst_ip, total_bytes in connections:
                # Skip if we've already alerted on this IP
                if src_ip in alerted_ips:
                    continue
                
                # Skip local IPs
                if self.is_private_ip(src_ip):
                    continue
                
                # Get geolocation
                geo_data = self.get_ip_geolocation(src_ip)
                country_code = geo_data.get("country_code", "XX")
                country_name = geo_data.get("country_name", "Unknown")
                
                # Alert on high-risk countries
                if country_code in self.high_risk_countries:
                    alerts.append(f"Connection from high-risk country: {src_ip} ({country_name}) to {dst_ip} ({total_bytes/1024:.1f} KB)")
                    alerted_ips.add(src_ip)
                
                # Alert on all foreign countries if enabled
                elif self.alert_on_all_foreign and country_code != "LOCAL" and country_code != "XX":
                    alerts.append(f"Foreign connection: {src_ip} ({country_name}) to {dst_ip} ({total_bytes/1024:.1f} KB)")
                    alerted_ips.add(src_ip)
            
            return alerts
        except Exception as e:
            error_msg = f"Error in Geolocation rule: {str(e)}"
            logging.error(error_msg)
            return [error_msg]
    
    def get_params(self):
        return {
            "min_bytes": {
                "type": "int",
                "default": 5000,
                "current": self.min_bytes,
                "description": "Minimum bytes for a significant connection"
            },
            "alert_on_all_foreign": {
                "type": "bool",
                "default": False,
                "current": self.alert_on_all_foreign,
                "description": "Alert on all non-local countries (not just high-risk)"
            },
            "check_interval": {
                "type": "int",
                "default": 3600,
                "current": self.check_interval,
                "description": "Seconds between rule checks"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "min_bytes":
            self.min_bytes = int(value)
            return True
        elif param_name == "alert_on_all_foreign":
            self.alert_on_all_foreign = bool(value)
            return True
        elif param_name == "check_interval":
            self.check_interval = int(value)
            return True
        return False