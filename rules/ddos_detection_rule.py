# Rule class is injected by the RuleLoader
import time
import logging

class DDoSDetectionRule(Rule):
    """Rule that detects distributed denial of service attacks"""
    def __init__(self):
        super().__init__("DDoS Attack Detection", "Detects patterns of distributed denial of service attacks")
        self.connection_threshold = 100  # Minimum connections to same destination to trigger alert
        self.time_window = 300           # Time window in seconds (5 minutes)
        self.min_unique_sources = 10     # Minimum unique source IPs to consider DDoS
        self.check_interval = 60         # Seconds between checks
        self.last_check_time = 0
    
    def analyze(self, db_cursor):
        alerts = []
        pending_alerts = []
        
        current_time = time.time()
        
        # Only run this rule periodically
        if current_time - self.last_check_time < self.check_interval:
            return []
            
        self.last_check_time = current_time
        
        try:
            # Find destinations with high connection counts from multiple sources
            db_cursor.execute("""
                SELECT dst_ip, COUNT(*) as connection_count, COUNT(DISTINCT src_ip) as unique_sources
                FROM connections
                WHERE timestamp > datetime('now', ? || ' seconds')
                GROUP BY dst_ip
                HAVING connection_count > ? AND unique_sources > ?
            """, (f"-{self.time_window}", self.connection_threshold, self.min_unique_sources))
            
            # Store results locally
            potential_targets = []
            for row in db_cursor.fetchall():
                potential_targets.append(row)
            
            for dst_ip, conn_count, unique_sources in potential_targets:
                # Get the top source IPs
                db_cursor.execute("""
                    SELECT src_ip, COUNT(*) as conn_count
                    FROM connections
                    WHERE dst_ip = ? AND timestamp > datetime('now', ? || ' seconds')
                    GROUP BY src_ip
                    ORDER BY conn_count DESC
                    LIMIT 5
                """, (dst_ip, f"-{self.time_window}"))
                
                top_sources = [f"{row[0]} ({row[1]} conns)" for row in db_cursor.fetchall()]
                
                alert_msg = (f"Potential DDoS attack detected: {dst_ip} received {conn_count} connections "
                           f"from {unique_sources} unique sources in the last {self.time_window/60:.1f} minutes")
                
                alerts.append(alert_msg)
                alerts.append(f"Top sources: {', '.join(top_sources)}")
                
                pending_alerts.append((dst_ip, alert_msg, self.name))
                pending_alerts.append((dst_ip, f"Top sources: {', '.join(top_sources)}", self.name))
            
            # Queue all pending alerts
            for ip, msg, rule_name in pending_alerts:
                try:
                    # Use analysis_manager to add alerts to analysis_1.db
                    if hasattr(self.db_manager, 'analysis_manager') and self.db_manager.analysis_manager:
                        self.db_manager.analysis_manager.add_alert(ip, msg, rule_name)
                    else:
                        self.db_manager.queue_alert(ip, msg, rule_name)
                except Exception as e:
                    logging.error(f"Error queueing alert: {e}")
            
            return alerts
            
        except Exception as e:
            error_msg = f"Error in DDoS Detection rule: {str(e)}"
            logging.error(error_msg)
            # Try to queue the error alert
            try:
                # Use analysis_manager to add alerts to analysis_1.db
                if hasattr(self.db_manager, 'analysis_manager') and self.db_manager.analysis_manager:
                    self.db_manager.analysis_manager.add_alert("127.0.0.1", error_msg, self.name)
                else:
                    self.db_manager.queue_alert("127.0.0.1", error_msg, self.name)
            except Exception as e:
                logging.error(f"Failed to queue error alert: {e}")
            return [error_msg]
    
    def get_params(self):
        return {
            "connection_threshold": {
                "type": "int",
                "default": 100,
                "current": self.connection_threshold,
                "description": "Minimum connections to trigger alert"
            },
            "time_window": {
                "type": "int",
                "default": 300,
                "current": self.time_window,
                "description": "Time window in seconds to analyze"
            },
            "min_unique_sources": {
                "type": "int",
                "default": 10,
                "current": self.min_unique_sources,
                "description": "Minimum unique sources for DDoS pattern"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "connection_threshold":
            self.connection_threshold = int(value)
            return True
        elif param_name == "time_window":
            self.time_window = int(value)
            return True
        elif param_name == "min_unique_sources":
            self.min_unique_sources = int(value)
            return True
        return False