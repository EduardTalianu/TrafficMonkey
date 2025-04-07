# RDP Connection Detector Rule
# Note: Rule class is injected into the namespace by the RuleLoader
import logging

class RDPConnectionRule(Rule):
    def __init__(self):
        super().__init__(
            name="RDP Connection Detector",
            description="Detects Remote Desktop Protocol (RDP) connections"
        )
        self.rdp_port = 3389      # Standard RDP port
        self.min_bytes = 1000     # Minimum bytes for a significant RDP connection
        self.alert_on_all = False # Whether to alert on all RDP or just large connections
        self.analysis_manager = None  # Will be set by access to db_manager.analysis_manager
        
    def analyze(self, db_cursor):
        alerts = []
        pending_alerts = []  # For queueing alerts
        
        # First, check if the table has the expected columns to avoid SQL errors
        try:
            columns = [row[1] for row in db_cursor.execute("PRAGMA table_info(connections)").fetchall()]
            has_port_columns = "dst_port" in columns
            
            if not has_port_columns:
                error_msg = "ALERT: Port columns not found in database. Please update the database schema."
                alerts.append(error_msg)
                pending_alerts.append(("127.0.0.1", error_msg, self.name))
                
                # Queue alerts and return
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
                
            # Check if we still have the old is_rdp_client column
            has_rdp_column = "is_rdp_client" in columns
            
            # Look for RDP connections based on destination port
            query = """
                SELECT src_ip, dst_ip, total_bytes, packet_count
            """
            
            # Add port columns if they exist
            if "src_port" in columns and "dst_port" in columns:
                query = """
                    SELECT src_ip, dst_ip, src_port, dst_port, total_bytes, packet_count
                """
            
            # Complete the query
            query += " FROM connections WHERE "
            
            # Use either port-based or flag-based detection
            if has_port_columns:
                query += "dst_port = ?"
                params = [self.rdp_port]
            elif has_rdp_column:
                query += "is_rdp_client = 1"
                params = []
            else:
                error_msg = "ALERT: Cannot detect RDP connections - missing required columns"
                alerts.append(error_msg)
                pending_alerts.append(("127.0.0.1", error_msg, self.name))
                
                # Queue alerts and return
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
            
            # Add bytes filter if not alerting on all RDP connections
            if not self.alert_on_all:
                query += " AND total_bytes > ?"
                params.append(self.min_bytes)
            
            # Execute the query with the appropriate parameters
            db_cursor.execute(query, params)
            
            # Store results locally
            rdp_connections = []
            for row in db_cursor.fetchall():
                rdp_connections.append(row)
            
            for row in rdp_connections:
                if len(row) >= 6:  # We have port information
                    src_ip, dst_ip, src_port, dst_port, total_bytes, packet_count = row
                    alert_msg = f"ALERT: RDP connection from {src_ip}:{src_port} to {dst_ip}:{dst_port} ({total_bytes/1024:.2f} KB, {packet_count} packets)"
                    alerts.append(alert_msg)
                    # Add to pending alerts - use destination IP for the alert
                    pending_alerts.append((dst_ip, alert_msg, self.name))
                else:  # Old format without ports
                    src_ip, dst_ip, total_bytes, packet_count = row
                    alert_msg = f"ALERT: RDP connection from {src_ip} to {dst_ip} ({total_bytes/1024:.2f} KB, {packet_count} packets)"
                    alerts.append(alert_msg)
                    # Add to pending alerts - use destination IP for the alert
                    pending_alerts.append((dst_ip, alert_msg, self.name))
            
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
            error_msg = f"ERROR in RDP Connection Rule: {str(e)}"
            logging.error(error_msg)
            # Try to queue the error alert
            try:
                # Use analysis_manager to add alerts to analysis_1.db
                if hasattr(self.db_manager, 'analysis_manager') and self.db_manager.analysis_manager:
                    self.db_manager.analysis_manager.add_alert("127.0.0.1", error_msg, self.name)
                else:
                    self.db_manager.queue_alert("127.0.0.1", error_msg, self.name)
            except Exception as e:
                logging.error(f"Error queueing alert: {e}")
            return [error_msg]
    
    def get_params(self):
        return {
            "rdp_port": {
                "type": "int",
                "default": 3389,
                "current": self.rdp_port,
                "description": "Port used for RDP connections (usually 3389)"
            },
            "min_bytes": {
                "type": "int",
                "default": 1000,
                "current": self.min_bytes,
                "description": "Minimum bytes for significant RDP connections"
            },
            "alert_on_all": {
                "type": "bool",
                "default": False,
                "current": self.alert_on_all,
                "description": "Alert on all RDP connections regardless of size"
            }
        }
    
    def update_param(self, param_name, value):
        if param_name == "rdp_port":
            self.rdp_port = int(value)
            return True
        elif param_name == "min_bytes":
            self.min_bytes = int(value)
            return True
        elif param_name == "alert_on_all":
            self.alert_on_all = bool(value)
            return True
        return False