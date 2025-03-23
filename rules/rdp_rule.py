# RDP Connection Detector Rule
# Note: Rule class is injected into the namespace by the RuleLoader

class RDPConnectionRule(Rule):
    def __init__(self):
        super().__init__(
            name="RDP Connection Detector",
            description="Detects Remote Desktop Protocol (RDP) connections"
        )
        self.rdp_port = 3389      # Standard RDP port
        self.min_bytes = 1000     # Minimum bytes for a significant RDP connection
        self.alert_on_all = False # Whether to alert on all RDP or just large connections
        
    def analyze(self, db_cursor):
        alerts = []
        
        # First, check if the table has the expected columns to avoid SQL errors
        try:
            columns = [row[1] for row in db_cursor.execute("PRAGMA table_info(connections)").fetchall()]
            has_port_columns = "dst_port" in columns
            
            if not has_port_columns:
                return ["ALERT: Port columns not found in database. Please update the database schema."]
                
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
                return ["ALERT: Cannot detect RDP connections - missing required columns"]
            
            # Add bytes filter if not alerting on all RDP connections
            if not self.alert_on_all:
                query += " AND total_bytes > ?"
                params.append(self.min_bytes)
            
            # Execute the query with the appropriate parameters
            db_cursor.execute(query, params)
            
            rdp_connections = db_cursor.fetchall()
            
            for row in rdp_connections:
                if len(row) >= 6:  # We have port information
                    src_ip, dst_ip, src_port, dst_port, total_bytes, packet_count = row
                    alerts.append(f"ALERT: RDP connection from {src_ip}:{src_port} to {dst_ip}:{dst_port} ({total_bytes/1024:.2f} KB, {packet_count} packets)")
                else:  # Old format without ports
                    src_ip, dst_ip, total_bytes, packet_count = row
                    alerts.append(f"ALERT: RDP connection from {src_ip} to {dst_ip} ({total_bytes/1024:.2f} KB, {packet_count} packets)")
                    
            return alerts
                
        except Exception as e:
            return [f"ERROR in RDP Connection Rule: {str(e)}"]
    
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