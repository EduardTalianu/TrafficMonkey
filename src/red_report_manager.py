import os
import time
import json
import logging
import sqlite3
from datetime import datetime

# Configure logging
logger = logging.getLogger('red_report_manager')

class RedReportManager:
    """Manages the storage of rule results in the 'red' folder and x_red table"""
    
    def __init__(self, app_root, analysis_manager=None):
        self.app_root = app_root
        self.analysis_manager = analysis_manager
        
        # Create red directory if it doesn't exist
        self.red_dir = os.path.join(app_root, "red")
        os.makedirs(self.red_dir, exist_ok=True)
        logger.info(f"Red reports directory created at {self.red_dir}")
        
        # Ensure the x_red table exists in analysis_1.db
        self._ensure_table_exists()
        
    def _ensure_table_exists(self):
        """Ensure the x_red table exists in analysis_1.db"""
        if not self.analysis_manager:
            logger.warning("No analysis manager provided, cannot create x_red table")
            return
            
        try:
            cursor = self.analysis_manager.get_cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS x_red (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    rule_name TEXT,
                    severity TEXT,
                    description TEXT,
                    details TEXT,
                    connection_key TEXT,
                    remediation TEXT
                )
            """)
            
            # Create indices for better query performance
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_red_timestamp ON x_red(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_red_src_ip ON x_red(src_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_red_dst_ip ON x_red(dst_ip)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_red_rule ON x_red(rule_name)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_x_red_severity ON x_red(severity)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("Ensured x_red table exists in analysis_1.db")
        except Exception as e:
            logger.error(f"Error ensuring x_red table exists: {e}")
    
    def add_red_finding(self, src_ip, dst_ip, rule_name, description, 
                       severity="medium", details=None, connection_key=None, remediation=None):
        """
        Add a red team finding to both the database and a file
        
        Parameters:
        - src_ip: Source IP address
        - dst_ip: Destination IP address
        - rule_name: Name of the rule that triggered the finding
        - description: Description of the finding
        - severity: Severity level (low, medium, high, critical)
        - details: Additional details as a dict (will be stored as JSON)
        - connection_key: Optional connection key
        - remediation: Optional remediation guidance
        
        Returns:
        - True if successful, False otherwise
        """
        try:
            current_time = time.time()
            
            # Convert details to JSON if it's a dict
            details_json = None
            if details:
                if isinstance(details, dict):
                    details_json = json.dumps(details)
                else:
                    details_json = str(details)
            
            # 1. Store in x_red table
            if self.analysis_manager:
                cursor = self.analysis_manager.get_cursor()
                cursor.execute("""
                    INSERT INTO x_red 
                    (timestamp, src_ip, dst_ip, rule_name, severity, description, details, connection_key, remediation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (current_time, src_ip, dst_ip, rule_name, severity, description, details_json, connection_key, remediation))
                self.analysis_manager.analysis1_conn.commit()
            
            # 2. Store in red folder as a JSON file
            timestamp_str = datetime.fromtimestamp(current_time).strftime("%Y%m%d_%H%M%S")
            safe_rule_name = rule_name.replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')
            filename = f"{timestamp_str}_{safe_rule_name}_{src_ip}_{dst_ip}.json"
            file_path = os.path.join(self.red_dir, filename)
            
            report_data = {
                "timestamp": current_time,
                "timestamp_readable": datetime.fromtimestamp(current_time).strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "rule_name": rule_name,
                "severity": severity,
                "description": description,
                "details": details,
                "connection_key": connection_key,
                "remediation": remediation
            }
            
            with open(file_path, 'w') as f:
                json.dump(report_data, f, indent=4)
            
            logger.info(f"Added red finding for {rule_name} to both database and file: {filename}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding red finding: {e}")
            return False
    
    def get_recent_findings(self, limit=100):
        """Get recent red findings from the database"""
        if not self.analysis_manager:
            return []
            
        try:
            cursor = self.analysis_manager.get_cursor()
            cursor.execute("""
                SELECT timestamp, src_ip, dst_ip, rule_name, severity, description 
                FROM x_red 
                ORDER BY timestamp DESC 
                LIMIT ?
            """, (limit,))
            
            return cursor.fetchall()
        except Exception as e:
            logger.error(f"Error getting recent findings: {e}")
            return []
    
    def clear_findings(self):
        """Clear all red findings from both the database and folder"""
        try:
            # Clear database
            if self.analysis_manager:
                cursor = self.analysis_manager.get_cursor()
                cursor.execute("DELETE FROM x_red")
                self.analysis_manager.analysis1_conn.commit()
            
            # Clear folder (delete all JSON files)
            for filename in os.listdir(self.red_dir):
                if filename.endswith('.json'):
                    os.remove(os.path.join(self.red_dir, filename))
            
            logger.info("Cleared all red findings")
            return True
        except Exception as e:
            logger.error(f"Error clearing red findings: {e}")
            return False