# connection_statistics.py - Aggregates connection statistics
import time
import logging
import json

logger = logging.getLogger('connection_statistics')

class ConnectionStatisticsAnalyzer(AnalysisBase):
    """Aggregates connection statistics for dashboard display"""
    
    def __init__(self):
        super().__init__(
            name="Connection Statistics",
            description="Aggregates network connection statistics"
        )
        self.last_aggregation_time = 0
        self.aggregation_interval = 300  # 5 minutes
    
    def initialize(self):
        # Create or update required tables
        cursor = self.analysis_manager.get_cursor()
        try:
            # Create statistics table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS connection_statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    total_connections INTEGER,
                    active_connections INTEGER,
                    total_bytes REAL,
                    unique_src_ips INTEGER,
                    unique_dst_ips INTEGER,
                    rdp_connections INTEGER,
                    http_connections INTEGER,
                    https_connections INTEGER,
                    dns_queries INTEGER
                )
            """)
            
            # Create index
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_conn_stats_time ON connection_statistics(timestamp)")
            
            self.analysis_manager.analysis1_conn.commit()
            logger.info("Connection statistics tables initialized")
        except Exception as e:
            logger.error(f"Error initializing connection statistics tables: {e}")
        finally:
            cursor.close()
    
    def process_packet(self, packet_data):
        """Process a packet for connection statistics"""
        # We don't process individual packets, only aggregate periodically
        return False
    
    def run_periodic_analysis(self):
        """Run periodic aggregation of connection statistics"""
        current_time = time.time()
        if current_time - self.last_aggregation_time < self.aggregation_interval:
            return False  # Not time for aggregation yet
        
        self.last_aggregation_time = current_time
        return self.aggregate_connection_statistics()
    
    def aggregate_connection_statistics(self):
        """
        Aggregate connection statistics and store in analysis_1.db
        """
        try:
            cursor = self.analysis_manager.get_cursor()
            
            # Get connection statistics
            cursor.execute("""
                SELECT 
                    COUNT(*) as total_connections,
                    COUNT(CASE WHEN timestamp > ? THEN 1 END) as active_connections,
                    SUM(total_bytes) as total_bytes,
                    COUNT(DISTINCT src_ip) as unique_src_ips,
                    COUNT(DISTINCT dst_ip) as unique_dst_ips,
                    SUM(CASE WHEN is_rdp_client = 1 THEN 1 ELSE 0 END) as rdp_connections
                FROM connections
            """, (time.time() - 3600,))  # Active means activity in the last hour
            
            conn_stats = cursor.fetchone()
            
            # Get protocol-specific statistics
            cursor.execute("SELECT COUNT(*) FROM http_requests")
            http_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM tls_connections")
            tls_count = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM dns_queries")
            dns_count = cursor.fetchone()[0]
            
            # Store aggregated statistics
            current_time = time.time()
            cursor.execute("""
                INSERT INTO connection_statistics
                (timestamp, total_connections, active_connections, total_bytes, 
                unique_src_ips, unique_dst_ips, rdp_connections, 
                http_connections, https_connections, dns_queries)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                current_time,
                conn_stats[0] or 0,
                conn_stats[1] or 0,
                conn_stats[2] or 0,
                conn_stats[3] or 0,
                conn_stats[4] or 0,
                conn_stats[5] or 0,
                http_count,
                tls_count,
                dns_count
            ))
            
            self.analysis_manager.analysis1_conn.commit()
            
            # Log summary
            logger.info(f"Connection statistics aggregated: {conn_stats[1] or 0} active connections, {conn_stats[3] or 0} unique source IPs")
            
            cursor.close()
            return True
        except Exception as e:
            logger.error(f"Error aggregating connection statistics: {e}")
            return False
    
    def get_statistics_summary(self):
        """Get a summary of recent statistics for display"""
        try:
            cursor = self.analysis_manager.get_cursor()
            
            # Get the most recent statistics
            cursor.execute("""
                SELECT total_connections, active_connections, total_bytes, unique_src_ips, 
                       unique_dst_ips, rdp_connections, http_connections, https_connections, dns_queries
                FROM connection_statistics
                ORDER BY timestamp DESC
                LIMIT 1
            """)
            
            stats = cursor.fetchone()
            cursor.close()
            
            if stats:
                return {
                    "total_connections": stats[0],
                    "active_connections": stats[1],
                    "total_bytes": stats[2],
                    "unique_src_ips": stats[3],
                    "unique_dst_ips": stats[4],
                    "rdp_connections": stats[5],
                    "http_connections": stats[6],
                    "https_connections": stats[7],
                    "dns_queries": stats[8],
                }
            return None
        except Exception as e:
            logger.error(f"Error getting statistics summary: {e}")
            return None