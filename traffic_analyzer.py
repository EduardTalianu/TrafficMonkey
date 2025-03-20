import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import sqlite3
from collections import deque
import requests
import subprocess
import re
import socket
import sys
import os
import importlib.util
import json
import logging
import pandas as pd
import random
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('traffic_analyzer')

# Load environment variables from .env file
load_dotenv()

class Rule:
    """Base class for all rules"""
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.enabled = True
    
    def analyze(self, db_cursor):
        """Analyze traffic and return list of alerts"""
        return []
    
    def get_params(self):
        """Get configurable parameters"""
        return {}
    
    def update_param(self, param_name, value):
        """Update a configurable parameter"""
        return False

class RuleLoader:
    """Handles loading rule modules from the rules directory"""
    
    def __init__(self):
        """Initialize the rule loader"""
        self.rules = []
        
        # Root directory of the application
        self.app_root = os.path.dirname(os.path.abspath(__file__))
        self.rules_dir = os.path.join(self.app_root, 'rules')
        
        # Load all rules
        self.load_rules()
    
    def load_rules(self):
        """Load all rule modules from the rules directory"""
        # Check if rules directory exists
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir, exist_ok=True)
            logger.warning(f"Rules directory created at {self.rules_dir}")
            return
        
        # Load rule files
        for filename in os.listdir(self.rules_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]  # Remove .py extension
                module_path = os.path.join(self.rules_dir, filename)
                
                try:
                    # Create a custom namespace for the module
                    rule_namespace = {'Rule': Rule}
                    
                    # Load the module content
                    with open(module_path, 'r') as f:
                        module_code = f.read()
                    
                    # Execute the module code in the custom namespace
                    exec(module_code, rule_namespace)
                    
                    # Find rule classes in the namespace (subclasses of Rule)
                    for name, obj in rule_namespace.items():
                        if (isinstance(obj, type) and 
                            issubclass(obj, Rule) and 
                            obj != Rule and 
                            hasattr(obj, '__init__')):
                            
                            # Create an instance of the rule
                            rule_instance = obj()
                            self.rules.append(rule_instance)
                            logger.info(f"Loaded rule: {rule_instance.name} from {filename}")
                            print(f"Loaded rule: {rule_instance.name} from {filename}")
                
                except Exception as e:
                    logger.error(f"Error loading rule {module_name}: {e}")
                    import traceback
                    traceback.print_exc()
        
        # Log summary of loaded rules
        logger.info(f"Loaded {len(self.rules)} rule modules")
        print(f"Loaded {len(self.rules)} rule modules")
        
        # Add some built-in rules if no rules were loaded
        if not self.rules:
            self._add_default_rules()
    
    def _add_default_rules(self):
        """Add default built-in rules"""
        # Built-in rule: Large Data Transfer
        class LargeDataTransferRule(Rule):
            def __init__(self):
                super().__init__(
                    name="Large Data Transfer Detector",
                    description="Detects unusually large data transfers"
                )
                self.threshold_kb = 5000  # Default 5MB threshold
                
            def analyze(self, db_cursor):
                alerts = []
                
                # Query for connections with large data transfers
                db_cursor.execute("""
                    SELECT src_ip, dst_ip, total_bytes
                    FROM connections
                    WHERE total_bytes > ?
                """, (self.threshold_kb * 1024,))
                
                large_transfers = db_cursor.fetchall()
                
                for src_ip, dst_ip, total_bytes in large_transfers:
                    alerts.append(f"ALERT: Large data transfer from {src_ip} to {dst_ip} - {total_bytes/1024/1024:.2f} MB")
                    
                return alerts
            
            def get_params(self):
                return {
                    "threshold_kb": {
                        "type": "int",
                        "default": 5000,
                        "current": self.threshold_kb,
                        "description": "Threshold in KB for large transfers"
                    }
                }
            
            def update_param(self, param_name, value):
                if param_name == "threshold_kb":
                    self.threshold_kb = int(value)
                    return True
                return False
                
        # Add the built-in rule
        self.rules.append(LargeDataTransferRule())
        logger.info("Added built-in rule: Large Data Transfer Detector")

class LiveCaptureGUI:
    def __init__(self, master):
        self.master = master
        master.title("Live Network Traffic Analyzer")

        # Configuration Variables
        self.batch_size = tk.IntVar(value=100)
        self.sliding_window_size = tk.IntVar(value=1000)
        self.selected_interface = tk.StringVar()
        self.show_inactive_interfaces = tk.BooleanVar(value=False)

        # Get VirusTotal API Key from environment variable or use default
        self.virus_total_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(master, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(side=tk.BOTTOM, fill=tk.X)

        # Set log file path
        self.app_root = os.path.dirname(os.path.abspath(__file__))
        self.log_file = os.path.join(self.app_root, "traffic_analyzer.log")

        # Database Setup - Do this BEFORE creating any tabs that need the database
        self.setup_database()

        # UI Setup
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.interfaces_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        self.rules_tab = ttk.Frame(self.notebook)
        self.db_tab = ttk.Frame(self.notebook)  # New Database tab
        
        self.notebook.add(self.interfaces_tab, text="Network Interfaces")
        self.notebook.add(self.settings_tab, text="Detection Settings")
        self.notebook.add(self.rules_tab, text="Rules")
        self.notebook.add(self.db_tab, text="Database/Stats")  # Add new tab
        
        # Initialize interfaces
        self.interface_info = []
        
        # Create UI tabs
        self.create_interfaces_tab()
        self.create_settings_tab()
        self.create_rules_tab()
        self.create_db_tab()  # Create the new database tab

        # Capture Variables
        self.packet_queue = deque()
        self.running = False
        self.capture_thread = None
        self.tshark_process = None
        
        # Load Rules
        self.rule_loader = RuleLoader()
        self.rules = self.rule_loader.rules
        self.selected_rule = None
        self.param_vars = {}
        self.update_rules_list()
        
        # Initialize interfaces after UI is set up
        self.refresh_interfaces()

    def setup_database(self):
        """Set up the database connection and create tables"""
        try:
            # Close existing connection if any
            try:
                if hasattr(self, 'db_conn'):
                    self.db_conn.close()
            except:
                pass
                
            # Create a new connection
            self.db_conn = sqlite3.connect("traffic_stats.db", check_same_thread=False)
            self.db_cursor = self.db_conn.cursor()
            
            # Enable WAL mode for better performance and reliability
            self.db_cursor.execute("PRAGMA journal_mode=WAL")
            self.db_cursor.execute("PRAGMA synchronous=NORMAL")
            
            # Create tables with simplified schema
            self.db_cursor.execute("""
                CREATE TABLE IF NOT EXISTS connections (
                    connection_key TEXT PRIMARY KEY,
                    src_ip TEXT,
                    dst_ip TEXT,
                    total_bytes INTEGER DEFAULT 0,
                    packet_count INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Check if required columns exist and add them if they don't
            existing_columns = [row[1] for row in self.db_cursor.execute("PRAGMA table_info(connections)").fetchall()]
            
            # Add vt_result column if it doesn't exist
            if "vt_result" not in existing_columns:
                self.db_cursor.execute("ALTER TABLE connections ADD COLUMN vt_result TEXT DEFAULT 'unknown'")
                logger.info("Added missing column: vt_result")
                
            # Add is_rdp_client column if it doesn't exist
            if "is_rdp_client" not in existing_columns:
                self.db_cursor.execute("ALTER TABLE connections ADD COLUMN is_rdp_client BOOLEAN DEFAULT 0")
                logger.info("Added missing column: is_rdp_client")
            
            # Create an index for faster lookups
            self.db_cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_connections_ips 
                ON connections(src_ip, dst_ip)
            """)
            
                        # Verify database connection at the end
            self.verify_database_connection()
            
            self.db_conn.commit()
            logger.info("Database setup complete")
            return True
        

            
        except Exception as e:
            logger.error(f"Database setup error: {e}")
            print(f"Database setup error: {e}")
            return False

    def create_interfaces_tab(self):
        control_frame = ttk.Frame(self.interfaces_tab)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Checkbutton(control_frame, text="Show Inactive Interfaces", 
                       variable=self.show_inactive_interfaces, 
                       command=self.update_interface_list).pack(side="left", padx=5)
        
        self.refresh_button = ttk.Button(control_frame, text="Refresh Interfaces", 
                                        command=self.refresh_interfaces)
        self.refresh_button.pack(side="right", padx=5)
        
        self.start_button = ttk.Button(control_frame, text="Start Capture", 
                                      command=self.toggle_capture)
        self.start_button.pack(side="right", padx=5)
        self.start_button.config(state="disabled")
        
        list_frame = ttk.Frame(self.interfaces_tab)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ttk.Label(list_frame, text="Select an interface to capture traffic:").pack(anchor="w", padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        # Simplified interface display to show only description and IP
        self.interface_listbox = ttk.Treeview(list_frame, 
                                             columns=("name", "ip"),
                                             show="headings",
                                             selectmode="browse",
                                             height=10)
        self.interface_listbox.pack(fill="both", expand=True)
        
        self.interface_listbox.heading("name", text="Interface Description")
        self.interface_listbox.heading("ip", text="IP Address")
        
        self.interface_listbox.column("name", width=300)
        self.interface_listbox.column("ip", width=200)
        
        scrollbar.config(command=self.interface_listbox.yview)
        self.interface_listbox.config(yscrollcommand=scrollbar.set)
        
        self.interface_listbox.bind("<<TreeviewSelect>>", self.on_interface_selected)
        
        info_frame = ttk.LabelFrame(self.interfaces_tab, text="Interface Details")
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.interface_info_text = tk.Text(info_frame, height=5, wrap=tk.WORD)
        self.interface_info_text.pack(fill="both", expand=True, padx=5, pady=5)

    def create_settings_tab(self):
        settings_frame = ttk.LabelFrame(self.settings_tab, text="Analysis Settings")
        settings_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(settings_frame, text="Batch Size:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(settings_frame, textvariable=self.batch_size).grid(row=0, column=1, sticky="ew", padx=5, pady=5)
        ttk.Label(settings_frame, text="Packets per analysis batch").grid(row=0, column=2, sticky="w", padx=5, pady=5)
        
        ttk.Label(settings_frame, text="Sliding Window Size:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(settings_frame, textvariable=self.sliding_window_size).grid(row=1, column=1, sticky="ew", padx=5, pady=5)
        ttk.Label(settings_frame, text="Max packets in memory").grid(row=1, column=2, sticky="w", padx=5, pady=5)
        
        ttk.Label(settings_frame, text="VirusTotal API Key:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        vt_entry = ttk.Entry(settings_frame)
        vt_entry.grid(row=2, column=1, sticky="ew", padx=5, pady=5)
        vt_entry.insert(0, self.virus_total_api_key)
        ttk.Label(settings_frame, text="API key for VirusTotal (or set in .env file)").grid(row=2, column=2, sticky="w", padx=5, pady=5)
        
        ttk.Label(settings_frame, text="Log File:").grid(row=3, column=0, sticky="w", padx=5, pady=5)
        ttk.Label(settings_frame, text=self.log_file).grid(row=3, column=1, sticky="w", padx=5, pady=5)
        ttk.Label(settings_frame, text="Logs are automatically saved").grid(row=3, column=2, sticky="w", padx=5, pady=5)
        
        ttk.Button(settings_frame, text="Apply Settings", command=self.apply_settings).grid(row=4, column=1, sticky="e", padx=5, pady=10)
        settings_frame.columnconfigure(1, weight=1)
        
        output_frame = ttk.LabelFrame(self.settings_tab, text="Output")
        output_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        button_frame = ttk.Frame(output_frame)
        button_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Clear Output", command=self.clear_output).pack(side="right", padx=5)
        
        scrollbar = ttk.Scrollbar(output_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.output_text = tk.Text(output_frame, state=tk.DISABLED, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        self.output_text.pack(fill="both", expand=True, padx=5, pady=5)
        scrollbar.config(command=self.output_text.yview)

    def create_rules_tab(self):
        button_frame = ttk.Frame(self.rules_tab)
        button_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(button_frame, text="Add Rule File", command=self.add_rule_file).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Reload Rules", command=self.reload_rules).pack(side="left", padx=5)
        
        list_frame = ttk.Frame(self.rules_tab)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ttk.Label(list_frame, text="Active Rules:").pack(anchor="w", padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.rules_listbox = ttk.Treeview(list_frame, 
                                         columns=("name", "description", "status"),
                                         show="headings",
                                         selectmode="browse",
                                         height=10)
        self.rules_listbox.pack(fill="both", expand=True)
        
        self.rules_listbox.heading("name", text="Rule Name")
        self.rules_listbox.heading("description", text="Description")
        self.rules_listbox.heading("status", text="Status")
        
        self.rules_listbox.column("name", width=150)
        self.rules_listbox.column("description", width=300)
        self.rules_listbox.column("status", width=100)
        
        scrollbar.config(command=self.rules_listbox.yview)
        self.rules_listbox.config(yscrollcommand=scrollbar.set)
        
        self.rules_listbox.bind("<Double-1>", self.toggle_rule)
        self.rules_listbox.bind("<<TreeviewSelect>>", self.show_rule_details)
        
        details_frame = ttk.LabelFrame(self.rules_tab, text="Rule Details")
        details_frame.pack(fill="x", padx=10, pady=5)
        
        self.rule_details_text = tk.Text(details_frame, height=5, wrap=tk.WORD)
        self.rule_details_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        params_frame = ttk.LabelFrame(self.rules_tab, text="Rule Parameters")
        params_frame.pack(fill="x", padx=10, pady=5)
        
        self.params_content_frame = ttk.Frame(params_frame)
        self.params_content_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.apply_params_button = ttk.Button(params_frame, text="Apply Parameters", command=self.apply_rule_params)
        self.apply_params_button.pack(side="right", padx=5, pady=5)
        self.apply_params_button.config(state="disabled")

    def create_db_tab(self):
        """Create a lightweight Database/Stats tab"""
        # Control buttons frame
        control_frame = ttk.Frame(self.db_tab)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="Refresh Database Stats", command=self.refresh_db_stats).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Verify Database", command=self.verify_database).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Test Connection", command=self.test_db_insert).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Optimize Database", command=self.optimize_database).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Export Data", command=self.export_db_data).pack(side="left", padx=5)
        
        # Database summary information
        summary_frame = ttk.LabelFrame(self.db_tab, text="Database Summary")
        summary_frame.pack(fill="x", padx=10, pady=5)
        
        # Summary statistics text
        self.db_summary_text = tk.Text(summary_frame, height=6, wrap=tk.WORD)
        self.db_summary_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create a simple connection list
        connections_frame = ttk.LabelFrame(self.db_tab, text="Top Connections")
        connections_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Add a simple treeview for connections
        scrollbar = ttk.Scrollbar(connections_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.connections_tree = ttk.Treeview(connections_frame, 
                                             columns=("src_ip", "dst_ip", "bytes", "packets", "timestamp"),
                                             show="headings",
                                             height=15,
                                             yscrollcommand=scrollbar.set)
        self.connections_tree.pack(fill="both", expand=True, padx=5, pady=5)
        scrollbar.config(command=self.connections_tree.yview)
        
        # Configure the columns
        self.connections_tree.heading("src_ip", text="Source IP")
        self.connections_tree.heading("dst_ip", text="Destination IP")
        self.connections_tree.heading("bytes", text="Bytes")
        self.connections_tree.heading("packets", text="Packets")
        self.connections_tree.heading("timestamp", text="Last Seen")
        
        # Set width for columns
        self.connections_tree.column("src_ip", width=150)
        self.connections_tree.column("dst_ip", width=150)
        self.connections_tree.column("bytes", width=100)
        self.connections_tree.column("packets", width=70)
        self.connections_tree.column("timestamp", width=150)
        
        # Initial message
        self.db_summary_text.insert(tk.END, "Click 'Refresh Database Stats' to load statistics")

    def refresh_db_stats(self):
        """Refresh all database statistics"""
        try:
            # Get database summary statistics
            db_file_size = os.path.getsize("traffic_stats.db") if os.path.exists("traffic_stats.db") else 0
            
            # Get database counts
            try:
                conn_count = self.db_cursor.execute("SELECT COUNT(*) FROM connections").fetchone()[0]
            except Exception:
                conn_count = 0
                
            try:
                total_bytes = self.db_cursor.execute("SELECT SUM(total_bytes) FROM connections").fetchone()[0] or 0
            except Exception:
                total_bytes = 0
                
            try:
                total_packets = self.db_cursor.execute("SELECT SUM(packet_count) FROM connections").fetchone()[0] or 0
            except Exception:
                total_packets = 0
                
            try:
                unique_src_ips = self.db_cursor.execute("SELECT COUNT(DISTINCT src_ip) FROM connections").fetchone()[0]
            except Exception:
                unique_src_ips = 0
                
            try:
                unique_dst_ips = self.db_cursor.execute("SELECT COUNT(DISTINCT dst_ip) FROM connections").fetchone()[0]
            except Exception:
                unique_dst_ips = 0
            
            # Update the summary text widget
            self.db_summary_text.delete(1.0, tk.END)
            self.db_summary_text.insert(tk.END, f"Database File Size: {db_file_size:,} bytes\n")
            self.db_summary_text.insert(tk.END, f"Total Connections: {conn_count:,}\n")
            self.db_summary_text.insert(tk.END, f"Total Data Transferred: {total_bytes:,} bytes ({total_bytes/1024/1024:.2f} MB)\n")
            self.db_summary_text.insert(tk.END, f"Total Packets: {total_packets:,}\n")
            self.db_summary_text.insert(tk.END, f"Unique Source IPs: {unique_src_ips:,}\n")
            self.db_summary_text.insert(tk.END, f"Unique Destination IPs: {unique_dst_ips:,}\n")
            
            # Update connections display
            self.update_connections_display()
            
            self.update_output("Database statistics refreshed")
            self.status_var.set("DB Stats Updated")
        except Exception as e:
            self.update_output(f"Error refreshing database stats: {e}")
            self.status_var.set("DB Stats Error")

    def update_connections_display(self):
        """Update the connections treeview with current data"""
        # Clear existing items
        for item in self.connections_tree.get_children():
            self.connections_tree.delete(item)
        
        try:
            # Fetch connections data
            query = """
                SELECT src_ip, dst_ip, total_bytes, packet_count, timestamp
                FROM connections
                ORDER BY total_bytes DESC
                LIMIT 1000
            """
            
            rows = self.db_cursor.execute(query).fetchall()
            
            for row in rows:
                # Format byte size
                bytes_formatted = f"{row[2]:,}" if row[2] is not None else "0"
                # Insert row into treeview
                self.connections_tree.insert("", "end", values=(row[0], row[1], bytes_formatted, row[3], row[4]))
            
            self.update_output(f"Displaying {len(rows)} connections")
        except Exception as e:
            self.update_output(f"Error updating connections display: {e}")

    def test_db_insert(self):
        """Test database insertions to verify DB is working"""
        test_conn_key = f"test_src->test_dst_{int(time.time())}"
        try:
            # Try inserting a test record
            self.db_cursor.execute("""
                INSERT INTO connections 
                (connection_key, src_ip, dst_ip, total_bytes, packet_count, timestamp)
                VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (test_conn_key, "192.168.1.1", "8.8.8.8", 1024, 1))
            self.db_conn.commit()
            
            # Verify the record was inserted
            result = self.db_cursor.execute("SELECT connection_key FROM connections WHERE connection_key = ?", (test_conn_key,)).fetchone()
            
            if result:
                self.update_output(f"✅ Database test insertion successful. Key: {test_conn_key}")
                messagebox.showinfo("Database Test", "Database insertion test successful!")
            else:
                self.update_output("❌ Database insertion failed - record not found after insert")
                messagebox.showerror("Database Test", "Database insertion failed: Record not found after insert")
        except Exception as e:
            self.update_output(f"❌ Database test insertion error: {e}")
            messagebox.showerror("Database Error", f"Database test failed with error: {e}")

    def verify_database(self):
        """Verify database integrity and show database file information"""
        try:
            # Get database file info
            db_path = os.path.abspath("traffic_stats.db")
            db_exists = os.path.exists(db_path)
            db_size = os.path.getsize(db_path) if db_exists else 0
            
            results = []
            results.append(f"Database file: {db_path}")
            results.append(f"File exists: {db_exists}")
            results.append(f"File size: {db_size:,} bytes")
            
            # Check for tables
            tables = self.db_cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            results.append(f"Tables in database: {', '.join([t[0] for t in tables])}")
            
            # Check transaction journal mode
            journal_mode = self.db_cursor.execute("PRAGMA journal_mode").fetchone()[0]
            results.append(f"Journal mode: {journal_mode}")
            
            # Check synchronous setting
            sync_mode = self.db_cursor.execute("PRAGMA synchronous").fetchone()[0]
            results.append(f"Synchronous mode: {sync_mode}")
            
            # Count rows in tables
            for table in [t[0] for t in tables]:
                try:
                    count = self.db_cursor.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                    results.append(f"Table '{table}': {count:,} rows")
                except:
                    results.append(f"Table '{table}': Unable to count rows")
            
            # Run integrity check
            integrity = self.db_cursor.execute("PRAGMA integrity_check").fetchone()[0]
            results.append(f"Integrity check: {integrity}")
            
            # Show results in a message box
            result_text = "\n".join(results)
            messagebox.showinfo("Database Verification", result_text)
            self.update_output("Database verification completed")
            
            return db_exists and integrity == "ok"
        except Exception as e:
            self.update_output(f"Database verification error: {e}")
            messagebox.showerror("Database Error", f"Verification failed: {e}")
            return False

    def optimize_database(self):
        """Optimize the database for better performance and reliability"""
        try:
            # Close and reopen the database to ensure no active transactions
            self.db_conn.commit()
            self.db_conn.close()
            
            # Back up the database
            import shutil
            backup_path = "traffic_stats_backup.db"
            if os.path.exists("traffic_stats.db"):
                shutil.copy("traffic_stats.db", backup_path)
                self.update_output(f"Database backed up to {backup_path}")
            
            # Reconnect to the database
            self.db_conn = sqlite3.connect("traffic_stats.db", check_same_thread=False)
            self.db_cursor = self.db_conn.cursor()
            
            # Run VACUUM to reclaim space and defragment
            self.db_cursor.execute("VACUUM")
            
            # Run integrity check
            integrity = self.db_cursor.execute("PRAGMA integrity_check").fetchone()[0]
            
            # Reset all SQLite journal files
            self.db_cursor.execute("PRAGMA wal_checkpoint(FULL)")
            
            self.update_output(f"Database optimized. Integrity: {integrity}")
            messagebox.showinfo("Database Optimized", 
                              f"Database optimization complete.\nBackup created: {backup_path}\nIntegrity: {integrity}")
        except Exception as e:
            self.update_output(f"Database optimization error: {e}")
            messagebox.showerror("Optimization Error", str(e))

    def export_db_data(self):
        """Export the database data to a CSV file"""
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv"), ("All files", "*.*")])
        if not file_path:
            return
        
        try:
            # Get the connection data
            connections = self.db_cursor.execute("SELECT * FROM connections").fetchall()
            column_names = [description[0] for description in self.db_cursor.description]
            
            # Create a dataframe
            df = pd.DataFrame(connections, columns=column_names)
            
            # Save to CSV
            df.to_csv(file_path, index=False)
            self.update_output(f"Database exported to {file_path}")
            messagebox.showinfo("Export Complete", f"Database exported to {file_path}")
        except Exception as e:
            self.update_output(f"Export error: {e}")
            messagebox.showerror("Export Error", str(e))

    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.update_output("Output cleared")
        self.update_output(f"Logs are being saved to: {self.log_file}")

    def apply_settings(self):
        vt_entry = self.settings_tab.winfo_children()[0].grid_slaves(row=2, column=1)[0]
        self.virus_total_api_key = vt_entry.get()
        self.update_output("Settings applied")

    def on_interface_selected(self, event):
        if self.running:
            return
        selected_items = self.interface_listbox.selection()
        if selected_items:
            item = selected_items[0]
            interface_name = self.interface_listbox.item(item, "values")[0]
            ip = self.interface_listbox.item(item, "values")[1]
            
            # Get the interface ID from our internal storage
            interface_id = None
            for name, iface_id, ip_addr, desc in self.interface_info:
                if name == interface_name and ip_addr == ip:
                    interface_id = iface_id
                    break
            
            if interface_id:
                self.selected_interface.set(interface_id)
                
                self.interface_info_text.delete(1.0, tk.END)
                self.interface_info_text.insert(tk.END, f"Selected Interface: {interface_name}\nIP Address: {ip}\nInterface ID: {interface_id}\n")
                
                # Enable start button
                self.start_button.config(state="normal")
                self.update_output(f"Selected interface: {interface_name} ({ip})")
            else:
                self.update_output(f"Error: Could not find interface ID for {interface_name}")

    def get_tshark_interfaces(self):
        """Get network interfaces using tshark directly"""
        interfaces = []
        try:
            cmd = ["tshark", "-D"]
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode('utf-8', errors='ignore')
            
            for line in output.splitlines():
                if not line.strip():
                    continue
                    
                # Parse tshark interface line which has format: NUMBER. NAME (DESCRIPTION)
                match = re.match(r'(\d+)\.\s+(.+?)(?:\s+\((.+)\))?$', line)
                if match:
                    idx, iface_id, desc = match.groups()
                    desc = desc or iface_id  # Use ID as description if none provided
                    
                    # Get IP address if possible
                    ip_addr = self.get_interface_ip(iface_id)
                    
                    # Add to interfaces list (name, id, ip, description)
                    # name and description are for display, id is for tshark
                    interfaces.append((desc, iface_id, ip_addr, desc))
                    
            return interfaces
        except subprocess.CalledProcessError as e:
            self.update_output(f"Error getting tshark interfaces: {e.output.decode('utf-8', errors='ignore')}")
            return []
        except Exception as e:
            self.update_output(f"Error listing interfaces: {e}")
            return []

    def get_interface_ip(self, interface_id):
        """Try to get the IP address for an interface"""
        # This is a simplified approach - a more robust method would use
        # platform-specific commands to get accurate IP addresses
        try:
            # Check for an IPv4 address at the end of the interface name
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', interface_id)
            if ip_match:
                return ip_match.group(1)
            
            # For Windows adapters with GUIDs, we can't easily determine the IP
            # A more robust approach would use ipconfig or equivalent
            return "Unknown"
        except Exception:
            return "Unknown"

    def update_interface_list(self):
        for item in self.interface_listbox.get_children():
            self.interface_listbox.delete(item)
        
        # Only use description and IP for display
        for name, iface_id, ip, desc in self.interface_info:
            self.interface_listbox.insert("", "end", values=(name, ip))
        
        if self.interface_info:
            # Select the first item
            first_item = self.interface_listbox.get_children()[0]
            self.interface_listbox.selection_set(first_item)
            self.on_interface_selected(None)

    def refresh_interfaces(self):
        self.update_output("Refreshing interfaces...")
        self.status_var.set("Refreshing...")
        threading.Thread(target=self._refresh_interfaces_thread, daemon=True).start()

    def _refresh_interfaces_thread(self):
        self.interface_info = self.get_tshark_interfaces()
        self.master.after(0, self.update_interface_list)
        self.master.after(0, lambda: self.update_output(f"Found {len(self.interface_info)} interfaces"))
        self.master.after(0, lambda: self.status_var.set("Ready"))

    def toggle_capture(self):
        if self.running:
            self.stop_capture()
        else:
            self.start_capture()

    def start_capture(self):
        interface = self.selected_interface.get()
        if not interface:
            messagebox.showerror("Error", "Select a valid interface")
            return
        self.running = True
        self.start_button.config(text="Stop Capture")
        self.refresh_button.config(state="disabled")
        self.update_output(f"Starting capture on {interface}...")
        self.status_var.set("Capturing...")
        self.capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
        self.capture_thread.start()

    def stop_capture(self):
        self.running = False
        if self.tshark_process:
            try:
                # Terminate the tshark process
                self.tshark_process.terminate()
                self.tshark_process = None
            except Exception as e:
                self.update_output(f"Error stopping tshark: {e}")
        
        self.start_button.config(text="Start Capture")
        self.refresh_button.config(state="normal")
        self.update_output("Stopping capture...")
        self.status_var.set("Stopped")
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
            self.capture_thread = None

    def parse_concatenated_json(self, data):
        """Parse JSON that might have multiple objects concatenated together"""
        if not isinstance(data, str):
            return  # Only process string data
            
        decoder = json.JSONDecoder()
        data = data.strip()
        pos = 0
        
        while pos < len(data):
            try:
                # Skip leading whitespace
                data = data[pos:].lstrip()
                if not data:
                    break
                    
                # Try to decode a JSON object
                obj, index = decoder.raw_decode(data)
                
                # Only yield if we got a dictionary
                if isinstance(obj, dict):
                    yield obj
                    
                # Move position forward
                pos += index
                
            except json.JSONDecodeError:
                # Move forward by one character and try again
                pos += 1

    def extract_json_objects(self, s):
        """
        Extracts complete JSON object strings from a string 's' by scanning for balanced curly braces.
        Returns a list of JSON object strings.
        """
        objects = []
        start = None
        bracket_count = 0
        for i, char in enumerate(s):
            if char == '{':
                if start is None:
                    start = i
                bracket_count += 1
            elif char == '}':
                bracket_count -= 1
                if bracket_count == 0 and start is not None:
                    # A complete object is found
                    objects.append(s[start:i+1])
                    start = None
        return objects

    def capture_packets(self):
        """Capture packets with streaming JSON parser"""
        try:
            interface = self.selected_interface.get()
            self.update_output(f"Capturing on interface: {interface}")
            
            # Construct tshark command with JSON output
            cmd = [
                "tshark",
                "-i", interface,
                "-T", "json",
                "-l"  # Line-buffered output
            ]
            
            self.update_output(f"Running command: {' '.join(cmd)}")
            
            # Start tshark process
            self.tshark_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            packet_count = 0
            buffer = ""  # Buffer to accumulate JSON output
            
            # Process each line from tshark
            for line in iter(self.tshark_process.stdout.readline, ''):
                if not self.running:
                    break
                    
                line = line.strip()
                if not line:
                    continue
                
                # Add line to buffer
                buffer += line
                
                # Log buffer size occasionally
                if random.random() < 0.01:
                    self.update_output(f"Buffer size: {len(buffer)} chars")
                
                # Extract complete JSON objects from the buffer
                objs = self.extract_json_objects(buffer)  # Changed to self.extract_json_objects
                if objs:
                    self.update_output(f"Found {len(objs)} complete JSON objects")
                    
                    for obj_str in objs:
                        try:
                            packet_data = json.loads(obj_str)
                            self.process_packet_json(packet_data)
                            packet_count += 1
                        except json.JSONDecodeError as e:
                            self.update_output(f"JSON Decode Error: {e}")
                    
                    # Remove parsed objects from buffer - find last closing brace
                    last_obj_end = buffer.rfind(objs[-1]) + len(objs[-1])
                    buffer = buffer[last_obj_end:]
                    
                    # Commit database changes
                    self.db_conn.commit()
                    
                    # Periodically analyze traffic and update UI
                    if packet_count > 0 and packet_count % self.batch_size.get() == 0:
                        self.analyze_traffic()
                        self.update_output(f"Processed {packet_count} packets total")
                        self.master.after(0, lambda pc=packet_count: self.status_var.set(f"Captured: {pc} packets"))
                
                # Prevent buffer from growing too large (10MB limit)
                if len(buffer) > 10_000_000:
                    self.update_output("Buffer exceeded 10MB limit, resetting...")
                    buffer = ""
            
            # Check for any errors from tshark
            if self.tshark_process:
                errors = self.tshark_process.stderr.read()
                if errors:
                    self.update_output(f"Tshark errors: {errors}")
        
        except PermissionError:
            self.update_output("Permission denied. Run with elevated privileges.")
        except Exception as e:
            self.update_output(f"Capture error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.update_output("Capture stopped")
            self.master.after(0, lambda: self.status_var.set("Ready"))
            if self.tshark_process:
                self.tshark_process.terminate()
                self.tshark_process = None

    def process_packet_json(self, packet_data):
        """Process a packet with robust error handling"""
        try:
            # Verify we have a dictionary
            if not isinstance(packet_data, dict):
                self.update_output(f"Skipping packet: not a valid dict: {type(packet_data)}")
                return
                
            # Extract source and destination IPs from packet
            source = packet_data.get("_source", {})
            if not source:
                self.update_output("Skipping packet: No _source in packet_data")
                return
                
            layers = source.get("layers", {})
            if not layers or not isinstance(layers, dict):
                self.update_output("Skipping packet: No valid layers in packet_data._source")
                return
            
            # Get IP info if available
            if "ip" not in layers:
                # This is probably not an IP packet - not an error, just skip it
                return
                
            ip_layer = layers["ip"]
            if not isinstance(ip_layer, dict):
                self.update_output(f"Skipping packet: IP layer is not a dict: {type(ip_layer)}")
                return
                
            src_ip = ip_layer.get("ip.src")
            if not src_ip:
                self.update_output("Skipping packet: No source IP in packet")
                return
                
            dst_ip = ip_layer.get("ip.dst")
            if not dst_ip:
                self.update_output("Skipping packet: No destination IP in packet")
                return
            
            # Get frame info
            frame = layers.get("frame", {})
            if not frame:
                self.update_output("Warning: No frame info in packet, using default length 0")
                length = 0
            else:
                try:
                    length = int(frame.get("frame.len", 0))
                except (ValueError, TypeError):
                    self.update_output(f"Error converting frame.len to int: {frame.get('frame.len')}")
                    length = 0
            
            connection_key = f"{src_ip}->{dst_ip}"
            
            # Database operations with explicit success/failure logging
            try:
                # Try to update existing record first
                update_query = """
                    UPDATE connections 
                    SET total_bytes = total_bytes + ?,
                        packet_count = packet_count + 1,
                        timestamp = CURRENT_TIMESTAMP
                    WHERE connection_key = ?
                """
                self.db_cursor.execute(update_query, (length, connection_key))
                
                rows_updated = self.db_cursor.rowcount
                
                # If no rows were updated, insert a new record
                if rows_updated == 0:
                    insert_query = """
                        INSERT INTO connections 
                        (connection_key, src_ip, dst_ip, total_bytes, packet_count, timestamp)
                        VALUES (?, ?, ?, ?, 1, CURRENT_TIMESTAMP)
                    """
                    self.db_cursor.execute(insert_query, (connection_key, src_ip, dst_ip, length))
                    self.update_output(f"Inserted new connection: {connection_key} ({length} bytes)")
                
                # Note: We'll commit in batches instead of every packet for performance
                return True
                    
            except sqlite3.Error as e:
                self.update_output(f"SQLite error processing {connection_key}: {e}")
                return False
                    
        except Exception as e:
            self.update_output(f"Error processing packet: {e}")
            return False

    def verify_database_connection(self):
        """Verify that the database connection is working properly"""
        try:
            # Try a simple query
            self.db_cursor.execute("SELECT 1")
            result = self.db_cursor.fetchone()
            
            if result and result[0] == 1:
                self.update_output("Database connection is working properly")
                
                # Check if we can read from the connections table
                try:
                    self.db_cursor.execute("SELECT COUNT(*) FROM connections")
                    count = self.db_cursor.fetchone()[0]
                    self.update_output(f"Found {count} connections in database")
                    
                    # List a few connections
                    if count > 0:
                        self.db_cursor.execute("SELECT connection_key, src_ip, dst_ip, total_bytes FROM connections LIMIT 5")
                        connections = self.db_cursor.fetchall()
                        for conn in connections:
                            self.update_output(f"Connection: {conn[0]}, Src: {conn[1]}, Dst: {conn[2]}, Bytes: {conn[3]}")
                    
                    return True
                except sqlite3.Error as e:
                    self.update_output(f"Error reading connections table: {e}")
                    return False
            else:
                self.update_output("Database connection test failed")
                return False
        except sqlite3.Error as e:
            self.update_output(f"Database verification failed: {e}")
            return False

    def check_virustotal(self, ip_address):
        if not self.virus_total_api_key:
            return None
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        headers = {"x-apikey": self.virus_total_api_key}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return "Malicious" if stats.get("malicious", 0) > 0 else "Clean"
        except requests.exceptions.HTTPError as e:
            self.update_output(f"VirusTotal error: {e}")
            return None
        except requests.exceptions.RequestException as e:
            self.update_output(f"VirusTotal connection error: {e}")
            return None

    def analyze_traffic(self):
        alerts = []
        for rule in self.rules:
            if rule.enabled:
                try:
                    rule_alerts = rule.analyze(self.db_cursor)
                    if rule_alerts:
                        alerts.extend(rule_alerts)
                except Exception as e:
                    self.update_output(f"Rule {rule.name} error: {e}")
        
        if alerts:
            for alert in alerts:
                self.update_output(alert)
        else:
            self.update_output("No anomalies in this batch")

        # Periodically refresh the database stats tab (but not too often to avoid performance issues)
        if random.random() < 0.2:  # ~20% chance to refresh stats
            try:
                self.master.after(0, self.refresh_db_stats)
            except:
                pass

    def update_output(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"[{timestamp}] {message}"
        
        # Update UI
        self.master.after(0, lambda: self._update_output_ui(formatted_message))
        
        # Save to log file automatically
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(formatted_message + "\n")
        except Exception as e:
            print(f"Error writing to log file: {e}")
    
    def _update_output_ui(self, message):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)

    def add_rule_file(self):
        file_path = filedialog.askopenfilename(title="Select Rule File", filetypes=[("Python Files", "*.py"), ("All Files", "*.*")])
        if file_path:
            rules_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules")
            os.makedirs(rules_dir, exist_ok=True)
            dest_path = os.path.join(rules_dir, os.path.basename(file_path))
            
            try:
                with open(file_path, 'rb') as src, open(dest_path, 'wb') as dest:
                    dest.write(src.read())
                self.update_output(f"Added rule file: {os.path.basename(file_path)}")
                self.reload_rules()
            except Exception as e:
                self.update_output(f"Error adding rule file: {e}")
                messagebox.showerror("Error", f"Failed to add rule file: {e}")

    def reload_rules(self):
        # Save current rule states
        rule_states = {rule.name: rule.enabled for rule in self.rules}
        
        # Reload rules
        self.rule_loader = RuleLoader()
        self.rules = self.rule_loader.rules
        
        # Restore rule states
        for rule in self.rules:
            if rule.name in rule_states:
                rule.enabled = rule_states[rule.name]
        
        # Update UI
        self.update_rules_list()
        self.update_output("Rules reloaded")

    def update_rules_list(self):
        # Clear the listbox
        for item in self.rules_listbox.get_children():
            self.rules_listbox.delete(item)
        
        # Add each rule to the listbox
        for rule in self.rules:
            status = "Enabled" if rule.enabled else "Disabled"
            self.rules_listbox.insert("", "end", values=(rule.name, rule.description, status))

    def toggle_rule(self, event):
        selected = self.rules_listbox.selection()
        if selected:
            rule_name = self.rules_listbox.item(selected[0], "values")[0]
            for rule in self.rules:
                if rule.name == rule_name:
                    rule.enabled = not rule.enabled
                    status = "Enabled" if rule.enabled else "Disabled"
                    self.rules_listbox.item(selected[0], values=(rule.name, rule.description, status))
                    self.update_output(f"Rule '{rule_name}' {status.lower()}")
                    self.show_rule_details(None)
                    break

    def show_rule_details(self, event):
        selected = self.rules_listbox.selection()
        if not selected:
            return
        rule_name = self.rules_listbox.item(selected[0], "values")[0]
        self.selected_rule = next((r for r in self.rules if r.name == rule_name), None)
        if not self.selected_rule:
            return
        
        self.rule_details_text.delete(1.0, tk.END)
        self.rule_details_text.insert(tk.END, f"Rule: {self.selected_rule.name}\nDescription: {self.selected_rule.description}\nStatus: {'Enabled' if self.selected_rule.enabled else 'Disabled'}\n")
        
        for widget in self.params_content_frame.winfo_children():
            widget.destroy()
        params = self.selected_rule.get_params()
        if params:
            self.param_vars = {}
            for row, (param_name, info) in enumerate(params.items()):
                ttk.Label(self.params_content_frame, text=f"{param_name}:").grid(row=row, column=0, sticky="w", padx=5, pady=5)
                var_type = info.get('type', 'str')
                if var_type == 'int':
                    var = tk.IntVar(value=info.get('current', info.get('default', 0)))
                    ttk.Entry(self.params_content_frame, textvariable=var).grid(row=row, column=1, sticky="ew", padx=5, pady=5)
                elif var_type == 'float':
                    var = tk.DoubleVar(value=info.get('current', info.get('default', 0.0)))
                    ttk.Entry(self.params_content_frame, textvariable=var).grid(row=row, column=1, sticky="ew", padx=5, pady=5)
                elif var_type == 'bool':
                    var = tk.BooleanVar(value=info.get('current', info.get('default', False)))
                    ttk.Checkbutton(self.params_content_frame, variable=var).grid(row=row, column=1, sticky="w", padx=5, pady=5)
                else:
                    var = tk.StringVar(value=str(info.get('current', info.get('default', ''))))
                    ttk.Entry(self.params_content_frame, textvariable=var).grid(row=row, column=1, sticky="ew", padx=5, pady=5)
                ttk.Label(self.params_content_frame, text=info.get('description', '')).grid(row=row, column=2, sticky="w", padx=5, pady=5)
                self.param_vars[param_name] = var
            self.params_content_frame.columnconfigure(1, weight=1)
            self.apply_params_button.config(state="normal")
        else:
            ttk.Label(self.params_content_frame, text="No parameters available").pack(padx=5, pady=5)
            self.apply_params_button.config(state="disabled")

    def apply_rule_params(self):
        if self.selected_rule and self.param_vars:
            for param_name, var in self.param_vars.items():
                if self.selected_rule.update_param(param_name, var.get()):
                    self.update_output(f"Updated {param_name} to {var.get()} for {self.selected_rule.name}")
            self.show_rule_details(None)

if __name__ == "__main__":
    try:
        # Set up root window
        root = tk.Tk()
        root.geometry("950x700")  # Slightly wider to accommodate the new tab
        
        # Create application instance
        app = LiveCaptureGUI(root)
        
        # Start the main loop
        root.mainloop()
    except Exception as e:
        # Show critical errors
        import traceback
        print(f"Critical error during startup: {e}")
        traceback.print_exc()