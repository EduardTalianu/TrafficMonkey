import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import sqlite3
import os
import sys
import logging
import re
import random
from dotenv import load_dotenv
import json

# Required for system tray and notifications
import pystray
from PIL import Image, ImageDraw
from plyer import notification

# Import the traffic capture module - this contains all packet parsing logic
from traffic_capture import TrafficCaptureEngine

# Import the database manager
from database_manager import DatabaseManager

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('traffic_analyzer')

# Load environment variables from .env file
load_dotenv()

class Rule:
    """Base class for all rules with dual-database support"""
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.enabled = True
        self.db_manager = None  # Will be set by RuleLoader
    
    def analyze(self, db_cursor):
        """
        Analyze traffic and return list of alerts
        The db_cursor is from the analysis database (read-only)
        """
        return []
    
    def get_params(self):
        """Get configurable parameters"""
        return {}
    
    def update_param(self, param_name, value):
        """Update a configurable parameter"""
        return False
    
    def update_connection(self, connection_key, field, value):
        """
        Update a connection in the database
        This method ensures updates go to the capture database
        """
        if self.db_manager:
            return self.db_manager.update_connection_field(connection_key, field, value)
        return False

class RuleLoader:
    """Handles loading rule modules from the rules directory"""
    
    def __init__(self, db_manager):
        """Initialize the rule loader with a database manager"""
        self.rules = []
        self.db_manager = db_manager
        
        # Root directory of the application
        self.app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
                    rule_namespace = {
                        'Rule': Rule,
                        'db_manager': self.db_manager,  # Inject database manager
                        'os': os,
                        'time': time,
                        'logging': logging,
                        're': re,
                        'requests': __import__('requests') if 'requests' in sys.modules else None,
                        'json': json,
                        'hashlib': __import__('hashlib') if 'hashlib' in sys.modules else None,
                        'ipaddress': __import__('ipaddress') if 'ipaddress' in sys.modules else None
                    }
                    
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
                            
                            # Inject database manager into the rule instance
                            rule_instance.db_manager = self.db_manager
                            
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
    
    def patch_loaded_rules(self):
        """
        No-op function that replaces the original patching functionality.
        All rules should now be compatible with the dual-database system.
        """
        logger.info("Rule patching disabled - using dual-database compatible rules")
        return
    
    def patch_virustotal_rule(self, rule_instance, db_manager):
        """
        No-op function that replaces the original VirusTotal patch.
        The VirusTotal rule is now inherently compatible with the dual-database system.
        """
        logger.info(f"Skipping patch for {rule_instance.name} - rule is already compatible")
        return
    
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
                
            def analyze(self, db_cursor, *args):
                """Updated to accept variable arguments for compatibility"""
                alerts = []
                
                # Query for connections with large data transfers
                try:
                    large_transfers = []
                    for row in db_cursor.execute("""
                        SELECT src_ip, dst_ip, total_bytes
                        FROM connections
                        WHERE total_bytes > ?
                    """, (self.threshold_kb * 1024,)):
                        large_transfers.append(row)
                
                    for src_ip, dst_ip, total_bytes in large_transfers:
                        alerts.append(f"ALERT: Large data transfer from {src_ip} to {dst_ip} - {total_bytes/1024/1024:.2f} MB")
                except Exception as e:
                    logging.error(f"Error in LargeDataTransferRule: {e}")
                    
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
        
        # Create instance and inject database manager
        rule_instance = LargeDataTransferRule()
        rule_instance.db_manager = self.db_manager
        
        # Add the built-in rule
        self.rules.append(rule_instance)
        logger.info("Added built-in rule: Large Data Transfer Detector")

class SystemTrayApp:
    """Manages the system tray icon and notification behavior"""
    
    def __init__(self, app):
        self.app = app
        self.create_icon()
        self.notification_enabled = True
        self.notification_cooldown = 30  # seconds between notifications
        self.last_notification_time = {}  # Track time by alert type
    
    def create_icon(self):
        """Create the system tray icon"""
        # Create icon image (a simple circle)
        icon_size = 64
        image = Image.new('RGBA', (icon_size, icon_size), (0, 0, 0, 0))
        dc = ImageDraw.Draw(image)
        dc.ellipse((5, 5, icon_size-5, icon_size-5), fill=(0, 120, 212))
        
        # Create the system tray icon
        self.icon = pystray.Icon(
            "TrafficAnalyzer",
            image,
            "Network Traffic Analyzer",
            menu=self.create_menu()
        )
    
    def create_menu(self):
        """Create the context menu for the tray icon"""
        return pystray.Menu(
            pystray.MenuItem("Show Window", self.show_window),
            pystray.MenuItem("Exit", self.exit_app)
        )
    
    def show_window(self, icon, item):
        """Display the main application window"""
        self.app.master.deiconify()
        self.app.master.lift()
        self.app.master.state('normal')
        self.app.master.focus_force()
    
    def exit_app(self, icon, item):
        """Exit the application"""
        if messagebox.askyesno("Exit", "Are you sure you want to exit?", 
                              parent=self.app.master):
            # Stop capturing if needed
            if self.app.running:
                self.app.stop_capture()
            
            # Stop the icon
            icon.stop()
            
            # Close the application
            self.app.on_closing()
    
    def run(self):
        """Run the system tray icon in a separate thread"""
        self.icon_thread = threading.Thread(target=self.icon.run)
        self.icon_thread.daemon = True
        self.icon_thread.start()
    
    def show_notification(self, title, message):
        """Show a notification bubble from the system tray"""
        if not self.notification_enabled:
            return
        
        # Use plyer's notification system
        try:
            notification.notify(
                title=title,
                message=message,
                app_name="Network Traffic Analyzer",
                timeout=5  # seconds
            )
        except Exception as e:
            logger.error(f"Error showing notification: {e}")
    
    def show_alert_notification(self, alert_message, rule_name, ip_address):
        """Show alert notification with rate limiting"""
        # Rate limiting based on rule type
        current_time = time.time()
        if rule_name in self.last_notification_time:
            time_diff = current_time - self.last_notification_time[rule_name]
            if time_diff < self.notification_cooldown:
                return  # Skip notification if still in cooldown
        
        # Update last notification time
        self.last_notification_time[rule_name] = current_time
        
        # Format the alert message to be shorter for notification
        short_message = f"IP: {ip_address} - {alert_message[:60]}..."
        
        # Show the notification
        self.show_notification(f"Alert: {rule_name}", short_message)

class LiveCaptureGUI:
    def __init__(self, master):
        self.master = master
        master.title("Live Network Traffic Analyzer")

        # Set app root path
        self.src_dir = os.path.dirname(os.path.abspath(__file__))
        self.app_root = os.path.dirname(self.src_dir)

        # Configuration Variables
        self.batch_size = tk.IntVar(value=100)
        self.sliding_window_size = tk.IntVar(value=1000)
        self.selected_interface = tk.StringVar()
        self.show_inactive_interfaces = tk.BooleanVar(value=False)
        
        # Enable notifications by default
        self.enable_notifications = tk.BooleanVar(value=True)

        # Get VirusTotal API Key from environment variable
        self.virus_total_api_key = os.getenv("VIRUSTOTAL_API_KEY", "")

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(master, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(side=tk.BOTTOM, fill=tk.X)

        # Set log file path
        self.log_file = os.path.join(self.app_root, "logs", "traffic_analyzer.log")

        # Make sure log directory exists
        os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        # Path to false positives file
        self.false_positives_file = os.path.join(self.app_root, "db", "false_positives.txt")
        self.false_positives = self.load_false_positives()

        # Database Setup - Use new DatabaseManager
        self.setup_database()

        # UI Setup
        self.notebook = ttk.Notebook(master)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.interfaces_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        self.rules_tab = ttk.Frame(self.notebook)
        self.db_tab = ttk.Frame(self.notebook)
        self.alerts_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.interfaces_tab, text="Network Interfaces")
        self.notebook.add(self.settings_tab, text="Detection Settings")
        self.notebook.add(self.rules_tab, text="Rules")
        self.notebook.add(self.db_tab, text="Database/Stats")
        self.notebook.add(self.alerts_tab, text="Alerts")
        
        # Initialize interfaces
        self.interface_info = []
        
        # Initialize system tray icon
        self.tray_app = SystemTrayApp(self)
        self.tray_app.notification_enabled = self.enable_notifications.get()

        # Create UI tabs
        self.create_interfaces_tab()
        self.create_settings_tab()
        self.create_rules_tab()
        self.create_db_tab()
        self.create_alerts_tab()
        
        # Capture Variables
        self.running = False
        self.capture_thread = None
        
        # Initialize TrafficCaptureEngine with database manager
        self.capture_engine = TrafficCaptureEngine(self)
        
        # Load Rules with database manager
        self.rule_loader = RuleLoader(self.db_manager)
        self.rules = self.rule_loader.rules
        self.selected_rule = None
        self.param_vars = {}
        self.update_rules_list()
        
        # Start system tray icon
        self.tray_app.run()
        
        # Initialize interfaces after UI is set up
        self.refresh_interfaces()
        
        # Set up window close handler
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Initialize status flags for refresh operations
        self.malicious_refresh_in_progress = False
        self.leaderboard_refresh_in_progress = False

    def on_closing(self):
        """Handle application closing"""
        if messagebox.askyesno("Exit", "Are you sure you want to exit?"):
            # Stop capturing if needed
            if self.running:
                self.stop_capture()
                
            # Close database connections
            if hasattr(self, 'db_manager'):
                self.db_manager.close()
                
            # Destroy the window
            self.master.destroy()

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
            return false_positives
        except Exception as e:
            self.update_output(f"Error loading false positives: {e}")
            return false_positives

    def save_false_positives(self):
        """Save false positives to file"""
        try:
            with open(self.false_positives_file, 'w') as f:
                f.write("# False positives list - one IP per line\n")
                f.write("# Generated by Network Traffic Analyzer\n")
                f.write("# Last updated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
                for ip in sorted(self.false_positives):
                    f.write(ip + "\n")
            self.update_output(f"Saved {len(self.false_positives)} false positives to {self.false_positives_file}")
        except Exception as e:
            self.update_output(f"Error saving false positives: {e}")

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
        
        ttk.Label(settings_frame, text="Log File:").grid(row=2, column=0, sticky="w", padx=5, pady=5)
        ttk.Label(settings_frame, text=self.log_file).grid(row=2, column=1, sticky="w", padx=5, pady=5)
        ttk.Label(settings_frame, text="Logs are automatically saved").grid(row=2, column=2, sticky="w", padx=5, pady=5)
        
        note_label = ttk.Label(settings_frame, text="Note: VirusTotal API key is read from .env file")
        note_label.grid(row=3, column=0, columnspan=3, sticky="w", padx=5, pady=5)
        
        ttk.Checkbutton(settings_frame, text="Enable alert notifications", 
                      variable=self.enable_notifications,
                      command=self.update_notification_settings).grid(row=4, column=0, sticky="w", padx=5, pady=5)
        
        ttk.Button(settings_frame, text="Apply Settings", command=self.apply_settings).grid(row=5, column=1, sticky="e", padx=5, pady=10)
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

    def update_notification_settings(self):
        """Update notification settings based on checkbox"""
        self.tray_app.notification_enabled = self.enable_notifications.get()
        self.update_output(f"Notifications {'enabled' if self.enable_notifications.get() else 'disabled'}")

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
        """Create a simplified Database/Stats tab"""
        # Control buttons frame
        control_frame = ttk.Frame(self.db_tab)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="Refresh Database Stats", command=self.refresh_db_stats).pack(side="left", padx=5)
        
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

    def create_alerts_tab(self):
        """Create a new Alerts tab with subtabs"""
        # Create inner notebook for subtabs
        self.alerts_notebook = ttk.Notebook(self.alerts_tab)
        self.alerts_notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create the subtabs
        self.alerts_by_ip_tab = ttk.Frame(self.alerts_notebook)
        self.alerts_by_alert_tab = ttk.Frame(self.alerts_notebook)
        self.alerts_malicious_tab = ttk.Frame(self.alerts_notebook)
        self.alerts_leaderboard_tab = ttk.Frame(self.alerts_notebook)  # New leaderboard tab
        
        self.alerts_notebook.add(self.alerts_by_ip_tab, text="By IP Address")
        self.alerts_notebook.add(self.alerts_by_alert_tab, text="By Alert Type")
        self.alerts_notebook.add(self.alerts_malicious_tab, text="Possible Malicious")
        self.alerts_notebook.add(self.alerts_leaderboard_tab, text="Threat Leaderboard")  # Add the new tab
        
        # Create the IP-focused tab
        self.create_alerts_by_ip_subtab()
        
        # Create the Alert-focused tab
        self.create_alerts_by_alert_subtab()
        
        # Create the Possible Malicious tab
        self.create_alerts_malicious_subtab()
        
        # Create the new Leaderboard tab
        self.create_alerts_leaderboard_subtab()

    def create_alerts_by_ip_subtab(self):
        """Create the IP-focused alerts tab with right-click menu"""
        # Control buttons frame
        control_frame = ttk.Frame(self.alerts_by_ip_tab)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="Refresh Alerts", command=self.refresh_alerts).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Clear All Alerts", command=self.clear_alerts).pack(side="left", padx=5)
        
        # IP Selection frame
        ip_frame = ttk.Frame(self.alerts_by_ip_tab)
        ip_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(ip_frame, text="Filter by IP:").pack(side="left", padx=5)
        self.ip_filter = ttk.Entry(ip_frame, width=20)
        self.ip_filter.pack(side="left", padx=5)
        ttk.Button(ip_frame, text="Apply Filter", command=self.apply_ip_filter).pack(side="left", padx=5)
        ttk.Button(ip_frame, text="Clear Filter", command=self.clear_ip_filter).pack(side="left", padx=5)
        
        # Alerts treeview
        alerts_frame = ttk.Frame(self.alerts_by_ip_tab)
        alerts_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Scrollbar for the treeview
        scrollbar = ttk.Scrollbar(alerts_frame)
        scrollbar.pack(side="right", fill="y")
        
        # Create treeview for alerts by IP
        self.alerts_tree = ttk.Treeview(alerts_frame,
                                    columns=("ip", "alert_count", "last_seen"),
                                    show="headings",
                                    height=10,
                                    yscrollcommand=scrollbar.set)
        self.alerts_tree.pack(fill="both", expand=True, padx=5, pady=5)
        scrollbar.config(command=self.alerts_tree.yview)
        
        # Configure columns
        self.alerts_tree.heading("ip", text="IP Address")
        self.alerts_tree.heading("alert_count", text="Alert Count")
        self.alerts_tree.heading("last_seen", text="Last Detected")
        
        self.alerts_tree.column("ip", width=150)
        self.alerts_tree.column("alert_count", width=100)
        self.alerts_tree.column("last_seen", width=150)
        
        # Bind event to show alerts for selected IP
        self.alerts_tree.bind("<<TreeviewSelect>>", self.show_ip_alerts)
        
        # Add right-click context menu
        self.create_alerts_tree_context_menu()
        
        # Alerts details frame
        details_frame = ttk.LabelFrame(self.alerts_by_ip_tab, text="Alert Details")
        details_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Scrollbar for details
        details_scrollbar = ttk.Scrollbar(details_frame)
        details_scrollbar.pack(side="right", fill="y")
        
        # Create alerts details list
        self.alerts_details_tree = ttk.Treeview(details_frame,
                                            columns=("alert", "rule", "timestamp"),
                                            show="headings",
                                            height=10,
                                            yscrollcommand=details_scrollbar.set)
        self.alerts_details_tree.pack(fill="both", expand=True, padx=5, pady=5)
        details_scrollbar.config(command=self.alerts_details_tree.yview)
        
        # Configure details columns
        self.alerts_details_tree.heading("alert", text="Alert Message")
        self.alerts_details_tree.heading("rule", text="Rule Name")
        self.alerts_details_tree.heading("timestamp", text="Timestamp")
        
        self.alerts_details_tree.column("alert", width=300)
        self.alerts_details_tree.column("rule", width=150)
        self.alerts_details_tree.column("timestamp", width=150)
        
        # Info and button frame for selected IP
        info_frame = ttk.Frame(self.alerts_by_ip_tab)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.alerts_ip_var = tk.StringVar()
        ttk.Label(info_frame, text="Selected IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(info_frame, textvariable=self.alerts_ip_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        button_frame = ttk.Frame(info_frame)
        button_frame.grid(row=0, column=2, sticky="e", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Copy IP", command=self.copy_alerts_ip).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Mark as False Positive", command=self.mark_alerts_ip_as_false_positive).pack(side="left", padx=5)
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)

    def create_alerts_tree_context_menu(self):
        """Create right-click context menu for the alerts IP tree"""
        self.alerts_tree_menu = tk.Menu(self.master, tearoff=0)
        self.alerts_tree_menu.add_command(label="Copy IP", command=self.copy_alerts_ip)
        self.alerts_tree_menu.add_command(label="Mark as False Positive", command=self.mark_alerts_ip_as_false_positive)
        self.alerts_tree_menu.add_command(label="Show Details", command=self.show_alerts_ip_details_from_menu)
        
        # Bind right-click to show context menu
        self.alerts_tree.bind("<Button-3>", self.show_alerts_tree_context_menu)
        
        # Also bind selection to update the IP entry
        self.alerts_tree.bind("<<TreeviewSelect>>", self.update_alerts_selected_ip)

    def show_alerts_tree_context_menu(self, event):
        """Show context menu on right-click in alerts tree"""
        # Select the item under cursor
        item = self.alerts_tree.identify_row(event.y)
        if item:
            self.alerts_tree.selection_set(item)
            self.update_alerts_selected_ip(None)
            self.alerts_tree_menu.post(event.x_root, event.y_root)

    def update_alerts_selected_ip(self, event):
        """Update the IP entry when a row is selected in alerts tree"""
        # First handle the primary function of showing details
        if event is not None:
            self.show_ip_alerts(event)
        
        # Then update the IP field
        selected = self.alerts_tree.selection()
        if selected:
            ip = self.alerts_tree.item(selected[0], "values")[0]
            self.alerts_ip_var.set(ip)
        else:
            self.alerts_ip_var.set("")

    def copy_alerts_ip(self):
        """Copy the selected IP from alerts tree to clipboard"""
        ip = self.alerts_ip_var.get()
        if ip:
            self.master.clipboard_clear()
            self.master.clipboard_append(ip)
            self.update_output(f"Copied IP {ip} to clipboard")

    def mark_alerts_ip_as_false_positive(self):
        """Mark the selected IP as a false positive from alerts tree"""
        ip = self.alerts_ip_var.get()
        if ip:
            self.false_positives.add(ip)
            self.save_false_positives()
            self.update_output(f"Marked {ip} as false positive")
            
            # Update status in all relevant trees
            self._update_status_in_treeview(self.malicious_tree, ip, "False Positive")
            self._update_status_in_treeview(self.leaderboard_tree, ip, "False Positive")
            
            # Refresh views to ensure consistency
            self.refresh_alerts()
            self.refresh_malicious_list()
            self.refresh_leaderboard()

    def show_alerts_ip_details_from_menu(self):
        """Show details for selected IP (called from context menu)"""
        selected = self.alerts_tree.selection()
        if selected:
            self.show_ip_alerts(None)

    def create_alerts_by_alert_subtab(self):
        """Create the Alert-focused tab"""
        # Control buttons frame
        control_frame = ttk.Frame(self.alerts_by_alert_tab)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="Refresh Alerts", command=self.refresh_alerts_by_type).pack(side="left", padx=5)
        
        # Rule filter frame
        filter_frame = ttk.Frame(self.alerts_by_alert_tab)
        filter_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(filter_frame, text="Filter by Rule:").pack(side="left", padx=5)
        self.rule_filter = ttk.Entry(filter_frame, width=20)
        self.rule_filter.pack(side="left", padx=5)
        ttk.Button(filter_frame, text="Apply Filter", command=self.apply_rule_filter).pack(side="left", padx=5)
        ttk.Button(filter_frame, text="Clear Filter", command=self.clear_rule_filter).pack(side="left", padx=5)
        
        # Alert types treeview
        alerts_frame = ttk.Frame(self.alerts_by_alert_tab)
        alerts_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Scrollbar for the treeview
        scrollbar = ttk.Scrollbar(alerts_frame)
        scrollbar.pack(side="right", fill="y")
        
        # Create treeview for alerts by rule
        self.alert_types_tree = ttk.Treeview(alerts_frame,
                                           columns=("rule", "alert_count", "last_seen"),
                                           show="headings",
                                           height=10,
                                           yscrollcommand=scrollbar.set)
        self.alert_types_tree.pack(fill="both", expand=True, padx=5, pady=5)
        scrollbar.config(command=self.alert_types_tree.yview)
        
        # Configure columns
        self.alert_types_tree.heading("rule", text="Rule Name")
        self.alert_types_tree.heading("alert_count", text="Alert Count")
        self.alert_types_tree.heading("last_seen", text="Last Detected")
        
        self.alert_types_tree.column("rule", width=200)
        self.alert_types_tree.column("alert_count", width=100)
        self.alert_types_tree.column("last_seen", width=150)
        
        # Bind event to show alerts for selected rule
        self.alert_types_tree.bind("<<TreeviewSelect>>", self.show_rule_alerts)
        
        # Alert instances frame
        instances_frame = ttk.LabelFrame(self.alerts_by_alert_tab, text="Alert Instances")
        instances_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Scrollbar for instances
        instances_scrollbar = ttk.Scrollbar(instances_frame)
        instances_scrollbar.pack(side="right", fill="y")
        
        # Create rule alerts instances list
        self.rule_alerts_tree = ttk.Treeview(instances_frame,
                                           columns=("ip", "alert", "timestamp"),
                                           show="headings",
                                           height=10,
                                           yscrollcommand=instances_scrollbar.set)
        self.rule_alerts_tree.pack(fill="both", expand=True, padx=5, pady=5)
        instances_scrollbar.config(command=self.rule_alerts_tree.yview)
        
        # Configure instances columns
        self.rule_alerts_tree.heading("ip", text="IP Address")
        self.rule_alerts_tree.heading("alert", text="Alert Message")
        self.rule_alerts_tree.heading("timestamp", text="Timestamp")
        
        self.rule_alerts_tree.column("ip", width=150)
        self.rule_alerts_tree.column("alert", width=300)
        self.rule_alerts_tree.column("timestamp", width=150)

    def create_alerts_malicious_subtab(self):
        """Create the Possible Malicious tab with fixes for display issues"""
        # Control buttons frame
        control_frame = ttk.Frame(self.alerts_malicious_tab)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="Refresh List", command=self.refresh_malicious_list).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Manage False Positives", command=self.manage_false_positives).pack(side="left", padx=5)
        
        # Malicious IP treeview
        malicious_frame = ttk.Frame(self.alerts_malicious_tab)
        malicious_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Scrollbar for the treeview
        scrollbar = ttk.Scrollbar(malicious_frame)
        scrollbar.pack(side="right", fill="y")
        
        # Create treeview for malicious IPs
        self.malicious_tree = ttk.Treeview(malicious_frame,
                                         columns=("ip", "alert_type", "status", "timestamp"),
                                         show="headings",
                                         height=15,
                                         yscrollcommand=scrollbar.set)
        self.malicious_tree.pack(fill="both", expand=True, padx=5, pady=5)
        scrollbar.config(command=self.malicious_tree.yview)
        
        # Configure columns
        self.malicious_tree.heading("ip", text="IP Address")
        self.malicious_tree.heading("alert_type", text="Alert Type")
        self.malicious_tree.heading("status", text="Status")
        self.malicious_tree.heading("timestamp", text="Detected")
        
        self.malicious_tree.column("ip", width=150)
        self.malicious_tree.column("alert_type", width=150)
        self.malicious_tree.column("status", width=100)
        self.malicious_tree.column("timestamp", width=150)
        
        # Add right-click menu
        self.create_malicious_context_menu()
        
        # Info and button frame
        info_frame = ttk.Frame(self.alerts_malicious_tab)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.ip_var = tk.StringVar()
        ttk.Label(info_frame, text="Selected IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(info_frame, textvariable=self.ip_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        button_frame = ttk.Frame(info_frame)
        button_frame.grid(row=0, column=2, sticky="e", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Copy IP", command=self.copy_selected_ip).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Mark as False Positive", command=self.mark_as_false_positive).pack(side="left", padx=5)
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)

    def create_alerts_leaderboard_subtab(self):
        """Create the Threat Leaderboard tab"""
        # Control buttons frame
        control_frame = ttk.Frame(self.alerts_leaderboard_tab)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Button(control_frame, text="Refresh Leaderboard", command=self.refresh_leaderboard).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Manage False Positives", command=self.manage_false_positives).pack(side="left", padx=5)
        
        # Leaderboard treeview
        leaderboard_frame = ttk.Frame(self.alerts_leaderboard_tab)
        leaderboard_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Scrollbar for the treeview
        scrollbar = ttk.Scrollbar(leaderboard_frame)
        scrollbar.pack(side="right", fill="y")
        
        # Create treeview for threat leaderboard
        self.leaderboard_tree = ttk.Treeview(leaderboard_frame,
                                     columns=("ip", "distinct_rules", "total_alerts", "status"),
                                     show="headings",
                                     height=15,
                                     yscrollcommand=scrollbar.set)
        self.leaderboard_tree.pack(fill="both", expand=True, padx=5, pady=5)
        scrollbar.config(command=self.leaderboard_tree.yview)
        
        # Configure columns
        self.leaderboard_tree.heading("ip", text="IP Address")
        self.leaderboard_tree.heading("distinct_rules", text="Distinct Alert Types")
        self.leaderboard_tree.heading("total_alerts", text="Total Alerts")
        self.leaderboard_tree.heading("status", text="Status")
        
        self.leaderboard_tree.column("ip", width=150)
        self.leaderboard_tree.column("distinct_rules", width=150)
        self.leaderboard_tree.column("total_alerts", width=100)
        self.leaderboard_tree.column("status", width=100)
        
        # Add right-click menu
        self.create_leaderboard_context_menu()
        
        # Detail frame for showing triggered rules
        details_frame = ttk.LabelFrame(self.alerts_leaderboard_tab, text="Triggered Rules")
        details_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Scrollbar for details
        details_scrollbar = ttk.Scrollbar(details_frame)
        details_scrollbar.pack(side="right", fill="y")
        
        # Create treeview for rule details
        self.leaderboard_details_tree = ttk.Treeview(details_frame,
                                               columns=("rule", "count", "last_alert"),
                                               show="headings",
                                               height=10,
                                               yscrollcommand=details_scrollbar.set)
        self.leaderboard_details_tree.pack(fill="both", expand=True, padx=5, pady=5)
        details_scrollbar.config(command=self.leaderboard_details_tree.yview)
        
        # Configure details columns
        self.leaderboard_details_tree.heading("rule", text="Rule Name")
        self.leaderboard_details_tree.heading("count", text="Alert Count")
        self.leaderboard_details_tree.heading("last_alert", text="Last Alert")
        
        self.leaderboard_details_tree.column("rule", width=250)
        self.leaderboard_details_tree.column("count", width=100)
        self.leaderboard_details_tree.column("last_alert", width=150)
        
        # Info and button frame
        info_frame = ttk.Frame(self.alerts_leaderboard_tab)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.leaderboard_ip_var = tk.StringVar()
        ttk.Label(info_frame, text="Selected IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(info_frame, textvariable=self.leaderboard_ip_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        button_frame = ttk.Frame(info_frame)
        button_frame.grid(row=0, column=2, sticky="e", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Copy IP", command=self.copy_leaderboard_ip).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Mark as False Positive", command=self.mark_leaderboard_as_false_positive).pack(side="left", padx=5)
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)
        
        # Bind selection event
        self.leaderboard_tree.bind("<<TreeviewSelect>>", self.show_leaderboard_details)

    def create_leaderboard_context_menu(self):
        """Create right-click context menu for leaderboard IPs"""
        self.leaderboard_menu = tk.Menu(self.master, tearoff=0)
        self.leaderboard_menu.add_command(label="Copy IP", command=self.copy_leaderboard_ip)
        self.leaderboard_menu.add_command(label="Mark as False Positive", command=self.mark_leaderboard_as_false_positive)
        self.leaderboard_menu.add_command(label="Show Details", command=self.show_leaderboard_details_from_menu)
        
        # Bind right-click to show context menu
        self.leaderboard_tree.bind("<Button-3>", self.show_leaderboard_context_menu)
        
        # Also bind selection to update the IP entry
        self.leaderboard_tree.bind("<<TreeviewSelect>>", self.update_leaderboard_selected_ip)

    def show_leaderboard_context_menu(self, event):
        """Show context menu on right-click"""
        # Select the item under cursor
        item = self.leaderboard_tree.identify_row(event.y)
        if item:
            self.leaderboard_tree.selection_set(item)
            self.update_leaderboard_selected_ip(None)
            self.leaderboard_menu.post(event.x_root, event.y_root)

    def update_leaderboard_selected_ip(self, event):
        """Update the IP entry when a row is selected"""
        selected = self.leaderboard_tree.selection()
        if selected:
            ip = self.leaderboard_tree.item(selected[0], "values")[0]
            self.leaderboard_ip_var.set(ip)
        else:
            self.leaderboard_ip_var.set("")

    def copy_leaderboard_ip(self):
        """Copy the selected IP from leaderboard to clipboard"""
        ip = self.leaderboard_ip_var.get()
        if ip:
            self.master.clipboard_clear()
            self.master.clipboard_append(ip)
            self.update_output(f"Copied IP {ip} to clipboard")

    def mark_leaderboard_as_false_positive(self):
        """Mark the selected IP as a false positive from leaderboard"""
        ip = self.leaderboard_ip_var.get()
        if ip:
            self.false_positives.add(ip)
            self.save_false_positives()
            self.update_output(f"Marked {ip} as false positive")
            
            # Update status in all relevant trees
            self._update_status_in_treeview(self.leaderboard_tree, ip, "False Positive")
            self._update_status_in_treeview(self.malicious_tree, ip, "False Positive")
            
            # Refresh both views to ensure consistency
            self.refresh_leaderboard()
            self.refresh_malicious_list()

    def show_leaderboard_details_from_menu(self):
        """Show details for selected IP (called from context menu)"""
        self.show_leaderboard_details(None)

    def show_leaderboard_details(self, event):
        """Show rule details for the selected IP in leaderboard"""
        # Clear existing items
        for item in self.leaderboard_details_tree.get_children():
            self.leaderboard_details_tree.delete(item)
        
        # Get selected IP
        selected = self.leaderboard_tree.selection()
        if not selected:
            return
            
        ip = self.leaderboard_tree.item(selected[0], "values")[0]
        
        # Queue the query for rule details by IP
        self.db_manager.queue_query(
            self._get_ip_rule_details,
            callback=lambda rows: self._update_leaderboard_details_display(rows, ip),
            ip_address=ip
        )

    def _get_ip_rule_details(self, ip_address):
        """Get rule details for an IP, showing each distinct rule type only once"""
        try:
            cursor = self.db_manager.analysis_conn.cursor()
            
            query = """
                SELECT rule_name, COUNT(*) as alert_count, MAX(timestamp) as last_alert
                FROM alerts
                WHERE ip_address = ?
                GROUP BY rule_name
                ORDER BY last_alert DESC
            """
            
            rows = cursor.execute(query, (ip_address,)).fetchall()
            cursor.close()
            return rows
        except Exception as e:
            logging.error(f"Error getting rule details for IP {ip_address}: {e}")
            return []

    def _update_leaderboard_details_display(self, rows, ip):
        """Update the leaderboard details display with rule information"""
        try:
            # Add to details tree
            for row in rows:
                self.leaderboard_details_tree.insert("", "end", values=(row[0], row[1], row[2]))
            
            self.update_output(f"Showing {len(rows)} rule types triggered by IP: {ip}")
        except Exception as e:
            self.update_output(f"Error fetching rule details for {ip}: {e}")

    def refresh_leaderboard(self):
        """Refresh the threat leaderboard display"""
        # Set flag to indicate refresh is in progress
        self.leaderboard_refresh_in_progress = True
        
        # Clear current items
        for item in self.leaderboard_tree.get_children():
            self.leaderboard_tree.delete(item)
        
        # Queue the leaderboard query
        self.db_manager.queue_query(
            self._get_leaderboard_data,
            callback=self._update_leaderboard_display
        )
        
        self.update_output("Refreshing threat leaderboard...")

    def _get_leaderboard_data(self):
        """Get data for the threat leaderboard with correct rule type counting"""
        try:
            cursor = self.db_manager.analysis_conn.cursor()
            
            # First, get distinct rule types triggered by each IP
            query = """
                SELECT 
                    ip_address, 
                    COUNT(DISTINCT rule_name) as distinct_rules,
                    MAX(timestamp) as last_alert
                FROM alerts
                GROUP BY ip_address
                ORDER BY distinct_rules DESC
            """
            
            rows = cursor.execute(query).fetchall()
            
            # Get local machine's IP addresses to exclude
            local_ips = self.get_local_ips()
            if local_ips is None:
                local_ips = set(['127.0.0.1', 'localhost'])
            
            # Process results and add total alert count for reference
            result_data = []
            for ip, distinct_rules, last_alert in rows:
                # Skip local IPs
                if ip in local_ips:
                    continue
                
                # Get total number of alerts for this IP (just for reference)
                total_alerts = cursor.execute(
                    "SELECT COUNT(*) FROM alerts WHERE ip_address = ?", 
                    (ip,)
                ).fetchone()[0]
                
                # Determine status
                status = "False Positive" if ip in self.false_positives else "Active"
                
                # Add to results
                result_data.append((ip, distinct_rules, total_alerts, status, last_alert))
            
            cursor.close()
            return result_data
        except Exception as e:
            logging.error(f"Error getting leaderboard data: {e}")
            return []

    def _update_leaderboard_display(self, data):
        """Update the leaderboard display with the results"""
        try:
            # Add each item to the tree
            for ip, distinct_rules, total_alerts, status, last_alert in data:
                self.leaderboard_tree.insert("", "end", values=(ip, distinct_rules, total_alerts, status))
            
            self.update_output(f"Leaderboard updated with {len(data)} IP addresses")
            
            # Reset the refresh flag
            self.leaderboard_refresh_in_progress = False
        except Exception as e:
            self.update_output(f"Error updating leaderboard display: {e}")
            self.leaderboard_refresh_in_progress = False

    def _update_status_in_treeview(self, tree, ip, new_status):
        """Update the status field for an IP in the specified treeview"""
        for item in tree.get_children():
            values = tree.item(item, "values")
            if values and values[0] == ip:
                new_values = list(values)
                # Find the status column (usually index 2 or 3)
                status_index = None
                if len(values) >= 4 and values[3] in ("Active", "False Positive"):
                    status_index = 3
                elif len(values) >= 3 and values[2] in ("Active", "False Positive"):
                    status_index = 2
                
                if status_index is not None:
                    new_values[status_index] = new_status
                    tree.item(item, values=new_values)

    def create_malicious_context_menu(self):
        """Create right-click context menu for malicious IPs"""
        self.malicious_menu = tk.Menu(self.master, tearoff=0)
        self.malicious_menu.add_command(label="Copy IP", command=self.copy_selected_ip)
        self.malicious_menu.add_command(label="Mark as False Positive", command=self.mark_as_false_positive)
        
        # Bind right-click to show context menu
        self.malicious_tree.bind("<Button-3>", self.show_malicious_context_menu)
        
        # Also bind selection to update the IP entry
        self.malicious_tree.bind("<<TreeviewSelect>>", self.update_selected_ip)

    def show_malicious_context_menu(self, event):
        """Show context menu on right-click"""
        # Select the item under cursor
        item = self.malicious_tree.identify_row(event.y)
        if item:
            self.malicious_tree.selection_set(item)
            self.update_selected_ip(None)
            self.malicious_menu.post(event.x_root, event.y_root)

    def update_selected_ip(self, event):
        """Update the IP entry when a row is selected"""
        selected = self.malicious_tree.selection()
        if selected:
            ip = self.malicious_tree.item(selected[0], "values")[0]
            self.ip_var.set(ip)
        else:
            self.ip_var.set("")

    def copy_selected_ip(self):
        """Copy the selected IP to clipboard"""
        ip = self.ip_var.get()
        if ip:
            self.master.clipboard_clear()
            self.master.clipboard_append(ip)
            self.update_output(f"Copied IP {ip} to clipboard")

    def mark_as_false_positive(self):
        """Mark the selected IP as a false positive"""
        ip = self.ip_var.get()
        if ip:
            self.false_positives.add(ip)
            self.save_false_positives()
            self.update_output(f"Marked {ip} as false positive")
            
            # Update the status in all tree views
            self._update_status_in_treeview(self.malicious_tree, ip, "False Positive")
            self._update_status_in_treeview(self.leaderboard_tree, ip, "False Positive")
            
            # Refresh views to ensure consistency
            self.refresh_malicious_list()
            self.refresh_leaderboard()

    def manage_false_positives(self):
        """Open dialog to manage false positives"""
        # Create a simple dialog to view and edit false positives
        dialog = tk.Toplevel(self.master)
        dialog.title("Manage False Positives")
        dialog.geometry("400x400")
        dialog.transient(self.master)
        dialog.grab_set()
        
        # Create listbox with scrollbar
        frame = ttk.Frame(dialog)
        frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ttk.Label(frame, text="False Positives:").pack(anchor="w")
        
        # Create listbox with scrollbar
        list_frame = ttk.Frame(frame)
        list_frame.pack(fill="both", expand=True, pady=5)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        
        false_positive_list = tk.Listbox(list_frame, yscrollcommand=scrollbar.set)
        false_positive_list.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=false_positive_list.yview)
        
        # Populate listbox
        for ip in sorted(self.false_positives):
            false_positive_list.insert(tk.END, ip)
        
        # Add buttons
        button_frame = ttk.Frame(frame)
        button_frame.pack(fill="x", pady=10)
        
        ttk.Button(button_frame, text="Remove Selected", 
                  command=lambda: self.remove_false_positive(false_positive_list)).pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Close", 
                  command=dialog.destroy).pack(side="right", padx=5)

    def remove_false_positive(self, listbox):
        """Remove the selected IP from false positives"""
        selected = listbox.curselection()
        if selected:
            ip = listbox.get(selected[0])
            self.false_positives.discard(ip)
            self.save_false_positives()
            self.update_output(f"Removed {ip} from false positives")
            
            # Update listbox
            listbox.delete(selected[0])
            
            # Refresh all views
            self.refresh_malicious_list()
            self.refresh_leaderboard()

    def refresh_malicious_list(self):
        """Refresh the malicious IPs list with fixed duplicate handling"""
        # Clear current items
        for item in self.malicious_tree.get_children():
            self.malicious_tree.delete(item)
        
        # Set a flag to indicate refresh is in progress
        self.malicious_refresh_in_progress = True
        
        # Queue a query to get alert data
        self.db_manager.queue_query(
            self._get_malicious_ip_data,
            callback=self._update_malicious_display
        )
        
        self.update_output("Refreshing malicious IP list...")

    def _get_malicious_ip_data(self):
        """Get data for malicious IP display with improved duplicate handling"""
        try:
            # Create a dedicated cursor for this operation
            cursor = self.db_manager.analysis_conn.cursor()
            
            # Get all alerts (not just ones with "Malicious" in the message)
            query = """
                SELECT ip_address, alert_message, rule_name, timestamp
                FROM alerts
                ORDER BY timestamp DESC
            """
            
            rows = cursor.execute(query).fetchall()
            
            if not rows:
                cursor.close()
                return []
            
            # Get local machine's IP addresses to exclude
            local_ips = self.get_local_ips()
            if local_ips is None:
                local_ips = set(['127.0.0.1', 'localhost'])
            
            # Use a dictionary to store results by IP to prevent duplicates
            result_dict = {}
            
            # Process each IP from alerts
            for row in rows:
                ip = row[0]
                alert = row[1]
                rule = row[2]
                timestamp = row[3]
                
                # Skip local IPs
                if ip in local_ips:
                    continue
                
                # Skip if we've already added this IP with the same rule (prevents duplicates)
                dict_key = f"{ip}:{rule}"
                if dict_key in result_dict:
                    continue
                
                # Determine alert type from the rule name
                if "VirusTotal" in rule:
                    alert_type = "VirusTotal"
                else:
                    alert_type = rule
                
                # Determine status
                status = "False Positive" if ip in self.false_positives else "Active"
                
                # Add to results dictionary
                result_dict[dict_key] = (ip, alert_type, status, timestamp)
                
                # Extract any additional IPs from the alert message
                additional_ips = self.extract_ips_from_message(alert)
                if additional_ips:
                    for add_ip in additional_ips:
                        # Skip local IPs
                        if add_ip in local_ips:
                            continue
                        
                        # Skip if already added with same rule
                        add_dict_key = f"{add_ip}:{rule}"
                        if add_dict_key in result_dict:
                            continue
                        
                        # Add to results with related alert info
                        add_status = "False Positive" if add_ip in self.false_positives else "Active"
                        result_dict[add_dict_key] = (add_ip, alert_type, add_status, timestamp)
            
            # Convert dictionary to list
            result_data = list(result_dict.values())
            
            # Close the dedicated cursor
            cursor.close()
            
            return result_data
                
        except Exception as e:
            logging.error(f"Error getting malicious IPs: {e}")
            return []

    def _update_malicious_display(self, data):
        """Update the malicious IP display with improved handling of UI updates"""
        try:
            # Add each item to the tree
            for ip, alert_type, status, timestamp in data:
                self.malicious_tree.insert("", "end", values=(ip, alert_type, status, timestamp))
            
            self.update_output(f"Found {len(data)} potentially malicious IPs from all alerts")
            
            # Reset the refresh flag
            self.malicious_refresh_in_progress = False
        except Exception as e:
            self.update_output(f"Error updating malicious IP display: {e}")
            self.malicious_refresh_in_progress = False

    def extract_ips_from_message(self, message):
        """Extract all IP addresses from an alert message"""
        # Regular expression to match IPv4 addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return re.findall(ip_pattern, message)

    def get_local_ips(self):
        """Get local machine IP addresses to exclude from alerts"""
        local_ips = set(['127.0.0.1', 'localhost'])
        
        try:
            # Get hostname and associated IPs
            import socket
            hostname = socket.gethostname()
            try:
                host_ips = socket.gethostbyname_ex(hostname)[2]
                local_ips.update(host_ips)
            except:
                pass  # Ignore errors in getting IP from hostname
            
            # Common local network ranges
            local_patterns = [
                r'192\.168\.',
                r'10\.',
                r'172\.(1[6-9]|2[0-9]|3[0-1])\.'
            ]
            
            # Check all interfaces
            if hasattr(self, 'capture_engine') and self.capture_engine:
                try:
                    for interface_info in self.capture_engine.get_interfaces():
                        if len(interface_info) >= 3:  # Make sure we have enough elements
                            name, iface_id, ip_addr = interface_info[0], interface_info[1], interface_info[2]
                            if ip_addr and ip_addr != "Unknown":
                                local_ips.add(ip_addr)
                except:
                    pass  # Ignore errors in getting IPs from interfaces
        except Exception as e:
            # If we can't determine local IPs, just use the defaults
            logger.error(f"Error getting local IPs: {e}")
                
        return local_ips

    def setup_database(self):
        """Set up the database manager"""
        try:
            # Create the database manager
            self.db_manager = DatabaseManager(self.app_root)
            
            logger.info("Database manager initialized")
            return True
            
        except Exception as e:
            logger.error(f"Database setup error: {e}")
            print(f"Database setup error: {e}")
            return False

    def refresh_alerts(self):
        """Queue a refresh for the alerts by IP display"""
        # Clear existing items
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # Queue the alerts query
        self.db_manager.queue_query(
            self.db_manager.get_alerts_by_ip,
            callback=self._update_alerts_display
        )
        
        self.update_output("Alerts refresh queued")

    def _update_alerts_display(self, rows):
        """Update the alerts treeview with the results"""
        try:
            # Add to tree view
            for row in rows:
                self.alerts_tree.insert("", "end", values=(row[0], row[1], row[2]))
            
            self.update_output(f"Found alerts for {len(rows)} IP addresses")
        except Exception as e:
            self.update_output(f"Error refreshing alerts: {e}")

    def show_ip_alerts(self, event):
        """Show alerts for the selected IP"""
        # Clear existing items
        for item in self.alerts_details_tree.get_children():
            self.alerts_details_tree.delete(item)
        
        # Get selected IP
        selected = self.alerts_tree.selection()
        if not selected:
            return
            
        ip = self.alerts_tree.item(selected[0], "values")[0]
        
        # Queue the IP alerts query
        self.db_manager.queue_query(
            self.db_manager.get_ip_alerts,
            callback=lambda rows: self._update_ip_alerts_display(rows, ip),
            ip_address=ip  # Changed to keyword argument
        )

    def _update_ip_alerts_display(self, rows, ip):
        """Update the IP alerts display with the results"""
        try:
            # Add to details tree
            for row in rows:
                self.alerts_details_tree.insert("", "end", values=(row[0], row[1], row[2]))
            
            self.update_output(f"Showing {len(rows)} alerts for IP: {ip}")
        except Exception as e:
            self.update_output(f"Error fetching alerts for {ip}: {e}")

    def apply_ip_filter(self):
        """Apply IP filter to alerts"""
        ip_filter = self.ip_filter.get().strip()
        if not ip_filter:
            self.update_output("No filter entered")
            return
            
        # Clear existing items
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        # Queue the filtered query
        self.db_manager.queue_query(
            self.db_manager.get_filtered_alerts_by_ip,
            callback=self._update_alerts_display,
            ip_filter=ip_filter  # Changed to keyword argument
        )
        
        self.update_output(f"Querying alerts matching filter: {ip_filter}")

    def clear_ip_filter(self):
        """Clear the IP filter and refresh alerts"""
        self.ip_filter.delete(0, tk.END)
        self.refresh_alerts()
        self.update_output("Filter cleared")

    def refresh_alerts_by_type(self):
        """Queue a refresh for the alerts by rule type display"""
        # Clear existing items
        for item in self.alert_types_tree.get_children():
            self.alert_types_tree.delete(item)
        
        # Queue the alerts query
        self.db_manager.queue_query(
            self.db_manager.get_alerts_by_rule_type,
            callback=self._update_alerts_by_type_display
        )
        
        self.update_output("Alerts by type refresh queued")

    def _update_alerts_by_type_display(self, rows):
        """Update the alerts by type treeview with the results"""
        try:
            if not rows:
                self.update_output("No alerts found in database")
                return
            
            # Add to tree view
            for row in rows:
                self.alert_types_tree.insert("", "end", values=(row[0], row[1], row[2]))
            
            self.update_output(f"Found alerts for {len(rows)} rule types")
        except Exception as e:
            self.update_output(f"Error refreshing alerts by type: {e}")

    def show_rule_alerts(self, event):
        """Show alerts for the selected rule"""
        # Clear existing items
        for item in self.rule_alerts_tree.get_children():
            self.rule_alerts_tree.delete(item)
        
        # Get selected rule
        selected = self.alert_types_tree.selection()
        if not selected:
            return
            
        rule_name = self.alert_types_tree.item(selected[0], "values")[0]
        
        # Queue the query
        self.db_manager.queue_query(
            self.db_manager.get_rule_alerts,
            callback=lambda rows: self._update_rule_alerts_display(rows, rule_name),
            rule_name=rule_name  # Changed to keyword argument
        )

    def _update_rule_alerts_display(self, rows, rule_name):
        """Update the rule alerts display with the results"""
        try:
            # Add to details tree
            for row in rows:
                self.rule_alerts_tree.insert("", "end", values=(row[0], row[1], row[2]))
            
            self.update_output(f"Showing {len(rows)} alerts for rule: {rule_name}")
        except Exception as e:
            self.update_output(f"Error fetching alerts for rule {rule_name}: {e}")

    def apply_rule_filter(self):
        """Apply rule filter to alerts"""
        rule_filter = self.rule_filter.get().strip()
        if not rule_filter:
            self.update_output("No filter entered")
            return
            
        # Clear existing items
        for item in self.alert_types_tree.get_children():
            self.alert_types_tree.delete(item)
        
        # Queue the filtered query
        self.db_manager.queue_query(
            self.db_manager.get_filtered_alerts_by_rule,
            callback=self._update_alerts_by_type_display,
            rule_filter=rule_filter  # Changed to keyword argument
        )
        
        self.update_output(f"Querying rules matching filter: {rule_filter}")

    def clear_rule_filter(self):
        """Clear the rule filter and refresh alerts"""
        self.rule_filter.delete(0, tk.END)
        self.refresh_alerts_by_type()
        self.update_output("Rule filter cleared")

    def clear_alerts(self):
        """Clear all alerts from the database"""
        if messagebox.askyesno("Clear Alerts", "Are you sure you want to clear all alerts?"):
            # Queue the clear operation
            self.db_manager.queue_query(
                self.db_manager.clear_alerts,
                callback=self._after_clear_alerts
            )
            
            # Clear the alerts dictionaries
            self.capture_engine.alerts_by_ip.clear()
            
            self.update_output("Alert clearing operation queued")

    def _after_clear_alerts(self, success):
        """Callback after clearing alerts"""
        if success:
            # Clear the tree views
            for item in self.alerts_tree.get_children():
                self.alerts_tree.delete(item)
                
            for item in self.alerts_details_tree.get_children():
                self.alerts_details_tree.delete(item)
            
            for item in self.alert_types_tree.get_children():
                self.alert_types_tree.delete(item)
                
            for item in self.rule_alerts_tree.get_children():
                self.rule_alerts_tree.delete(item)
            
            for item in self.malicious_tree.get_children():
                self.malicious_tree.delete(item)
                
            for item in self.leaderboard_tree.get_children():
                self.leaderboard_tree.delete(item)
                
            for item in self.leaderboard_details_tree.get_children():
                self.leaderboard_details_tree.delete(item)
            
            self.update_output("All alerts cleared")
        else:
            self.update_output("Error clearing alerts")

    def refresh_db_stats(self):
        """Queue a stats refresh request"""
        # Disable the refresh button to prevent multiple clicks
        refresh_button = None
        for widget in self.db_tab.winfo_children():
            if isinstance(widget, ttk.Frame):
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Button) and "Refresh" in str(child['text']):
                        refresh_button = child
                        refresh_button['state'] = 'disabled'
                        break
                if refresh_button:
                    break
        
        # Queue the database stats query
        self.db_manager.queue_query(
            self.db_manager.get_database_stats,
            callback=lambda stats: self._update_stats_display(stats, refresh_button)
        )
        
        # Queue the connections query
        self.db_manager.queue_query(
            self.db_manager.get_top_connections,
            callback=self._update_connections_display
        )
        self.update_output("Database statistics refresh queued")
        self.status_var.set("DB Stats Queued")

    def _update_stats_display(self, stats, refresh_button=None):
        """Update the database stats display with the results"""
        try:
            # Update the summary text widget
            self.db_summary_text.delete(1.0, tk.END)
            self.db_summary_text.insert(tk.END, f"Database File Size: {stats['db_file_size']:,} bytes\n")
            self.db_summary_text.insert(tk.END, f"Total Connections: {stats['conn_count']:,}\n")
            self.db_summary_text.insert(tk.END, f"Total Data Transferred: {stats['total_bytes']:,} bytes ({stats['total_bytes']/1024/1024:.2f} MB)\n")
            self.db_summary_text.insert(tk.END, f"Total Packets: {stats['total_packets']:,}\n")
            self.db_summary_text.insert(tk.END, f"Unique Source IPs: {stats['unique_src_ips']:,}\n")
            self.db_summary_text.insert(tk.END, f"Unique Destination IPs: {stats['unique_dst_ips']:,}\n")
            
            self.update_output("Database statistics updated")
            self.status_var.set("DB Stats Updated")
        except Exception as e:
            self.update_output(f"Error updating stats display: {e}")
        finally:
            # Re-enable the refresh button after a short delay
            if refresh_button:
                self.master.after(2000, lambda: refresh_button.config(state='normal'))

    def _update_connections_display(self, connections):
        """Update the connections treeview with the results"""
        try:
            # Clear existing items
            for item in self.connections_tree.get_children():
                self.connections_tree.delete(item)
            
            # Add rows to the treeview
            count = 0
            for row in connections:
                # Format byte size
                bytes_formatted = f"{row[2]:,}" if row[2] is not None else "0"
                # Insert row into treeview
                self.connections_tree.insert("", "end", values=(row[0], row[1], bytes_formatted, row[3], row[4]))
                count += 1
                
                # Process UI events every 50 rows to keep application responsive
                if count % 50 == 0:
                    self.master.update_idletasks()
            
            self.update_output(f"Displaying {len(connections)} connections")
        except Exception as e:
            self.update_output(f"Error updating connections display: {e}")

    def clear_output(self):
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.update_output("Output cleared")
        self.update_output(f"Logs are being saved to: {self.log_file}")

    def apply_settings(self):
        self.tray_app.notification_enabled = self.enable_notifications.get()
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

    def update_interface_list(self):
        for item in self.interface_listbox.get_children():
            self.interface_listbox.delete(item)
        
        # Only display interfaces according to the show_inactive_interfaces setting
        for name, iface_id, ip, desc in self.interface_info:
            # Skip interfaces with unknown IP if show_inactive is False
            if not self.show_inactive_interfaces.get() and (not ip or ip == "Unknown"):
                continue
            self.interface_listbox.insert("", "end", values=(name, ip))
        
        if self.interface_listbox.get_children():
            # Select the first item
            first_item = self.interface_listbox.get_children()[0]
            self.interface_listbox.selection_set(first_item)
            self.on_interface_selected(None)

    def refresh_interfaces(self):
        self.update_output("Refreshing interfaces...")
        self.status_var.set("Refreshing...")
        threading.Thread(target=self._refresh_interfaces_thread, daemon=True).start()

    def _refresh_interfaces_thread(self):
        self.interface_info = self.capture_engine.get_interfaces()
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
        
        # Start the capture engine
        self.capture_engine.start_capture(interface, self.batch_size.get(), self.sliding_window_size.get())

    def stop_capture(self):
        self.running = False
        self.capture_engine.stop_capture()
        
        self.start_button.config(text="Start Capture")
        self.refresh_button.config(state="normal")
        self.update_output("Stopping capture...")
        self.status_var.set("Stopped")

    def analyze_traffic(self):
        """Analyze traffic with the loaded rules and show alerts with controlled update frequency"""
        # Get a dedicated cursor for rules to use (from analysis database)
        analysis_cursor = self.db_manager.get_cursor_for_rules()
        
        # Track time since last UI updates
        current_time = time.time()
        if not hasattr(self, 'last_alerts_update_time'):
            self.last_alerts_update_time = 0
        
        # Define minimum time between updates (in seconds)
        min_update_interval = 15  # Update alerts tabs at most every 15 seconds
        
        alerts = []
        try:
            for rule in self.rules:
                if rule.enabled:
                    try:
                        # Run the rule with the analysis database cursor (read-only)
                        rule_alerts = rule.analyze(analysis_cursor)
                        
                        if rule_alerts:
                            for alert in rule_alerts:
                                # First, identify which IP is malicious based on the alert message
                                malicious_ip = None
                                
                                # Extract IPs from the alert message (source and destination)
                                ip_matches = re.findall(r'(\d+\.\d+\.\d+\.\d+)', alert)
                                
                                if len(ip_matches) >= 2:
                                    # If we have at least two IPs (typical src->dst format)
                                    src_ip, dst_ip = ip_matches[0], ip_matches[1]
                                    
                                    # Check the message context to determine which IP is malicious
                                    if "Malicious IP detected in connection from" in alert:
                                        # The destination IP is malicious in this case
                                        malicious_ip = dst_ip
                                    elif "from Malicious IP" in alert or "from suspicious IP" in alert:
                                        # The source IP is malicious
                                        malicious_ip = src_ip
                                    elif "VirusTotal" in alert:
                                        # In VirusTotal alerts, typically the destination is flagged
                                        malicious_ip = dst_ip
                                    else:
                                        # Default: use first IP in the message
                                        malicious_ip = ip_matches[0]
                                elif len(ip_matches) == 1:
                                    # Only one IP found, use it
                                    malicious_ip = ip_matches[0]
                                
                                if malicious_ip:
                                    # Skip if this IP is marked as a false positive
                                    if malicious_ip in self.false_positives:
                                        continue
                                    
                                    # Use in-memory check first (for efficiency)
                                    if alert not in self.capture_engine.alerts_by_ip[malicious_ip]:
                                        # Add to in-memory collection
                                        self.capture_engine.alerts_by_ip[malicious_ip].add(alert)
                                        
                                        # Queue the alert for processing
                                        self.db_manager.queue_alert(malicious_ip, alert, rule.name)
                                        
                                        # Only show notification for malicious traffic
                                        if 'malicious' in alert.lower() or 'virustotal' in alert.lower():
                                            self.tray_app.show_alert_notification(alert, rule.name, malicious_ip)
                                        
                                alerts.append(alert)
                    except Exception as e:
                        self.update_output(f"Rule {rule.name} error: {e}")
        finally:
            # Make sure to close the cursor when done
            analysis_cursor.close()
        
        if alerts:
            for alert in alerts:
                self.update_output(alert)
            
            # Check if it's time to update the alerts tabs (every min_update_interval seconds)
            time_since_last_update = current_time - self.last_alerts_update_time
            if time_since_last_update >= min_update_interval:
                # Reset the timer
                self.last_alerts_update_time = current_time
                
                # Queue UI updates through database manager
                self.db_manager.queue_query(
                    self.db_manager.get_alerts_by_ip,
                    callback=self._update_alerts_display
                )
                
                self.db_manager.queue_query(
                    self.db_manager.get_alerts_by_rule_type,
                    callback=self._update_alerts_by_type_display
                )
                
                # Don't refresh malicious list if it's already refreshing
                if not hasattr(self, 'malicious_refresh_in_progress') or not self.malicious_refresh_in_progress:
                    # Queue malicious list refresh
                    self.master.after(0, self.refresh_malicious_list)
                    
                # Also refresh the leaderboard
                if not hasattr(self, 'leaderboard_refresh_in_progress') or not self.leaderboard_refresh_in_progress:
                    self.master.after(0, self.refresh_leaderboard)
                
                self.update_output("Alert displays updated (next update in ~15 seconds)")
        else:
            self.update_output("No anomalies in this batch")

        # Periodically refresh the database stats tab (at most every 30 seconds)
        if not hasattr(self, 'last_stats_update_time'):
            self.last_stats_update_time = 0
        
        stats_update_interval = 30  # Update stats at most every 30 seconds
        time_since_stats_update = current_time - self.last_stats_update_time
        
        if time_since_stats_update >= stats_update_interval:
            # Reset the timer
            self.last_stats_update_time = current_time
            
            self.db_manager.queue_query(
                self.db_manager.get_database_stats,
                callback=lambda stats: self._update_stats_display(stats, None)
            )
            
            self.db_manager.queue_query(
                self.db_manager.get_top_connections,
                callback=self._update_connections_display
            )
            
            self.update_output("Database statistics updated (next update in ~30 seconds)")

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
            rules_dir = os.path.join(self.app_root, "rules")
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
        self.rule_loader = RuleLoader(self.db_manager)
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
        selected = self