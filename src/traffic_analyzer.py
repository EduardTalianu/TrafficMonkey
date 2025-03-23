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

# Required for system tray and notifications
import pystray
from PIL import Image, ImageDraw
from plyer import notification

# Import the traffic capture module - this contains all packet parsing logic
from traffic_capture import TrafficCaptureEngine

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
            self.app.master.destroy()
            sys.exit(0)
    
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
        self.false_positives_file = os.path.join(self.app_root, "rules", "false_positives.txt")
        self.false_positives = self.load_false_positives()

        # Database Setup - Do this BEFORE creating any tabs that need the database
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
        
        # Initialize TrafficCaptureEngine
        self.capture_engine = TrafficCaptureEngine(self)
        
        # Load Rules
        self.rule_loader = RuleLoader()
        self.rules = self.rule_loader.rules
        self.selected_rule = None
        self.param_vars = {}
        self.update_rules_list()
        
        # Start system tray icon
        self.tray_app.run()
        
        # Initialize interfaces after UI is set up
        self.refresh_interfaces()

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
        
        self.alerts_notebook.add(self.alerts_by_ip_tab, text="By IP Address")
        self.alerts_notebook.add(self.alerts_by_alert_tab, text="By Alert Type")
        self.alerts_notebook.add(self.alerts_malicious_tab, text="Possible Malicious")
        
        # Create the IP-focused tab
        self.create_alerts_by_ip_subtab()
        
        # Create the Alert-focused tab
        self.create_alerts_by_alert_subtab()
        
        # Create the Possible Malicious tab
        self.create_alerts_malicious_subtab()

    def create_alerts_by_ip_subtab(self):
        """Create the IP-focused alerts tab"""
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
        """Create the Possible Malicious tab"""
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
            
            # Update the status in the tree
            selected = self.malicious_tree.selection()
            if selected:
                values = list(self.malicious_tree.item(selected[0], "values"))
                values[2] = "False Positive"
                self.malicious_tree.item(selected[0], values=values)

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
            
            # Refresh malicious list
            self.refresh_malicious_list()

    def refresh_malicious_list(self):
        """Refresh the malicious IPs list"""
        # Clear current items
        for item in self.malicious_tree.get_children():
            self.malicious_tree.delete(item)
        
        try:
            # Get alerts with "Malicious" in the message
            query = """
                SELECT ip_address, alert_message, rule_name, timestamp
                FROM alerts
                WHERE alert_message LIKE '%Malicious%' OR alert_message LIKE '%VirusTotal%'
                ORDER BY timestamp DESC
            """
            
            rows = self.db_cursor.execute(query).fetchall()
            
            if not rows:
                self.update_output("No malicious activity detected")
                return
            
            # Add each malicious IP to the tree
            for row in rows:
                ip = row[0]
                alert = row[1]
                rule = row[2]
                timestamp = row[3]
                
                # Determine alert type from the message
                if "VirusTotal" in alert:
                    alert_type = "VirusTotal"
                elif "Malicious" in alert:
                    alert_type = "Malicious Traffic"
                else:
                    alert_type = rule
                
                # Determine status
                status = "False Positive" if ip in self.false_positives else "Active"
                
                # Add to tree
                self.malicious_tree.insert("", "end", values=(ip, alert_type, status, timestamp))
            
            self.update_output(f"Found {len(rows)} potentially malicious alerts")
            
        except Exception as e:
            self.update_output(f"Error refreshing malicious list: {e}")

    def setup_database(self):
        """Set up the database connection and create tables"""
        try:
            # Close existing connection if any
            try:
                if hasattr(self, 'db_conn'):
                    self.db_conn.close()
            except:
                pass
                
            # Create the db directory if it doesn't exist
            db_dir = os.path.join(self.app_root, "db")
            os.makedirs(db_dir, exist_ok=True)
            
            # Create a new connection with the absolute path to ensure it's in the right place
            db_path = os.path.join(db_dir, "traffic_stats.db")
            self.db_conn = sqlite3.connect(db_path, check_same_thread=False)
            self.db_cursor = self.db_conn.cursor()
            
            # Enable WAL mode for better performance and reliability
            self.db_cursor.execute("PRAGMA journal_mode=WAL")
            self.db_cursor.execute("PRAGMA synchronous=NORMAL")
            
            # Create tables with enhanced schema including port information
            self.db_cursor.execute("""
                CREATE TABLE IF NOT EXISTS connections (
                    connection_key TEXT PRIMARY KEY,
                    src_ip TEXT,
                    dst_ip TEXT,
                    src_port INTEGER DEFAULT NULL,
                    dst_port INTEGER DEFAULT NULL,
                    total_bytes INTEGER DEFAULT 0,
                    packet_count INTEGER DEFAULT 0,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Check if required columns exist and add them if they don't
            existing_columns = [row[1] for row in self.db_cursor.execute("PRAGMA table_info(connections)").fetchall()]
            
            # Add missing port columns if they don't exist
            if "src_port" not in existing_columns:
                self.db_cursor.execute("ALTER TABLE connections ADD COLUMN src_port INTEGER DEFAULT NULL")
                logger.info("Added missing column: src_port")
                
            if "dst_port" not in existing_columns:
                self.db_cursor.execute("ALTER TABLE connections ADD COLUMN dst_port INTEGER DEFAULT NULL")
                logger.info("Added missing column: dst_port")
            
            # Add vt_result column if it doesn't exist
            if "vt_result" not in existing_columns:
                self.db_cursor.execute("ALTER TABLE connections ADD COLUMN vt_result TEXT DEFAULT 'unknown'")
                logger.info("Added missing column: vt_result")
                
            # Add is_rdp_client column if it doesn't exist
            if "is_rdp_client" not in existing_columns:
                self.db_cursor.execute("ALTER TABLE connections ADD COLUMN is_rdp_client BOOLEAN DEFAULT 0")
                logger.info("Added missing column: is_rdp_client")
            
            # Create indices for faster lookups
            self.db_cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_connections_ips 
                ON connections(src_ip, dst_ip)
            """)
            
            self.db_cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_connections_ports 
                ON connections(src_port, dst_port)
            """)
            
            # Create alerts table if it doesn't exist
            self.db_cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT,
                    alert_message TEXT,
                    rule_name TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            self.db_cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_ip 
                ON alerts(ip_address)
            """)
            
            self.db_cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_rule
                ON alerts(rule_name)
            """)
            
            self.db_conn.commit()
            logger.info("Database setup complete")
            return True
            
        except Exception as e:
            logger.error(f"Database setup error: {e}")
            print(f"Database setup error: {e}")
            return False

    def refresh_alerts_by_type(self):
        """Refresh the alerts by rule type display"""
        # Clear existing items
        for item in self.alert_types_tree.get_children():
            self.alert_types_tree.delete(item)
        
        try:
            # Get unique rules with alerts
            query = """
                SELECT rule_name, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM alerts 
                GROUP BY rule_name
                ORDER BY last_seen DESC
            """
            
            rows = self.db_cursor.execute(query).fetchall()
            
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
        
        try:
            # Get alerts for the selected rule
            query = """
                SELECT ip_address, alert_message, timestamp
                FROM alerts
                WHERE rule_name = ?
                ORDER BY timestamp DESC
            """
            
            rows = self.db_cursor.execute(query, (rule_name,)).fetchall()
            
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
        
        try:
            # Get unique rules with alerts matching filter
            query = """
                SELECT rule_name, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM alerts 
                WHERE rule_name LIKE ?
                GROUP BY rule_name
                ORDER BY last_seen DESC
            """
            
            # Add wildcards to make it more user-friendly
            filter_pattern = f"%{rule_filter}%"
            rows = self.db_cursor.execute(query, (filter_pattern,)).fetchall()
            
            if not rows:
                self.update_output(f"No alerts found matching filter: {rule_filter}")
                return
            
            # Add to tree view
            for row in rows:
                self.alert_types_tree.insert("", "end", values=(row[0], row[1], row[2]))
            
            self.update_output(f"Found {len(rows)} rule types matching filter: {rule_filter}")
            
        except Exception as e:
            self.update_output(f"Error applying filter: {e}")

    def clear_rule_filter(self):
        """Clear the rule filter and refresh alerts"""
        self.rule_filter.delete(0, tk.END)
        self.refresh_alerts_by_type()
        self.update_output("Rule filter cleared")

    def refresh_alerts(self):
        """Refresh the alerts by IP display"""
        # Clear existing items
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)
        
        try:
            # Get unique IPs with alerts
            query = """
                SELECT ip_address, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM alerts 
                GROUP BY ip_address
                ORDER BY last_seen DESC
            """
            
            rows = self.db_cursor.execute(query).fetchall()
            
            if not rows:
                self.update_output("No alerts found in database")
                return
            
            # Add to tree view
            for row in rows:
                self.alerts_tree.insert("", "end", values=(row[0], row[1], row[2]))
            
            self.update_output(f"Found alerts for {len(rows)} IP addresses")
            
            # Also refresh the malicious IPs list
            self.refresh_malicious_list()
            
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
        
        try:
            # Get alerts for the selected IP
            query = """
                SELECT alert_message, rule_name, timestamp
                FROM alerts
                WHERE ip_address = ?
                ORDER BY timestamp DESC
            """
            
            rows = self.db_cursor.execute(query, (ip,)).fetchall()
            
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
        
        try:
            # Get unique IPs with alerts matching filter
            query = """
                SELECT ip_address, COUNT(*) as alert_count, MAX(timestamp) as last_seen
                FROM alerts 
                WHERE ip_address LIKE ?
                GROUP BY ip_address
                ORDER BY last_seen DESC
            """
            
            # Add wildcards to make it more user-friendly
            filter_pattern = f"%{ip_filter}%"
            rows = self.db_cursor.execute(query, (filter_pattern,)).fetchall()
            
            if not rows:
                self.update_output(f"No alerts found matching filter: {ip_filter}")
                return
            
            # Add to tree view
            for row in rows:
                self.alerts_tree.insert("", "end", values=(row[0], row[1], row[2]))
            
            self.update_output(f"Found {len(rows)} IP addresses matching filter: {ip_filter}")
            
        except Exception as e:
            self.update_output(f"Error applying filter: {e}")

    def clear_ip_filter(self):
        """Clear the IP filter and refresh alerts"""
        self.ip_filter.delete(0, tk.END)
        self.refresh_alerts()
        self.update_output("Filter cleared")

    def clear_alerts(self):
        """Clear all alerts from the database"""
        if messagebox.askyesno("Clear Alerts", "Are you sure you want to clear all alerts?"):
            try:
                self.db_cursor.execute("DELETE FROM alerts")
                self.db_conn.commit()
                
                # Clear the alerts dictionaries
                self.capture_engine.alerts_by_ip.clear()
                
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
                
                self.update_output("All alerts cleared")
            except Exception as e:
                self.update_output(f"Error clearing alerts: {e}")

    def refresh_db_stats(self):
        """Refresh all database statistics"""
        try:
            # Get database path
            db_dir = os.path.join(self.app_root, "db")
            db_path = os.path.join(db_dir, "traffic_stats.db")
            
            # Get database summary statistics
            db_file_size = os.path.getsize(db_path) if os.path.exists(db_path) else 0
            
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
        """Analyze traffic with the loaded rules and show alerts"""
        alerts = []
        for rule in self.rules:
            if rule.enabled:
                try:
                    rule_alerts = rule.analyze(self.db_cursor)
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
                                
                                # Store alerts by IP and save to database
                                if alert not in self.capture_engine.alerts_by_ip[malicious_ip]:
                                    self.capture_engine.alerts_by_ip[malicious_ip].add(alert)
                                    
                                    # Save alert to database
                                    try:
                                        self.db_cursor.execute("""
                                            INSERT INTO alerts (ip_address, alert_message, rule_name)
                                            VALUES (?, ?, ?)
                                        """, (malicious_ip, alert, rule.name))
                                        self.db_conn.commit()
                                        
                                        # Only show notification for malicious traffic
                                        if 'malicious' in alert.lower() or 'virustotal' in alert.lower():
                                            self.tray_app.show_alert_notification(alert, rule.name, malicious_ip)
                                    except Exception as e:
                                        self.update_output(f"Error saving alert to database: {e}")
                            
                            alerts.append(alert)
                except Exception as e:
                    self.update_output(f"Rule {rule.name} error: {e}")
        
        if alerts:
            for alert in alerts:
                self.update_output(alert)
            
            # Update alerts tab if there are new alerts
            if random.random() < 0.5:  # ~50% chance to refresh, to avoid too frequent updates
                self.master.after(0, self.refresh_alerts)
                self.master.after(0, self.refresh_alerts_by_type)
                self.master.after(0, self.refresh_malicious_list)
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