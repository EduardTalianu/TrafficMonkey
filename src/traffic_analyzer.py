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
from collections import defaultdict
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

# Refactored System Tray implementation
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

# Unified IP and Context Menu Management
class IPManager:
    """Manages IP operations and context menus across the application"""
    
    def __init__(self, app):
        self.app = app
        self.master = app.master
        self.false_positives = app.false_positives
        self.false_positives_file = app.false_positives_file
    
    def create_context_menu(self, tree_widget, ip_var=None, show_details_callback=None):
        """Create a unified context menu for IP-based operations"""
        # Create the menu
        menu = tk.Menu(self.master, tearoff=0)
        
        # Add standard commands
        menu.add_command(label="Copy IP", 
                        command=lambda: self.copy_ip_to_clipboard(ip_var.get() if ip_var else self._get_selected_ip(tree_widget)))
        menu.add_command(label="Mark as False Positive", 
                        command=lambda: self.mark_as_false_positive(ip_var.get() if ip_var else self._get_selected_ip(tree_widget)))
        
        # Add Show Details if callback provided
        if show_details_callback:
            menu.add_command(label="Show Details", command=show_details_callback)
        
        # Bind the menu to the tree widget
        tree_widget.bind("<Button-3>", lambda event: self._show_context_menu(event, tree_widget, menu, ip_var))
        
        return menu
    
    def _show_context_menu(self, event, tree_widget, menu, ip_var=None):
        """Show context menu and select the item under cursor"""
        # Select the item under cursor
        item = tree_widget.identify_row(event.y)
        if item:
            tree_widget.selection_set(item)
            
            # Update IP variable if provided
            if ip_var:
                selected_ip = self._get_selected_ip(tree_widget)
                ip_var.set(selected_ip)
            
            # Show the menu
            menu.post(event.x_root, event.y_root)
    
    def _get_selected_ip(self, tree_widget):
        """Get the IP address from the selected tree item"""
        selected = tree_widget.selection()
        if selected:
            # Assume IP is always the first column
            return tree_widget.item(selected[0], "values")[0]
        return ""
    
    def copy_ip_to_clipboard(self, ip):
        """Copy an IP address to clipboard"""
        if ip:
            self.master.clipboard_clear()
            self.master.clipboard_append(ip)
            self.app.update_output(f"Copied IP {ip} to clipboard")
    
    def mark_as_false_positive(self, ip):
        """Mark an IP as a false positive"""
        if ip:
            # Add to false positives set
            self.false_positives.add(ip)
            self.save_false_positives()
            self.app.update_output(f"Marked {ip} as false positive")
            
            # Update status in all tree views
            self._update_status_in_all_trees(ip, "False Positive")
            
            # Refresh relevant views
            self.app.refresh_alerts()
            self.app.refresh_malicious_list()
            self.app.refresh_leaderboard()
    
    def _update_status_in_all_trees(self, ip, new_status):
        """Update IP status in all tree views"""
        trees_to_update = [
            self.app.malicious_tree,
            self.app.leaderboard_tree
        ]
        
        for tree in trees_to_update:
            self._update_status_in_treeview(tree, ip, new_status)
    
    def _update_status_in_treeview(self, tree, ip, new_status):
        """Update the status field for an IP in a treeview"""
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
    
    def save_false_positives(self):
        """Save false positives to file"""
        try:
            with open(self.false_positives_file, 'w') as f:
                f.write("# False positives list - one IP per line\n")
                f.write("# Generated by Network Traffic Analyzer\n")
                f.write("# Last updated: " + time.strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
                for ip in sorted(self.false_positives):
                    f.write(ip + "\n")
            self.app.update_output(f"Saved {len(self.false_positives)} false positives to {self.false_positives_file}")
        except Exception as e:
            self.app.update_output(f"Error saving false positives: {e}")

# TreeView Manager for standardized tree operations
class TreeViewManager:
    """Manages operations on TreeView widgets"""
    
    @staticmethod
    def clear_tree(tree):
        """Clear all items from a tree"""
        for item in tree.get_children():
            tree.delete(item)
    
    @staticmethod
    def populate_tree(tree, data, columns=None, batch_size=50):
        """Populate a tree with data rows in batches to avoid UI freezing"""
        if not data:
            return
            
        # Process in batches
        for i in range(0, len(data), batch_size):
            batch = data[i:i+batch_size]
            # Process the current batch
            if columns is None:
                for row in batch:
                    tree.insert("", "end", values=row)
            else:
                for row in batch:
                    values = [row[col] for col in columns]
                    tree.insert("", "end", values=values)
            
            # Update the UI after each batch
            tree.update_idletasks()
    
    @staticmethod
    def get_selected_value(tree, column_index=0):
        """Get a value from the selected row at specified column index"""
        selected = tree.selection()
        if selected:
            return tree.item(selected[0], "values")[column_index]
        return None

# Unified tab creation and management
class TabFactory:
    """Factory for creating standardized tab components"""
    
    def __init__(self, app):
        self.app = app
        self.master = app.master
    
    def create_tree_with_scrollbar(self, parent, columns, headings, widths=None, height=10):
        """Create a TreeView with scrollbar"""
        frame = ttk.Frame(parent)
        frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create scrollbar
        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side="right", fill="y")
        
        # Create TreeView
        tree = ttk.Treeview(frame,
                           columns=columns,
                           show="headings",
                           height=height,
                           yscrollcommand=scrollbar.set)
        tree.pack(fill="both", expand=True)
        
        # Configure scrollbar
        scrollbar.config(command=tree.yview)
        
        # Set headings
        for i, col in enumerate(columns):
            tree.heading(col, text=headings[i])
            
            # Set column width if provided
            if widths and i < len(widths):
                tree.column(col, width=widths[i])
        
        return tree, frame
    
    def create_filter_frame(self, parent, label_text, apply_callback, clear_callback):
        """Create a standardized filter frame"""
        filter_frame = ttk.Frame(parent)
        filter_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(filter_frame, text=label_text).pack(side="left", padx=5)
        filter_var = ttk.Entry(filter_frame, width=20)
        filter_var.pack(side="left", padx=5)
        
        ttk.Button(filter_frame, text="Apply Filter", 
                  command=lambda: apply_callback(filter_var.get())).pack(side="left", padx=5)
        ttk.Button(filter_frame, text="Clear Filter", 
                  command=lambda: (filter_var.delete(0, tk.END), clear_callback())).pack(side="left", padx=5)
        
        return filter_var
    
    def create_control_buttons(self, parent, buttons):
        """Create a standardized control button frame"""
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        for button in buttons:
            ttk.Button(control_frame, text=button["text"], 
                      command=button["command"]).pack(side="left", padx=5)
        
        return control_frame

# The main application class with refactored implementation
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

        # Create Managers and Factories
        self.ip_manager = IPManager(self)
        self.tree_manager = TreeViewManager()
        self.tab_factory = TabFactory(self)

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
        self.last_alerts_update_time = 0
        self.last_stats_update_time = 0
        
        #Data caching

        self.data_cache = {}
        self.cache_expiry = {}
        self.cache_lifetime = 60  # seconds

    def get_cached_data(self, cache_key, query_func, *args, force_refresh=False, **kwargs):
        """Get data from cache or fetch from database if expired"""
        current_time = time.time()
        
        if not force_refresh and cache_key in self.data_cache:
            if current_time < self.cache_expiry.get(cache_key, 0):
                return self.data_cache[cache_key]
        
        # Fetch fresh data
        data = query_func(*args, **kwargs)

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
        """Save false positives to file using the IPManager"""
        self.ip_manager.save_false_positives()

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
        control_frame = self.tab_factory.create_control_buttons(
            self.db_tab,
            [{"text": "Refresh Database Stats", "command": self.refresh_db_stats}]
        )
        
        # Database summary information
        summary_frame = ttk.LabelFrame(self.db_tab, text="Database Summary")
        summary_frame.pack(fill="x", padx=10, pady=5)
        
        # Summary statistics text
        self.db_summary_text = tk.Text(summary_frame, height=6, wrap=tk.WORD)
        self.db_summary_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create a simple connection list
        connections_frame = ttk.LabelFrame(self.db_tab, text="Top Connections")
        connections_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create connections treeview
        self.connections_tree, _ = self.tab_factory.create_tree_with_scrollbar(
            connections_frame,
            columns=("src_ip", "dst_ip", "bytes", "packets", "timestamp"),
            headings=["Source IP", "Destination IP", "Bytes", "Packets", "Last Seen"],
            widths=[150, 150, 100, 70, 150],
            height=15
        )
        
        # Initial message
        self.db_summary_text.insert(tk.END, "Click 'Refresh Database Stats' to load statistics")

    def create_alerts_tab(self):
        """Create alerts tab with subtabs using unified components"""
        # Create inner notebook for subtabs
        self.alerts_notebook = ttk.Notebook(self.alerts_tab)
        self.alerts_notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Create the subtabs
        self.alerts_by_ip_tab = ttk.Frame(self.alerts_notebook)
        self.alerts_by_alert_tab = ttk.Frame(self.alerts_notebook)
        self.alerts_malicious_tab = ttk.Frame(self.alerts_notebook)
        self.alerts_leaderboard_tab = ttk.Frame(self.alerts_notebook)
        
        self.alerts_notebook.add(self.alerts_by_ip_tab, text="By IP Address")
        self.alerts_notebook.add(self.alerts_by_alert_tab, text="By Alert Type")
        self.alerts_notebook.add(self.alerts_malicious_tab, text="Possible Malicious")
        self.alerts_notebook.add(self.alerts_leaderboard_tab, text="Threat Leaderboard")
        
        # Create each subtab
        self.create_alerts_by_ip_subtab()
        self.create_alerts_by_alert_subtab()
        self.create_alerts_malicious_subtab()
        self.create_alerts_leaderboard_subtab()

        # Bind to tab selection event to load data only for visible tab
        self.alerts_notebook.bind("<<NotebookTabChanged>>", self.on_alert_tab_selected)

    def on_alert_tab_selected(self, event):
        """Load data for the selected tab"""
        selected_tab = self.alerts_notebook.select()
        tab_id = self.alerts_notebook.index(selected_tab)
        
        if tab_id == 0:  # By IP Address tab
            self.refresh_alerts()
        elif tab_id == 1:  # By Alert Type tab
            self.refresh_alerts_by_type()
        elif tab_id == 2:  # Malicious tab
            self.refresh_malicious_list()
        elif tab_id == 3:  # Leaderboard tab
            self.refresh_leaderboard()

    def create_alerts_by_ip_subtab(self):
        """Create the IP-focused alerts tab with unified components"""
        # Control buttons frame
        self.tab_factory.create_control_buttons(
            self.alerts_by_ip_tab,
            [
                {"text": "Refresh Alerts", "command": self.refresh_alerts},
                {"text": "Clear All Alerts", "command": self.clear_alerts}
            ]
        )
        
        # IP filter frame
        self.ip_filter = self.tab_factory.create_filter_frame(
            self.alerts_by_ip_tab,
            "Filter by IP:",
            self.apply_ip_filter,
            self.refresh_alerts
        )
        
        # Alerts treeview
        self.alerts_tree, _ = self.tab_factory.create_tree_with_scrollbar(
            self.alerts_by_ip_tab,
            columns=("ip", "alert_count", "last_seen"),
            headings=["IP Address", "Alert Count", "Last Detected"],
            widths=[150, 100, 150],
            height=10
        )
        
        # Create alerts details list
        details_frame = ttk.LabelFrame(self.alerts_by_ip_tab, text="Alert Details")
        details_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.alerts_details_tree, _ = self.tab_factory.create_tree_with_scrollbar(
            details_frame,
            columns=("alert", "rule", "timestamp"),
            headings=["Alert Message", "Rule Name", "Timestamp"],
            widths=[300, 150, 150],
            height=10
        )
        
        # Info and button frame for selected IP
        info_frame = ttk.Frame(self.alerts_by_ip_tab)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.alerts_ip_var = tk.StringVar()
        ttk.Label(info_frame, text="Selected IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(info_frame, textvariable=self.alerts_ip_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        button_frame = ttk.Frame(info_frame)
        button_frame.grid(row=0, column=2, sticky="e", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Copy IP", 
                  command=lambda: self.ip_manager.copy_ip_to_clipboard(self.alerts_ip_var.get())
                 ).pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Mark as False Positive", 
                  command=lambda: self.ip_manager.mark_as_false_positive(self.alerts_ip_var.get())
                 ).pack(side="left", padx=5)
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)
        
        # Bind event to show alerts for selected IP
        self.alerts_tree.bind("<<TreeviewSelect>>", self.show_ip_alerts)
        
        # Create context menu
        self.ip_manager.create_context_menu(
            self.alerts_tree, 
            self.alerts_ip_var, 
            lambda: self.show_ip_alerts(None)
        )

    def create_alerts_by_alert_subtab(self):
        """Create the Alert-focused tab with unified components"""
        # Control buttons
        self.tab_factory.create_control_buttons(
            self.alerts_by_alert_tab,
            [{"text": "Refresh Alerts", "command": self.refresh_alerts_by_type}]
        )
        
        # Rule filter
        self.rule_filter = self.tab_factory.create_filter_frame(
            self.alerts_by_alert_tab,
            "Filter by Rule:",
            self.apply_rule_filter,
            self.refresh_alerts_by_type
        )
        
        # Alert types treeview
        self.alert_types_tree, _ = self.tab_factory.create_tree_with_scrollbar(
            self.alerts_by_alert_tab,
            columns=("rule", "alert_count", "last_seen"),
            headings=["Rule Name", "Alert Count", "Last Detected"],
            widths=[200, 100, 150],
            height=10
        )
        
        # Alert instances frame
        instances_frame = ttk.LabelFrame(self.alerts_by_alert_tab, text="Alert Instances")
        instances_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create rule alerts instances list
        self.rule_alerts_tree, _ = self.tab_factory.create_tree_with_scrollbar(
            instances_frame,
            columns=("ip", "alert", "timestamp"),
            headings=["IP Address", "Alert Message", "Timestamp"],
            widths=[150, 300, 150],
            height=10
        )
        
        # Bind event to show alerts for selected rule
        self.alert_types_tree.bind("<<TreeviewSelect>>", self.show_rule_alerts)

    def create_alerts_malicious_subtab(self):
        """Create the Possible Malicious tab with unified components"""
        # Control buttons
        self.tab_factory.create_control_buttons(
            self.alerts_malicious_tab,
            [
                {"text": "Refresh List", "command": self.refresh_malicious_list},
                {"text": "Manage False Positives", "command": self.manage_false_positives}
            ]
        )
        
        # Malicious IP treeview
        self.malicious_tree, _ = self.tab_factory.create_tree_with_scrollbar(
            self.alerts_malicious_tab,
            columns=("ip", "alert_type", "status", "timestamp"),
            headings=["IP Address", "Alert Type", "Status", "Detected"],
            widths=[150, 150, 100, 150],
            height=15
        )
        
        # Info and button frame
        info_frame = ttk.Frame(self.alerts_malicious_tab)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.ip_var = tk.StringVar()
        ttk.Label(info_frame, text="Selected IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(info_frame, textvariable=self.ip_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        button_frame = ttk.Frame(info_frame)
        button_frame.grid(row=0, column=2, sticky="e", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Copy IP", 
                  command=lambda: self.ip_manager.copy_ip_to_clipboard(self.ip_var.get())
                 ).pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Mark as False Positive", 
                  command=lambda: self.ip_manager.mark_as_false_positive(self.ip_var.get())
                 ).pack(side="left", padx=5)
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)
        
        # Create context menu
        self.ip_manager.create_context_menu(self.malicious_tree, self.ip_var)
        
        # Bind selection event to update IP variable
        self.malicious_tree.bind("<<TreeviewSelect>>", lambda event: self.update_selected_ip(self.malicious_tree, self.ip_var))

    def create_alerts_leaderboard_subtab(self):
        """Create the Threat Leaderboard tab with unified components"""
        # Control buttons
        self.tab_factory.create_control_buttons(
            self.alerts_leaderboard_tab,
            [
                {"text": "Refresh Leaderboard", "command": self.refresh_leaderboard},
                {"text": "Manage False Positives", "command": self.manage_false_positives}
            ]
        )
        
        # Leaderboard treeview
        self.leaderboard_tree, _ = self.tab_factory.create_tree_with_scrollbar(
            self.alerts_leaderboard_tab,
            columns=("ip", "distinct_rules", "total_alerts", "status"),
            headings=["IP Address", "Distinct Alert Types", "Total Alerts", "Status"],
            widths=[150, 150, 100, 100],
            height=15
        )
        
        # Detail frame for showing triggered rules
        details_frame = ttk.LabelFrame(self.alerts_leaderboard_tab, text="Triggered Rules")
        details_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create treeview for rule details
        self.leaderboard_details_tree, _ = self.tab_factory.create_tree_with_scrollbar(
            details_frame,
            columns=("rule", "count", "last_alert"),
            headings=["Rule Name", "Alert Count", "Last Alert"],
            widths=[250, 100, 150],
            height=10
        )
        
        # Info and button frame
        info_frame = ttk.Frame(self.alerts_leaderboard_tab)
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.leaderboard_ip_var = tk.StringVar()
        ttk.Label(info_frame, text="Selected IP:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Entry(info_frame, textvariable=self.leaderboard_ip_var, width=30).grid(row=0, column=1, sticky="w", padx=5, pady=5)
        
        button_frame = ttk.Frame(info_frame)
        button_frame.grid(row=0, column=2, sticky="e", padx=5, pady=5)
        
        ttk.Button(button_frame, text="Copy IP", 
                  command=lambda: self.ip_manager.copy_ip_to_clipboard(self.leaderboard_ip_var.get())
                 ).pack(side="left", padx=5)
        
        ttk.Button(button_frame, text="Mark as False Positive", 
                  command=lambda: self.ip_manager.mark_as_false_positive(self.leaderboard_ip_var.get())
                 ).pack(side="left", padx=5)
        
        # Make the third column (with buttons) expand
        info_frame.columnconfigure(2, weight=1)
        
        # Create context menu
        self.ip_manager.create_context_menu(
            self.leaderboard_tree, 
            self.leaderboard_ip_var, 
            lambda: self.show_leaderboard_details(None)
        )
        
        # Bind selection event
        self.leaderboard_tree.bind("<<TreeviewSelect>>", self.show_leaderboard_details)

    # Unified methods for handling selection events
    def update_selected_ip(self, tree, ip_var):
        """Update IP variable when a row is selected in any tree"""
        selected = tree.selection()
        if selected:
            ip = tree.item(selected[0], "values")[0]
            ip_var.set(ip)
        else:
            ip_var.set("")

    # Database and UI update methods
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
        self.tree_manager.clear_tree(self.alerts_tree)
        
        # Queue the alerts query
        self.db_manager.queue_query(
            self.db_manager.get_alerts_by_ip,
            callback=self._update_alerts_display
        )
        
        self.update_output("Alerts refresh queued")

    def _update_alerts_display(self, rows):
        """Update the alerts treeview with the results"""
        try:
            # Populate tree using TreeViewManager
            self.tree_manager.populate_tree(self.alerts_tree, rows)
            self.update_output(f"Found alerts for {len(rows)} IP addresses")
        except Exception as e:
            self.update_output(f"Error refreshing alerts: {e}")

    def show_ip_alerts(self, event):
        """Show alerts for the selected IP"""
        # Clear existing items
        self.tree_manager.clear_tree(self.alerts_details_tree)
        
        # Get selected IP
        selected = self.alerts_tree.selection()
        if not selected:
            return
            
        ip = self.alerts_tree.item(selected[0], "values")[0]
        self.alerts_ip_var.set(ip)
        
        # Queue the IP alerts query
        self.db_manager.queue_query(
            self.db_manager.get_ip_alerts,
            callback=lambda rows: self._update_ip_alerts_display(rows, ip),
            ip_address=ip
        )

    def _update_ip_alerts_display(self, rows, ip):
        """Update the IP alerts display with the results"""
        try:
            # Populate tree using TreeViewManager
            self.tree_manager.populate_tree(self.alerts_details_tree, rows)
            self.update_output(f"Showing {len(rows)} alerts for IP: {ip}")
        except Exception as e:
            self.update_output(f"Error fetching alerts for {ip}: {e}")

    def apply_ip_filter(self, ip_filter):
        """Apply IP filter to alerts"""
        if not ip_filter:
            self.update_output("No filter entered")
            return
            
        # Clear existing items
        self.tree_manager.clear_tree(self.alerts_tree)
        
        # Queue the filtered query
        self.db_manager.queue_query(
            self.db_manager.get_filtered_alerts_by_ip,
            callback=self._update_alerts_display,
            ip_filter=ip_filter
        )
        
        self.update_output(f"Querying alerts matching filter: {ip_filter}")

    def refresh_alerts_by_type(self):
        """Queue a refresh for the alerts by rule type display"""
        # Clear existing items
        self.tree_manager.clear_tree(self.alert_types_tree)
        
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
            
            # Populate tree using TreeViewManager
            self.tree_manager.populate_tree(self.alert_types_tree, rows)
            self.update_output(f"Found alerts for {len(rows)} rule types")
        except Exception as e:
            self.update_output(f"Error refreshing alerts by type: {e}")

    def show_rule_alerts(self, event):
        """Show alerts for the selected rule"""
        # Clear existing items
        self.tree_manager.clear_tree(self.rule_alerts_tree)
        
        # Get selected rule
        selected = self.alert_types_tree.selection()
        if not selected:
            return
            
        rule_name = self.alert_types_tree.item(selected[0], "values")[0]
        
        # Queue the query
        self.db_manager.queue_query(
            self.db_manager.get_rule_alerts,
            callback=lambda rows: self._update_rule_alerts_display(rows, rule_name),
            rule_name=rule_name
        )

    def _update_rule_alerts_display(self, rows, rule_name):
        """Update the rule alerts display with the results"""
        try:
            # Populate tree using TreeViewManager
            self.tree_manager.populate_tree(self.rule_alerts_tree, rows)
            self.update_output(f"Showing {len(rows)} alerts for rule: {rule_name}")
        except Exception as e:
            self.update_output(f"Error fetching alerts for rule {rule_name}: {e}")

    def apply_rule_filter(self, rule_filter):
        """Apply rule filter to alerts"""
        if not rule_filter:
            self.update_output("No filter entered")
            return
            
        # Clear existing items
        self.tree_manager.clear_tree(self.alert_types_tree)
        
        # Queue the filtered query
        self.db_manager.queue_query(
            self.db_manager.get_filtered_alerts_by_rule,
            callback=self._update_alerts_by_type_display,
            rule_filter=rule_filter
        )
        
        self.update_output(f"Querying rules matching filter: {rule_filter}")

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
            # Clear all tree views
            trees_to_clear = [
                self.alerts_tree, 
                self.alerts_details_tree, 
                self.alert_types_tree,
                self.rule_alerts_tree, 
                self.malicious_tree, 
                self.leaderboard_tree,
                self.leaderboard_details_tree
            ]
            
            for tree in trees_to_clear:
                self.tree_manager.clear_tree(tree)
            
            self.update_output("All alerts cleared")
        else:
            self.update_output("Error clearing alerts")

    def refresh_malicious_list(self):
        """Refresh the malicious IPs list with fixed duplicate handling"""
        # Clear current items
        self.tree_manager.clear_tree(self.malicious_tree)
        
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
            # Populate tree using TreeViewManager
            self.tree_manager.populate_tree(self.malicious_tree, data)
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

    def show_leaderboard_details(self, event):
        """Show rule details for the selected IP in leaderboard"""
        # Clear existing items
        self.tree_manager.clear_tree(self.leaderboard_details_tree)
        
        # Get selected IP
        selected = self.leaderboard_tree.selection()
        if not selected:
            return
            
        ip = self.leaderboard_tree.item(selected[0], "values")[0]
        self.leaderboard_ip_var.set(ip)
        
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
            # Populate tree using TreeViewManager
            self.tree_manager.populate_tree(self.leaderboard_details_tree, rows)
            self.update_output(f"Showing {len(rows)} rule types triggered by IP: {ip}")
        except Exception as e:
            self.update_output(f"Error fetching rule details for {ip}: {e}")

    def refresh_leaderboard(self):
        """Refresh the threat leaderboard display"""
        # Set flag to indicate refresh is in progress
        self.leaderboard_refresh_in_progress = True
        
        # Clear current items
        self.tree_manager.clear_tree(self.leaderboard_tree)
        
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
            # Extract just the fields we want to display (excluding timestamp which is used for sorting)
            display_data = [(row[0], row[1], row[2], row[3]) for row in data]
            
            # Populate tree using TreeViewManager
            self.tree_manager.populate_tree(self.leaderboard_tree, display_data)
            self.update_output(f"Leaderboard updated with {len(data)} IP addresses")
            
            # Reset the refresh flag
            self.leaderboard_refresh_in_progress = False
        except Exception as e:
            self.update_output(f"Error updating leaderboard display: {e}")
            self.leaderboard_refresh_in_progress = False

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
            self.ip_manager.save_false_positives()
            self.update_output(f"Removed {ip} from false positives")
            
            # Update listbox
            listbox.delete(selected[0])
            
            # Refresh all views
            self.refresh_malicious_list()
            self.refresh_leaderboard()

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
            self.tree_manager.clear_tree(self.connections_tree)
            
            # Format connections data
            formatted_connections = []
            for row in connections:
                # Format byte size
                bytes_formatted = f"{row[2]:,}" if row[2] is not None else "0"
                # Add to formatted list
                formatted_connections.append((row[0], row[1], bytes_formatted, row[3], row[4]))
            
            # Use TreeManager to populate tree in batches
            # This avoids UI freezing with large datasets
            batch_size = 50
            for i in range(0, len(formatted_connections), batch_size):
                batch = formatted_connections[i:i+batch_size]
                self.tree_manager.populate_tree(self.connections_tree, batch)
                # Process UI events every batch
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
        self.tree_manager.clear_tree(self.interface_listbox)
        
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
        
        # Define minimum time between updates (in seconds)
        min_update_interval = 30  # Update alerts tabs at most every 30 seconds
        
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
                
                self.update_output("Alert displays updated (next update in ~30 seconds)")
        else:
            self.update_output("No anomalies in this batch")

        # Periodically refresh the database stats tab (at most every 30 seconds)
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
        self.tree_manager.clear_tree(self.rules_listbox)
        
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