# red_findings_subtab.py - save this in the alerts/subtabs directory

import tkinter as tk
from tkinter import ttk
import logging
import time
import json
import os
from datetime import datetime
from subtab_base import SubtabBase

class RedFindingsSubtab(SubtabBase):
    """Display red team findings from the consolidated system"""
    
    def __init__(self):
        super().__init__("Red Findings", "Displays security findings for red team activities")
        self.filter_text = ""
    
    def create_ui(self):
        """Create the UI elements for the Red Findings tab"""
        # Create control frame with filter and buttons
        control_frame = ttk.Frame(self.tab_frame)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        # Add filter
        ttk.Label(control_frame, text="Filter:").pack(side="left", padx=5)
        self.filter_entry = ttk.Entry(control_frame, width=20)
        self.filter_entry.pack(side="left", padx=5)
        
        ttk.Button(control_frame, text="Apply Filter", 
                  command=self.apply_filter).pack(side="left", padx=5)
        ttk.Button(control_frame, text="Clear Filter", 
                  command=self.clear_filter).pack(side="left", padx=5)
        
        # Add refresh and clear buttons
        ttk.Button(control_frame, text="Refresh", 
                  command=self.refresh).pack(side="right", padx=5)
        ttk.Button(control_frame, text="Clear All", 
                  command=self.clear_findings).pack(side="right", padx=5)
        
        # Create TreeView
        tree_frame = ttk.Frame(self.tab_frame)
        tree_frame.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side="right", fill="y")
        
        # Create treeview
        self.tree = ttk.Treeview(tree_frame,
                            columns=("timestamp", "severity", "rule_name", "src_ip", "dst_ip", "description"),
                            show="headings",
                            height=10,
                            yscrollcommand=scrollbar.set)
        self.tree.pack(fill="both", expand=True)
        
        # Configure scrollbar
        scrollbar.config(command=self.tree.yview)
        
        # Configure columns
        self.tree.heading("timestamp", text="Time")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("rule_name", text="Rule")
        self.tree.heading("src_ip", text="Source IP")
        self.tree.heading("dst_ip", text="Destination IP")
        self.tree.heading("description", text="Description")
        
        self.tree.column("timestamp", width=150)
        self.tree.column("severity", width=80)
        self.tree.column("rule_name", width=150)
        self.tree.column("src_ip", width=120)
        self.tree.column("dst_ip", width=120)
        self.tree.column("description", width=600)
        
        # Add detail view
        detail_frame = ttk.LabelFrame(self.tab_frame, text="Finding Details")
        detail_frame.pack(fill="x", padx=10, pady=5)
        
        self.detail_text = tk.Text(detail_frame, height=10, wrap="word")
        self.detail_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Bind selection event
        self.tree.bind("<<TreeviewSelect>>", self.on_finding_selected)
        
        # Create context menu for right-click
        self.setup_context_menu()
        
        # Initial load
        self.refresh()
    
    def setup_context_menu(self):
        """Create a context menu for the tree"""
        self.context_menu = tk.Menu(self.tab_frame, tearoff=0)
        self.context_menu.add_command(label="Show Details", command=self.show_details)
        
        if hasattr(self.gui, 'ip_manager'):
            # Add IP menu options
            self.context_menu.add_separator()
            self.context_menu.add_command(label="Copy Source IP", 
                                        command=lambda: self.copy_ip("src"))
            self.context_menu.add_command(label="Copy Destination IP", 
                                        command=lambda: self.copy_ip("dst"))
        
        self.tree.bind("<Button-3>", self.show_context_menu)
    
    def show_context_menu(self, event):
        """Show the context menu on right-click"""
        try:
            # Select the item under cursor
            item = self.tree.identify_row(event.y)
            if item:
                self.tree.selection_set(item)
                self.context_menu.post(event.x_root, event.y_root)
        except Exception as e:
            self.update_output(f"Error showing context menu: {e}")
    
    def copy_ip(self, ip_type):
        """Copy the selected IP address"""
        selected = self.tree.selection()
        if not selected:
            return
            
        values = self.tree.item(selected[0], "values")
        if not values or len(values) < 6:
            return
            
        if ip_type == "src":
            ip = values[3]  # src_ip
        else:
            ip = values[4]  # dst_ip
            
        if hasattr(self.gui, 'ip_manager'):
            self.gui.ip_manager.copy_ip_to_clipboard(ip)
    
    def apply_filter(self):
        """Apply filter to findings"""
        self.filter_text = self.filter_entry.get()
        self.refresh()
    
    def clear_filter(self):
        """Clear filter and refresh"""
        self.filter_entry.delete(0, tk.END)
        self.filter_text = ""
        self.refresh()
    
    def _get_rule_instance(self):
        """Get a rule instance to work with (any rule will do)"""
        # This method becomes less critical if we query analysis_manager directly
        if hasattr(self.gui, 'rules') and self.gui.rules:
            return self.gui.rules[0]
        return None
    
    def clear_findings(self):
        """Clear all findings using AnalysisManager"""
        # MODIFY TO USE ANALYSIS_MANAGER DIRECTLY IF POSSIBLE
        if hasattr(self.gui, 'analysis_manager') and hasattr(self.gui.analysis_manager, 'clear_red_findings'):
             # Assumes AnalysisManager has a clear_red_findings method
             self.gui.analysis_manager.queue_query(
                 self.gui.analysis_manager.clear_red_findings,
                 callback=self._after_clear_findings
             )
        else:
            # Fallback to using a rule instance
            rule = self._get_rule_instance()
            if rule:
                if rule.clear_red_findings():
                    self.update_output("Red findings cleared")
                    self.refresh()
                else:
                    self.update_output("Failed to clear red findings")
            else:
                self.update_output("Cannot clear findings: No rules or analysis manager method available")

    def _after_clear_findings(self, success):
        """Callback after clearing findings via analysis_manager"""
        if success:
            self.update_output("Red findings cleared via AnalysisManager")
            self.refresh()
        else:
            self.update_output("Failed to clear red findings via AnalysisManager")
    
    def refresh(self):
        """Refresh the findings display"""
        rule = self._get_rule_instance()
        if not rule:
            self.update_output("No rules available to get red findings")
            return
            
        try:
            # Get findings from any rule (they all have access to the same data)
            findings = rule.get_recent_red_findings(limit=1000)
            
            # If no findings are found in the database, try to load from files
            if not findings:
                findings = self._load_findings_from_files()
            
            # Clear current items
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            # Filter if needed
            if self.filter_text:
                filter_text_lower = self.filter_text.lower()
                findings = [f for f in findings if 
                           filter_text_lower in str(f[1]).lower() or # src_ip
                           filter_text_lower in str(f[2]).lower() or # dst_ip
                           filter_text_lower in str(f[3]).lower() or # rule_name
                           filter_text_lower in str(f[4]).lower() or # severity
                           filter_text_lower in str(f[5]).lower()]   # description
            
            # Add filtered items
            for finding in findings:
                timestamp, src_ip, dst_ip, rule_name, severity, description = finding
                
                # Format timestamp
                try:
                    if isinstance(timestamp, (int, float)):
                        timestamp_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                    else:
                        timestamp_str = str(timestamp)
                except:
                    timestamp_str = str(timestamp)
                
                # Format severity with color
                severity = severity.lower() if severity else "medium"
                
                # Insert into tree
                item_id = self.tree.insert("", "end", values=(
                    timestamp_str, severity, rule_name, src_ip, dst_ip, description
                ))
                
                # Color by severity
                if severity == "critical":
                    self.tree.item(item_id, tags=("critical",))
                elif severity == "high":
                    self.tree.item(item_id, tags=("high",))
                elif severity == "medium":
                    self.tree.item(item_id, tags=("medium",))
                
            # Configure tag colors
            self.tree.tag_configure("critical", background="#ffcccc")
            self.tree.tag_configure("high", background="#ffffcc")  
            self.tree.tag_configure("medium", background="#e6f7ff")
            
            # Update count in tab name if possible
            parent = self.tab_frame.master
            if parent:
                for i in range(parent.index('end')):
                    if parent.winfo_children()[i] == self.tab_frame:
                        parent.tab(i, text=f"Red Findings ({len(findings)})")
                        break
            
        except Exception as e:
            self.update_output(f"Error refreshing red findings: {e}")
            import traceback
            traceback.print_exc()
    
    def _load_findings_from_files(self):
        """Load red findings directly from the files in the red directory"""
        findings = []
        
        try:
            # Get path to red directory
            red_dir = None
            if hasattr(self.gui, 'red_dir'):
                red_dir = self.gui.red_dir
            elif hasattr(self.gui, 'app_root'):
                red_dir = os.path.join(self.gui.app_root, "red")
            
            if not red_dir or not os.path.exists(red_dir):
                return findings
                
            for filename in os.listdir(red_dir):
                if filename.endswith('.json'):
                    try:
                        file_path = os.path.join(red_dir, filename)
                        with open(file_path, 'r') as f:
                            data = json.load(f)
                            
                        # Extract the key fields
                        timestamp = data.get("timestamp", 0)
                        src_ip = data.get("src_ip", "N/A")
                        dst_ip = data.get("dst_ip", "N/A")
                        rule_name = data.get("rule_name", "Unknown")
                        severity = data.get("severity", "medium")
                        description = data.get("description", "No description")
                        
                        findings.append((timestamp, src_ip, dst_ip, rule_name, severity, description))
                    except Exception as e:
                        self.update_output(f"Error loading finding file {filename}: {e}")
                        
            # Sort by timestamp descending
            findings.sort(reverse=True, key=lambda x: x[0])
            
            return findings
        except Exception as e:
            self.update_output(f"Error loading findings from files: {e}")
            return []
    
    def on_finding_selected(self, event):
        """Display details when a finding is selected"""
        self.show_details()
    
    def show_details(self):
        """Show detailed information about the selected finding using files or direct DB access"""
        selected = self.tree.selection()
        if not selected:
            return
            
        # Get selected item values
        values = self.tree.item(selected[0], "values")
        if not values or len(values) < 6:
            return
            
        timestamp_str, severity, rule_name, src_ip, dst_ip, description = values
        
        # Clear details area
        self.detail_text.delete(1.0, tk.END)
        
        # First try to find matching file
        finding_file = self._find_matching_file(timestamp_str, rule_name, src_ip, dst_ip)
        
        if finding_file:
            # We found a file, load details from it
            try:
                with open(finding_file, 'r') as f:
                    data = json.load(f)
                
                # Basic details
                self.detail_text.insert(tk.END, f"Rule: {rule_name}\n")
                self.detail_text.insert(tk.END, f"Severity: {severity.upper()}\n")
                self.detail_text.insert(tk.END, f"Time: {timestamp_str}\n")
                self.detail_text.insert(tk.END, f"Source IP: {src_ip}\n")
                self.detail_text.insert(tk.END, f"Destination IP: {dst_ip}\n")
                self.detail_text.insert(tk.END, f"Description: {description}\n\n")
                
                # Connection key if available
                if "connection_key" in data and data["connection_key"]:
                    self.detail_text.insert(tk.END, f"Connection: {data['connection_key']}\n")
                
                # Additional details
                if "details" in data and data["details"]:
                    self.detail_text.insert(tk.END, "Details:\n")
                    if isinstance(data["details"], dict):
                        for key, value in data["details"].items():
                            self.detail_text.insert(tk.END, f"  {key}: {value}\n")
                    else:
                        self.detail_text.insert(tk.END, f"  {data['details']}\n")
                
                # Remediation if available
                if "remediation" in data and data["remediation"]:
                    self.detail_text.insert(tk.END, f"\nRemediation:\n{data['remediation']}\n")
                    
                return
            except Exception as e:
                self.update_output(f"Error reading finding file: {e}")
        
        # If we reach here, either no file was found or there was an error reading it
        # Try to get details from database
        rule = self._get_rule_instance()
        if rule and hasattr(rule, 'db_manager'):
            try:
                # Determine which database connection to use
                conn = None
                if hasattr(rule.db_manager, 'analysis_conn'):
                    conn = rule.db_manager.analysis_conn
                elif hasattr(rule.db_manager, 'capture_conn'):
                    conn = rule.db_manager.capture_conn
                    
                if conn:
                    cursor = conn.cursor()
                    cursor.execute("""
                        SELECT details, connection_key, remediation
                        FROM x_red
                        WHERE rule_name = ? AND src_ip = ? AND dst_ip = ? AND description = ?
                        ORDER BY timestamp DESC
                        LIMIT 1
                    """, (rule_name, src_ip, dst_ip, description))
                    
                    row = cursor.fetchone()
                    if row:
                        details_json, connection_key, remediation = row
                        
                        # Format details for display
                        self.detail_text.insert(tk.END, f"Rule: {rule_name}\n")
                        self.detail_text.insert(tk.END, f"Severity: {severity.upper()}\n")
                        self.detail_text.insert(tk.END, f"Time: {timestamp_str}\n")
                        self.detail_text.insert(tk.END, f"Source IP: {src_ip}\n")
                        self.detail_text.insert(tk.END, f"Destination IP: {dst_ip}\n")
                        self.detail_text.insert(tk.END, f"Description: {description}\n\n")
                        
                        if connection_key:
                            self.detail_text.insert(tk.END, f"Connection: {connection_key}\n")
                        
                        if details_json:
                            try:
                                details = json.loads(details_json)
                                self.detail_text.insert(tk.END, "Details:\n")
                                for key, value in details.items():
                                    self.detail_text.insert(tk.END, f"  {key}: {value}\n")
                            except:
                                self.detail_text.insert(tk.END, f"Details: {details_json}\n")
                        
                        if remediation:
                            self.detail_text.insert(tk.END, f"\nRemediation:\n{remediation}\n")
                        
                        return
            except Exception as e:
                self.update_output(f"Error retrieving finding details from database: {e}")
        
        # Fallback to basic info if both approaches fail
        self.detail_text.insert(tk.END, f"Rule: {rule_name}\n")
        self.detail_text.insert(tk.END, f"Severity: {severity.upper()}\n")
        self.detail_text.insert(tk.END, f"Time: {timestamp_str}\n")
        self.detail_text.insert(tk.END, f"Source IP: {src_ip}\n")
        self.detail_text.insert(tk.END, f"Destination IP: {dst_ip}\n")
        self.detail_text.insert(tk.END, f"Description: {description}\n")
        self.detail_text.insert(tk.END, "\n(Detailed information not available)\n")
    
    def _find_matching_file(self, timestamp_str, rule_name, src_ip, dst_ip):
        """Try to find a matching finding file based on the information we have"""
        try:
            # Get path to red directory
            red_dir = None
            if hasattr(self.gui, 'red_dir'):
                red_dir = self.gui.red_dir
            elif hasattr(self.gui, 'app_root'):
                red_dir = os.path.join(self.gui.app_root, "red")
            
            if not red_dir or not os.path.exists(red_dir):
                return None
                
            # Convert timestamp string to datetime object if possible
            timestamp_obj = None
            try:
                timestamp_obj = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
                timestamp_file_prefix = timestamp_obj.strftime("%Y%m%d_%H%M%S")
            except:
                timestamp_file_prefix = None
                
            # Sanitize values for filename matching
            safe_rule_name = rule_name.replace(' ', '_').replace('(', '').replace(')', '').replace('/', '_')
            safe_src_ip = src_ip.replace(':', '_')
            safe_dst_ip = dst_ip.replace(':', '_')
            
            # First try exact timestamp match if available
            if timestamp_file_prefix:
                exact_match = f"{timestamp_file_prefix}_{safe_rule_name}_{safe_src_ip}_{safe_dst_ip}.json"
                exact_path = os.path.join(red_dir, exact_match)
                if os.path.exists(exact_path):
                    return exact_path
                    
                # Try without timestamps
                for filename in os.listdir(red_dir):
                    if (filename.endswith('.json') and 
                        safe_rule_name in filename and 
                        safe_src_ip in filename and 
                        safe_dst_ip in filename):
                        return os.path.join(red_dir, filename)
                        
                # Try with just IPs
                for filename in os.listdir(red_dir):
                    if (filename.endswith('.json') and 
                        (safe_src_ip in filename or safe_dst_ip in filename) and
                        safe_rule_name in filename):
                        return os.path.join(red_dir, filename)
            else:
                # No timestamp, try by rule and IPs
                for filename in os.listdir(red_dir):
                    if (filename.endswith('.json') and 
                        safe_rule_name in filename and 
                        (safe_src_ip in filename or safe_dst_ip in filename)):
                        return os.path.join(red_dir, filename)
            
            # No match found
            return None
            
        except Exception as e:
            self.update_output(f"Error finding matching file: {e}")
            return None