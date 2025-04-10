# red_findings_subtab.py - save this in the alerts/subtabs directory

import tkinter as tk
from tkinter import ttk
import logging
import time
import json
from datetime import datetime
from subtab_base import SubtabBase

class RedFindingsSubtab(SubtabBase):
    """Display red team findings from analysis_1.db"""
    
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
    
    def clear_findings(self):
        """Clear all findings"""
        if hasattr(self.gui, 'red_report_manager') and self.gui.red_report_manager:
            self.gui.red_report_manager.clear_findings()
            self.refresh()
    
    def refresh(self):
        """Refresh the findings display"""
        if not hasattr(self.gui, 'red_report_manager'):
            self.update_output("Red Report Manager not initialized")
            return
            
        try:
            # Get data from manager
            findings = self.gui.red_report_manager.get_recent_findings(limit=1000)
            
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
                    timestamp_str = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
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
    
    def on_finding_selected(self, event):
        """Display details when a finding is selected"""
        self.show_details()
    
    def show_details(self):
        """Show detailed information about the selected finding"""
        selected = self.tree.selection()
        if not selected:
            return
            
        # Get selected item values
        values = self.tree.item(selected[0], "values")
        if not values or len(values) < 6:
            return
            
        timestamp_str, severity, rule_name, src_ip, dst_ip, description = values
        
        # Query database for full details
        if hasattr(self.gui, 'red_report_manager') and self.gui.red_report_manager and self.gui.red_report_manager.analysis_manager:
            try:
                cursor = self.gui.red_report_manager.analysis_manager.get_cursor()
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
                    self.detail_text.delete(1.0, tk.END)
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
                self.update_output(f"Error retrieving finding details: {e}")
        
        # Fallback to basic info if query fails
        self.detail_text.delete(1.0, tk.END)
        self.detail_text.insert(tk.END, f"Rule: {rule_name}\n")
        self.detail_text.insert(tk.END, f"Severity: {severity.upper()}\n")
        self.detail_text.insert(tk.END, f"Time: {timestamp_str}\n")
        self.detail_text.insert(tk.END, f"Source IP: {src_ip}\n")
        self.detail_text.insert(tk.END, f"Destination IP: {dst_ip}\n")
        self.detail_text.insert(tk.END, f"Description: {description}\n")