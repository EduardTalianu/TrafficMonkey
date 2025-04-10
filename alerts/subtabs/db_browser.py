import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import time
import sqlite3
import os
from subtab_base import SubtabBase

class DatabaseBrowserSubtab(SubtabBase):
    """Subtab that allows browsing database tables and running queries"""
    
    def __init__(self):
        super().__init__(
            name="Database Browser",
            description="Browse database tables and run custom queries"
        )
        self.results_tree = None
        self.query_text = None
        self.table_var = tk.StringVar()
        self.db_var = tk.StringVar(value="analysis_1")  # Default to analysis_1
        self.limit_var = tk.StringVar(value="100")
        self.status_var = tk.StringVar(value="Ready")
        self.column_names = []
        self.available_databases = []
        
    def create_ui(self):
        # Create notebook for different modes
        self.browser_notebook = ttk.Notebook(self.tab_frame)
        self.browser_notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Table browser tab
        self.table_browser_tab = ttk.Frame(self.browser_notebook)
        self.browser_notebook.add(self.table_browser_tab, text="Table Browser")
        self.create_table_browser()
        
        # Custom query tab
        self.query_tab = ttk.Frame(self.browser_notebook)
        self.browser_notebook.add(self.query_tab, text="Custom Query")
        self.create_query_tab()
        
        # Database Structure tab
        self.structure_tab = ttk.Frame(self.browser_notebook)
        self.browser_notebook.add(self.structure_tab, text="Database Structure")
        self.create_structure_tab()
        
        # Status bar
        status_frame = ttk.Frame(self.tab_frame)
        status_frame.pack(fill="x", side="bottom")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side="left", padx=5)
        
    def detect_available_databases(self):
        """Detect all available databases in the application"""
        self.available_databases = []
        
        # Standard databases
        standard_dbs = ["capture", "analysis", "analysis_1"]
        for db in standard_dbs:
            self.available_databases.append(db)
            
        # Check database directory for additional SQLite files
        try:
            # Try to get the database directory from the application
            if hasattr(self.gui, 'config') and 'database_dir' in self.gui.config:
                db_dir = self.gui.config['database_dir']
                if os.path.exists(db_dir):
                    for file in os.listdir(db_dir):
                        if file.endswith('.db') and file not in [f"{db}.db" for db in standard_dbs]:
                            db_name = os.path.splitext(file)[0]
                            if db_name not in self.available_databases:
                                self.available_databases.append(db_name)
        except Exception as e:
            self.update_output(f"Warning: Could not scan for additional databases: {e}")
            
        return self.available_databases
        
    def create_table_browser(self):
        """Create the table browser UI"""
        # Control panel
        control_frame = ttk.Frame(self.table_browser_tab)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        # Detect available databases
        self.detect_available_databases()
        
        # Database selection
        ttk.Label(control_frame, text="Database:").pack(side="left", padx=5)
        db_combobox = ttk.Combobox(control_frame, textvariable=self.db_var, 
                                  values=self.available_databases, width=15, state="readonly")
        db_combobox.pack(side="left", padx=5)
        db_combobox.bind("<<ComboboxSelected>>", lambda e: self.refresh_tables())
        
        # Table selection
        ttk.Label(control_frame, text="Table:").pack(side="left", padx=5)
        self.table_combobox = ttk.Combobox(control_frame, textvariable=self.table_var, width=25)
        self.table_combobox.pack(side="left", padx=5)
        self.table_combobox.bind("<<ComboboxSelected>>", lambda e: self.refresh_table_data())
        
        # Limit entries
        ttk.Label(control_frame, text="Limit:").pack(side="left", padx=5)
        ttk.Entry(control_frame, textvariable=self.limit_var, width=6).pack(side="left", padx=5)
        
        # Actions
        ttk.Button(control_frame, text="Refresh Databases", 
                  command=self.refresh_databases).pack(side="right", padx=5)
        ttk.Button(control_frame, text="Refresh Tables", 
                  command=self.refresh_tables).pack(side="right", padx=5)
        ttk.Button(control_frame, text="Refresh Data", 
                  command=self.refresh_table_data).pack(side="right", padx=5)
        ttk.Button(control_frame, text="Export to CSV", 
                  command=self.export_table_to_csv).pack(side="right", padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(self.table_browser_tab, text="Table Data")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Placeholder for results tree
        self.results_container = ttk.Frame(results_frame)
        self.results_container.pack(fill="both", expand=True)
        
        # Table info
        info_frame = ttk.LabelFrame(self.table_browser_tab, text="Table Information")
        info_frame.pack(fill="x", padx=10, pady=5)
        
        self.table_info_text = tk.Text(info_frame, height=4, wrap=tk.WORD)
        self.table_info_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Initialize tables list
        self.refresh_tables()
        
    def create_query_tab(self):
        """Create the custom query UI"""
        # Query input
        query_input_frame = ttk.LabelFrame(self.query_tab, text="SQL Query")
        query_input_frame.pack(fill="x", padx=10, pady=5)
        
        # Database selection for query
        db_frame = ttk.Frame(query_input_frame)
        db_frame.pack(fill="x", padx=5, pady=5)
        
        # Detect available databases again to ensure consistency
        self.detect_available_databases()
        
        ttk.Label(db_frame, text="Database:").pack(side="left", padx=5)
        query_db_combobox = ttk.Combobox(db_frame, textvariable=self.db_var, 
                                        values=self.available_databases, width=15, state="readonly")
        query_db_combobox.pack(side="left", padx=5)
        
        # Refresh databases button
        ttk.Button(db_frame, text="Refresh DBs", 
                  command=lambda: self.refresh_databases(query_db_combobox)).pack(side="left", padx=5)
        
        ttk.Button(db_frame, text="Run Query", 
                  command=self.run_custom_query).pack(side="right", padx=5)
        ttk.Button(db_frame, text="Export Results", 
                  command=self.export_query_results).pack(side="right", padx=5)
        
        # Query editor
        query_editor_frame = ttk.Frame(query_input_frame)
        query_editor_frame.pack(fill="x", padx=5, pady=5)
        
        self.query_text = tk.Text(query_editor_frame, height=5, wrap=tk.WORD)
        self.query_text.pack(fill="both", expand=True, side="left")
        
        # Add some example queries
        example_queries = [
            "-- Example: Show the top 10 connections by total bytes",
            "SELECT src_ip, dst_ip, total_bytes FROM connections",
            "ORDER BY total_bytes DESC LIMIT 10;",
            "",
            "-- Example: List all tables in this database",
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;",
            "",
            "-- Example: Count alerts by rule name",
            "-- SELECT rule_name, COUNT(*) as alert_count FROM alerts",
            "-- GROUP BY rule_name ORDER BY alert_count DESC;"
        ]
        self.query_text.insert(tk.END, "\n".join(example_queries))
        
        # Scrollbar for query text
        query_scroll = ttk.Scrollbar(query_editor_frame, command=self.query_text.yview)
        query_scroll.pack(side="right", fill="y")
        self.query_text.config(yscrollcommand=query_scroll.set)
        
        # Query results
        query_results_frame = ttk.LabelFrame(self.query_tab, text="Query Results")
        query_results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.query_results_container = ttk.Frame(query_results_frame)
        self.query_results_container.pack(fill="both", expand=True)
        
    def create_structure_tab(self):
        """Create the database structure view UI"""
        # Control panel
        control_frame = ttk.Frame(self.structure_tab)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        # Detect available databases again to ensure consistency
        self.detect_available_databases()
        
        # Database selection
        ttk.Label(control_frame, text="Database:").pack(side="left", padx=5)
        structure_db_combobox = ttk.Combobox(control_frame, textvariable=self.db_var, 
                                           values=self.available_databases, width=15, state="readonly")
        structure_db_combobox.pack(side="left", padx=5)
        
        # Refresh databases button for structure tab
        ttk.Button(control_frame, text="Refresh DBs", 
                  command=lambda: self.refresh_databases(structure_db_combobox)).pack(side="left", padx=5)
        
        # Export buttons
        ttk.Button(control_frame, text="Export to CSV", 
                  command=self.export_structure_to_csv).pack(side="right", padx=5)
        ttk.Button(control_frame, text="Export to Markdown", 
                  command=self.export_structure_to_markdown).pack(side="right", padx=5)
        
        # Refresh button
        ttk.Button(control_frame, text="Refresh Structure", 
                  command=self.refresh_db_structure).pack(side="right", padx=5)
        
        # Structure tree frame
        self.structure_frame = ttk.Frame(self.structure_tab)
        self.structure_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create structure treeview
        self.create_structure_tree()
        
        # Details frame
        self.details_frame = ttk.LabelFrame(self.structure_tab, text="Details")
        self.details_frame.pack(fill="x", padx=10, pady=5)
        
        self.details_text = tk.Text(self.details_frame, height=6, wrap=tk.WORD)
        self.details_text.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Initialize structure view
        structure_db_combobox.bind("<<ComboboxSelected>>", lambda e: self.refresh_db_structure())
        
    def refresh_databases(self, combobox=None):
        """Refresh the list of available databases"""
        current_db = self.db_var.get()
        self.detect_available_databases()
        
        # Update all database comboboxes
        if combobox:
            combobox['values'] = self.available_databases
        
        # Update all tabs' database comboboxes
        for widget in self.table_browser_tab.winfo_children():
            if isinstance(widget, ttk.Frame):
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Combobox) and child.cget('values') and 'analysis' in child.cget('values')[0]:
                        child['values'] = self.available_databases
                        
        for widget in self.query_tab.winfo_children():
            if isinstance(widget, ttk.LabelFrame):
                for frame in widget.winfo_children():
                    if isinstance(frame, ttk.Frame):
                        for child in frame.winfo_children():
                            if isinstance(child, ttk.Combobox) and child.cget('values') and 'analysis' in child.cget('values')[0]:
                                child['values'] = self.available_databases
                                
        for widget in self.structure_tab.winfo_children():
            if isinstance(widget, ttk.Frame):
                for child in widget.winfo_children():
                    if isinstance(child, ttk.Combobox) and child.cget('values') and 'analysis' in child.cget('values')[0]:
                        child['values'] = self.available_databases
        
        # Restore current selection if possible, otherwise select first available
        if current_db in self.available_databases:
            self.db_var.set(current_db)
        elif self.available_databases:
            self.db_var.set(self.available_databases[0])
            
        self.status_var.set(f"Detected {len(self.available_databases)} databases")
        self.update_output(f"Found {len(self.available_databases)} available databases")
    
    def create_structure_tree(self):
        """Create the database structure treeview"""
        # Clear existing widgets
        for widget in self.structure_frame.winfo_children():
            widget.destroy()
            
        # Create a frame for the tree and scrollbar
        frame = ttk.Frame(self.structure_frame)
        frame.pack(fill="both", expand=True)
        
        # Create vertical scrollbar
        vsb = ttk.Scrollbar(frame, orient="vertical")
        vsb.pack(side="right", fill="y")
        
        # Create horizontal scrollbar
        hsb = ttk.Scrollbar(frame, orient="horizontal")
        hsb.pack(side="bottom", fill="x")
        
        # Create structure tree
        self.structure_tree = ttk.Treeview(frame, show="tree headings", 
                                          yscrollcommand=vsb.set,
                                          xscrollcommand=hsb.set)
        
        # Configure scrollbars
        vsb.config(command=self.structure_tree.yview)
        hsb.config(command=self.structure_tree.xview)
        
        # Configure column
        self.structure_tree["columns"] = ("type", "details")
        self.structure_tree.column("#0", width=200, stretch=tk.YES)
        self.structure_tree.column("type", width=100, stretch=tk.NO)
        self.structure_tree.column("details", width=300, stretch=tk.YES)
        
        self.structure_tree.heading("#0", text="Name")
        self.structure_tree.heading("type", text="Type")
        self.structure_tree.heading("details", text="Details")
        
        self.structure_tree.pack(fill="both", expand=True)
        
        # Bind selection event
        self.structure_tree.bind("<<TreeviewSelect>>", self.on_structure_select)
        
        # Load initial structure
        self.refresh_db_structure()
        
    def refresh_db_structure(self):
        """Refresh the database structure view"""
        try:
            # Get database connection
            db_conn = self.get_db_connection()
            if not db_conn:
                self.status_var.set(f"Could not connect to database: {self.db_var.get()}")
                return
                
            # Clear existing items
            self.structure_tree.delete(*self.structure_tree.get_children())
            
            # Get all tables
            cursor = db_conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = cursor.fetchall()
            
            # Get all indices
            cursor.execute("SELECT name, tbl_name FROM sqlite_master WHERE type='index' ORDER BY tbl_name, name")
            indices = cursor.fetchall()
            
            # Add tables to tree
            for table in tables:
                table_name = table[0]
                
                # Count rows in table
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM '{table_name}'")
                    row_count = cursor.fetchone()[0]
                except sqlite3.OperationalError:
                    row_count = "N/A"
                    
                # Get table schema
                try:
                    cursor.execute(f"PRAGMA table_info('{table_name}')")
                    columns = cursor.fetchall()
                    column_count = len(columns)
                except sqlite3.OperationalError:
                    columns = []
                    column_count = 0
                
                # Add table to tree
                table_id = self.structure_tree.insert("", "end", text=table_name, 
                                                    values=("Table", f"{column_count} columns, {row_count} rows"))
                
                # Add columns to tree
                for col in columns:
                    col_id, col_name, col_type, not_null, default_val, primary_key = col
                    
                    constraints = []
                    if primary_key == 1:
                        constraints.append("PRIMARY KEY")
                    if not_null == 1:
                        constraints.append("NOT NULL")
                    if default_val is not None:
                        constraints.append(f"DEFAULT {default_val}")
                        
                    constraints_str = ", ".join(constraints)
                    
                    self.structure_tree.insert(table_id, "end", text=col_name, 
                                              values=("Column", f"{col_type} {constraints_str}"))
                
            # Add indices node if there are any indices
            if indices:
                indices_id = self.structure_tree.insert("", "end", text="Indices", 
                                                      values=("Category", f"{len(indices)} indices"))
                
                # Group indices by table
                index_groups = {}
                for index in indices:
                    index_name, table_name = index
                    if table_name not in index_groups:
                        index_groups[table_name] = []
                    index_groups[table_name].append(index_name)
                    
                # Add indices to tree
                for table_name, index_list in index_groups.items():
                    table_indices_id = self.structure_tree.insert(indices_id, "end", text=table_name, 
                                                               values=("Table", f"{len(index_list)} indices"))
                    
                    for index_name in index_list:
                        # Get index info
                        try:
                            cursor.execute(f"PRAGMA index_info('{index_name}')")
                            index_columns = cursor.fetchall()
                            
                            # Get column names
                            column_names = []
                            for idx_col in index_columns:
                                col_id = idx_col[2]
                                try:
                                    # Ensure col_id is an integer
                                    col_id = int(col_id) if col_id is not None else 0
                                    cursor.execute(f"PRAGMA table_info('{table_name}')")
                                    table_cols = cursor.fetchall()
                                    if 0 <= col_id < len(table_cols):  # Ensure col_id is a valid index
                                        column_names.append(table_cols[col_id][1])
                                except (ValueError, TypeError, IndexError):
                                    continue
                                    
                            self.structure_tree.insert(table_indices_id, "end", text=index_name, 
                                                     values=("Index", f"Columns: {', '.join(column_names)}"))
                        except sqlite3.OperationalError:
                            # Skip problematic indices
                            self.structure_tree.insert(table_indices_id, "end", text=index_name, 
                                                     values=("Index", "Could not retrieve columns"))
            
            self.status_var.set(f"Loaded structure for {self.db_var.get()} database")
            self.update_output(f"Browsing structure of {self.db_var.get()} database")
            
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            self.update_output(f"Error loading database structure: {e}")
    
    def export_structure_to_csv(self):
        """Export the database structure to CSV format"""
        try:
            # Ask for filename to save
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile=f"{self.db_var.get()}_structure.csv"
            )
            
            if not filename:
                return  # User cancelled
                
            # Get database connection
            db_conn = self.get_db_connection()
            if not db_conn:
                self.status_var.set(f"Could not connect to database: {self.db_var.get()}")
                return
                
            cursor = db_conn.cursor()
            
            # Prepare data structure
            structure_data = []
            
            # Add header row
            structure_data.append(["DATABASE", self.db_var.get(), "", "", "", "", ""])
            structure_data.append(["", "", "", "", "", "", ""])  # Empty row for separation
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = cursor.fetchall()
            
            # Add tables section header
            structure_data.append(["TABLES", f"Total: {len(tables)}", "", "", "", "", ""])
            structure_data.append(["Table Name", "Row Count", "Column Count", "", "", "", ""])
            
            # Process each table
            for table in tables:
                table_name = table[0]
                
                # Count rows in table
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM '{table_name}'")
                    row_count = cursor.fetchone()[0]
                except sqlite3.OperationalError:
                    row_count = "N/A"
                    
                # Get table schema
                try:
                    cursor.execute(f"PRAGMA table_info('{table_name}')")
                    columns = cursor.fetchall()
                    column_count = len(columns)
                except sqlite3.OperationalError:
                    columns = []
                    column_count = 0
                
                # Add table row
                structure_data.append([table_name, row_count, column_count, "", "", "", ""])
                
                # Add column header for this table
                structure_data.append(["", "Column Name", "Type", "NOT NULL", "DEFAULT", "PRIMARY KEY", "Position"])
                
                # Add columns
                for col in columns:
                    col_id, col_name, col_type, not_null, default_val, primary_key = col
                    structure_data.append(["", col_name, col_type, "Yes" if not_null == 1 else "No", 
                                        default_val if default_val is not None else "", 
                                        "Yes" if primary_key == 1 else "No", col_id])
                
                # Add empty row for separation
                structure_data.append(["", "", "", "", "", "", ""])
                
            # Get all indices
            cursor.execute("SELECT name, tbl_name FROM sqlite_master WHERE type='index' ORDER BY tbl_name, name")
            indices = cursor.fetchall()
            
            # Add indices section header
            structure_data.append(["INDICES", f"Total: {len(indices)}", "", "", "", "", ""])
            structure_data.append(["Index Name", "Table", "Columns", "", "", "", ""])
            
            # Process each index
            for index in indices:
                index_name, table_name = index
                
                # Get index info
                try:
                    cursor.execute(f"PRAGMA index_info('{index_name}')")
                    index_columns = cursor.fetchall()
                    
                    # Get column names
                    column_names = []
                    for idx_col in index_columns:
                        col_id = idx_col[2]
                        # Make sure col_id is an integer
                        try:
                            col_id = int(col_id) if col_id is not None else 0
                            cursor.execute(f"PRAGMA table_info('{table_name}')")
                            table_cols = cursor.fetchall()
                            if 0 <= col_id < len(table_cols):  # Ensure col_id is a valid index
                                column_names.append(table_cols[col_id][1])
                        except (ValueError, TypeError, IndexError):
                            # Skip if col_id is not a valid integer
                            continue
                        
                    # Check if unique
                    cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='index' AND name='{index_name}'")
                    sql = cursor.fetchone()
                    is_unique = False
                    if sql and sql[0] and "UNIQUE" in sql[0].upper():
                        is_unique = True
                    
                    # Add index row
                    structure_data.append([index_name, table_name, ", ".join(column_names), 
                                        "UNIQUE" if is_unique else "INDEX", "", "", ""])
                except sqlite3.OperationalError:
                    # Add index row with error info
                    structure_data.append([index_name, table_name, "Could not retrieve columns", 
                                        "INDEX", "", "", ""])
                
            # Write to CSV
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerows(structure_data)
                
            self.status_var.set(f"Exported database structure to {filename}")
            self.update_output(f"Successfully exported {self.db_var.get()} database structure to CSV")
            
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            self.update_output(f"Error exporting database structure: {e}")
            
    def export_structure_to_markdown(self):
        """Export the database structure to Markdown format"""
        try:
            # Ask for filename to save
            filename = filedialog.asksaveasfilename(
                defaultextension=".md",
                filetypes=[("Markdown files", "*.md"), ("All files", "*.*")],
                initialfile=f"{self.db_var.get()}_structure.md"
            )
            
            if not filename:
                return  # User cancelled
                
            # Get database connection
            db_conn = self.get_db_connection()
            if not db_conn:
                self.status_var.set(f"Could not connect to database: {self.db_var.get()}")
                return
                
            cursor = db_conn.cursor()
            
            # Prepare markdown content
            md_content = []
            
            # Add header
            md_content.append(f"# Database Structure: {self.db_var.get()}")
            md_content.append(f"*Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}*")
            md_content.append("")
            
            # Get all tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = cursor.fetchall()
            
            # Add tables section
            md_content.append(f"## Tables ({len(tables)})")
            md_content.append("")
            
            # Process each table
            for table in tables:
                table_name = table[0]
                
                # Count rows in table
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM '{table_name}'")
                    row_count = cursor.fetchone()[0]
                except sqlite3.OperationalError:
                    row_count = "N/A"
                    
                # Get table schema
                try:
                    cursor.execute(f"PRAGMA table_info('{table_name}')")
                    columns = cursor.fetchall()
                    column_count = len(columns)
                except sqlite3.OperationalError:
                    columns = []
                    column_count = 0
                
                # Add table header
                md_content.append(f"### Table: {table_name}")
                md_content.append(f"- **Rows:** {row_count}")
                md_content.append(f"- **Columns:** {column_count}")
                md_content.append("")
                
                if columns:
                    # Add columns table
                    md_content.append("| Position | Column Name | Type | Constraints |")
                    md_content.append("| -------- | ----------- | ---- | ----------- |")
                    
                    # Add columns
                    for col in columns:
                        col_id, col_name, col_type, not_null, default_val, primary_key = col
                        
                        constraints = []
                        if primary_key == 1:
                            constraints.append("PRIMARY KEY")
                        if not_null == 1:
                            constraints.append("NOT NULL")
                        if default_val is not None:
                            constraints.append(f"DEFAULT {default_val}")
                            
                        constraints_str = ", ".join(constraints)
                        
                        md_content.append(f"| {col_id} | {col_name} | {col_type} | {constraints_str} |")
                else:
                    md_content.append("*Could not retrieve column information*")
                
                md_content.append("")
                
                # Get indices for this table
                cursor.execute(f"SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='{table_name}'")
                table_indices = cursor.fetchall()
                
                if table_indices:
                    md_content.append(f"#### Indices for {table_name}")
                    md_content.append("")
                    
                    for idx in table_indices:
                        index_name = idx[0]
                        
                        # Get index info
                        try:
                            cursor.execute(f"PRAGMA index_info('{index_name}')")
                            index_columns = cursor.fetchall()
                            
                            # Get column names
                            column_names = []
                            for idx_col in index_columns:
                                try:
                                    col_id = int(idx_col[2]) if idx_col[2] is not None else 0
                                    cursor.execute(f"PRAGMA table_info('{table_name}')")
                                    table_cols = cursor.fetchall()
                                    if 0 <= col_id < len(table_cols):  # Ensure col_id is a valid index
                                        column_names.append(table_cols[col_id][1])
                                except (ValueError, TypeError, IndexError):
                                    # Skip if col_id is not a valid integer
                                    continue
                                
                            # Check if unique
                            cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='index' AND name='{index_name}'")
                            sql = cursor.fetchone()
                            is_unique = False
                            if sql and sql[0] and "UNIQUE" in sql[0].upper():
                                is_unique = True
                            
                            # Add index info
                            md_content.append(f"- **{index_name}**")
                            md_content.append(f"  - Type: {'UNIQUE INDEX' if is_unique else 'INDEX'}")
                            md_content.append(f"  - Columns: {', '.join(column_names)}")
                            md_content.append("")
                        except sqlite3.OperationalError:
                            # Add error info
                            md_content.append(f"- **{index_name}**")
                            md_content.append(f"  - *Could not retrieve index information*")
                            md_content.append("")
                
                md_content.append("")  # Extra blank line between tables
            
            # Get all views
            cursor.execute("SELECT name FROM sqlite_master WHERE type='view' ORDER BY name")
            views = cursor.fetchall()
            
            if views:
                # Add views section
                md_content.append(f"## Views ({len(views)})")
                md_content.append("")
                
                for view in views:
                    view_name = view[0]
                    
                    # Get view definition
                    cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='view' AND name='{view_name}'")
                    view_sql = cursor.fetchone()
                    if view_sql and view_sql[0]:
                        # Add view info
                        md_content.append(f"### View: {view_name}")
                        md_content.append("```sql")
                        md_content.append(view_sql[0])
                        md_content.append("```")
                        md_content.append("")
            
            # Write to markdown file
            with open(filename, 'w', encoding='utf-8') as mdfile:
                mdfile.write("\n".join(md_content))
                
            self.status_var.set(f"Exported database structure to {filename}")
            self.update_output(f"Successfully exported {self.db_var.get()} database structure to Markdown")
            
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            self.update_output(f"Error exporting database structure: {e}")
    
    def on_structure_select(self):
        """Handle selection in the structure tree"""
        selected_item = self.structure_tree.selection()
        if not selected_item:
            return
            
        item_id = selected_item[0]
        item_text = self.structure_tree.item(item_id, "text")
        item_type = self.structure_tree.item(item_id, "values")[0]
        
        # Clear details text
        self.details_text.delete("1.0", tk.END)
        
        try:
            # Get database connection
            db_conn = self.get_db_connection()
            if not db_conn:
                self.status_var.set(f"Could not connect to database: {self.db_var.get()}")
                self.details_text.insert(tk.END, "Could not connect to database")
                return
                
            cursor = db_conn.cursor()
            
            if item_type == "Table":
                # Get table info
                try:
                    cursor.execute(f"PRAGMA table_info('{item_text}')")
                    columns = cursor.fetchall()
                    
                    # Count rows
                    try:
                        cursor.execute(f"SELECT COUNT(*) FROM '{item_text}'")
                        row_count = cursor.fetchone()[0]
                    except sqlite3.OperationalError:
                        row_count = "N/A"
                        
                    # Show details
                    details = f"Table: {item_text}\n"
                    details += f"Total Rows: {row_count}\n"
                    details += f"Total Columns: {len(columns)}\n\n"
                    details += "Columns:\n"
                    
                    for col in columns:
                        col_id, col_name, col_type, not_null, default_val, primary_key = col
                        primary = " (PRIMARY KEY)" if primary_key == 1 else ""
                        not_null_str = " NOT NULL" if not_null == 1 else ""
                        default = f" DEFAULT {default_val}" if default_val is not None else ""
                        details += f"  {col_name} ({col_type}{not_null_str}{default}{primary})\n"
                        
                    # Get indices for this table
                    cursor.execute(f"SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='{item_text}'")
                    indices = cursor.fetchall()
                    
                    if indices:
                        details += "\nIndices:\n"
                        for idx in indices:
                            details += f"  {idx[0]}\n"
                    
                    self.details_text.insert(tk.END, details)
                except sqlite3.OperationalError as e:
                    self.details_text.insert(tk.END, f"Error retrieving table details: {str(e)}")
                
            elif item_type == "Column":
                # Get parent (table) info
                parent_id = self.structure_tree.parent(item_id)
                table_name = self.structure_tree.item(parent_id, "text")
                
                # Get column info
                try:
                    cursor.execute(f"PRAGMA table_info('{table_name}')")
                    columns = cursor.fetchall()
                    
                    column_info = None
                    for col in columns:
                        if col[1] == item_text:
                            column_info = col
                            break
                            
                    if column_info:
                        col_id, col_name, col_type, not_null, default_val, primary_key = column_info
                        
                        details = f"Column: {col_name}\n"
                        details += f"Table: {table_name}\n"
                        details += f"Type: {col_type}\n"
                        details += f"Position: {col_id}\n"
                        details += f"NOT NULL: {'Yes' if not_null == 1 else 'No'}\n"
                        details += f"DEFAULT: {default_val if default_val is not None else 'None'}\n"
                        details += f"PRIMARY KEY: {'Yes' if primary_key == 1 else 'No'}\n"
                        
                        # Check if this column is indexed
                        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='{table_name}'")
                        indices = cursor.fetchall()
                        
                        indexed = []
                        for idx in indices:
                            index_name = idx[0]
                            cursor.execute(f"PRAGMA index_info('{index_name}')")
                            index_columns = cursor.fetchall()
                            
                            for idx_col in index_columns:
                                try:
                                    if int(idx_col[2]) == col_id:
                                        indexed.append(index_name)
                                        break
                                except (ValueError, TypeError):
                                    continue
                                    
                        if indexed:
                            details += f"\nIndices using this column:\n"
                            for idx in indexed:
                                details += f"  {idx}\n"
                        
                        self.details_text.insert(tk.END, details)
                    else:
                        self.details_text.insert(tk.END, f"Column '{item_text}' not found in table '{table_name}'")
                except sqlite3.OperationalError as e:
                    self.details_text.insert(tk.END, f"Error retrieving column details: {str(e)}")
                
            elif item_type == "Index":
                # Get parent (table) info
                parent_id = self.structure_tree.parent(item_id)
                table_name = self.structure_tree.item(parent_id, "text")
                
                # Get index info
                try:
                    cursor.execute(f"PRAGMA index_info('{item_text}')")
                    index_columns = cursor.fetchall()
                    
                    details = f"Index: {item_text}\n"
                    details += f"Table: {table_name}\n"
                    
                    if index_columns:
                        details += f"Columns:\n"
                        
                        # Get table columns
                        cursor.execute(f"PRAGMA table_info('{table_name}')")
                        table_cols = cursor.fetchall()
                        
                        for idx_col in index_columns:
                            seq = idx_col[0]
                            col_id = idx_col[2]
                            try:
                                col_id_int = int(col_id) if col_id is not None else 0
                                if 0 <= col_id_int < len(table_cols):
                                    col_name = table_cols[col_id_int][1]
                                    details += f"  {seq}: {col_name}\n"
                                else:
                                    details += f"  {seq}: Column ID {col_id} (out of range)\n"
                            except (ValueError, TypeError):
                                details += f"  {seq}: Invalid column ID\n"
                    
                    # Check if unique
                    cursor.execute(f"SELECT sql FROM sqlite_master WHERE type='index' AND name='{item_text}'")
                    sql = cursor.fetchone()
                    if sql and sql[0] and "UNIQUE" in sql[0].upper():
                        details += "\nType: UNIQUE INDEX\n"
                    else:
                        details += "\nType: INDEX\n"
                        
                    self.details_text.insert(tk.END, details)
                except sqlite3.OperationalError as e:
                    self.details_text.insert(tk.END, f"Error retrieving index details: {str(e)}")
        
        except Exception as e:
            self.details_text.insert(tk.END, f"Error retrieving details: {str(e)}")
    
    def refresh_tables(self):
        """Refresh the list of tables in the selected database"""
        try:
            # Get the selected database connection
            db_conn = self.get_db_connection()
            if not db_conn:
                self.status_var.set(f"Could not connect to database: {self.db_var.get()}")
                return
                
            # Get list of tables
            cursor = db_conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = [row[0] for row in cursor.fetchall()]
            cursor.close()
            
            # Update combobox
            self.table_combobox['values'] = tables
            
            if tables:
                # Preserve current selection if possible
                current_table = self.table_var.get()
                if current_table in tables:
                    self.table_var.set(current_table)
                else:
                    self.table_var.set(tables[0])
                self.refresh_table_data()
            else:
                self.table_var.set("")
                self.status_var.set("No tables found in database")
                # Clear the results
                for widget in self.results_container.winfo_children():
                    widget.destroy()
                
            self.update_output(f"Found {len(tables)} tables in {self.db_var.get()} database")
            
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            self.update_output(f"Error refreshing tables: {e}")
    
    def refresh_table_data(self):
        """Refresh the data displayed for the selected table"""
        table_name = self.table_var.get()
        if not table_name:
            self.status_var.set("No table selected")
            return
            
        try:
            # Get limit
            try:
                limit = int(self.limit_var.get())
            except ValueError:
                limit = 100
                self.limit_var.set("100")
            
            # Get database connection
            db_conn = self.get_db_connection()
            if not db_conn:
                self.status_var.set(f"Could not connect to database: {self.db_var.get()}")
                return
                
            # Get table schema
            cursor = db_conn.cursor()
            try:
                cursor.execute(f"PRAGMA table_info('{table_name}')")
                schema = cursor.fetchall()
            except sqlite3.OperationalError as e:
                self.status_var.set(f"Error reading table schema: {e}")
                return
                
            # Get total row count
            try:
                cursor.execute(f"SELECT COUNT(*) FROM '{table_name}'")
                total_rows = cursor.fetchone()[0]
            except sqlite3.OperationalError as e:
                total_rows = "N/A"
                self.status_var.set(f"Warning: Could not count rows: {e}")
            
            # Get table data
            try:
                cursor.execute(f"SELECT * FROM '{table_name}' LIMIT {limit}")
                data = cursor.fetchall()
                self.column_names = [col[1] for col in schema]  # Store column names
            except sqlite3.OperationalError as e:
                self.status_var.set(f"Error reading table data: {e}")
                return
                
            # Update table info
            self.update_table_info(table_name, schema, len(data), limit, total_rows)
            
            # Create or update results tree
            self.create_or_update_results_tree(self.results_container, self.column_names, data)
            
            self.status_var.set(f"Loaded {len(data)} rows from {table_name} (total: {total_rows} rows)")
            self.update_output(f"Browsing table {table_name} with {len(data)} rows shown of {total_rows} total")
            
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            self.update_output(f"Error loading table data: {e}")
    
    def run_custom_query(self):
        """Run a custom SQL query"""
        query = self.query_text.get("1.0", tk.END).strip()
        if not query:
            self.status_var.set("No query provided")
            return
            
        # Check for potentially dangerous operations
        dangerous_operations = ["DROP", "DELETE", "UPDATE", "INSERT", "ALTER", "CREATE"]
        if any(op in query.upper() for op in dangerous_operations):
            if not messagebox.askyesno("Warning", 
                                      "This query contains operations that might modify the database. Continue?"):
                return
        
        try:
            # Get database connection
            db_conn = self.get_db_connection()
            if not db_conn:
                self.status_var.set(f"Could not connect to database: {self.db_var.get()}")
                return
                
            # Execute query
            cursor = db_conn.cursor()
            start_time = time.time()
            cursor.execute(query)
            
            # Fetch results if it's a SELECT query
            if query.strip().upper().startswith("SELECT"):
                data = cursor.fetchall()
                column_names = [description[0] for description in cursor.description]
                
                # Create or update query results tree
                self.create_or_update_results_tree(self.query_results_container, column_names, data)
                
                execution_time = time.time() - start_time
                self.status_var.set(f"Query executed in {execution_time:.3f}s, returned {len(data)} rows")
                self.update_output(f"Query executed successfully: {len(data)} rows returned")
            else:
                # For non-SELECT queries
                db_conn.commit()
                execution_time = time.time() - start_time
                rowcount = cursor.rowcount if cursor.rowcount >= 0 else "N/A"
                self.status_var.set(f"Query executed in {execution_time:.3f}s, {rowcount} rows affected")
                self.update_output(f"Query executed successfully: {rowcount} rows affected")
                
                # Create empty results tree
                self.create_or_update_results_tree(self.query_results_container, [], [])
            
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            self.update_output(f"Error executing query: {e}")
    
    def export_table_to_csv(self):
        """Export the current table data to CSV"""
        table_name = self.table_var.get()
        if not table_name:
            self.status_var.set("No table selected")
            return
            
        try:
            # Ask for filename to save
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile=f"{table_name}.csv"
            )
            
            if not filename:
                return  # User cancelled
                
            # Get database connection
            db_conn = self.get_db_connection()
            if not db_conn:
                self.status_var.set(f"Could not connect to database: {self.db_var.get()}")
                return
                
            # Get table data
            cursor = db_conn.cursor()
            try:
                cursor.execute(f"SELECT * FROM '{table_name}'")
                data = cursor.fetchall()
                column_names = [description[0] for description in cursor.description]
            except sqlite3.OperationalError as e:
                self.status_var.set(f"Error reading table data: {e}")
                return
                
            # Write to CSV
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(column_names)  # Write header
                writer.writerows(data)  # Write data
                
            self.status_var.set(f"Exported {len(data)} rows to {filename}")
            self.update_output(f"Exported table {table_name} to {filename}")
            
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            self.update_output(f"Error exporting table: {e}")
    
    def export_query_results(self):
        """Export the current query results to CSV"""
        # Check if we have any results
        if not hasattr(self, 'query_results_tree') or not self.query_results_tree.get_children():
            self.status_var.set("No query results to export")
            return
            
        try:
            # Ask for filename to save
            filename = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
                initialfile="query_results.csv"
            )
            
            if not filename:
                return  # User cancelled
                
            # Get the data from the tree
            data = []
            for item_id in self.query_results_tree.get_children():
                data.append(self.query_results_tree.item(item_id, 'values'))
            
            # Get column names
            column_names = []
            for col in self.query_results_tree['columns']:
                column_names.append(self.query_results_tree.heading(col, 'text'))
            
            # Write to CSV
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(column_names)  # Write header
                writer.writerows(data)  # Write data
                
            self.status_var.set(f"Exported {len(data)} rows to {filename}")
            self.update_output(f"Exported query results to {filename}")
            
        except Exception as e:
            self.status_var.set(f"Error: {e}")
            self.update_output(f"Error exporting query results: {e}")
    
    def get_db_connection(self):
        """Get the selected database connection"""
        db_type = self.db_var.get()
        
        try:
            # Check for standard database connections
            if db_type == "capture":
                if hasattr(self.gui, 'db_manager') and hasattr(self.gui.db_manager, 'capture_conn'):
                    return self.gui.db_manager.capture_conn
            elif db_type == "analysis":
                if hasattr(self.gui, 'db_manager') and hasattr(self.gui.db_manager, 'analysis_conn'):
                    return self.gui.db_manager.analysis_conn
            elif db_type == "analysis_1":
                if hasattr(self.gui, 'analysis_manager') and hasattr(self.gui.analysis_manager, 'analysis1_conn'):
                    return self.gui.analysis_manager.analysis1_conn
                    
            # If we couldn't find a standard connection, try to create a new connection
            if hasattr(self.gui, 'config') and 'database_dir' in self.gui.config:
                db_path = os.path.join(self.gui.config['database_dir'], f"{db_type}.db")
                if os.path.exists(db_path):
                    conn = sqlite3.connect(db_path)
                    # Enable foreign keys
                    conn.execute("PRAGMA foreign_keys = ON")
                    return conn
                    
            # Final fallback - try to connect to a database in the current directory
            db_path = f"{db_type}.db"
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                # Enable foreign keys
                conn.execute("PRAGMA foreign_keys = ON")
                return conn
                
            # If we get here, we couldn't connect to the database
            self.status_var.set(f"Could not connect to database: {db_type}")
            return None
            
        except Exception as e:
            self.status_var.set(f"Error connecting to database: {e}")
            return None
    
    def update_table_info(self, table_name, schema, row_count, limit, total_rows):
        """Update the table information text"""
        self.table_info_text.delete("1.0", tk.END)
        
        info = f"Table: {table_name}\n"
        info += f"Total Rows: {total_rows}\n"
        info += f"Total Columns: {len(schema)}\n"
        info += f"Displaying: {row_count}"
        if row_count == limit and total_rows > limit:
            info += f" (limited to {limit})\n"
        else:
            info += "\n"
            
        info += "Columns:\n"
        for col in schema:
            col_id, col_name, col_type, not_null, default_val, primary_key = col
            primary = " (PRIMARY KEY)" if primary_key == 1 else ""
            not_null_str = " NOT NULL" if not_null == 1 else ""
            default = f" DEFAULT {default_val}" if default_val is not None else ""
            info += f"  {col_name} ({col_type}{not_null_str}{default}{primary})\n"
            
        self.table_info_text.insert(tk.END, info)
    
    def create_or_update_results_tree(self, container, column_names, data):
        """Create or update a results tree with the given data"""
        # Clear existing widgets in container
        for widget in container.winfo_children():
            widget.destroy()
            
        # Create a frame for the tree and scrollbars
        frame = ttk.Frame(container)
        frame.pack(fill="both", expand=True)
        
        # Create vertical scrollbar
        vsb = ttk.Scrollbar(frame, orient="vertical")
        vsb.pack(side="right", fill="y")
        
        # Create horizontal scrollbar
        hsb = ttk.Scrollbar(frame, orient="horizontal")
        hsb.pack(side="bottom", fill="x")
        
        # Create tree with scrollbars
        tree = ttk.Treeview(frame, columns=column_names, show="headings",
                           yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        
        # Configure scrollbars
        vsb.config(command=tree.yview)
        hsb.config(command=tree.xview)
        
        # Set up column headings
        for col in column_names:
            tree.heading(col, text=col)
            tree.column(col, width=100)  # Default width
            
        # Add data to tree
        for row in data:
            # Convert any non-string values to strings to avoid display issues
            formatted_row = []
            for item in row:
                if item is None:
                    formatted_row.append("")
                else:
                    formatted_row.append(str(item))
            tree.insert("", "end", values=formatted_row)
            
        tree.pack(fill="both", expand=True)
        
        # Store reference to the tree
        if container == self.results_container:
            self.results_tree = tree
        else:
            self.query_results_tree = tree
            
    def refresh(self):
        """Refresh data based on current tab"""
        # First refresh the database list
        self.refresh_databases()
        
        # Then refresh the current tab
        current_tab = self.browser_notebook.index(self.browser_notebook.select())
        
        if current_tab == 0:  # Table Browser tab
            self.refresh_tables()
        elif current_tab == 1:  # Custom Query tab
            pass  # Custom queries are refreshed manually
        elif current_tab == 2:  # Database Structure tab
            self.refresh_db_structure()