import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import csv
import time
import sqlite3
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
        self.db_var = tk.StringVar(value="analysis")
        self.limit_var = tk.StringVar(value="100")
        self.status_var = tk.StringVar(value="Ready")
        self.column_names = []
        
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
        
        # Status bar
        status_frame = ttk.Frame(self.tab_frame)
        status_frame.pack(fill="x", side="bottom")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side="left", padx=5)
        
    def create_table_browser(self):
        """Create the table browser UI"""
        # Control panel
        control_frame = ttk.Frame(self.table_browser_tab)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        # Database selection
        ttk.Label(control_frame, text="Database:").pack(side="left", padx=5)
        db_combobox = ttk.Combobox(control_frame, textvariable=self.db_var, 
                                  values=["capture", "analysis"], width=10, state="readonly")
        db_combobox.pack(side="left", padx=5)
        db_combobox.bind("<<ComboboxSelected>>", lambda e: self.refresh_tables())
        
        # Table selection
        ttk.Label(control_frame, text="Table:").pack(side="left", padx=5)
        self.table_combobox = ttk.Combobox(control_frame, textvariable=self.table_var, width=20)
        self.table_combobox.pack(side="left", padx=5)
        self.table_combobox.bind("<<ComboboxSelected>>", lambda e: self.refresh_table_data())
        
        # Limit entries
        ttk.Label(control_frame, text="Limit:").pack(side="left", padx=5)
        ttk.Entry(control_frame, textvariable=self.limit_var, width=6).pack(side="left", padx=5)
        
        # Actions
        ttk.Button(control_frame, text="Refresh Tables", 
                  command=self.refresh_tables).pack(side="right", padx=5)
        ttk.Button(control_frame, text="Refresh Data", 
                  command=self.refresh_table_data).pack(side="right", padx=5)
        ttk.Button(control_frame, text="Export to CSV", 
                  command=self.export_table_to_csv).pack(side="right", padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(self.table_browser_tab, text="Table Data")
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Placeholder for results tree - will be created when a table is selected
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
        
        ttk.Label(db_frame, text="Database:").pack(side="left", padx=5)
        query_db_combobox = ttk.Combobox(db_frame, textvariable=self.db_var, 
                                        values=["capture", "analysis"], width=10, state="readonly")
        query_db_combobox.pack(side="left", padx=5)
        
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
        
    def refresh_tables(self):
        """Refresh the list of tables in the selected database"""
        try:
            # Get the selected database connection
            db_conn = self.get_db_connection()
            
            # Get list of tables
            cursor = db_conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            tables = [row[0] for row in cursor.fetchall()]
            cursor.close()
            
            # Update combobox
            self.table_combobox['values'] = tables
            
            if tables:
                self.table_var.set(tables[0])
                self.refresh_table_data()
            else:
                self.table_var.set("")
                self.status_var.set("No tables found in database")
                
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
            
            # Get table schema
            cursor = db_conn.cursor()
            cursor.execute(f"PRAGMA table_info({table_name})")
            schema = cursor.fetchall()
            
            # Get table data
            cursor.execute(f"SELECT * FROM {table_name} LIMIT {limit}")
            data = cursor.fetchall()
            self.column_names = [col[1] for col in schema]  # Store column names
            
            # Update table info
            self.update_table_info(table_name, schema, len(data), limit)
            
            # Create or update results tree
            self.create_or_update_results_tree(self.results_container, self.column_names, data)
            
            self.status_var.set(f"Loaded {len(data)} rows from {table_name}")
            self.update_output(f"Browsing table {table_name} with {len(data)} rows")
            
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
                self.status_var.set(f"Query executed in {execution_time:.3f}s, {cursor.rowcount} rows affected")
                self.update_output(f"Query executed successfully: {cursor.rowcount} rows affected")
                
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
            
            # Get table data
            cursor = db_conn.cursor()
            cursor.execute(f"SELECT * FROM {table_name}")
            data = cursor.fetchall()
            column_names = [description[0] for description in cursor.description]
            
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
        if db_type == "capture":
            return self.gui.db_manager.capture_conn
        else:  # default to analysis
            return self.gui.db_manager.analysis_conn
    
    def update_table_info(self, table_name, schema, row_count, limit):
        """Update the table information text"""
        self.table_info_text.delete("1.0", tk.END)
        
        info = f"Table: {table_name}\n"
        info += f"Rows: {row_count}"
        if row_count == limit:
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
            tree.insert("", "end", values=row)
            
        tree.pack(fill="both", expand=True)
        
        # Store reference to the tree
        if container == self.results_container:
            self.results_tree = tree
        else:
            self.query_results_tree = tree
            
    def refresh(self):
        """Refresh data based on current tab"""
        current_tab = self.browser_notebook.index(self.browser_notebook.select())
        
        if current_tab == 0:  # Table Browser tab
            self.refresh_table_data()
        else:  # Custom Query tab
            self.run_custom_query()