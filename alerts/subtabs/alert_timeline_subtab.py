# SubtabBase class is injected by the Loader
import time
import datetime
from collections import defaultdict

class AlertTimelineSubtab(SubtabBase):
    """Subtab that visualizes alerts over time to identify patterns and trends"""
    
    def __init__(self):
        super().__init__(
            name="Alert Timeline",
            description="Visualizes alert patterns over time"
        )
        self.timeline_canvas = None
        self.time_range_var = None
        self.selected_alert_type_var = None
        self.details_tree = None
        self.alert_types = []
        self.timeline_data = {}
        self.current_time_range = "24h"
        self.chart_height = 200
        self.time_markers = []
        self.alert_type_colors = {
            # Default colors for different alert types
            "Large Data Transfer Detector": "#3498db",  # Blue
            "Local Threat Intelligence": "#e74c3c",    # Red
            "Suspicious HTTP Traffic": "#f39c12",      # Orange
            "Time-Based Access Detection": "#9b59b6",  # Purple
            "SSL Certificate Validation": "#2ecc71",   # Green
            "default": "#95a5a6"                       # Gray
        }
        self.canvas_padding = 60  # Padding for canvas to ensure labels are visible
    
    def create_ui(self):
        """Create user interface components for Alert Timeline subtab"""
        # Control buttons frame
        control_frame = ttk.Frame(self.tab_frame)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        # Time range selector
        ttk.Label(control_frame, text="Time Range:").pack(side="left", padx=5)
        self.time_range_var = tk.StringVar(value="24h")
        time_range_combo = ttk.Combobox(control_frame, 
                                        textvariable=self.time_range_var,
                                        values=["1h", "6h", "12h", "24h", "7d", "30d", "All"],
                                        width=5,
                                        state="readonly")
        time_range_combo.pack(side="left", padx=5)
        time_range_combo.bind("<<ComboboxSelected>>", self.on_time_range_changed)
        
        # Alert type filter
        ttk.Label(control_frame, text="Alert Type:").pack(side="left", padx=5)
        self.selected_alert_type_var = tk.StringVar(value="All Types")
        self.alert_type_combo = ttk.Combobox(control_frame, 
                                             textvariable=self.selected_alert_type_var,
                                             width=25,
                                             state="readonly")
        self.alert_type_combo.pack(side="left", padx=5)
        self.alert_type_combo.bind("<<ComboboxSelected>>", self.on_alert_type_changed)
        
        # Refresh button
        ttk.Button(control_frame, text="Refresh Timeline", 
                  command=self.refresh).pack(side="right", padx=5)
        
        # Timeline visualization frame
        viz_frame = ttk.LabelFrame(self.tab_frame, text="Alert Timeline")
        viz_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Create a main timeline container frame with proper padding
        timeline_container = ttk.Frame(viz_frame)
        timeline_container.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Y-axis canvas - positioned on the left
        self.y_axis_canvas = tk.Canvas(timeline_container, bg="white", width=50, height=self.chart_height)
        self.y_axis_canvas.pack(side="left", fill="y")
        
        # Timeline canvas frame - this will contain the scrollable canvas
        timeline_frame = ttk.Frame(timeline_container)
        timeline_frame.pack(side="left", fill="both", expand=True)
        
        # Canvas for timeline visualization
        self.timeline_canvas = tk.Canvas(timeline_frame, bg="white", height=self.chart_height)
        self.timeline_canvas.pack(fill="both", expand=True)
        
        # Add a horizontal scrollbar for the timeline
        timeline_scrollbar = ttk.Scrollbar(timeline_frame, orient="horizontal", command=self.timeline_canvas.xview)
        timeline_scrollbar.pack(fill="x")
        self.timeline_canvas.configure(xscrollcommand=timeline_scrollbar.set)
        
        # Add event binding for timeline
        self.timeline_canvas.bind("<ButtonRelease-1>", self.on_timeline_click)
        
        # Create alert details frame
        details_frame = ttk.LabelFrame(self.tab_frame, text="Alerts for Selected Time Period")
        details_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        # Alert details tree
        self.details_tree, _ = gui.tab_factory.create_tree_with_scrollbar(
            details_frame,
            columns=("timestamp", "rule", "ip", "alert"),
            headings=["Timestamp", "Rule", "IP Address", "Alert Message"],
            widths=[150, 180, 120, 400],
            height=8
        )
        
        # Stats frame for summary information
        stats_frame = ttk.LabelFrame(self.tab_frame, text="Alert Statistics")
        stats_frame.pack(fill="x", padx=10, pady=5)
        
        # Statistics grid
        self.stats_labels = {}
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill="x", padx=5, pady=5)
        
        for i, stat in enumerate([
            "Total Alerts:", "Peak Time:", "Most Common Rule:", 
            "Most Targeted IP:", "Alert Density:", "Quietest Period:"
        ]):
            row, col = divmod(i, 3)
            ttk.Label(stats_grid, text=stat).grid(row=row, column=col*2, sticky="w", padx=5, pady=2)
            self.stats_labels[stat] = ttk.Label(stats_grid, text="--")
            self.stats_labels[stat].grid(row=row, column=col*2+1, sticky="w", padx=5, pady=2)
        
        # Make columns expandable
        for i in range(6):
            stats_grid.columnconfigure(i, weight=1)
        
        # Create legend for alert types
        self.legend_frame = ttk.Frame(stats_frame)
        self.legend_frame.pack(fill="x", padx=5, pady=5)
        ttk.Label(self.legend_frame, text="Legend:").pack(side="left", padx=5)
    
    def on_time_range_changed(self, event):
        """Handle time range change"""
        self.current_time_range = self.time_range_var.get()
        self.refresh()
    
    def on_alert_type_changed(self, event):
        """Handle alert type filter change"""
        self.refresh()
    
    def on_timeline_click(self, event):
        """Handle click on timeline to show alerts for that time period"""
        # Get x coordinate of click
        x = self.timeline_canvas.canvasx(event.x)
        
        # Find the closest time marker
        closest_marker = None
        min_distance = float('inf')
        for marker, time_val in self.time_markers:
            marker_x = int(marker.split()[0])  # Marker is stored as "x y" coordinates
            distance = abs(marker_x - x)
            if distance < min_distance:
                min_distance = distance
                closest_marker = time_val
        
        if closest_marker and min_distance < 20:  # Within reasonable clicking distance
            # Query alerts for this time period
            self.show_alerts_for_time(closest_marker)
    
    def show_alerts_for_time(self, timestamp):
        """Show alerts for a specific time period"""
        # Clear the details tree
        gui.tree_manager.clear_tree(self.details_tree)
        
        # Format timestamp for display
        time_str = datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        
        # Get time window based on current range
        if self.current_time_range == "1h":
            window = 3600
        elif self.current_time_range == "6h":
            window = 21600
        elif self.current_time_range == "12h":
            window = 43200
        elif self.current_time_range == "24h":
            window = 86400
        elif self.current_time_range == "7d":
            window = 604800
        elif self.current_time_range == "30d":
            window = 2592000
        else:
            window = 86400  # Default to 24h
        
        # Calculate start and end times for the window
        end_time = timestamp + (window / 2)
        start_time = timestamp - (window / 2)
        
        # Format time range for query
        start_str = datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
        end_str = datetime.datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S')
        
        # Query alerts in this time window using analysis_manager
        gui.analysis_manager.queue_query(
            lambda: self._get_alerts_in_timeframe(start_time, end_time),
            lambda rows: self._update_details_tree(rows, time_str)
        )
    
    def _get_alerts_in_timeframe(self, start_time, end_time):
        """Get alerts in a specific timeframe from analysis_1.db"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            
            # Format time range for query
            start_str = datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
            end_str = datetime.datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S')
            
            # Create SQL query
            sql = """
                SELECT timestamp, rule_name, ip_address, alert_message
                FROM alerts
                WHERE timestamp BETWEEN ? AND ?
            """
            
            # Add alert type filter if selected
            selected_type = self.selected_alert_type_var.get()
            if selected_type != "All Types":
                sql += " AND rule_name = ?"
                params = (start_str, end_str, selected_type)
            else:
                params = (start_str, end_str)
            
            sql += " ORDER BY timestamp DESC"
            
            # Execute query
            rows = cursor.execute(sql, params).fetchall()
            cursor.close()
            return rows
        except Exception as e:
            gui.update_output(f"Error getting alerts in timeframe: {e}")
            return []
    
    def _update_details_tree(self, rows, time_str):
        """Update details tree with alerts for selected time period"""
        if not rows:
            self.update_output(f"No alerts found for time period around {time_str}")
            return
        
        # Format data for the tree
        formatted_rows = []
        for timestamp, rule_name, ip_address, alert_message in rows:
            formatted_rows.append((timestamp, rule_name, ip_address, alert_message))
        
        # Populate tree
        gui.tree_manager.populate_tree(self.details_tree, formatted_rows)
        self.update_output(f"Showing {len(rows)} alerts for time period around {time_str}")
    
    def refresh(self):
        """Refresh the timeline visualization"""
        # Clear the canvas
        self.timeline_canvas.delete("all")
        self.y_axis_canvas.delete("all")
        self.time_markers = []
        
        # Clear and rebuild the legend
        for widget in self.legend_frame.winfo_children()[1:]:  # Keep the "Legend:" label
            widget.destroy()
        
        # First, get all rule types for the alert type combo
        # Use analysis_manager instead of db_manager
        gui.analysis_manager.queue_query(
            self._get_alert_types,
            self._update_alert_types
        )
        
        # Get timeline data
        self._get_timeline_data()
    
    def _get_alert_types(self):
        """Get alert types from analysis_1.db"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            rule_types = cursor.execute("SELECT DISTINCT rule_name FROM alerts ORDER BY rule_name").fetchall()
            cursor.close()
            return rule_types
        except Exception as e:
            gui.update_output(f"Error getting alert types: {e}")
            return []
    
    def _update_alert_types(self, rule_types):
        """Update the alert type combobox"""
        self.alert_types = [row[0] for row in rule_types]
        self.alert_type_combo['values'] = ["All Types"] + self.alert_types
        
        # Add legend items
        for i, rule_type in enumerate(self.alert_types):
            color = self.alert_type_colors.get(rule_type, self.alert_type_colors['default'])
            
            # Create frame for this legend item
            legend_item = ttk.Frame(self.legend_frame)
            legend_item.pack(side="left", padx=10)
            
            # Color box
            color_canvas = tk.Canvas(legend_item, width=12, height=12, highlightthickness=0)
            color_canvas.pack(side="left")
            color_canvas.create_rectangle(0, 0, 12, 12, fill=color, outline="")
            
            # Rule name (abbreviated if needed)
            short_name = rule_type
            if len(short_name) > 15:
                short_name = short_name[:13] + "..."
            ttk.Label(legend_item, text=short_name).pack(side="left", padx=2)
    
    def _get_timeline_data(self):
        """Get data for the timeline visualization"""
        # Calculate time range
        now = time.time()
        if self.current_time_range == "1h":
            start_time = now - 3600
            interval = "5 minutes"
            interval_seconds = 300
            format_str = "%H:%M"
        elif self.current_time_range == "6h":
            start_time = now - 21600
            interval = "30 minutes"
            interval_seconds = 1800
            format_str = "%H:%M"
        elif self.current_time_range == "12h":
            start_time = now - 43200
            interval = "1 hour"
            interval_seconds = 3600
            format_str = "%H:%M"
        elif self.current_time_range == "24h":
            start_time = now - 86400
            interval = "2 hours"
            interval_seconds = 7200
            format_str = "%m-%d %H:%M"
        elif self.current_time_range == "7d":
            start_time = now - 604800
            interval = "12 hours"
            interval_seconds = 43200
            format_str = "%m-%d"
        elif self.current_time_range == "30d":
            start_time = now - 2592000
            interval = "1 day"
            interval_seconds = 86400
            format_str = "%m-%d"
        elif self.current_time_range == "All":
            # Get earliest alert time or default to 30 days
            gui.analysis_manager.queue_query(
                self._get_earliest_alert_time,
                lambda start_t: self._continue_timeline_data(start_t, now, format_str)
            )
            return  # Early return - will continue after getting earliest time
        else:
            # Default to 24h
            start_time = now - 86400
            interval = "2 hours"
            interval_seconds = 7200
            format_str = "%m-%d %H:%M"
        
        # Standard flow - continue with timeline data 
        self._continue_timeline_data(start_time, now, format_str, interval_seconds)
    
    def _get_earliest_alert_time(self):
        """Get earliest alert time from analysis_1.db"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            earliest = cursor.execute("SELECT MIN(timestamp) FROM alerts").fetchone()[0]
            cursor.close()
            
            now = time.time()
            if earliest:
                try:
                    # Try to parse as datetime string
                    dt = datetime.datetime.strptime(earliest, '%Y-%m-%d %H:%M:%S')
                    return dt.timestamp()
                except (ValueError, TypeError):
                    # If it's not a datetime string, it might be a timestamp
                    try:
                        return float(earliest)
                    except:
                        return now - 2592000  # Default to 30 days
            return now - 2592000  # Default to 30 days
        except Exception as e:
            gui.update_output(f"Error getting earliest alert time: {e}")
            return time.time() - 2592000  # Default to 30 days
    
    def _continue_timeline_data(self, start_time, now, format_str, interval_seconds=None):
        """Continue with timeline data after potentially getting earliest time"""
        # For "All" time range, calculate interval based on total time span
        if interval_seconds is None:
            interval_seconds = max(86400, int((now - start_time) / 20))  # At most 20 intervals
        
        # Convert start time to formatted string for SQLite
        start_time_str = datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
        
        # Queue the timeline data query using analysis_manager
        gui.analysis_manager.queue_query(
            lambda: self._query_timeline_data(start_time_str, interval_seconds),
            lambda rows: self._draw_timeline(rows, start_time, now, interval_seconds, format_str)
        )
    
    def _query_timeline_data(self, start_time_str, interval_seconds):
        """Query timeline data from analysis_1.db"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            
            # Construct SQL query
            sql = """
                SELECT 
                    strftime('%Y-%m-%d %H:%M:%S', 
                        datetime(timestamp, 'localtime', 'start of day', 
                        '+' || ((strftime('%H', timestamp, 'localtime') * 3600 + 
                        strftime('%M', timestamp, 'localtime') * 60 + 
                        strftime('%S', timestamp, 'localtime')) / ? * ?) || ' seconds')) as time_slot,
                    rule_name,
                    COUNT(*) as alert_count
                FROM alerts
                WHERE timestamp >= ?
            """
            
            # Add filter for alert type if selected
            selected_type = self.selected_alert_type_var.get()
            if selected_type != "All Types":
                sql += " AND rule_name = ?"
                params = (interval_seconds, interval_seconds, start_time_str, selected_type)
            else:
                params = (interval_seconds, interval_seconds, start_time_str)
            
            # Group by time slot and rule
            sql += " GROUP BY time_slot, rule_name ORDER BY time_slot, rule_name"
            
            rows = cursor.execute(sql, params).fetchall()
            cursor.close()
            return rows
        except Exception as e:
            gui.update_output(f"Error querying timeline data: {e}")
            return []
    
    def _draw_timeline(self, rows, start_time, end_time, interval_seconds, time_format):
        """Draw the timeline visualization based on the retrieved data"""
        if not rows:
            self.timeline_canvas.create_text(
                self.timeline_canvas.winfo_width() // 2, 
                self.chart_height // 2,
                text="No data available for selected time range",
                fill="gray"
            )
            
            # Update stats
            for label in self.stats_labels.values():
                label.config(text="--")
            
            return
        
        # Process data for visualization
        time_slots = {}
        rule_totals = defaultdict(int)
        total_alerts = 0
        max_count = 0
        
        # Pre-process into time slots
        for time_slot_str, rule_name, count in rows:
            # Convert time slot string to timestamp
            try:
                time_slot = datetime.datetime.strptime(time_slot_str, '%Y-%m-%d %H:%M:%S').timestamp()
            except ValueError:
                try:
                    # SQLite might return different format
                    time_slot = datetime.datetime.strptime(time_slot_str, '%Y-%m-%d %H:%M').timestamp()
                except ValueError:
                    # Last resort - try another format or use the string's hash
                    time_slot = hash(time_slot_str) % 1000000 + start_time
            
            # Initialize time slot if needed
            if time_slot not in time_slots:
                time_slots[time_slot] = defaultdict(int)
            
            # Add count for this rule
            time_slots[time_slot][rule_name] += count
            rule_totals[rule_name] += count
            total_alerts += count
            
            # Track max count for Y-axis scaling
            slot_total = sum(time_slots[time_slot].values())
            max_count = max(max_count, slot_total)
        
        # Sort time slots by timestamp
        sorted_slots = sorted(time_slots.items())
        
        # Ensure we have at least one data point
        if not sorted_slots:
            self.timeline_canvas.create_text(
                self.timeline_canvas.winfo_width() // 2, 
                self.chart_height // 2,
                text="No data available for selected time range",
                fill="gray"
            )
            return
        
        # Compute canvas dimensions - ensure enough space for all time slots
        num_slots = len(sorted_slots)
        slot_width = 80  # Default width per slot
        
        # Calculate required width with padding
        required_width = max(800, num_slots * slot_width + self.canvas_padding * 2)
        
        # Configure scrollable area
        self.timeline_canvas.config(scrollregion=(0, 0, required_width, self.chart_height))
        
        # Clear Y-axis canvas and redraw
        self.y_axis_canvas.delete("all")
        
        # Calculate scale for Y axis (add 10% headroom)
        y_scale = (self.chart_height - 40) / (max_count * 1.1) if max_count > 0 else 1
        
        # Draw Y axis labels and tick marks
        y_axis_step = max(1, max_count // 5)  # At most 5 y-axis labels
        
        for i in range(0, max_count + y_axis_step, y_axis_step):
            y_pos = self.chart_height - 20 - (i * y_scale)
            if y_pos < 20:  # Skip if too close to top
                continue
                
            # Draw tick mark and label
            self.y_axis_canvas.create_line(35, y_pos, 50, y_pos)
            self.y_axis_canvas.create_text(25, y_pos, text=str(i), anchor="e")
        
        # Draw X axis line
        self.timeline_canvas.create_line(
            self.canvas_padding, self.chart_height - 20, 
            required_width - self.canvas_padding, self.chart_height - 20, 
            width=1
        )
        
        # Calculate actual slot width based on available space
        usable_width = required_width - self.canvas_padding * 2
        slot_width = min(80, usable_width / num_slots)
        
        # Track statistics for the stats panel
        peak_time = None
        peak_count = 0
        quietest_time = None
        quietest_count = float('inf')
        
        # Draw data bars for each time slot
        for i, (time_slot, rules_data) in enumerate(sorted_slots):
            # Calculate x position with padding
            x = self.canvas_padding + i * slot_width
            
            # Store time marker for click interaction
            marker_pos = f"{x} {self.chart_height - 20}"
            self.time_markers.append((marker_pos, time_slot))
            
            # Format time label
            time_label = datetime.datetime.fromtimestamp(time_slot).strftime(time_format)
            
            # Determine if we should rotate labels (if lots of time slots)
            if num_slots > 10:
                # Draw rotated label with extra space
                self.timeline_canvas.create_text(
                    x, self.chart_height - 5, 
                    text=time_label, 
                    angle=45,
                    anchor="ne"
                )
            else:
                # Draw normal label
                self.timeline_canvas.create_text(
                    x, self.chart_height - 5, 
                    text=time_label, 
                    anchor="n"
                )
            
            # Draw tick mark
            self.timeline_canvas.create_line(
                x, self.chart_height - 20, 
                x, self.chart_height - 15
            )
            
            # Calculate total for this slot for statistics
            slot_total = sum(rules_data.values())
            
            # Track peak and quietest times
            if slot_total > peak_count:
                peak_count = slot_total
                peak_time = time_slot
            
            if slot_total < quietest_count and slot_total > 0:
                quietest_count = slot_total
                quietest_time = time_slot
            
            # Draw stacked bars for each rule type
            y_offset = self.chart_height - 20
            for rule_name, count in sorted(rules_data.items()):
                # Get color for this rule type
                color = self.alert_type_colors.get(rule_name, self.alert_type_colors['default'])
                
                # Calculate bar height
                bar_height = count * y_scale
                
                # Make sure bar is at least 2 pixels high if count > 0
                if count > 0 and bar_height < 2:
                    bar_height = 2
                
                # Draw the bar with smaller width to avoid overlap
                bar_width = slot_width * 0.8
                self.timeline_canvas.create_rectangle(
                    x - bar_width/2, y_offset - bar_height,
                    x + bar_width/2, y_offset,
                    fill=color, outline="white", width=1
                )
                
                # Update y_offset for next bar in stack
                y_offset -= bar_height
        
        # Update statistics with data from analysis_1.db
        if total_alerts > 0:
            # Most common rule
            most_common_rule = max(rule_totals.items(), key=lambda x: x[1])
            
            # Query for most targeted IP using analysis_manager
            gui.analysis_manager.queue_query(
                lambda: self._get_most_targeted_ip(start_time),
                self._update_most_targeted_ip_stat
            )
            
            # Calculate alert density (alerts per hour)
            time_range_hours = (end_time - start_time) / 3600
            alert_density = total_alerts / time_range_hours
            
            # Update the statistics labels
            self.stats_labels["Total Alerts:"].config(text=str(total_alerts))
            
            if peak_time:
                peak_time_str = datetime.datetime.fromtimestamp(peak_time).strftime('%Y-%m-%d %H:%M')
                self.stats_labels["Peak Time:"].config(text=f"{peak_time_str} ({peak_count} alerts)")
            
            if quietest_time:
                quietest_time_str = datetime.datetime.fromtimestamp(quietest_time).strftime('%Y-%m-%d %H:%M')
                self.stats_labels["Quietest Period:"].config(text=f"{quietest_time_str} ({quietest_count} alerts)")
                
            # Truncate rule name if too long
            rule_name = most_common_rule[0]
            if len(rule_name) > 15:
                rule_name = rule_name[:15] + "..."
                
            self.stats_labels["Most Common Rule:"].config(
                text=f"{rule_name} ({most_common_rule[1]})"
            )
            
            self.stats_labels["Alert Density:"].config(text=f"{alert_density:.2f} alerts/hour")
        
        self.update_output(f"Timeline updated with {total_alerts} alerts across {len(sorted_slots)} time periods")
    
    def _get_most_targeted_ip(self, start_time):
        """Get most targeted IP from analysis_1.db"""
        try:
            cursor = gui.analysis_manager.get_cursor()
            
            start_time_str = datetime.datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S')
            sql = """
                SELECT ip_address, COUNT(*) as count
                FROM alerts
                WHERE timestamp >= ?
            """
            
            if self.selected_alert_type_var.get() != "All Types":
                sql += " AND rule_name = ?"
                params = (start_time_str, self.selected_alert_type_var.get())
            else:
                params = (start_time_str,)
                
            sql += " GROUP BY ip_address ORDER BY count DESC LIMIT 1"
            
            result = cursor.execute(sql, params).fetchone()
            cursor.close()
            return result if result else ("None", 0)
        except Exception as e:
            gui.update_output(f"Error getting most targeted IP: {e}")
            return ("Error", 0)
    
    def _update_most_targeted_ip_stat(self, result):
        """Update most targeted IP statistic"""
        if result:
            ip, count = result
            self.stats_labels["Most Targeted IP:"].config(text=f"{ip} ({count})")
        else:
            self.stats_labels["Most Targeted IP:"].config(text="--")