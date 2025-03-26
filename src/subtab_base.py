import tkinter as tk
from tkinter import ttk
import logging

class SubtabBase:
    """Base class for alert subtab plugins"""
    
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.gui = None  # Will be set by SubtabLoader
        self.tab_frame = None
    
    def initialize(self, parent_notebook):
        """Initialize the subtab UI in the parent notebook"""
        self.tab_frame = ttk.Frame(parent_notebook)
        parent_notebook.add(self.tab_frame, text=self.name)
        self.create_ui()
        return self.tab_frame
    
    def create_ui(self):
        """Create UI components - must be implemented by subclasses"""
        raise NotImplementedError("Subtab plugins must implement create_ui method")
    
    def refresh(self):
        """Refresh data display - must be implemented by subclasses"""
        raise NotImplementedError("Subtab plugins must implement refresh method")
    
    def on_tab_selected(self):
        """Called when this tab is selected"""
        self.refresh()
        
    def update_output(self, message):
        """Shortcut to update the output window"""
        if self.gui:
            self.gui.update_output(message)
        else:
            logging.info(message)