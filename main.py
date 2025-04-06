import tkinter as tk
import sys
import os
import logging
from tkinter import messagebox

# Add src folder to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def setup_directories():
    """Create necessary application directories"""
    app_root = os.path.dirname(os.path.abspath(__file__))
    
    # Create required directories
    dirs = {
        "logs": os.path.join(app_root, "logs"),
        "db": os.path.join(app_root, "db"),
        "rules": os.path.join(app_root, "rules"),
        "alerts": os.path.join(app_root, "alerts"),
        "alerts/subtabs": os.path.join(app_root, "alerts", "subtabs")
    }
    
    for dir_name, dir_path in dirs.items():
        os.makedirs(dir_path, exist_ok=True)
        print(f"Ensuring {dir_name} directory exists at {dir_path}")
    
    # Setup logging
    log_file = os.path.join(dirs["logs"], "traffic_analyzer.log")
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Also log to console
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    
    logging.info("Application starting up - directories initialized")
    
    return app_root

def main():
    """Main application entry point"""
    # Setup directories first
    app_root = setup_directories()
    
    # Create main window
    root = tk.Tk()
    root.geometry("950x700")
    root.title("Traffic Monkey")
    
    try:
        # Set icon if available
        if sys.platform.startswith('win'):
            icon_path = os.path.join(app_root, "icons", "app_icon.ico")
            if os.path.exists(icon_path):
                root.iconbitmap(icon_path)
        else:
            icon_path = os.path.join(app_root, "icons", "app_icon.png")
            if os.path.exists(icon_path):
                img = tk.PhotoImage(file=icon_path)
                root.iconphoto(True, img)
    except Exception as e:
        logging.warning(f"Could not set application icon: {e}")
    
    # Import necessary components directly
    try:
        # Import the database manager first
        from src.database_manager import DatabaseManager
        
        # Create the database manager first
        db_manager = DatabaseManager(app_root)
        
        # Import and initialize the analysis manager in the background
        # but don't integrate it with the main app yet
        try:
            from src.analysis_manager import AnalysisManager
            analysis_manager = AnalysisManager(app_root, db_manager)
            logging.info("Analysis manager initialized in parallel mode")
        except Exception as e:
            logging.warning(f"Could not initialize analysis manager: {e}")
        
        # Create LiveCaptureGUI with pre-initialized database manager
        from src.traffic_analyzer import LiveCaptureGUI
        
        # Create the application with the database manager only (no analysis manager yet)
        app = LiveCaptureGUI(root, db_manager)
        
        # Start the main event loop
        root.mainloop()
    except Exception as e:
        logging.error(f"Error starting application: {e}", exc_info=True)
        messagebox.showerror("Startup Error", f"Error starting application: {e}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Show critical errors
        import traceback
        print(f"Critical error during startup: {e}")
        traceback.print_exc()
        
        # Try to show GUI error message
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Critical Error", f"Application failed to start: {e}")
        except:
            pass