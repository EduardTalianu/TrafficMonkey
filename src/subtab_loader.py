import os
import sys
import logging
import importlib.util
from subtab_base import SubtabBase

class SubtabLoader:
    """Loads subtab plugins from the alerts/subtabs directory"""
    
    def __init__(self, gui):
        self.gui = gui
        self.subtabs = []
        
        # Root directory of the application
        self.app_root = gui.app_root
        self.subtabs_dir = os.path.join(self.app_root, 'alerts', 'subtabs')
        
        # Load all subtabs
        self.load_subtabs()
    
    def load_subtabs(self):
        """Load all subtab modules from the subtabs directory"""
        # Check if subtabs directory exists
        if not os.path.exists(self.subtabs_dir):
            os.makedirs(self.subtabs_dir, exist_ok=True)
            logging.warning(f"Subtabs directory created at {self.subtabs_dir}")
            return
        
        # Add the subtabs directory to Python path
        if self.subtabs_dir not in sys.path:
            sys.path.append(self.subtabs_dir)
        
        # Load subtab files
        for filename in os.listdir(self.subtabs_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                module_name = filename[:-3]  # Remove .py extension
                module_path = os.path.join(self.subtabs_dir, filename)
                
                try:
                    # Create a custom namespace for the module
                    subtab_namespace = {
                        'SubtabBase': SubtabBase,
                        'tk': __import__('tkinter'),
                        'ttk': __import__('tkinter.ttk', fromlist=['ttk']),
                        'logging': logging,
                        'os': os,
                        'gui': self.gui,  # Provide access to the GUI
                    }
                    
                    # Load the module content
                    with open(module_path, 'r') as f:
                        module_code = f.read()
                    
                    # Execute the module code in the custom namespace
                    exec(module_code, subtab_namespace)
                    
                    # Find subtab classes in the namespace (subclasses of SubtabBase)
                    for name, obj in subtab_namespace.items():
                        if (isinstance(obj, type) and 
                            issubclass(obj, SubtabBase) and 
                            obj != SubtabBase and 
                            hasattr(obj, '__init__')):
                            
                            # Create an instance of the subtab
                            subtab_instance = obj()
                            
                            # Inject GUI reference
                            subtab_instance.gui = self.gui
                            
                            self.subtabs.append(subtab_instance)
                            logging.info(f"Loaded subtab: {subtab_instance.name} from {filename}")
                            print(f"Loaded subtab: {subtab_instance.name} from {filename}")
                
                except Exception as e:
                    logging.error(f"Error loading subtab {module_name}: {e}")
                    import traceback
                    traceback.print_exc()
        
        # Sort subtabs alphabetically by name for consistent ordering
        self.subtabs.sort(key=lambda x: x.name)
        
        # Log summary of loaded subtabs
        logging.info(f"Loaded {len(self.subtabs)} subtab plugins")
        print(f"Loaded {len(self.subtabs)} subtab plugins")
        
        # If no subtabs were loaded, show a warning
        if not self.subtabs:
            logging.warning("No subtabs were loaded! The alerts tab will be empty.")
            print("WARNING: No subtabs were loaded! The alerts tab will be empty.")