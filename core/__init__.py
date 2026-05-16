import importlib
import pkgutil
import logging
from pathlib import Path

def get_plugins(plugin_type):
    """Dynamically load all plugins of specified type"""
    plugins = []
    plugin_dir = Path(__file__).parent
    
    for finder, name, _ in pkgutil.iter_modules([str(plugin_dir)]):
        try:
            module = importlib.import_module(f"plugins.{name}")
            if hasattr(module, 'PLUGIN_TYPE') and module.PLUGIN_TYPE == plugin_type:
                plugins.append(module.Plugin)
                logging.info(f"Loaded {plugin_type} plugin: {name}")
        except Exception as e:
            logging.error(f"Failed to load plugin {name}: {e}")
    
    return plugins
