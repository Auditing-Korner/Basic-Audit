import importlib
import pkgutil
import logging
from typing import Dict, Type, List, Any
from .base_auditor import BaseAuditor

class ModuleLoader:
    """Loads and manages audit modules."""
    
    def __init__(self, config_manager):
        """
        Initialize the module loader.
        
        Args:
            config_manager: Configuration manager instance
        """
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        self.available_modules: Dict[str, Type[BaseAuditor]] = {}
        self.loaded_modules: Dict[str, BaseAuditor] = {}
        
    def discover_modules(self, package_path: str) -> None:
        """
        Discover available audit modules in the given package path.
        
        Args:
            package_path (str): Path to the modules package
        """
        try:
            package = importlib.import_module(package_path)
            for _, name, _ in pkgutil.iter_modules(package.__path__):
                module_name = f"{package_path}.{name}"
                try:
                    module = importlib.import_module(module_name)
                    for item_name in dir(module):
                        item = getattr(module, item_name)
                        if (isinstance(item, type) and 
                            issubclass(item, BaseAuditor) and 
                            item != BaseAuditor):
                            self.available_modules[name] = item
                            self.logger.info(f"Discovered module: {name}")
                except Exception as e:
                    self.logger.error(f"Error loading module {name}: {e}")
        except Exception as e:
            self.logger.error(f"Error discovering modules: {e}")
            
    def load_module(self, module_name: str, target: str) -> BaseAuditor:
        """
        Load a specific module.
        
        Args:
            module_name (str): Name of the module to load
            target (str): Target to audit
            
        Returns:
            BaseAuditor: Loaded module instance
        """
        if module_name not in self.available_modules:
            raise ValueError(f"Module {module_name} not found")
            
        if module_name not in self.loaded_modules:
            module_config = self.config_manager.get(f"modules.{module_name}", {})
            module_class = self.available_modules[module_name]
            self.loaded_modules[module_name] = module_class(target, module_config)
            self.logger.info(f"Loaded module: {module_name}")
            
        return self.loaded_modules[module_name]
        
    def get_enabled_modules(self) -> List[str]:
        """
        Get list of enabled modules from configuration.
        
        Returns:
            List[str]: List of enabled module names
        """
        return self.config_manager.get("modules.enabled", [])
        
    def run_all_modules(self, target: str) -> Dict[str, Any]:
        """
        Run all enabled modules against the target.
        
        Args:
            target (str): Target to audit
            
        Returns:
            Dict[str, Any]: Combined findings from all modules
        """
        findings = {
            'target': target,
            'findings': []
        }
        
        for module_name in self.get_enabled_modules():
            try:
                module = self.load_module(module_name, target)
                module.run_all_checks()
                module_report = module.generate_report()
                findings['findings'].extend(module_report.get('findings', []))
            except Exception as e:
                self.logger.error(f"Error running module {module_name}: {e}")
                
        return findings 