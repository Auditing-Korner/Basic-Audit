import importlib
import pkgutil
import logging
import json
import os
from typing import Dict, Type, List, Any
from .base_auditor import BaseAuditor

class ModuleLoader:
    """Loads and manages audit modules."""
    
    def __init__(self, config_manager=None):
        """
        Initialize the module loader.
        
        Args:
            config_manager: Configuration manager instance (optional)
        """
        self.logger = logging.getLogger(__name__)
        self.config_manager = config_manager
        self.available_modules: Dict[str, Type[BaseAuditor]] = {}
        self.loaded_modules: Dict[str, BaseAuditor] = {}
        
        # Load default configuration if no config manager provided
        if not config_manager:
            self._load_default_config()
            
    def _load_default_config(self) -> None:
        """Load default configuration from JSON file."""
        try:
            config_path = os.path.join(os.path.dirname(__file__), "..", "config", "default_config.json")
            with open(config_path, "r") as f:
                self.default_config = json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading default configuration: {e}")
            self.default_config = {
                "modules": {
                    "enabled": ["dns_security", "ssl_security", "oauth_security", "smtp_security"]
                }
            }
        
    def discover_modules(self, package_path: str) -> None:
        """
        Discover available audit modules in the given package path.
        
        Args:
            package_path (str): Path to the modules package
        """
        try:
            package = importlib.import_module(package_path)
            for _, name, is_pkg in pkgutil.iter_modules(package.__path__):
                module_name = f"{package_path}.{name}"
                try:
                    # If it's a package, look for auditor in the package
                    if is_pkg:
                        try:
                            auditor_module = importlib.import_module(f"{module_name}.{name}_auditor")
                            for item_name in dir(auditor_module):
                                item = getattr(auditor_module, item_name)
                                if (isinstance(item, type) and 
                                    issubclass(item, BaseAuditor) and 
                                    item != BaseAuditor):
                                    self.available_modules[name] = item
                                    self.logger.info(f"Discovered module: {name}")
                        except ImportError:
                            # Try importing the package itself
                            module = importlib.import_module(module_name)
                            for item_name in dir(module):
                                item = getattr(module, item_name)
                                if (isinstance(item, type) and 
                                    issubclass(item, BaseAuditor) and 
                                    item != BaseAuditor):
                                    self.available_modules[name] = item
                                    self.logger.info(f"Discovered module: {name}")
                    else:
                        # Direct module import
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
            
    def get_available_modules(self) -> Dict[str, Type[BaseAuditor]]:
        """
        Get all discovered modules.
        
        Returns:
            Dict[str, Type[BaseAuditor]]: Dictionary of module names and their classes
        """
        return self.available_modules
            
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
            self.logger.error(f"Module {module_name} not found")
            raise ValueError(f"Module {module_name} not found")
            
        if module_name not in self.loaded_modules:
            # Get module configuration
            if self.config_manager:
                module_config = self.config_manager.get(f"modules.{module_name}", {})
            else:
                module_config = self.default_config.get("modules", {}).get(module_name, {})
                
            module_class = self.available_modules[module_name]
            self.loaded_modules[module_name] = module_class(target, module_config)
            self.logger.debug(f"Loaded module: {module_name}")
            
        return self.loaded_modules[module_name]
        
    def get_enabled_modules(self) -> List[str]:
        """
        Get list of enabled modules from configuration.
        
        Returns:
            List[str]: List of enabled module names
        """
        if self.config_manager:
            enabled_modules = self.config_manager.get("modules.enabled", [])
        else:
            enabled_modules = self.default_config.get("modules", {}).get("enabled", [])
            
        # If no modules explicitly enabled, enable all available modules
        if not enabled_modules:
            enabled_modules = list(self.available_modules.keys())
            
        return enabled_modules
        
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
            'findings': [],
            'summary': {
                'total': 0,
                'by_severity': {
                    'Critical': 0,
                    'High': 0,
                    'Medium': 0,
                    'Low': 0,
                    'Info': 0
                },
                'by_module': {}
            }
        }
        
        for module_name in self.get_enabled_modules():
            try:
                module = self.load_module(module_name, target)
                module.run_all_checks()
                module_report = module.generate_report()
                module_findings = module_report.get('findings', [])
                findings['findings'].extend(module_findings)
                
                # Update summary statistics
                findings['summary']['total'] += len(module_findings)
                findings['summary']['by_module'][module_name] = len(module_findings)
                
                for finding in module_findings:
                    severity = finding.get('severity', 'Info')
                    findings['summary']['by_severity'][severity] = \
                        findings['summary']['by_severity'].get(severity, 0) + 1
                        
            except Exception as e:
                self.logger.error(f"Error running module {module_name}: {e}")
                
        return findings 