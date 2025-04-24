import os
import json
from typing import Dict, Any
import logging

class ConfigManager:
    """Manages configuration settings for the audit tool."""
    
    def __init__(self, config_file: str = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_file (str, optional): Path to configuration file
        """
        self.logger = logging.getLogger(__name__)
        self.config = self._load_default_config()
        
        if config_file and os.path.exists(config_file):
            self._load_config_file(config_file)
            
    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration settings."""
        return {
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(levelname)s - %(message)s',
                'file': 'security_audit.log'
            },
            'output': {
                'default_format': 'json',
                'json_indent': 2
            },
            'timeouts': {
                'http': 30,
                'dns': 10,
                'ssl': 10
            },
            'modules': {
                'enabled': ['dns_security'],
                'dns_security': {
                    # ISO 27002:2022 Controls
                    'check_redundancy': True,
                    'check_zone_transfer': True,
                    'check_recursion': True,
                    
                    # NIST SP 800-53 Controls
                    'check_dnssec': True,
                    'check_rrl': True,  # Response Rate Limiting
                    'check_version': True,
                    
                    # Additional Security Checks
                    'check_edns': True,
                    'check_tcp': True,
                    'check_cache_poisoning': True,
                    
                    # Thresholds and Limits
                    'min_nameservers': 2,
                    'rrl_query_count': 50,
                    'timeout': 10
                }
            }
        }
        
    def _load_config_file(self, config_file: str) -> None:
        """Load configuration from file."""
        try:
            with open(config_file, 'r') as f:
                file_config = json.load(f)
                self._merge_configs(file_config)
        except Exception as e:
            self.logger.error(f"Error loading config file: {e}")
            
    def _merge_configs(self, new_config: Dict[str, Any]) -> None:
        """Merge new configuration with existing config."""
        def deep_update(d: Dict[str, Any], u: Dict[str, Any]) -> Dict[str, Any]:
            for k, v in u.items():
                if isinstance(v, dict):
                    d[k] = deep_update(d.get(k, {}), v)
                else:
                    d[k] = v
            return d
            
        self.config = deep_update(self.config, new_config)
        
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            key (str): Configuration key (dot notation supported)
            default (Any, optional): Default value if key not found
            
        Returns:
            Any: Configuration value
        """
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k, default)
            else:
                return default
                
        return value
        
    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value.
        
        Args:
            key (str): Configuration key (dot notation supported)
            value (Any): Value to set
        """
        keys = key.split('.')
        current = self.config
        
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]
            
        current[keys[-1]] = value 