"""
Configuration management for ComplyChain.

This module provides centralized configuration loading from config.yaml
with singleton pattern and caching support.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Dict, Optional
from functools import lru_cache


class ConfigManager:
    """Singleton configuration manager for ComplyChain."""
    
    _instance = None
    _config = None
    _config_file = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigManager, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._config is None:
            self._load_default_config()
    
    def _load_default_config(self):
        """Load default configuration."""
        self._config = {
            "compliance": {
                "mode": "strict",
                "glba_sections": {
                    "314.4(c)(1)": "Data Encryption",
                    "314.4(c)(2)": "Access Controls", 
                    "314.4(c)(3)": "Device Authentication",
                    "314.4(b)": "Audit Trails",
                    "314.4(d)": "Incident Response",
                    "314.4(f)": "Employee Training"
                }
            },
            "crypto": {
                "algorithm": "Dilithium3",
                "fallback_algorithm": "RSA-4096",
                "key_size": 4096,
                "quantum_safe_enabled": True
            },
            "audit": {
                "log_level": "INFO",
                "retention_days": 365,
                "encryption_enabled": True
            },
            "scanner": {
                "ml_enabled": True,
                "threshold": 0.8,
                "batch_size": 100
            },
            "logging": {
                "level": "INFO",
                "file": None,
                "quantum_backend_monitoring": True
            }
        }
    
    def load_config(self, config_file: Optional[Path] = None) -> Dict[str, Any]:
        """
        Load configuration from file.
        
        Args:
            config_file: Path to configuration file
            
        Returns:
            Configuration dictionary
        """
        if config_file is None:
            # Try to find config.yaml in common locations
            config_locations = [
                Path("config.yaml"),
                Path("~/.complychain/config.yaml").expanduser(),
                Path("/etc/complychain/config.yaml"),
                Path(__file__).parent.parent.parent / "config.yaml"
            ]
            
            for location in config_locations:
                if location.exists():
                    config_file = location
                    break
        
        if config_file and config_file.exists():
            try:
                with open(config_file, 'r') as f:
                    file_config = yaml.safe_load(f)
                
                # Merge with default config if file_config is not None
                if file_config is not None:
                    self._merge_config(self._config, file_config)
                self._config_file = config_file
                
            except Exception as e:
                print(f"Warning: Failed to load config file {config_file}: {e}")
        
        return self._config
    
    def _merge_config(self, base: Dict[str, Any], override: Dict[str, Any]):
        """Recursively merge configuration dictionaries."""
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key (dot notation supported).
        
        Args:
            key: Configuration key (e.g., "compliance.mode")
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        if self._config is None:
            return default
            
        keys = key.split('.')
        value = self._config
        
        try:
            for k in keys:
                if isinstance(value, dict):
                    value = value[k]
                else:
                    return default
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any):
        """
        Set configuration value by key (dot notation supported).
        
        Args:
            key: Configuration key (e.g., "compliance.mode")
            value: Value to set
        """
        if self._config is None:
            self._load_default_config()
            
        keys = key.split('.')
        config = self._config
        
        for k in keys[:-1]:
            if k not in config or not isinstance(config[k], dict):
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
    
    def save_config(self, config_file: Optional[Path] = None):
        """
        Save current configuration to file.
        
        Args:
            config_file: Path to save configuration (uses loaded file if None)
        """
        if config_file is None:
            config_file = self._config_file or Path("config.yaml")
        
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w') as f:
            yaml.dump(self._config, f, default_flow_style=False, indent=2)
    
    def reload(self):
        """Reload configuration from file."""
        if self._config_file:
            self.load_config(self._config_file)


# Global configuration instance
_config_manager = ConfigManager()


@lru_cache(maxsize=1)
def get_config(config_file: Optional[Path] = None) -> Dict[str, Any]:
    """
    Get ComplyChain configuration.
    
    Args:
        config_file: Optional path to configuration file
        
    Returns:
        Configuration dictionary
    """
    return _config_manager.load_config(config_file)


def get_setting(key: str, default: Any = None) -> Any:
    """
    Get a specific configuration setting.
    
    Args:
        key: Configuration key (dot notation supported)
        default: Default value if key not found
        
    Returns:
        Configuration value
    """
    return _config_manager.get(key, default)


def set_setting(key: str, value: Any):
    """
    Set a specific configuration setting.
    
    Args:
        key: Configuration key (dot notation supported)
        value: Value to set
    """
    _config_manager.set(key, value)


def save_config(config_file: Optional[Path] = None):
    """
    Save current configuration to file.
    
    Args:
        config_file: Optional path to save configuration
    """
    _config_manager.save_config(config_file) 