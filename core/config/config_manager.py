from typing import Any, Dict
from pathlib import Path
import logging
import yaml

class ConfigManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.config_path = Path("config.yaml")
        self.config: Dict[str, Any] = {}
        self.load_config()

    def load_config(self) -> None:
        """Load configuration from YAML file"""
        try:
            if not self.config_path.exists():
                self.create_default_config()
                
            with open(self.config_path, 'r') as f:
                self.config = yaml.safe_load(f)
                
        except Exception as e:
            self.logger.error(f"Error loading config: {str(e)}")
            self.create_default_config()

    def create_default_config(self) -> None:
        """Create default configuration file"""
        default_config = {
            "app": {
                "name": "Secure File Guard",
                "version": "1.0.0"
            },
            "security": {
                "password": {
                    "min_length": 12,
                    "require_uppercase": True,
                    "require_lowercase": True,
                    "require_numbers": True,
                    "require_special": True,
                    "special_chars": "!@#$%^&*(),.?\":{}|<>"
                },
                "encryption": {
                    "algorithm": "AES-256",
                    "key_iterations": 100000
                }
            },
            "storage": {
                "secure_folder": ".secure-file-guard",
                "container_name": "container.encrypted",
                "metadata_name": "metadata.json",
                "max_file_size": 1073741824,  # 1GB
                "allowed_extensions": ["*"],
                "compression": True
            },
            "logging": {
                "level": "INFO",
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                "file": "secure_file_guard.log"
            }
        }
        
        try:
            with open(self.config_path, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            self.config = default_config
        except Exception as e:
            self.logger.error(f"Error creating default config: {str(e)}")

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        try:
            sections = section.split('.')
            value = self.config
            for s in sections:
                value = value[s]
            return value.get(key, default)
        except Exception:
            return default

    def update(self, section: str, key: str, value: Any) -> bool:
        """Update configuration value"""
        try:
            sections = section.split('.')
            config_section = self.config
            for s in sections[:-1]:
                config_section = config_section[s]
            config_section[sections[-1]][key] = value
            
            with open(self.config_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False)
            return True
        except Exception as e:
            self.logger.error(f"Error updating config: {str(e)}")
            return False 