# -*- coding: utf-8 -*-
"""
Settings - Configurations for the SecurityTool
This module manages the configuration settings for the SecurityTool.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv


class Settings:
    """Manage general configurations for the SecurityTool"""

    # Default settings
    DEFAULT_SETTINGS = {
        # Network settings
        'request_timeout': 30,
        'max_retries': 3,
        'retry_delay': 1,
        'user_agent': 'SecurityTool/1.0',
        
        # Rate limiting
        'rate_limit_delay': 1,
        'burst_requests': 5,
        
        # Output settings
        'max_results_display': 100,
        'output_format': 'table',  # table, json, csv
        'color_output': True,
        'verbose_mode': False,
        
        # File settings
        'max_file_size': 100 * 1024 * 1024,  # 100MB
        'temp_directory': 'temp',
        'log_directory': 'logs',
        
        # Analysis settings
        'dns_servers': ['8.8.8.8', '1.1.1.1'],
        'whois_timeout': 10,
        'sandbox_timeout': 300,
        
        # IOC settings
        'defang_iocs': True,
        'sanitize_output': True,
        
        # Email analysis
        'max_email_size': 50 * 1024 * 1024,  # 50MB
        'extract_attachments': True,
        'analyze_headers': True,
        
        # URL analysis
        'follow_redirects': True,
        'max_redirects': 10,
        'screenshot_urls': False,
        
        # Brand monitoring
        'similarity_threshold': 0.8,
        'check_subdomains': True,
        'social_media_check': True,
        
        # Logging
        'log_level': 'INFO',
        'log_file_max_size': 10 * 1024 * 1024,  # 10MB
        'log_backup_count': 5,
        
        # Cache settings
        'enable_cache': True,
        'cache_ttl': 3600,  # 1 hour
        
        # Security
        'verify_ssl': True,
        'allow_private_ips': False
    }
    
    # API Endpoints
    API_ENDPOINTS = {
        'virustotal': {
            'base_url': 'https://www.virustotal.com/vtapi/v2',
            'rate_limit': 4,  # requests per minute for free tier
            'premium_rate_limit': 1000
        },
        'abuseipdb': {
            'base_url': 'https://api.abuseipdb.com/api/v2',
            'rate_limit': 1000,  # requests per day for free tier
            'premium_rate_limit': 10000
        },
        'otx': {
            'base_url': 'https://otx.alienvault.com/api/v1',
            'rate_limit': 10000,  # requests per hour
            'premium_rate_limit': 100000
        },
        'shodan': {
            'base_url': 'https://api.shodan.io',
            'rate_limit': 100,  # requests per month for free
            'premium_rate_limit': 10000
        },
        'urlvoid': {
            'base_url': 'http://api.urlvoid.com/api1000',
            'rate_limit': 1000,  # requests per month
            'premium_rate_limit': 10000
        },
        'hybrid_analysis': {
            'base_url': 'https://www.hybrid-analysis.com/api/v2',
            'rate_limit': 200,  # requests per hour
            'premium_rate_limit': 2000
        },
        'ipinfo': {
            'base_url': 'https://ipinfo.io',
            'rate_limit': 50000,  # requests per month for free
            'premium_rate_limit': 250000
        }
    }
    
    def __init__(self, config_file: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        
        # Load environment variables
        load_dotenv()
        
        # Determine config file path
        if config_file:
            self.config_file = Path(config_file)
        else:
            self.config_file = Path(__file__).parent / "settings.json"
        
        # Initialize settings
        self.settings = self.DEFAULT_SETTINGS.copy()
        self._load_settings()
        self._setup_directories()
    
    def _load_settings(self):
        """Load settings from config file and environment variables"""
        # Load from file if exists
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    file_settings = json.load(f)
                self.settings.update(file_settings)
                self.logger.info("Settings loaded from config file")
            except Exception as e:
                self.logger.error(f"Error loading settings file: {e}")
        
        # Override with environment variables
        self._load_env_settings()
    
    def _load_env_settings(self):
        """Load settings from environment variables"""
        env_mappings = {
            'ST_REQUEST_TIMEOUT': ('request_timeout', int),
            'ST_MAX_RETRIES': ('max_retries', int),
            'ST_USER_AGENT': ('user_agent', str),
            'ST_VERBOSE': ('verbose_mode', bool),
            'ST_LOG_LEVEL': ('log_level', str),
            'ST_VERIFY_SSL': ('verify_ssl', bool),
            'ST_ENABLE_CACHE': ('enable_cache', bool),
            'ST_COLOR_OUTPUT': ('color_output', bool)
        }
        
        for env_var, (setting_key, type_func) in env_mappings.items():
            env_value = os.getenv(env_var)
            if env_value is not None:
                try:
                    if type_func == bool:
                        self.settings[setting_key] = env_value.lower() in ('true', '1', 'yes', 'on')
                    else:
                        self.settings[setting_key] = type_func(env_value)
                except ValueError as e:
                    self.logger.error(f"Invalid value for {env_var}: {env_value}")
    
    def _setup_directories(self):
        """Create necessary directories"""
        directories = [
            self.get('temp_directory'),
            self.get('log_directory'),
            Path(__file__).parent.parent / "data"
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
    
    def get(self, key: str, default=None) -> Any:
        """Get setting value"""
        return self.settings.get(key, default)
    
    def set(self, key: str, value: Any) -> bool:
        """Set setting value"""
        try:
            self.settings[key] = value
            return self.save_settings()
        except Exception as e:
            self.logger.error(f"Error setting {key}: {e}")
            return False
    
    def save_settings(self) -> bool:
        """Save settings to file"""
        try:
            # Only save non-default settings
            settings_to_save = {}
            for key, value in self.settings.items():
                if key not in self.DEFAULT_SETTINGS or self.DEFAULT_SETTINGS[key] != value:
                    settings_to_save[key] = value
            
            with open(self.config_file, 'w') as f:
                json.dump(settings_to_save, f, indent=2)
            
            self.logger.info("Settings saved successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error saving settings: {e}")
            return False
    
    def reset_settings(self) -> bool:
        """Reset to default settings"""
        try:
            self.settings = self.DEFAULT_SETTINGS.copy()
            if self.config_file.exists():
                self.config_file.unlink()
            self.logger.info("Settings reset to defaults")
            return True
        except Exception as e:
            self.logger.error(f"Error resetting settings: {e}")
            return False
    
    def get_api_endpoint(self, service: str) -> Dict[str, Any]:
        """Get API endpoint information for a service"""
        return self.API_ENDPOINTS.get(service, {})
    
    def get_rate_limit(self, service: str, premium: bool = False) -> int:
        """Get rate limit for a service"""
        endpoint_info = self.get_api_endpoint(service)
        if premium:
            return endpoint_info.get('premium_rate_limit', 1000)
        return endpoint_info.get('rate_limit', 100)
    
    def is_verbose(self) -> bool:
        """Check if verbose mode is enabled"""
        return self.get('verbose_mode', False)
    
    def is_color_enabled(self) -> bool:
        """Check if color output is enabled"""
        return self.get('color_output', True)
    
    def get_temp_dir(self) -> Path:
        """Get temporary directory"""
        return Path(self.get('temp_directory', 'temp'))
    
    def get_log_dir(self) -> Path:
        """Get log directory"""
        return Path(self.get('log_directory', 'logs'))
    
    def get_dns_servers(self) -> list:
        """Get list of DNS servers"""
        return self.get('dns_servers', ['8.8.8.8', '1.1.1.1'])
    
    def should_defang_iocs(self) -> bool:
        """Check if IOCs should be defanged"""
        return self.get('defang_iocs', True)
    
    def get_max_file_size(self) -> int:
        """Get max file size"""
        return self.get('max_file_size', 100 * 1024 * 1024)
    
    def get_request_timeout(self) -> int:
        """Get request timeout"""
        return self.get('request_timeout', 30)
    
    def get_max_retries(self) -> int:
        """Get max retries"""
        return self.get('max_retries', 3)
    
    def get_user_agent(self) -> str:
        """Get User-Agent string"""
        return self.get('user_agent', 'SecurityTool/1.0')
    
    def should_verify_ssl(self) -> bool:
        """Check if SSL verification is enabled"""
        return self.get('verify_ssl', True)
    
    def is_cache_enabled(self) -> bool:
        """Check if caching is enabled"""
        return self.get('enable_cache', True)
    
    def get_cache_ttl(self) -> int:
        """Get cache TTL"""
        return self.get('cache_ttl', 3600)
    
    def export_settings(self, file_path: str) -> bool:
        """Export settings to file"""
        try:
            export_data = {
                'current_settings': self.settings,
                'default_settings': self.DEFAULT_SETTINGS,
                'api_endpoints': self.API_ENDPOINTS
            }
            
            with open(file_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Settings exported to {file_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error exporting settings: {e}")
            return False
    
    def import_settings(self, file_path: str) -> bool:
        """Import settings from file"""
        try:
            with open(file_path, 'r') as f:
                import_data = json.load(f)
            
            if 'current_settings' in import_data:
                self.settings.update(import_data['current_settings'])
                self.save_settings()
                self.logger.info(f"Settings imported from {file_path}")
                return True
            else:
                self.logger.error("Invalid settings file format")
                return False
        except Exception as e:
            self.logger.error(f"Error importing settings: {e}")
            return False
    
    def validate_settings(self) -> Dict[str, Any]:
        """Validate current settings"""
        issues = []
        warnings = []
        
        # Check timeout values
        if self.get('request_timeout') < 5:
            warnings.append("Request timeout is very low (< 5 seconds)")
        
        # Check file size limits
        max_size = self.get('max_file_size')
        if max_size > 1024 * 1024 * 1024:  # 1GB
            warnings.append("Max file size is very large (> 1GB)")
        
        # Check log level
        valid_log_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if self.get('log_level') not in valid_log_levels:
            issues.append(f"Invalid log level: {self.get('log_level')}")
        
        # Check directories
        for dir_key in ['temp_directory', 'log_directory']:
            dir_path = Path(self.get(dir_key))
            if not dir_path.exists():
                try:
                    dir_path.mkdir(parents=True, exist_ok=True)
                except Exception:
                    issues.append(f"Cannot create directory: {dir_path}")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings
        }
    
    def __str__(self) -> str:
        """String representation of settings"""
        return f"Settings(config_file={self.config_file}, keys={len(self.settings)})"
    
    def __repr__(self) -> str:
        return self.__str__()