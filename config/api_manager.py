"""
API Manager - Manage API keys for threat intelligence services
This module provides functionality to manage API keys for various threat intelligence services.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Optional, Any
from getpass import getpass

from utils.encryption import EncryptionManager
from utils.validators import validate_api_key


class APIManager:
    """Manage API keys for threat intelligence services"""
    
    # List of supported services
    SUPPORTED_SERVICES = {
        'virustotal': {
            'name': 'VirusTotal',
            'description': 'Malware and URL analysis',
            'url': 'https://www.virustotal.com/gui/join-us',
            'key_format': '64 characters hex string'
        },
        'abuseipdb': {
            'name': 'AbuseIPDB', 
            'description': 'IP reputation and abuse reports',
            'url': 'https://www.abuseipdb.com/api',
            'key_format': 'API key string'
        },
        'otx': {
            'name': 'AlienVault OTX',
            'description': 'Open Threat Exchange',
            'url': 'https://otx.alienvault.com/api',
            'key_format': '40 characters hex string'
        },
        'shodan': {
            'name': 'Shodan',
            'description': 'Internet-connected devices search',
            'url': 'https://account.shodan.io/',
            'key_format': '32 characters string'
        },
        'urlvoid': {
            'name': 'URLVoid',
            'description': 'URL reputation checker',
            'url': 'https://www.urlvoid.com/api/',
            'key_format': 'API key string'
        },
        'hybrid_analysis': {
            'name': 'Hybrid Analysis',
            'description': 'Malware analysis sandbox',
            'url': 'https://www.hybrid-analysis.com/apikeys/info',
            'key_format': 'API key string'
        },
        'ipinfo': {
            'name': 'IPInfo',
            'description': 'IP geolocation and ASN data',
            'url': 'https://ipinfo.io/signup',
            'key_format': 'Token string'
        }
    }
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.data_dir = Path(__file__).parent.parent / "data"
        self.data_dir.mkdir(exist_ok=True)
        self.keys_file = self.data_dir / "encrypted_keys.dat"
        self.encryption_manager = EncryptionManager()
        self._api_keys = {}
        self._load_keys()
    
    def _load_keys(self):
        """Load and decrypt API keys from file"""
        try:
            if self.keys_file.exists():
                encrypted_data = self.keys_file.read_bytes()
                if encrypted_data:
                    decrypted_data = self.encryption_manager.decrypt(encrypted_data)
                    self._api_keys = json.loads(decrypted_data.decode('utf-8'))
                    self.logger.info("API keys loaded successfully")
        except Exception as e:
            self.logger.error(f"Error loading API keys: {e}")
            self._api_keys = {}
    
    def _save_keys(self):
        """Encrypt and save API keys to file"""
        try:
            json_data = json.dumps(self._api_keys, indent=2)
            encrypted_data = self.encryption_manager.encrypt(json_data.encode('utf-8'))
            self.keys_file.write_bytes(encrypted_data)
            self.logger.info("API keys saved successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error saving API keys: {e}")
            return False
    
    def has_api_keys(self) -> bool:
        """Check if any API keys are configured"""
        return len(self._api_keys) > 0
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a specific service"""
        return self._api_keys.get(service)
    
    def set_api_key(self, service: str, api_key: str) -> bool:
        """Set API key for a service"""
        if service not in self.SUPPORTED_SERVICES:
            self.logger.error(f"Unsupported service: {service}")
            return False

        # Validate API key format (basic)
        if not validate_api_key(service, api_key):
            self.logger.error(f"Invalid API key format for {service}")
            return False
        
        self._api_keys[service] = api_key
        return self._save_keys()
    
    def remove_api_key(self, service: str) -> bool:
        """Remove API key for a service"""
        if service in self._api_keys:
            del self._api_keys[service]
            return self._save_keys()
        return True
    
    def list_configured_services(self) -> list:
        """List configured services"""
        return list(self._api_keys.keys())
    
    def setup_api_keys(self):
        """Interactive setup for API keys"""
        print("\n🔑 API KEY CONFIGURATION")
        print("=" * 50)
        print("Configure API keys for threat intelligence services.")
        print("You can skip any service by pressing Enter without input.\n")
        
        for service_id, service_info in self.SUPPORTED_SERVICES.items():
            current_key = self._api_keys.get(service_id)
            status = "✅ Configured" if current_key else "❌ Not configured"
            
            print(f"\n{service_info['name']} ({status})")
            print(f"Description: {service_info['description']}")
            print(f"Get API key: {service_info['url']}")
            print(f"Key format: {service_info['key_format']}")
            
            if current_key:
                choice = input(f"Update existing key? (y/n/delete): ").strip().lower()
                if choice == 'delete':
                    self.remove_api_key(service_id)
                    print("✅ API key deleted")
                    continue
                elif choice != 'y':
                    continue
            
            api_key = getpass(f"Enter API key for {service_info['name']} (hidden): ").strip()
            
            if api_key:
                if self.set_api_key(service_id, api_key):
                    print("✅ API key saved successfully")
                else:
                    print("❌ Failed to save API key")
            else:
                print("⏭️  Skipped")
        
        print(f"\n✅ Configuration completed!")
        print(f"Configured services: {len(self._api_keys)}")
    
    def show_configuration(self):
        """Display current configuration"""
        print("\n⚙️  CURRENT CONFIGURATION")
        print("=" * 40)
        
        if not self._api_keys:
            print("❌ No API keys configured")
            return
        
        for service_id in self._api_keys:
            service_info = self.SUPPORTED_SERVICES.get(service_id, {})
            name = service_info.get('name', service_id)
            print(f"✅ {name}")
        
        print(f"\nTotal configured services: {len(self._api_keys)}")
    
    def test_connections(self):
        """Test connections to API services"""
        print("\n🔍 TESTING API CONNECTIONS")
        print("=" * 40)
        
        if not self._api_keys:
            print("❌ No API keys to test")
            return

        # Import test modules (to be implemented later)
        test_results = {}
        
        for service_id, api_key in self._api_keys.items():
            service_name = self.SUPPORTED_SERVICES[service_id]['name']
            print(f"Testing {service_name}... ", end="")
            
            try:
                # Test connection logic will be implemented in each module
                if service_id == 'virustotal':
                    result = self._test_virustotal(api_key)
                elif service_id == 'abuseipdb':
                    result = self._test_abuseipdb(api_key)
                else:
                    result = False  # Placeholder
                
                if result:
                    print("✅ Success")
                    test_results[service_id] = True
                else:
                    print("❌ Failed")
                    test_results[service_id] = False
                    
            except Exception as e:
                print(f"❌ Error: {e}")
                test_results[service_id] = False
        
        # Summary
        success_count = sum(test_results.values())
        total_count = len(test_results)
        print(f"\n📊 Test Results: {success_count}/{total_count} services working")
    
    def _test_virustotal(self, api_key: str) -> bool:
        """Test VirusTotal API connection"""
        try:
            import requests
            url = "https://www.virustotal.com/vtapi/v2/url/report"
            params = {
                'apikey': api_key,
                'resource': 'http://www.google.com'
            }
            response = requests.get(url, params=params, timeout=10)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"VirusTotal test failed: {e}")
            return False
    
    def _test_abuseipdb(self, api_key: str) -> bool:
        """Test AbuseIPDB API connection"""
        try:
            import requests
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': '8.8.8.8',
                'maxAgeInDays': 90
            }
            response = requests.get(url, headers=headers, params=params, timeout=10)
            return response.status_code == 200
        except Exception as e:
            self.logger.error(f"AbuseIPDB test failed: {e}")
            return False
    
    def reset_configuration(self):
        """Reset all configurations"""
        try:
            self._api_keys = {}
            if self.keys_file.exists():
                self.keys_file.unlink()
            print("✅ Configuration reset successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error resetting configuration: {e}")
            print(f"❌ Error resetting configuration: {e}")
            return False
    
    def export_configuration(self, file_path: str):
        """Export configuration (excluding actual API keys)"""
        try:
            config = {
                'configured_services': list(self._api_keys.keys()),
                'total_services': len(self._api_keys),
                'supported_services': self.SUPPORTED_SERVICES
            }
            
            with open(file_path, 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"✅ Configuration exported to {file_path}")
            return True
        except Exception as e:
            self.logger.error(f"Error exporting configuration: {e}")
            return False
    
    def get_service_info(self, service: str) -> Dict[str, Any]:
        """Get information about a service"""
        return self.SUPPORTED_SERVICES.get(service, {})
    
    def is_service_configured(self, service: str) -> bool:
        """Check if a service is configured"""
        return service in self._api_keys