# -*- coding: utf-8 -*-
"""
Encryption Manager - Manage sensitive data encryption and decryption
This module provides functionality to encrypt and decrypt sensitive data
"""

import os
import base64
import logging
from pathlib import Path
from typing import Optional
from getpass import getpass

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class EncryptionManager:
    """Manage encryption and decryption of sensitive data"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.key_file = Path(__file__).parent.parent / "data" / ".encryption_key"
        self._fernet = None
        self._setup_encryption()
    
    def _setup_encryption(self):
        """Setup encryption key"""
        try:
            if self.key_file.exists():
                # Load existing key
                with open(self.key_file, 'rb') as f:
                    key = f.read()
                self._fernet = Fernet(key)
            else:
                # Create new key với password
                self._create_new_key()
        except Exception as e:
            self.logger.error(f"Error setting up encryption: {e}")
            raise
    
    def _create_new_key(self):
        """Create a new encryption key with a password"""
        print("\n🔐 ENCRYPTION SETUP")
        print("=" * 40)
        print("This is the first time running the tool.")
        print("Please set a master password to encrypt your API keys.")
        print("⚠️  Remember this password - it cannot be recovered!")
        
        while True:
            password = getpass("Enter master password: ").encode()
            confirm_password = getpass("Confirm master password: ").encode()
            
            if password == confirm_password:
                if len(password) < 8:
                    print("❌ Password must be at least 8 characters long")
                    continue
                break
            else:
                print("❌ Passwords do not match. Please try again.")

        # Generate salt and derive key
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))

        # Save key and salt
        key_data = salt + key
        with open(self.key_file, 'wb') as f:
            f.write(key_data)
        
        # Set permissions (Unix only)
        if os.name != 'nt':  # Not Windows
            os.chmod(self.key_file, 0o600)
        
        self._fernet = Fernet(key)
        print("✅ Encryption setup completed!")
    
    def _load_key_with_password(self) -> bool:
        """Load key with password (if needed)"""
        try:
            with open(self.key_file, 'rb') as f:
                key_data = f.read()
            
            salt = key_data[:16]
            stored_key = key_data[16:]
            
            password = getpass("Enter master password: ").encode()
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            derived_key = base64.urlsafe_b64encode(kdf.derive(password))
            
            if derived_key == stored_key:
                self._fernet = Fernet(derived_key)
                return True
            else:
                print("❌ Invalid password")
                return False
                
        except Exception as e:
            self.logger.error(f"Error loading key with password: {e}")
            return False
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data"""
        try:
            if self._fernet is None:
                raise ValueError("Encryption not initialized")
            return self._fernet.encrypt(data)
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            raise
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data"""
        try:
            if self._fernet is None:
                # Try to load with password
                if not self._load_key_with_password():
                    raise ValueError("Cannot decrypt - invalid password")
            
            return self._fernet.decrypt(encrypted_data)
        except Exception as e:
            self.logger.error(f"Decryption error: {e}")
            raise
    
    def encrypt_string(self, text: str) -> str:
        """Encrypt string and return base64"""
        encrypted_bytes = self.encrypt(text.encode('utf-8'))
        return base64.b64encode(encrypted_bytes).decode('ascii')
    
    def decrypt_string(self, encrypted_text: str) -> str:
        """Decrypt from base64 string"""
        encrypted_bytes = base64.b64decode(encrypted_text.encode('ascii'))
        decrypted_bytes = self.decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')
    
    def is_initialized(self) -> bool:
        """Check if encryption has been set up"""
        return self.key_file.exists() and self._fernet is not None
    
    def change_password(self) -> bool:
        """Change master password"""
        print("\n🔐 CHANGE MASTER PASSWORD")
        print("=" * 40)
        
        # Verify current password first
        if not self._load_key_with_password():
            print("❌ Current password verification failed")
            return False
        
        # Get new password
        while True:
            new_password = getpass("Enter new master password: ").encode()
            confirm_password = getpass("Confirm new master password: ").encode()
            
            if new_password == confirm_password:
                if len(new_password) < 8:
                    print("❌ Password must be at least 8 characters long")
                    continue
                break
            else:
                print("❌ Passwords do not match. Please try again.")
        
        try:
            # Generate new salt và key
            salt = os.urandom(16)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            new_key = base64.urlsafe_b64encode(kdf.derive(new_password))
            
            # Save new key
            key_data = salt + new_key
            with open(self.key_file, 'wb') as f:
                f.write(key_data)
            
            self._fernet = Fernet(new_key)
            print("✅ Master password changed successfully!")
            return True
            
        except Exception as e:
            self.logger.error(f"Error changing password: {e}")
            print(f"❌ Error changing password: {e}")
            return False
    
    def reset_encryption(self) -> bool:
        """Reset encryption (xóa key file)"""
        try:
            if self.key_file.exists():
                self.key_file.unlink()
            self._fernet = None
            print("✅ Encryption reset successfully")
            return True
        except Exception as e:
            self.logger.error(f"Error resetting encryption: {e}")
            return False
    
    def backup_key(self, backup_path: str) -> bool:
        """Backup encryption key"""
        try:
            if not self.key_file.exists():
                print("❌ No encryption key to backup")
                return False
            
            # Copy key file
            backup_file = Path(backup_path)
            backup_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.key_file, 'rb') as src:
                with open(backup_file, 'wb') as dst:
                    dst.write(src.read())
            
            # Set permissions
            if os.name != 'nt':
                os.chmod(backup_file, 0o600)
            
            print(f"✅ Encryption key backed up to {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error backing up key: {e}")
            return False
    
    def restore_key(self, backup_path: str) -> bool:
        """Restore encryption key từ backup"""
        try:
            backup_file = Path(backup_path)
            if not backup_file.exists():
                print(f"❌ Backup file not found: {backup_path}")
                return False
            
            # Copy backup to key location
            with open(backup_file, 'rb') as src:
                with open(self.key_file, 'wb') as dst:
                    dst.write(src.read())
            
            # Set permissions
            if os.name != 'nt':
                os.chmod(self.key_file, 0o600)
            
            # Try to load the restored key
            self._setup_encryption()
            
            print(f"✅ Encryption key restored from {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error restoring key: {e}")
            return False
    
    def get_key_info(self) -> dict:
        """Get information of encryption key"""
        info = {
            'key_file_exists': self.key_file.exists(),
            'encryption_initialized': self._fernet is not None,
            'key_file_path': str(self.key_file)
        }
        
        if self.key_file.exists():
            stat = self.key_file.stat()
            info.update({
                'key_file_size': stat.st_size,
                'key_created': stat.st_ctime,
                'key_modified': stat.st_mtime
            })
        
        return info


# Convenience functions
def generate_random_password(length: int = 16) -> str:
    """Generate random password"""
    import secrets
    import string
    
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple:
    """Hash password với salt"""
    if salt is None:
        salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    hashed = kdf.derive(password.encode())
    return hashed, salt


def verify_password(password: str, hashed: bytes, salt: bytes) -> bool:
    """Verify password"""
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        kdf.verify(password.encode(), hashed)
        return True
    except Exception:
        return False