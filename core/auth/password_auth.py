from typing import Tuple
import hashlib
import logging
import os
import re

class PasswordAuth:
    def __init__(self, config):
        self.logger = logging.getLogger(__name__)
        self.config = config
        
    def validate_password_strength(self, password: str) -> Tuple[bool, str]:
        """Validate password strength using criteria from config"""
        min_length = self.config.get('security.password', 'min_length', 12)
        require_upper = self.config.get('security.password', 'require_uppercase', True)
        require_lower = self.config.get('security.password', 'require_lowercase', True)
        require_numbers = self.config.get('security.password', 'require_numbers', True)
        require_special = self.config.get('security.password', 'require_special', True)
        special_chars = self.config.get('security.password', 'special_chars', "!@#$%^&*(),.?\":{}|<>")
        
        if len(password) < min_length:
            return False, f"Password must be at least {min_length} characters long"
            
        if require_upper and not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
            
        if require_lower and not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
            
        if require_numbers and not re.search(r"\d", password):
            return False, "Password must contain at least one number"
            
        if require_special and not any(c in special_chars for c in password):
            return False, "Password must contain at least one special character"
            
        return True, "Password meets strength requirements"
        
    def hash_password(self, password: str) -> Tuple[bytes, bytes]:
        """Hash password using strong algorithm with salt"""
        salt = os.urandom(32)
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,  # Number of iterations
            dklen=32
        )
        return key, salt
        
    def verify_password(self, password: str, stored_key: bytes, salt: bytes) -> bool:
        """Verify a password against stored hash"""
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
        return key == stored_key 