from PIL import Image
import hashlib
import io
from typing import Tuple
import logging
from pathlib import Path
import os

class ImageAuth:
    def __init__(self, config):
        self.logger = logging.getLogger(__name__)
        self.config = config
        self.auth_folder = Path.home() / '.secure-file-guard' / 'auth'
        self.image_hash_file = self.auth_folder / 'image_hash'
        
    def register_image(self, image_path: Path) -> Tuple[bool, str]:
        """Register an authentication image"""
        try:
            if not image_path.exists():
                return False, "Image file not found"
                
            # Load and process image
            with Image.open(image_path) as img:
                # Normalize image
                img = img.convert('RGB')
                img = img.resize((256, 256))  # Standard size
                
                # Convert image to bytes
                img_byte_arr = io.BytesIO()
                img.save(img_byte_arr, format='PNG')
                img_byte_arr = img_byte_arr.getvalue()
                
                # Create hash
                image_hash = hashlib.sha256(img_byte_arr).hexdigest()
                
                # Save hash with secure permissions
                self.auth_folder.mkdir(parents=True, exist_ok=True)
                with open(self.image_hash_file, 'wb') as f:
                    f.write(image_hash.encode())
                
                # Set secure file permissions
                if os.name == 'nt':  # Windows
                    try:
                        import win32security
                        import win32api
                        import ntsecuritycon as con
                        
                        # Get current user's SID
                        user_sid = win32security.GetTokenInformation(
                            win32security.OpenProcessToken(
                                win32api.GetCurrentProcess(),
                                win32security.TOKEN_QUERY
                            ),
                            win32security.TokenUser
                        )[0]
                        
                        # Create a new DACL with only owner access
                        dacl = win32security.ACL()
                        dacl.AddAccessAllowedAce(
                            win32security.ACL_REVISION,
                            con.FILE_ALL_ACCESS,
                            user_sid
                        )
                        
                        # Set the security
                        security_descriptor = win32security.SECURITY_DESCRIPTOR()
                        security_descriptor.SetSecurityDescriptorDacl(1, dacl, 0)
                        win32security.SetFileSecurity(
                            str(self.image_hash_file),
                            win32security.DACL_SECURITY_INFORMATION,
                            security_descriptor
                        )
                    except ImportError:
                        self.logger.warning("pywin32 not installed, file permissions might not be secure")
                else:  # Unix-like systems
                    os.chmod(self.image_hash_file, 0o600)  # Read/write for owner only
                    os.chmod(self.auth_folder, 0o700)  # Read/write/execute for owner only
                    
                return True, "Authentication image registered successfully"
                
        except Exception as e:
            self.logger.error(f"Error registering image: {str(e)}")
            return False, f"Failed to register image: {str(e)}"
            
    def verify_image(self, image_path: Path) -> Tuple[bool, str]:
        """Verify an authentication image"""
        try:
            if not self.image_hash_file.exists():
                return False, "No registered authentication image found"
                
            if not image_path.exists():
                return False, "Image file not found"
                
            with Image.open(image_path) as img:
                # Normalize image
                img = img.convert('RGB')
                img = img.resize((256, 256))
                
                # Get image hash
                img_byte_arr = io.BytesIO()
                img.save(img_byte_arr, format='PNG')
                img_byte_arr = img_byte_arr.getvalue()
                image_hash = hashlib.sha256(img_byte_arr).hexdigest()
                
                # Compare with stored hash
                with open(self.image_hash_file, 'r') as f:
                    stored_hash = f.read().strip()
                    
                if image_hash == stored_hash:
                    return True, "Image authentication successful"
                return False, "Image authentication failed"
                
        except Exception as e:
            self.logger.error(f"Error verifying image: {str(e)}")
            return False, f"Failed to verify image: {str(e)}" 