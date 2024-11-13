from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet

from typing import Dict, Tuple
from datetime import datetime
from pathlib import Path
import logging
import base64
import shutil
import json
import os

class SecureStorage:
    def __init__(self, password: str, config):
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # Get storage paths from config
        base_folder = Path.home() / self.config.get('storage', 'secure_folder', '.secure-file-guard')
        self.secure_folder = base_folder / 'secure_storage'
        self.metadata_file = self.secure_folder / self.config.get('storage', 'metadata_name', 'metadata.json')
        self.container_file = self.secure_folder / self.config.get('storage', 'container_name', 'container.encrypted')
        self.verification_file = self.secure_folder / 'vault.key'
        self.salt_file = self.secure_folder / 'vault.salt'
        self.lockout_file = self.secure_folder / 'lockout.json'
        
        # Generate encryption key from password
        self.salt = self._get_or_create_salt()
        self.key = self._generate_key_from_password(password, self.salt)
        self.fernet = Fernet(self.key)
        
    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or create new one"""
        if self.salt_file.exists():
            with open(self.salt_file, 'rb') as f:
                return f.read()
        else:
            # Only create new salt if we're initializing a new vault
            salt = os.urandom(32)
            return salt
        
    def _generate_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Generate a Fernet key from password using PBKDF2"""
        iterations = self.config.get('security.encryption', 'key_iterations', 100000)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
        
    def verify_password(self) -> bool:
        """Verify if the password is correct for this vault"""
        try:
            if not self.verification_file.exists():
                return False
                
            with open(self.verification_file, 'rb') as f:
                encrypted_check = f.read()
                
            decrypted = self.fernet.decrypt(encrypted_check)
            return decrypted == b"VALID_VAULT_KEY"
        except Exception:
            return False
        
    def initialize_storage(self, force_new: bool = False) -> Tuple[bool, str]:
        """Initialize secure storage directory and files"""
        try:
            if force_new and self.secure_folder.exists():
                shutil.rmtree(self.secure_folder)
                
            self.secure_folder.mkdir(parents=True, exist_ok=True)
            
            # Set directory permissions to be accessible only by the owner
            os.chmod(self.secure_folder, 0o700)
            
            # Save the salt with restricted permissions
            with open(self.salt_file, 'wb') as f:
                f.write(self.salt)
            os.chmod(self.salt_file, 0o600)
            
            encrypted_check = self.fernet.encrypt(b"VALID_VAULT_KEY")
            with open(self.verification_file, 'wb') as f:
                f.write(encrypted_check)
            os.chmod(self.verification_file, 0o600)
            
            metadata = {
                'files': {},
                'created_at': datetime.now().isoformat(),
                'last_modified': datetime.now().isoformat()
            }
            self._save_metadata(metadata)
            os.chmod(self.metadata_file, 0o600)
            
            with open(self.container_file, 'wb') as f:
                pass
            os.chmod(self.container_file, 0o600)
            
            return True, "Storage initialized successfully"
        except Exception as e:
            self.logger.error(f"Error initializing storage: {str(e)}")
            return False
            
    def add_file(self, file_path: Path) -> Tuple[bool, str]:
        """Add a file to secure storage"""
        try:
            if not file_path.exists():
                self.logger.error(f"File not found: {file_path}")
                return False, "File does not exist"

            self.logger.info(f"Adding file: {file_path}")
            file_size = file_path.stat().st_size
            self.logger.debug(f"File size: {file_size} bytes")

            with open(file_path, 'rb') as f:
                content = f.read()
                self.logger.debug(f"Read {len(content)} bytes from file")

            # Update metadata
            metadata = self._load_metadata()
            file_info = {
                'original_path': str(file_path),
                'size': len(content),
                'added_at': datetime.now().isoformat(),
                'modified_at': datetime.fromtimestamp(os.path.getmtime(file_path)).isoformat()
            }
            metadata['files'][file_path.name] = file_info
            self._save_metadata(metadata)
            self.logger.debug("Updated metadata")

            # Encrypt and save content
            encrypted_content = self.fernet.encrypt(content)
            self._append_to_container(encrypted_content)
            self.logger.info(f"Successfully added file: {file_path.name}")

            return True, "File added successfully"

        except Exception as e:
            self.logger.error(f"Error adding file: {str(e)}", exc_info=True)
            return False, f"Failed to add file: {str(e)}"
            
    def extract_file(self, filename: str, destination: Path) -> Tuple[bool, str]:
        """Extract a file from the vault"""
        try:
            self.logger.info(f"Attempting to extract file: {filename}")
            
            metadata = self._load_metadata()
            if filename not in metadata['files']:
                self.logger.warning(f"File not found in vault: {filename}")
                return False, f"File '{filename}' not found in vault"

            try:
                encrypted_content = self._get_file_content(filename)
                if not encrypted_content:
                    self.logger.error(f"Could not retrieve content for: {filename}")
                    return False, f"Could not retrieve content for '{filename}'"

                destination = Path(destination)
                if destination.is_dir():
                    destination = destination / filename
                
                self.logger.debug(f"Extracting to: {destination}")
                
                # Decrypt and save
                decrypted_content = self.fernet.decrypt(encrypted_content)
                destination.parent.mkdir(parents=True, exist_ok=True)
                
                with open(destination, 'wb') as f:
                    f.write(decrypted_content)
                
                self.logger.info(f"Successfully extracted file: {filename}")
                return True, f"File extracted successfully to: {destination}"

            except Exception as e:
                self.logger.error(f"Error extracting file: {str(e)}", exc_info=True)
                return False, f"Failed to extract file: {str(e)}"

        except Exception as e:
            self.logger.error(f"Error accessing vault: {str(e)}", exc_info=True)
            return False, f"Failed to access vault: {str(e)}"
            
    def _save_metadata(self, metadata: Dict):
        """Save metadata to file"""
        with open(self.metadata_file, 'w') as f:
            json.dump(metadata, f, indent=4)
            
    def _load_metadata(self) -> Dict:
        """Load metadata from file"""
        if not self.metadata_file.exists():
            return {'files': {}}
        with open(self.metadata_file, 'r') as f:
            return json.load(f)
            
    def _append_to_container(self, encrypted_content: bytes):
        """Append encrypted content to container file"""
        try:
            mode = 'ab' if self.container_file.exists() else 'wb'
            with open(self.container_file, mode) as f:
                f.write(len(encrypted_content).to_bytes(8, 'big'))
                f.write(encrypted_content)
        except Exception as e:
            self.logger.error(f"Error appending to container: {str(e)}")
            raise

    def _get_file_content(self, filename: str) -> bytes:
        """Get encrypted content for a specific file from the container"""
        try:
            if not self.container_file.exists():
                self.logger.error("Container file does not exist")
                return b''

            metadata = self._load_metadata()
            if filename not in metadata['files']:
                self.logger.error(f"File '{filename}' not found in metadata")
                return b''

            target_size = metadata['files'][filename]['size']
            
            # Read the container file and find the correct content
            with open(self.container_file, 'rb') as f:
                while True:
                    size_bytes = f.read(8)
                    if not size_bytes:
                        break

                    size = int.from_bytes(size_bytes, 'big')
                    content = f.read(size)

                    try:
                        decrypted = self.fernet.decrypt(content)
                        if len(decrypted) == target_size:
                            return content
                    except:
                        # Not our file, continue
                        continue

            self.logger.error(f"Could not find content for '{filename}'")
            return b''

        except Exception as e:
            self.logger.error(f"Error retrieving file content: {str(e)}")
            return b''
            
    def _set_secure_permissions(self, path: Path):
        """
        Set secure permissions for files based on OS
        Windows: Uses ACLs to restrict access to owner only
        Unix: Uses chmod to set 600 permissions
        """
        try:
            if os.name == 'nt':  # Windows
                from win32security import (
                    GetFileSecurity, OpenProcessToken, GetTokenInformation,
                    TokenUser, ACL, ACL_REVISION, SetFileSecurity,
                    OWNER_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION,
                    SECURITY_DESCRIPTOR
                )
                from win32api import GetCurrentProcess
                from ntsecuritycon import FILE_ALL_ACCESS

                try:
                    path_str = str(path)

                    # Get the current process token
                    token = OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY)
                    
                    # Get the user SID from the token
                    user_sid = GetTokenInformation(token, TokenUser)[0]

                    # Create a new ACL (Access Control List)
                    dacl = ACL()
                    
                    # Add an ACE (Access Control Entry)
                    dacl.AddAccessAllowedAce(
                        ACL_REVISION,
                        FILE_ALL_ACCESS,
                        user_sid
                    )

                    # Create a new security descriptor
                    sd = SECURITY_DESCRIPTOR()
                    
                    # Set the DACL in the security descriptor
                    sd.SetSecurityDescriptorDacl(1, dacl, 0)

                    # Apply the security descriptor to the file
                    SetFileSecurity(
                        path_str,
                        DACL_SECURITY_INFORMATION,
                        sd
                    )

                    self.logger.debug(f"Successfully set Windows ACL for {path}")

                except Exception as e:
                    self.logger.error(f"Failed to set Windows ACL for {path}: {str(e)}")
                    raise

            else:  # Unix-like systems
                os.chmod(path, 0o600)
                
                # Verify permissions were set correctly
                actual_mode = os.stat(path).st_mode & 0o777
                if actual_mode != 0o600:
                    raise PermissionError(
                        f"Failed to set correct permissions. "
                        f"Expected 600, got {oct(actual_mode)[2:]}"
                    )

        except Exception as e:
            self.logger.error(f"Error setting secure permissions for {path}: {str(e)}")
            raise RuntimeError(f"Could not secure {path}: {str(e)}")

    def secure_delete_file(self, filename: str) -> Tuple[bool, str]:
        """Delete a file using secure deletion"""
        try:
            self.logger.info(f"Attempting to securely delete file: {filename}")
            
            metadata = self._load_metadata()
            if filename not in metadata['files']:
                self.logger.warning(f"File not found for deletion: {filename}")
                return False, f"File '{filename}' not found in vault"

            try:
                original_size = metadata['files'][filename]['size']
                self.logger.debug(f"Original file size: {original_size} bytes")

                # Remove from metadata
                del metadata['files'][filename]
                self._save_metadata(metadata)
                self.logger.debug("Updated metadata")

                # Reorganize container
                self._reorganize_container(filename)
                self.logger.info(f"Successfully deleted file: {filename}")

                return True, f"File '{filename}' has been securely deleted"

            except Exception as e:
                self.logger.error(f"Error during secure deletion: {str(e)}", exc_info=True)
                return False, f"Error during secure deletion: {str(e)}"

        except Exception as e:
            self.logger.error(f"Error accessing vault for deletion: {str(e)}", exc_info=True)
            return False, f"Error accessing vault: {str(e)}"

    def _verify_deletion(self, filename: str, original_size: int) -> Tuple[bool, str]:
        """Verify that a file has been properly deleted from the vault"""
        try:
            # Check metadata
            metadata = self._load_metadata()
            if filename in metadata['files']:
                return False, "File still exists in metadata"
                
            # Check container content
            with open(self.container_file, 'rb') as f:
                container_data = f.read()
                
            # Calculate container size change
            expected_size_change = original_size + 8
            original_container_size = os.path.getsize(self.container_file)
            
            if len(container_data) != original_container_size - expected_size_change:
                return False, "Container size mismatch after deletion"
                
            # Try to retrieve deleted file content
            try:
                content = self._get_file_content(filename)
                if content:
                    return False, "File content still retrievable"
            except:
                pass
                
            return True, "File successfully deleted and verified"
            
        except Exception as e:
            return False, f"Verification failed: {str(e)}"

    def _overwrite_content(self, filename: str, data: bytes):
        """Overwrite file content in container"""
        try:
            metadata = self._load_metadata()
            files = list(metadata['files'].keys())
            target_index = files.index(filename)
            
            with open(self.container_file, 'rb') as f:
                container_data = f.read()
            
            current_pos = 0
            for i in range(target_index + 1):
                size_bytes = container_data[current_pos:current_pos + 8]
                size = int.from_bytes(size_bytes, 'big')
                if i == target_index:
                    with open(self.container_file, 'rb+') as f:
                        f.seek(current_pos + 8)
                        f.write(self.fernet.encrypt(data))
                current_pos += 8 + size
                
        except Exception as e:
            self.logger.error(f"Error overwriting content: {str(e)}")
            raise

    def _reorganize_container(self, deleted_filename: str):
        """Reorganize container after file deletion"""
        try:
            metadata = self._load_metadata()
            temp_container = self.container_file.with_suffix('.temp')
            
            with open(self.container_file, 'rb') as old_f, \
                 open(temp_container, 'wb') as new_f:
                
                current_pos = 0
                while True:
                    size_bytes = old_f.read(8)
                    if not size_bytes:
                        break
                        
                    size = int.from_bytes(size_bytes, 'big')
                    content = old_f.read(size)
                    
                    if current_pos != self._get_file_position(deleted_filename):
                        new_f.write(size_bytes)
                        new_f.write(content)
                    
                    current_pos += 8 + size
            
            # Replace old container with new one
            os.replace(temp_container, self.container_file)
            
        except Exception as e:
            self.logger.error(f"Error reorganizing container: {str(e)}")
            if temp_container.exists():
                temp_container.unlink()
            raise

    def _get_file_position(self, filename: str) -> int:
        """Get the position of a file in the container"""
        metadata = self._load_metadata()
        files = list(metadata['files'].keys())
        if filename not in files:
            return -1
            
        # Calculate position by reading sizes of previous files
        position = 0
        with open(self.container_file, 'rb') as f:
            for current_file in files:
                if current_file == filename:
                    break
                size_bytes = f.read(8)
                size = int.from_bytes(size_bytes, 'big')
                position += 8 + size
                f.seek(size, 1)
                
        return position