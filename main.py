from core.storage.secure_storage import SecureStorage
from core.config.config_manager import ConfigManager
from core.auth.password_auth import PasswordAuth
from datetime import datetime, timedelta
from typing import Optional, Tuple
from pathlib import Path
import logging
import getpass
import sys
import json

class SecureFileGuard:
    def __init__(self):
        # Load configuration
        self.config = ConfigManager()
        
        # Set up logging
        logging.basicConfig(
            level=getattr(logging, self.config.get("logging", "level", "INFO")),
            format=self.config.get("logging", "format", "%(asctime)s - %(levelname)s - %(message)s"),
            filename=self.config.get("logging", "file", "secure_file_guard.log")
        )
        self.logger = logging.getLogger(__name__)
        
        self.password_auth = PasswordAuth(self.config)
        self.storage: Optional[SecureStorage] = None
        
        self.max_attempts = 3
        self.lockout_duration = 300
        self.failed_attempts = 0
        self.last_attempt_time = None
        self.lockout_until = None
        self.lockout_file = Path.home() / '.secure-file-guard' / 'secure_storage' / 'lockout.json'
        self.load_lockout_state()

    def load_lockout_state(self):
        """Load lockout state from file"""
        try:
            if self.lockout_file.exists():
                with open(self.lockout_file, 'r') as f:
                    state = json.load(f)
                    
                if 'lockout_until' in state:
                    lockout_time = datetime.fromisoformat(state['lockout_until'])
                    if datetime.now() < lockout_time:
                        self.lockout_until = lockout_time
                        self.failed_attempts = state.get('failed_attempts', self.max_attempts)
                    else:
                        # Lockout period has expired
                        self.reset_attempts()
                        
        except Exception as e:
            self.logger.error(f"Error loading lockout state: {str(e)}")
            self.reset_attempts()

    def save_lockout_state(self):
        """Save lockout state to file"""
        try:
            state = {
                'failed_attempts': self.failed_attempts,
                'lockout_until': self.lockout_until.isoformat() if self.lockout_until else None,
                'last_attempt': self.last_attempt_time.isoformat() if self.last_attempt_time else None
            }
            
            # Ensure directory exists
            self.lockout_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(self.lockout_file, 'w') as f:
                json.dump(state, f)
                
        except Exception as e:
            self.logger.error(f"Error saving lockout state: {str(e)}")

    def is_locked_out(self) -> Tuple[bool, str]:
        """Check if the vault is currently locked out due to failed attempts"""
        if self.lockout_until is None:
            return False, ""
            
        if datetime.now() < self.lockout_until:
            remaining = (self.lockout_until - datetime.now()).seconds
            return True, f"Vault is locked. Try again in {remaining} seconds"
            
        # Reset lockout if time has passed
        self.reset_attempts()
        return False, ""

    def reset_attempts(self):
        """Reset failed attempts counter"""
        self.failed_attempts = 0
        self.last_attempt_time = None
        self.lockout_until = None
        
        # Remove lockout file if it exists
        try:
            if self.lockout_file.exists():
                self.lockout_file.unlink()
        except Exception as e:
            self.logger.error(f"Error removing lockout file: {str(e)}")

    def record_failed_attempt(self):
        """Record a failed password attempt"""
        current_time = datetime.now()
        
        # Reset counter if last attempt was more than 30 minutes ago
        if self.last_attempt_time and (current_time - self.last_attempt_time) > timedelta(minutes=30):
            self.failed_attempts = 0
            
        self.failed_attempts += 1
        self.last_attempt_time = current_time
        
        # Implement lockout if max attempts exceeded
        if self.failed_attempts >= self.max_attempts:
            self.lockout_until = current_time + timedelta(seconds=self.lockout_duration)
            self.logger.warning(f"Vault locked due to {self.failed_attempts} failed attempts")
            
        # Save state after each failed attempt
        self.save_lockout_state()

    def setup_new_vault(self, password: str) -> Tuple[bool, str]:
        """Set up a new secure vault with password"""
        try:
            # Validate password strength
            valid, message = self.password_auth.validate_password_strength(password)
            if not valid:
                return False, message
                
            self.storage = SecureStorage(password, self.config)
            success, message = self.storage.initialize_storage(force_new=True)
            
            if success:
                return True, "Secure vault created successfully"
            return False, message
            
        except Exception as e:
            self.logger.error(f"Error setting up vault: {str(e)}")
            return False, f"Failed to set up vault: {str(e)}"
            
    def unlock_vault(self, password: str) -> Tuple[bool, str]:
        """Unlock existing vault with password"""
        try:
            locked, message = self.is_locked_out()
            if locked:
                return False, message

            # Check if vault exists
            vault_path = Path.home() / '.secure-file-guard' / 'secure_storage'
            if not vault_path.exists():
                return False, "No vault found"

            # Initialize storage with password
            self.storage = SecureStorage(password, self.config)
            
            # Verify password
            if not self.storage.verify_password():
                self.record_failed_attempt()
                attempts_left = self.max_attempts - self.failed_attempts
                if attempts_left > 0:
                    return False, f"Invalid password. {attempts_left} attempts remaining"
                return False, "Too many failed attempts. Vault is locked"
                
            self.reset_attempts()
            return True, "Vault unlocked successfully"
            
        except Exception as e:
            self.logger.error(f"Error unlocking vault: {str(e)}")
            return False, f"Failed to unlock vault: {str(e)}"
            
    def add_file(self, file_path: Path) -> Tuple[bool, str]:
        """Add a file to the vault"""
        if not self.storage:
            return False, "Vault is not unlocked"
            
        return self.storage.add_file(file_path)
        
    def extract_file(self, filename: str, destination: Path) -> Tuple[bool, str]:
        """Extract a file from the vault"""
        if not self.storage:
            return False, "Vault is not unlocked"
            
        try:
            # Create destination directory if it doesn't exist
            destination = Path(destination)
            if destination.is_dir():
                destination = destination / filename
                
            # Ensure parent directory exists
            destination.parent.mkdir(parents=True, exist_ok=True)
            
            return self.storage.extract_file(filename, destination)
            
        except Exception as e:
            self.logger.error(f"Error extracting file: {str(e)}")
            return False, f"Failed to extract file: {str(e)}"
        
    def list_files(self) -> list:
        """List all files in the vault"""
        if not self.storage:
            return []
            
        metadata = self.storage._load_metadata()
        return list(metadata['files'].keys())
        
    def get_file_info(self, filename: str) -> dict:
        """Get information about a specific file"""
        if not self.storage:
            return {}
            
        metadata = self.storage._load_metadata()
        return metadata['files'].get(filename, {})

    def prompt_password(self, for_new_vault: bool = False) -> Optional[str]:
        """Prompt user for password"""
        action = "create new vault" if for_new_vault else "unlock vault"
        attempts = 0
        max_attempts = 3
        
        while attempts < max_attempts:
            password = getpass.getpass(f"\nEnter password to {action}: ")
            
            # Don't allow empty passwords
            if not password:
                print("Password cannot be empty. Please try again.")
                attempts += 1
                continue
                
            if for_new_vault:
                confirm = getpass.getpass("Confirm password: ")
                if password != confirm:
                    print("Passwords don't match. Please try again.")
                    attempts += 1
                    continue
                    
                # Validate password strength
                valid, message = self.password_auth.validate_password_strength(password)
                if not valid:
                    print(f"Password is not strong enough: {message}")
                    attempts += 1
                    continue
                    
            return password
            
        print(f"\nToo many failed attempts ({max_attempts}). Exiting...")
        return None

def main():
    app = SecureFileGuard()
    
    print("\nSecure File Guard")
    print("-" * 30)
    
    # Check if vault exists
    vault_path = Path.home() / '.secure-file-guard' / 'secure_storage'
    vault_exists = (vault_path.exists() and 
                   all((vault_path / f).exists() for f in ['vault.salt', 'vault.key', 'metadata.json', 'container.encrypted']))
    
    if vault_exists:
        # Try to unlock existing vault
        while True:
            locked, message = app.is_locked_out()
            if locked:
                print(f"\n{message}")
                sys.exit(1)
                
            password = app.prompt_password()
            if password is None:
                sys.exit(1)
                
            success, message = app.unlock_vault(password)
            print(f"\n{message}")
            
            if success:
                break
            elif "Vault is locked." in message:
                sys.exit(1)
    else:
        print("\nNo vault found. Creating new vault...")
        while True:
            password = app.prompt_password(for_new_vault=True)
            if password is None:
                sys.exit(1)
                
            success, message = app.setup_new_vault(password)
            if success:
                break
            print(f"\n{message}")
    
    # Main application loop
    while True:
        print("\nAvailable commands:")
        print("1. Add file")
        print("2. Extract file")
        print("3. List files")
        print("4. Delete file")
        print("5. Exit")
        
        choice = input("\nEnter command (1-5): ")
        
        if choice == "1":
            file_path = input("Enter file path to add: ")
            try:
                success, message = app.add_file(Path(file_path))
                print(f"Add file status: {message}")
            except Exception as e:
                print(f"Error: {str(e)}")
                
        elif choice == "2":
            filename = input("Enter filename to extract: ")
            destination = input("Enter destination path: ")
            try:
                success, message = app.storage.extract_file(filename, Path(destination))
                if success:
                    print(f"\nExtraction successful!")
                    print(f"File extracted to: {message}")
                else:
                    print(f"\nExtraction failed!")
                    print(f"Reason: {message}")
            except Exception as e:
                print(f"Error during extraction: {str(e)}")
                
        elif choice == "3":
            print("\nFiles in vault:")
            for filename in app.list_files():
                info = app.get_file_info(filename)
                print(f"- {filename} (Size: {info.get('size', 0)} bytes)")
                
        elif choice == "4":
            filename = input("Enter filename to delete: ")
            confirm = input(f"Are you sure you want to securely delete '{filename}'? (y/n): ")
            if confirm.lower() == 'y':
                try:
                    success, message = app.storage.secure_delete_file(filename)
                    print("\nDeletion Status:")
                    print("-" * 50)
                    print(message)
                    print("-" * 50)
                    if success:
                        print("\nFile has been securely deleted.")
                    else:
                        print("\nDeletion failed!")
                except Exception as e:
                    print(f"Error: {str(e)}")
                
        elif choice == "5":
            print("Exiting...")
            break
            
        else:
            print("Invalid command")

if __name__ == "__main__":
    main() 