#!/usr/bin/env python3
"""
Credential Vault - Secure storage for multiple personas and identities
Part of Lackadaisical Anonymity Toolkit
"""

import os
import sys
import json
import getpass
import argparse
import sqlite3
from pathlib import Path
from typing import Dict, List, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets

class CredentialVault:
    """Encrypted credential storage for multiple personas"""
    
    def __init__(self, vault_path: str = "~/.config/lackadaisical/vault.db"):
        self.vault_path = Path(vault_path).expanduser()
        self.vault_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.master_key: Optional[bytes] = None
        self.db: Optional[sqlite3.Connection] = None
        
    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def _encrypt(self, data: str, key: bytes) -> bytes:
        """Encrypt data using AES-256-GCM"""
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data.encode(), None)
        return nonce + ciphertext
    
    def _decrypt(self, encrypted: bytes, key: bytes) -> str:
        """Decrypt data using AES-256-GCM"""
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()
    
    def initialize_vault(self, password: str) -> bool:
        """Initialize a new vault"""
        try:
            # Generate random salt
            salt = secrets.token_bytes(32)
            
            # Derive master key
            self.master_key = self._derive_key(password, salt)
            
            # Create database
            self.db = sqlite3.connect(str(self.vault_path))
            self.db.execute('''
                CREATE TABLE IF NOT EXISTS config (
                    key TEXT PRIMARY KEY,
                    value BLOB
                )
            ''')
            
            self.db.execute('''
                CREATE TABLE IF NOT EXISTS personas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    data BLOB NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Store salt
            self.db.execute(
                'INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)',
                ('salt', salt)
            )
            
            self.db.commit()
            
            # Set secure permissions
            os.chmod(self.vault_path, 0o600)
            
            print(f"✓ Vault initialized: {self.vault_path}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to initialize vault: {e}")
            return False
    
    def unlock_vault(self, password: str) -> bool:
        """Unlock existing vault"""
        try:
            if not self.vault_path.exists():
                print("✗ Vault does not exist. Initialize first.")
                return False
            
            # Connect to database
            self.db = sqlite3.connect(str(self.vault_path))
            
            # Get salt
            cursor = self.db.execute('SELECT value FROM config WHERE key = ?', ('salt',))
            row = cursor.fetchone()
            
            if not row:
                print("✗ Vault corrupted: missing salt")
                return False
            
            salt = row[0]
            
            # Derive master key
            self.master_key = self._derive_key(password, salt)
            
            # Verify password by trying to decrypt a test entry
            cursor = self.db.execute('SELECT data FROM personas LIMIT 1')
            row = cursor.fetchone()
            
            if row:
                try:
                    self._decrypt(row[0], self.master_key)
                except:
                    print("✗ Invalid password")
                    self.master_key = None
                    return False
            
            print("✓ Vault unlocked")
            return True
            
        except Exception as e:
            print(f"✗ Failed to unlock vault: {e}")
            return False
    
    def add_persona(self, name: str, credentials: Dict) -> bool:
        """Add a new persona to the vault"""
        if not self.master_key:
            print("✗ Vault is locked")
            return False
        
        try:
            # Encrypt credentials
            data_json = json.dumps(credentials)
            encrypted = self._encrypt(data_json, self.master_key)
            
            # Store in database
            self.db.execute(
                'INSERT INTO personas (name, data) VALUES (?, ?)',
                (name, encrypted)
            )
            self.db.commit()
            
            print(f"✓ Persona added: {name}")
            return True
            
        except sqlite3.IntegrityError:
            print(f"✗ Persona '{name}' already exists")
            return False
        except Exception as e:
            print(f"✗ Failed to add persona: {e}")
            return False
    
    def get_persona(self, name: str) -> Optional[Dict]:
        """Retrieve a persona from the vault"""
        if not self.master_key:
            print("✗ Vault is locked")
            return None
        
        try:
            cursor = self.db.execute(
                'SELECT data FROM personas WHERE name = ?',
                (name,)
            )
            row = cursor.fetchone()
            
            if not row:
                print(f"✗ Persona '{name}' not found")
                return None
            
            # Decrypt data
            decrypted = self._decrypt(row[0], self.master_key)
            return json.loads(decrypted)
            
        except Exception as e:
            print(f"✗ Failed to retrieve persona: {e}")
            return None
    
    def list_personas(self) -> List[str]:
        """List all personas in the vault"""
        if not self.master_key:
            print("✗ Vault is locked")
            return []
        
        try:
            cursor = self.db.execute(
                'SELECT name, created_at FROM personas ORDER BY name'
            )
            return [(row[0], row[1]) for row in cursor.fetchall()]
            
        except Exception as e:
            print(f"✗ Failed to list personas: {e}")
            return []
    
    def delete_persona(self, name: str) -> bool:
        """Delete a persona from the vault"""
        if not self.master_key:
            print("✗ Vault is locked")
            return False
        
        try:
            cursor = self.db.execute(
                'DELETE FROM personas WHERE name = ?',
                (name,)
            )
            self.db.commit()
            
            if cursor.rowcount > 0:
                print(f"✓ Persona deleted: {name}")
                return True
            else:
                print(f"✗ Persona '{name}' not found")
                return False
                
        except Exception as e:
            print(f"✗ Failed to delete persona: {e}")
            return False
    
    def change_password(self, old_password: str, new_password: str) -> bool:
        """Change vault master password"""
        # Verify old password
        if not self.unlock_vault(old_password):
            return False
        
        try:
            # Get all personas
            cursor = self.db.execute('SELECT name, data FROM personas')
            personas = []
            
            for name, encrypted in cursor.fetchall():
                decrypted = self._decrypt(encrypted, self.master_key)
                personas.append((name, json.loads(decrypted)))
            
            # Generate new salt and key
            new_salt = secrets.token_bytes(32)
            new_key = self._derive_key(new_password, new_salt)
            
            # Re-encrypt all personas
            self.db.execute('DELETE FROM personas')
            
            for name, credentials in personas:
                data_json = json.dumps(credentials)
                encrypted = self._encrypt(data_json, new_key)
                self.db.execute(
                    'INSERT INTO personas (name, data) VALUES (?, ?)',
                    (name, encrypted)
                )
            
            # Update salt
            self.db.execute(
                'UPDATE config SET value = ? WHERE key = ?',
                (new_salt, 'salt')
            )
            
            self.db.commit()
            self.master_key = new_key
            
            print("✓ Password changed successfully")
            return True
            
        except Exception as e:
            print(f"✗ Failed to change password: {e}")
            self.db.rollback()
            return False
    
    def export_persona(self, name: str, output_file: str) -> bool:
        """Export a persona to JSON file"""
        credentials = self.get_persona(name)
        if not credentials:
            return False
        
        try:
            with open(output_file, 'w') as f:
                json.dump(credentials, f, indent=2)
            
            # Set secure permissions
            os.chmod(output_file, 0o600)
            
            print(f"✓ Persona exported: {output_file}")
            return True
            
        except Exception as e:
            print(f"✗ Failed to export persona: {e}")
            return False
    
    def import_persona(self, name: str, input_file: str) -> bool:
        """Import a persona from JSON file"""
        try:
            with open(input_file, 'r') as f:
                credentials = json.load(f)
            
            return self.add_persona(name, credentials)
            
        except Exception as e:
            print(f"✗ Failed to import persona: {e}")
            return False
    
    def close(self):
        """Close vault and clear sensitive data"""
        if self.db:
            self.db.close()
        
        if self.master_key:
            # Overwrite key in memory
            self.master_key = b'\x00' * len(self.master_key)
            self.master_key = None

def main():
    parser = argparse.ArgumentParser(
        description='Credential Vault - Secure persona management'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Init command
    subparsers.add_parser('init', help='Initialize new vault')
    
    # Add command
    add_parser = subparsers.add_parser('add', help='Add persona')
    add_parser.add_argument('name', help='Persona name')
    add_parser.add_argument('--interactive', '-i', action='store_true',
                          help='Interactive credential entry')
    
    # Get command
    get_parser = subparsers.add_parser('get', help='Get persona')
    get_parser.add_argument('name', help='Persona name')
    
    # List command
    subparsers.add_parser('list', help='List all personas')
    
    # Delete command
    del_parser = subparsers.add_parser('delete', help='Delete persona')
    del_parser.add_argument('name', help='Persona name')
    
    # Export command
    export_parser = subparsers.add_parser('export', help='Export persona')
    export_parser.add_argument('name', help='Persona name')
    export_parser.add_argument('output', help='Output file')
    
    # Import command
    import_parser = subparsers.add_parser('import', help='Import persona')
    import_parser.add_argument('name', help='Persona name')
    import_parser.add_argument('input', help='Input file')
    
    # Change password command
    subparsers.add_parser('passwd', help='Change vault password')
    
    parser.add_argument('--vault', default='~/.config/lackadaisical/vault.db',
                       help='Vault database path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    vault = CredentialVault(args.vault)
    
    try:
        if args.command == 'init':
            password = getpass.getpass("Set master password: ")
            confirm = getpass.getpass("Confirm password: ")
            
            if password != confirm:
                print("✗ Passwords do not match")
                return 1
            
            if len(password) < 12:
                print("✗ Password must be at least 12 characters")
                return 1
            
            return 0 if vault.initialize_vault(password) else 1
        
        else:
            # All other commands need unlocked vault
            password = getpass.getpass("Vault password: ")
            
            if not vault.unlock_vault(password):
                return 1
            
            if args.command == 'add':
                if args.interactive:
                    credentials = {}
                    print("Enter credentials (blank line to finish):")
                    while True:
                        key = input("  Key: ").strip()
                        if not key:
                            break
                        value = getpass.getpass(f"  {key}: ")
                        credentials[key] = value
                else:
                    # Non-interactive: read from stdin as JSON
                    credentials = json.load(sys.stdin)
                
                return 0 if vault.add_persona(args.name, credentials) else 1
            
            elif args.command == 'get':
                creds = vault.get_persona(args.name)
                if creds:
                    print(json.dumps(creds, indent=2))
                    return 0
                return 1
            
            elif args.command == 'list':
                personas = vault.list_personas()
                if personas:
                    print("\n=== Vault Personas ===")
                    for name, created in personas:
                        print(f"  {name} (created: {created})")
                    print()
                else:
                    print("No personas in vault")
                return 0
            
            elif args.command == 'delete':
                confirm = input(f"Delete persona '{args.name}'? (yes/no): ")
                if confirm.lower() == 'yes':
                    return 0 if vault.delete_persona(args.name) else 1
                else:
                    print("Cancelled")
                    return 1
            
            elif args.command == 'export':
                return 0 if vault.export_persona(args.name, args.output) else 1
            
            elif args.command == 'import':
                return 0 if vault.import_persona(args.name, args.input) else 1
            
            elif args.command == 'passwd':
                new_password = getpass.getpass("New password: ")
                confirm = getpass.getpass("Confirm password: ")
                
                if new_password != confirm:
                    print("✗ Passwords do not match")
                    return 1
                
                if len(new_password) < 12:
                    print("✗ Password must be at least 12 characters")
                    return 1
                
                return 0 if vault.change_password(password, new_password) else 1
    
    finally:
        vault.close()
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
