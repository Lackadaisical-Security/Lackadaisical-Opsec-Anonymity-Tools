#!/usr/bin/env python3
"""
Secure Messenger - End-to-end encrypted messaging
Part of Lackadaisical Anonymity Toolkit
"""

import os
import sys
import json
import base64
import socket
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SecureMessenger:
    """End-to-end encrypted messaging system"""
    
    def __init__(self, username: str, port: int = 8888):
        self.username = username
        self.port = port
        self.private_key = None
        self.public_key = None
        self.contacts = {}  # username -> public_key
        self.messages = []
        self.server_socket = None
        self.running = False
        
        # Generate or load keypair
        self._init_keys()
    
    def _init_keys(self):
        """Initialize RSA keypair"""
        key_dir = os.path.expanduser('~/.lackadaisical/keys')
        os.makedirs(key_dir, exist_ok=True)
        
        private_key_path = os.path.join(key_dir, f'{self.username}.pem')
        public_key_path = os.path.join(key_dir, f'{self.username}.pub')
        
        if os.path.exists(private_key_path):
            # Load existing keys
            with open(private_key_path, 'rb') as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(public_key_path, 'rb') as f:
                self.public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
        else:
            # Generate new keypair
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            
            # Save keys
            with open(private_key_path, 'wb') as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            with open(public_key_path, 'wb') as f:
                f.write(self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
            
            os.chmod(private_key_path, 0o600)
    
    def get_public_key_string(self) -> str:
        """Get public key as base64 string"""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return base64.b64encode(pem).decode()
    
    def add_contact(self, username: str, public_key_str: str):
        """Add contact with their public key"""
        try:
            pem = base64.b64decode(public_key_str)
            public_key = serialization.load_pem_public_key(
                pem, backend=default_backend()
            )
            self.contacts[username] = public_key
            print(f"Added contact: {username}")
        except Exception as e:
            print(f"Error adding contact: {e}")
    
    def encrypt_message(self, recipient: str, message: str) -> Optional[Dict]:
        """Encrypt message for recipient"""
        if recipient not in self.contacts:
            print(f"Unknown recipient: {recipient}")
            return None
        
        recipient_key = self.contacts[recipient]
        
        # Generate AES key
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        
        # Encrypt message with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Pad message
        message_bytes = message.encode()
        padding_length = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + bytes([padding_length] * padding_length)
        
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        
        # Encrypt AES key with recipient's RSA public key
        encrypted_key = recipient_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Sign message
        signature = self.private_key.sign(
            encrypted_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return {
            'sender': self.username,
            'recipient': recipient,
            'timestamp': datetime.utcnow().isoformat(),
            'encrypted_key': base64.b64encode(encrypted_key).decode(),
            'iv': base64.b64encode(iv).decode(),
            'message': base64.b64encode(encrypted_message).decode(),
            'signature': base64.b64encode(signature).decode()
        }
    
    def decrypt_message(self, encrypted_data: Dict) -> Optional[str]:
        """Decrypt received message"""
        try:
            sender = encrypted_data['sender']
            
            if sender not in self.contacts:
                print(f"Message from unknown sender: {sender}")
                return None
            
            sender_key = self.contacts[sender]
            
            # Decode base64
            encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])
            iv = base64.b64decode(encrypted_data['iv'])
            encrypted_message = base64.b64decode(encrypted_data['message'])
            signature = base64.b64decode(encrypted_data['signature'])
            
            # Verify signature
            sender_key.verify(
                signature,
                encrypted_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Decrypt AES key
            aes_key = self.private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt message
            cipher = Cipher(
                algorithms.AES(aes_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
            
            # Remove padding
            padding_length = padded_message[-1]
            message = padded_message[:-padding_length].decode()
            
            return message
            
        except Exception as e:
            print(f"Decryption error: {e}")
            return None
    
    def send_message(self, recipient: str, message: str, 
                    host: str = 'localhost', port: Optional[int] = None):
        """Send encrypted message to recipient"""
        encrypted_data = self.encrypt_message(recipient, message)
        if not encrypted_data:
            return
        
        # Send over network
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((host, port or self.port))
            
            # Send as JSON
            data = json.dumps(encrypted_data).encode()
            sock.send(len(data).to_bytes(4, 'big'))
            sock.send(data)
            
            sock.close()
            print(f"Message sent to {recipient}")
            
        except Exception as e:
            print(f"Failed to send message: {e}")
    
    def start_server(self):
        """Start message receiving server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(5)
        
        self.running = True
        print(f"Secure messenger listening on port {self.port}")
        
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address)
                ).start()
            except:
                break
    
    def _handle_client(self, client_socket: socket.socket, address: Tuple):
        """Handle incoming connection"""
        try:
            # Receive message length
            length_data = client_socket.recv(4)
            if not length_data:
                return
            
            message_length = int.from_bytes(length_data, 'big')
            
            # Receive message
            data = b''
            while len(data) < message_length:
                chunk = client_socket.recv(min(4096, message_length - len(data)))
                if not chunk:
                    break
                data += chunk
            
            # Parse and decrypt
            encrypted_data = json.loads(data.decode())
            
            if encrypted_data['recipient'] != self.username:
                print(f"Message not for us (recipient: {encrypted_data['recipient']})")
                return
            
            message = self.decrypt_message(encrypted_data)
            if message:
                self.messages.append({
                    'sender': encrypted_data['sender'],
                    'timestamp': encrypted_data['timestamp'],
                    'message': message
                })
                
                print(f"\n[{encrypted_data['timestamp']}] {encrypted_data['sender']}: {message}")
            
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()
    
    def stop_server(self):
        """Stop message server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
    
    def create_group(self, group_name: str, members: List[str]) -> bool:
        """Create encrypted group chat"""
        # Generate group key
        group_key = os.urandom(32)
        
        # Encrypt group key for each member
        group_data = {
            'name': group_name,
            'created_by': self.username,
            'created_at': datetime.utcnow().isoformat(),
            'members': {}
        }
        
        for member in members:
            if member not in self.contacts:
                print(f"Unknown member: {member}")
                return False
            
            # Encrypt group key with member's public key
            encrypted_key = self.contacts[member].encrypt(
                group_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            group_data['members'][member] = base64.b64encode(encrypted_key).decode()
        
        # Save group data
        group_file = os.path.expanduser(f'~/.lackadaisical/groups/{group_name}.json')
        os.makedirs(os.path.dirname(group_file), exist_ok=True)
        
        with open(group_file, 'w') as f:
            json.dump(group_data, f)
        
        print(f"Group '{group_name}' created with {len(members)} members")
        return True


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Secure Messenger')
    parser.add_argument('username', help='Your username')
    parser.add_argument('--port', type=int, default=8888, help='Listening port')
    
    subparsers = parser.add_subparsers(dest='command')
    
    # Get public key
    subparsers.add_parser('pubkey', help='Show your public key')
    
    # Add contact
    add_parser = subparsers.add_parser('add-contact', help='Add a contact')
    add_parser.add_argument('contact_name', help='Contact username')
    add_parser.add_argument('public_key', help='Contact public key (base64)')
    
    # Send message
    send_parser = subparsers.add_parser('send', help='Send a message')
    send_parser.add_argument('recipient', help='Recipient username')
    send_parser.add_argument('message', help='Message to send')
    send_parser.add_argument('--host', default='localhost', help='Recipient host')
    send_parser.add_argument('--port', type=int, help='Recipient port')
    
    # Listen for messages
    subparsers.add_parser('listen', help='Listen for messages')
    
    args = parser.parse_args()
    
    messenger = SecureMessenger(args.username, args.port)
    
    if args.command == 'pubkey':
        print(f"Your public key:\n{messenger.get_public_key_string()}")
    
    elif args.command == 'add-contact':
        messenger.add_contact(args.contact_name, args.public_key)
    
    elif args.command == 'send':
        messenger.send_message(args.recipient, args.message, 
                             args.host, args.port)
    
    elif args.command == 'listen':
        try:
            messenger.start_server()
        except KeyboardInterrupt:
            print("\nShutting down...")
            messenger.stop_server()
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
