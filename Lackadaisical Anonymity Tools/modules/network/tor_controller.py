#!/usr/bin/env python3
"""
Tor Controller - Manages Tor connections and circuits
Part of Lackadaisical Anonymity Toolkit
"""

import os
import sys
import time
import socket
import socks
import stem
from stem import Signal
from stem.control import Controller
import requests

class TorController:
    def __init__(self, tor_port=9050, control_port=9051, password=None):
        self.tor_port = tor_port
        self.control_port = control_port
        self.password = password or self._get_password()
        self.controller = None
        
    def _get_password(self):
        """Get Tor control password from environment or file"""
        if os.environ.get('TOR_CONTROL_PASSWORD'):
            return os.environ['TOR_CONTROL_PASSWORD']
        
        pwd_file = os.path.expanduser('~/.tor/control_auth_cookie')
        if os.path.exists(pwd_file):
            with open(pwd_file, 'rb') as f:
                return f.read()
        
        return 'password'
    
    def connect(self):
        """Connect to Tor control port"""
        try:
            self.controller = Controller.from_port(port=self.control_port)
            self.controller.authenticate(password=self.password)
            return True
        except Exception as e:
            print(f"Failed to connect to Tor: {e}")
            return False
    
    def new_identity(self):
        """Request new Tor identity"""
        if not self.controller:
            if not self.connect():
                return False
        
        try:
            self.controller.signal(Signal.NEWNYM)
            time.sleep(3)  # Wait for new circuit
            return True
        except Exception as e:
            print(f"Failed to get new identity: {e}")
            return False
    
    def get_ip(self):
        """Get current exit node IP"""
        try:
            # Configure requests to use Tor
            session = requests.Session()
            session.proxies = {
                'http': f'socks5h://127.0.0.1:{self.tor_port}',
                'https': f'socks5h://127.0.0.1:{self.tor_port}'
            }
            
            response = session.get('https://api.ipify.org?format=json', timeout=10)
            return response.json()['ip']
        except Exception as e:
            print(f"Failed to get IP: {e}")
            return None
    
    def get_circuit_info(self):
        """Get information about current circuits"""
        if not self.controller:
            if not self.connect():
                return []
        
        circuits = []
        for circuit in self.controller.get_circuits():
            if circuit.status == 'BUILT':
                path = []
                for fingerprint, nickname in circuit.path:
                    desc = self.controller.get_network_status(fingerprint)
                    if desc:
                        path.append({
                            'nickname': nickname,
                            'fingerprint': fingerprint,
                            'address': desc.address,
                            'country': self._get_country(desc.address)
                        })
                circuits.append({
                    'id': circuit.id,
                    'purpose': circuit.purpose,
                    'path': path
                })
        
        return circuits
    
    def _get_country(self, ip):
        """Get country code for IP (simplified)"""
        try:
            import geoip2.database
            reader = geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-Country.mmdb')
            response = reader.country(ip)
            return response.country.iso_code
        except:
            return 'Unknown'
    
    def set_exit_country(self, country_code):
        """Set preferred exit node country"""
        if not self.controller:
            if not self.connect():
                return False
        
        try:
            self.controller.set_conf('ExitNodes', f'{{{country_code}}}')
            return True
        except Exception as e:
            print(f"Failed to set exit country: {e}")
            return False
    
    def close(self):
        """Close controller connection"""
        if self.controller:
            self.controller.close()

def main():
    """CLI interface for Tor controller"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Tor Controller')
    parser.add_argument('--new-identity', action='store_true', help='Get new Tor identity')
    parser.add_argument('--get-ip', action='store_true', help='Show current exit IP')
    parser.add_argument('--circuits', action='store_true', help='Show circuit information')
    parser.add_argument('--exit-country', help='Set exit node country (2-letter code)')
    
    args = parser.parse_args()
    
    tor = TorController()
    
    if args.new_identity:
        if tor.new_identity():
            print("New identity requested")
            ip = tor.get_ip()
            if ip:
                print(f"New IP: {ip}")
    
    elif args.get_ip:
        ip = tor.get_ip()
        if ip:
            print(f"Current exit IP: {ip}")
    
    elif args.circuits:
        circuits = tor.get_circuit_info()
        for circuit in circuits:
            print(f"\nCircuit {circuit['id']} ({circuit['purpose']}):")
            for i, node in enumerate(circuit['path']):
                print(f"  {i+1}. {node['nickname']} ({node['country']}) - {node['address']}")
    
    elif args.exit_country:
        if tor.set_exit_country(args.exit_country.upper()):
            print(f"Exit country set to {args.exit_country.upper()}")
    
    else:
        parser.print_help()
    
    tor.close()

if __name__ == '__main__':
    main()
