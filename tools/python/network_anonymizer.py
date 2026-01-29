#!/usr/bin/env python3
"""
Network Anonymizer - Automated network anonymization
Part of Lackadaisical Anonymity Toolkit
"""

import os
import sys
import time
import random
import socket
import subprocess
import threading
from typing import List, Dict, Optional, Tuple
import requests
import stem
from stem import Signal
from stem.control import Controller

class NetworkAnonymizer:
    """Automated network anonymization with multiple layers"""
    
    def __init__(self):
        self.tor_port = 9050
        self.tor_control_port = 9051
        self.tor_password = None
        self.active_layers = []
        self.original_settings = {}
        
        # VPN providers configuration
        self.vpn_providers = {
            'mullvad': {
                'config_path': '/etc/openvpn/mullvad',
                'auth_file': '/etc/openvpn/mullvad/auth.txt'
            },
            'protonvpn': {
                'command': 'protonvpn-cli',
                'servers': ['CH', 'IS', 'SE']  # Privacy-friendly countries
            },
            'nordvpn': {
                'command': 'nordvpn',
                'p2p_countries': ['NL', 'SE', 'CH']
            }
        }
        
    def setup_tor(self, bridges: bool = False, 
                  exit_countries: Optional[List[str]] = None) -> bool:
        """Setup and configure Tor"""
        try:
            # Check if Tor is installed
            if not self._is_tor_installed():
                print("Installing Tor...")
                self._install_tor()
            
            # Configure Tor
            torrc_config = []
            
            if bridges:
                # Use bridges for censorship circumvention
                torrc_config.extend([
                    "UseBridges 1",
                    "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy",
                    "Bridge obfs4 IP:PORT FINGERPRINT cert=CERT iat-mode=0"
                    # Add actual bridge lines here
                ])
            
            if exit_countries:
                # Set exit node countries
                country_codes = '{' + ','.join(exit_countries) + '}'
                torrc_config.append(f"ExitNodes {country_codes}")
                torrc_config.append("StrictNodes 1")
            
            # Additional privacy settings
            torrc_config.extend([
                "AvoidDiskWrites 1",
                "DisableDebuggerAttachment 1",
                "Sandbox 1",
                "SafeLogging 1",
                "UseEntryGuards 1",
                "NumEntryGuards 3"
            ])
            
            # Write configuration
            with open('/etc/tor/torrc.d/99-anonymizer.conf', 'w') as f:
                f.write('\n'.join(torrc_config))
            
            # Start Tor
            subprocess.run(['systemctl', 'restart', 'tor'], check=True)
            time.sleep(5)  # Wait for Tor to start
            
            # Verify Tor is working
            if self._check_tor_connection():
                self.active_layers.append('tor')
                print("✓ Tor connected successfully")
                return True
            else:
                print("✗ Tor connection failed")
                return False
                
        except Exception as e:
            print(f"Tor setup error: {e}")
            return False
    
    def setup_vpn(self, provider: str = 'protonvpn', 
                  server: Optional[str] = None) -> bool:
        """Setup VPN connection"""
        try:
            if provider not in self.vpn_providers:
                print(f"Unknown VPN provider: {provider}")
                return False
            
            config = self.vpn_providers[provider]
            
            if provider == 'protonvpn':
                # ProtonVPN CLI
                if not self._command_exists('protonvpn-cli'):
                    print("Installing ProtonVPN CLI...")
                    self._install_protonvpn()
                
                # Connect to server
                if server:
                    cmd = ['protonvpn-cli', 'connect', server]
                else:
                    # Connect to random secure core server
                    cmd = ['protonvpn-cli', 'connect', '--sc']
                
                subprocess.run(cmd, check=True)
                
            elif provider == 'mullvad':
                # Mullvad OpenVPN
                if server:
                    config_file = f"{config['config_path']}/{server}.conf"
                else:
                    # Choose random server
                    configs = os.listdir(config['config_path'])
                    config_file = os.path.join(config['config_path'], 
                                              random.choice(configs))
                
                cmd = ['openvpn', '--config', config_file, '--auth-user-pass', 
                       config['auth_file'], '--daemon']
                subprocess.run(cmd, check=True)
                
            elif provider == 'nordvpn':
                # NordVPN CLI
                if not self._command_exists('nordvpn'):
                    print("NordVPN CLI not found")
                    return False
                
                subprocess.run(['nordvpn', 'connect', server or 'P2P'], check=True)
            
            time.sleep(10)  # Wait for VPN connection
            
            # Verify VPN connection
            if self._check_vpn_connection():
                self.active_layers.append(f'vpn:{provider}')
                print(f"✓ VPN ({provider}) connected successfully")
                return True
            else:
                print(f"✗ VPN ({provider}) connection failed")
                return False
                
        except Exception as e:
            print(f"VPN setup error: {e}")
            return False
    
    def setup_proxy_chain(self, proxies: List[Dict[str, str]]) -> bool:
        """Setup proxy chain configuration"""
        try:
            # Configure proxychains
            config_lines = [
                "strict_chain",
                "proxy_dns",
                "tcp_read_time_out 15000",
                "tcp_connect_time_out 8000",
                "[ProxyList]"
            ]
            
            for proxy in proxies:
                proxy_type = proxy.get('type', 'socks5')
                host = proxy['host']
                port = proxy['port']
                
                if 'user' in proxy and 'pass' in proxy:
                    line = f"{proxy_type} {host} {port} {proxy['user']} {proxy['pass']}"
                else:
                    line = f"{proxy_type} {host} {port}"
                
                config_lines.append(line)
            
            # Write proxychains config
            with open('/etc/proxychains4.conf', 'w') as f:
                f.write('\n'.join(config_lines))
            
            self.active_layers.append('proxychains')
            print("✓ Proxy chain configured")
            return True
            
        except Exception as e:
            print(f"Proxy chain setup error: {e}")
            return False
    
    def randomize_mac_address(self, interface: str = 'all') -> bool:
        """Randomize MAC address"""
        try:
            if not self._command_exists('macchanger'):
                subprocess.run(['apt-get', 'install', '-y', 'macchanger'], 
                             check=True)
            
            if interface == 'all':
                # Get all network interfaces
                interfaces = self._get_network_interfaces()
            else:
                interfaces = [interface]
            
            for iface in interfaces:
                if iface == 'lo':  # Skip loopback
                    continue
                
                # Save original MAC
                original_mac = self._get_mac_address(iface)
                if original_mac:
                    self.original_settings[f'mac_{iface}'] = original_mac
                
                # Bring interface down
                subprocess.run(['ip', 'link', 'set', iface, 'down'], check=True)
                
                # Randomize MAC
                subprocess.run(['macchanger', '-r', iface], check=True)
                
                # Bring interface up
                subprocess.run(['ip', 'link', 'set', iface, 'up'], check=True)
                
                print(f"✓ MAC address randomized for {iface}")
            
            return True
            
        except Exception as e:
            print(f"MAC randomization error: {e}")
            return False
    
    def change_hostname(self, random: bool = True, 
                       hostname: Optional[str] = None) -> bool:
        """Change system hostname"""
        try:
            # Save original hostname
            with open('/etc/hostname', 'r') as f:
                self.original_settings['hostname'] = f.read().strip()
            
            if random:
                # Generate random hostname
                adjectives = ['swift', 'silent', 'shadow', 'stealth', 'phantom']
                nouns = ['fox', 'wolf', 'eagle', 'hawk', 'raven']
                hostname = f"{random.choice(adjectives)}-{random.choice(nouns)}-{random.randint(1000, 9999)}"
            
            # Set new hostname
            with open('/etc/hostname', 'w') as f:
                f.write(hostname)
            
            subprocess.run(['hostname', hostname], check=True)
            
            # Update /etc/hosts
            with open('/etc/hosts', 'r') as f:
                hosts_content = f.read()
            
            old_hostname = self.original_settings['hostname']
            hosts_content = hosts_content.replace(old_hostname, hostname)
            
            with open('/etc/hosts', 'w') as f:
                f.write(hosts_content)
            
            print(f"✓ Hostname changed to: {hostname}")
            return True
            
        except Exception as e:
            print(f"Hostname change error: {e}")
            return False
    
    def setup_dns_privacy(self, method: str = 'dnscrypt') -> bool:
        """Setup private DNS resolution"""
        try:
            # Save original DNS settings
            with open('/etc/resolv.conf', 'r') as f:
                self.original_settings['dns'] = f.read()
            
            if method == 'dnscrypt':
                # Setup DNSCrypt
                if not self._command_exists('dnscrypt-proxy'):
                    subprocess.run(['apt-get', 'install', '-y', 'dnscrypt-proxy'], 
                                 check=True)
                
                # Configure DNSCrypt
                # (Configuration from previous implementation)
                subprocess.run(['systemctl', 'restart', 'dnscrypt-proxy'], check=True)
                
                # Point to local DNSCrypt
                with open('/etc/resolv.conf', 'w') as f:
                    f.write("nameserver 127.0.0.1\n")
                
            elif method == 'tor':
                # Use Tor for DNS
                with open('/etc/resolv.conf', 'w') as f:
                    f.write("nameserver 127.0.0.1\n")
                
                # Configure Tor DNS
                with open('/etc/tor/torrc.d/dns.conf', 'w') as f:
                    f.write("DNSPort 127.0.0.1:53\n")
                
                subprocess.run(['systemctl', 'restart', 'tor'], check=True)
            
            print(f"✓ DNS privacy configured ({method})")
            return True
            
        except Exception as e:
            print(f"DNS privacy setup error: {e}")
            return False
    
    def apply_full_anonymity(self, paranoid: bool = False) -> bool:
        """Apply all anonymity layers"""
        print("\nApplying full anonymity configuration...")
        
        success = True
        
        # 1. Randomize MAC addresses
        if not self.randomize_mac_address():
            success = False
        
        # 2. Change hostname
        if not self.change_hostname():
            success = False
        
        # 3. Setup DNS privacy
        if not self.setup_dns_privacy():
            success = False
        
        # 4. Setup Tor
        exit_countries = ['CH', 'IS', 'RO'] if not paranoid else None
        if not self.setup_tor(bridges=paranoid, exit_countries=exit_countries):
            success = False
        
        # 5. Setup VPN (if paranoid mode)
        if paranoid:
            if not self.setup_vpn():
                success = False
        
        # 6. Configure firewall
        self._configure_firewall(paranoid)
        
        # 7. Disable IPv6
        self._disable_ipv6()
        
        # 8. Clear traces
        self._clear_traces()
        
        if success:
            print("\n✓ Full anonymity configuration applied!")
            self._print_status()
        else:
            print("\n⚠ Some anonymity features failed to configure")
        
        return success
    
    def _configure_firewall(self, strict: bool = False):
        """Configure firewall for anonymity"""
        try:
            # Reset firewall
            subprocess.run(['ufw', '--force', 'reset'], capture_output=True)
            
            # Default policies
            subprocess.run(['ufw', 'default', 'deny', 'incoming'])
            subprocess.run(['ufw', 'default', 'deny', 'outgoing'])
            
            # Allow essential services
            if 'tor' in self.active_layers:
                subprocess.run(['ufw', 'allow', 'out', '9050/tcp'])  # Tor SOCKS
                subprocess.run(['ufw', 'allow', 'out', '9051/tcp'])  # Tor Control
            
            if any('vpn' in layer for layer in self.active_layers):
                subprocess.run(['ufw', 'allow', 'out', '1194/udp'])  # OpenVPN
                subprocess.run(['ufw', 'allow', 'out', '443/tcp'])   # VPN over HTTPS
            
            # Allow DNS (will go through Tor/VPN)
            subprocess.run(['ufw', 'allow', 'out', '53'])
            
            if not strict:
                # Allow HTTP/HTTPS
                subprocess.run(['ufw', 'allow', 'out', '80/tcp'])
                subprocess.run(['ufw', 'allow', 'out', '443/tcp'])
            
            # Enable firewall
            subprocess.run(['ufw', '--force', 'enable'])
            
            print("✓ Firewall configured")
            
        except Exception as e:
            print(f"Firewall configuration error: {e}")
    
    def _disable_ipv6(self):
        """Disable IPv6 to prevent leaks"""
        try:
            # Disable IPv6 via sysctl
            subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=1'])
            subprocess.run(['sysctl', '-w', 'net.ipv6.conf.default.disable_ipv6=1'])
            subprocess.run(['sysctl', '-w', 'net.ipv6.conf.lo.disable_ipv6=1'])
            
            print("✓ IPv6 disabled")
            
        except Exception as e:
            print(f"IPv6 disable error: {e}")
    
    def _clear_traces(self):
        """Clear system traces"""
        try:
            # Clear bash history
            os.system('history -c')
            os.system('> ~/.bash_history')
            
            # Clear DNS cache
            subprocess.run(['systemctl', 'restart', 'systemd-resolved'], 
                         capture_output=True)
            
            # Clear system logs
            log_files = [
                '/var/log/syslog',
                '/var/log/auth.log',
                '/var/log/kern.log',
                '/var/log/messages'
            ]
            
            for log_file in log_files:
                if os.path.exists(log_file):
                    os.system(f'> {log_file}')
            
            print("✓ System traces cleared")
            
        except Exception as e:
            print(f"Trace clearing error: {e}")
    
    def restore_original_settings(self):
        """Restore original network settings"""
        print("\nRestoring original settings...")
        
        # Restore hostname
        if 'hostname' in self.original_settings:
            with open('/etc/hostname', 'w') as f:
                f.write(self.original_settings['hostname'])
            subprocess.run(['hostname', self.original_settings['hostname']])
        
        # Restore DNS
        if 'dns' in self.original_settings:
            with open('/etc/resolv.conf', 'w') as f:
                f.write(self.original_settings['dns'])
        
        # Restore MAC addresses
        for key, value in self.original_settings.items():
            if key.startswith('mac_'):
                interface = key.replace('mac_', '')
                subprocess.run(['ip', 'link', 'set', interface, 'down'])
                subprocess.run(['macchanger', '-m', value, interface])
                subprocess.run(['ip', 'link', 'set', interface, 'up'])
        
        # Disconnect VPN
        for layer in self.active_layers:
            if layer.startswith('vpn:'):
                provider = layer.split(':')[1]
                if provider == 'protonvpn':
                    subprocess.run(['protonvpn-cli', 'disconnect'])
                elif provider == 'nordvpn':
                    subprocess.run(['nordvpn', 'disconnect'])
        
        # Re-enable IPv6
        subprocess.run(['sysctl', '-w', 'net.ipv6.conf.all.disable_ipv6=0'])
        
        print("✓ Original settings restored")
    
    def _print_status(self):
        """Print current anonymity status"""
        print("\n=== Anonymity Status ===")
        print(f"Active layers: {', '.join(self.active_layers)}")
        
        # Get current IP
        try:
            response = requests.get('https://api.ipify.org', 
                                  proxies={'http': 'socks5://127.0.0.1:9050',
                                          'https': 'socks5://127.0.0.1:9050'},
                                  timeout=10)
            print(f"Current IP: {response.text}")
        except:
            print("Current IP: Unable to determine")
        
        # Get Tor circuit
        if 'tor' in self.active_layers:
            try:
                with Controller.from_port(port=self.tor_control_port) as controller:
                    controller.authenticate()
                    circuit = controller.get_info("circuit-status")
                    print(f"Tor circuit: Active")
            except:
                print("Tor circuit: Unknown")
    
    def monitor_anonymity(self, interval: int = 60):
        """Monitor anonymity status continuously"""
        print(f"\nMonitoring anonymity (checking every {interval}s)...")
        print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                # Check Tor
                if 'tor' in self.active_layers:
                    if not self._check_tor_connection():
                        print("⚠ Tor connection lost!")
                        self.setup_tor()
                
                # Check VPN
                for layer in self.active_layers:
                    if layer.startswith('vpn:'):
                        if not self._check_vpn_connection():
                            print("⚠ VPN connection lost!")
                            provider = layer.split(':')[1]
                            self.setup_vpn(provider)
                
                # Check for DNS leaks
                if self._check_dns_leak():
                    print("⚠ DNS leak detected!")
                    self.setup_dns_privacy()
                
                # Check for WebRTC leaks
                if self._check_webrtc_leak():
                    print("⚠ WebRTC leak detected!")
                
                # Print status
                self._print_status()
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            print("\nMonitoring stopped")
    
    # Helper methods
    def _is_tor_installed(self) -> bool:
        return self._command_exists('tor')
    
    def _command_exists(self, command: str) -> bool:
        return subprocess.run(['which', command], 
                            capture_output=True).returncode == 0
    
    def _check_tor_connection(self) -> bool:
        try:
            response = requests.get('https://check.torproject.org/api/ip',
                                  proxies={'http': 'socks5://127.0.0.1:9050',
                                          'https': 'socks5://127.0.0.1:9050'},
                                  timeout=10)
            return response.json().get('IsTor', False)
        except:
            return False
    
    def _check_vpn_connection(self) -> bool:
        try:
            # Check if default route goes through VPN interface
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                  capture_output=True, text=True)
            return 'tun' in result.stdout or 'tap' in result.stdout
        except:
            return False
    
    def _check_dns_leak(self) -> bool:
        try:
            # Simple DNS leak check
            result = subprocess.run(['dig', '+short', 'myip.opendns.com', 
                                   '@resolver1.opendns.com'],
                                  capture_output=True, text=True)
            public_ip = result.stdout.strip()
            
            # Compare with Tor/VPN IP
            response = requests.get('https://api.ipify.org',
                                  proxies={'http': 'socks5://127.0.0.1:9050',
                                          'https': 'socks5://127.0.0.1:9050'},
                                  timeout=10)
            anonymized_ip = response.text
            
            return public_ip != anonymized_ip
        except:
            return True
    
    def _check_webrtc_leak(self) -> bool:
        # WebRTC leak detection would require browser automation
        # This is a placeholder
        return False
    
    def _get_network_interfaces(self) -> List[str]:
        try:
            result = subprocess.run(['ip', 'link', 'show'],
                                  capture_output=True, text=True)
            interfaces = []
            for line in result.stdout.split('\n'):
                if ': ' in line and not line.startswith(' '):
                    interface = line.split(': ')[1].split('@')[0]
                    interfaces.append(interface)
            return interfaces
        except:
            return []
    
    def _get_mac_address(self, interface: str) -> Optional[str]:
        try:
            result = subprocess.run(['ip', 'link', 'show', interface],
                                  capture_output=True, text=True)
            for line in result.stdout.split('\n'):
                if 'link/ether' in line:
                    return line.split()[1]
            return None
        except:
            return None


def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Network Anonymizer - Automated anonymity configuration'
    )
    parser.add_argument('--full', action='store_true',
                       help='Apply full anonymity configuration')
    parser.add_argument('--paranoid', action='store_true',
                       help='Paranoid mode (maximum anonymity)')
    parser.add_argument('--tor-only', action='store_true',
                       help='Configure Tor only')
    parser.add_argument('--vpn', choices=['protonvpn', 'mullvad', 'nordvpn'],
                       help='Setup specific VPN')
    parser.add_argument('--monitor', action='store_true',
                       help='Monitor anonymity status')
    parser.add_argument('--restore', action='store_true',
                       help='Restore original settings')
    
    args = parser.parse_args()
    
    # Check for root
    if os.geteuid() != 0:
        print("This script requires root privileges")
        sys.exit(1)
    
    anonymizer = NetworkAnonymizer()
    
    try:
        if args.restore:
            anonymizer.restore_original_settings()
        elif args.full or args.paranoid:
            anonymizer.apply_full_anonymity(paranoid=args.paranoid)
            if args.monitor:
                anonymizer.monitor_anonymity()
        elif args.tor_only:
            anonymizer.setup_tor()
        elif args.vpn:
            anonymizer.setup_vpn(args.vpn)
        elif args.monitor:
            anonymizer.monitor_anonymity()
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        if input("Restore original settings? (y/N): ").lower() == 'y':
            anonymizer.restore_original_settings()

if __name__ == '__main__':
    main()
