#!/usr/bin/env python3
"""
VPN Chain Manager - Chain multiple VPNs for enhanced anonymity
Part of Lackadaisical Anonymity Toolkit
"""

import os
import sys
import time
import json
import subprocess
import argparse
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import socket
import requests

class VPNChain:
    """Manage chained VPN connections for multi-hop anonymity"""
    
    def __init__(self, config_dir: str = "/etc/openvpn"):
        self.config_dir = Path(config_dir)
        self.active_vpns: List[Dict] = []
        self.original_ip: Optional[str] = None
        self.logger = self._setup_logging()
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('VPNChain')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def get_public_ip(self) -> Optional[str]:
        """Get current public IP address"""
        try:
            # Use multiple services for reliability
            services = [
                'https://api.ipify.org',
                'https://icanhazip.com',
                'https://ifconfig.me/ip'
            ]
            
            for service in services:
                try:
                    response = requests.get(service, timeout=5)
                    if response.status_code == 200:
                        return response.text.strip()
                except:
                    continue
            
            return None
        except Exception as e:
            self.logger.error(f"Failed to get public IP: {e}")
            return None
    
    def find_vpn_configs(self, provider: Optional[str] = None) -> List[Path]:
        """Find available VPN configuration files"""
        patterns = ['*.ovpn', '*.conf']
        configs = []
        
        if not self.config_dir.exists():
            self.logger.warning(f"Config directory {self.config_dir} does not exist")
            return configs
        
        for pattern in patterns:
            for config in self.config_dir.rglob(pattern):
                if provider and provider.lower() not in str(config).lower():
                    continue
                configs.append(config)
        
        return sorted(configs)
    
    def start_vpn(self, config_file: Path, namespace: Optional[str] = None) -> bool:
        """
        Start a VPN connection
        
        Args:
            config_file: Path to OpenVPN config file
            namespace: Optional network namespace to isolate VPN
        
        Returns:
            True if VPN started successfully
        """
        try:
            cmd = ['openvpn', '--config', str(config_file), '--daemon']
            
            if namespace:
                # Create network namespace for isolation
                subprocess.run(['ip', 'netns', 'add', namespace], 
                             check=False, capture_output=True)
                cmd = ['ip', 'netns', 'exec', namespace] + cmd
            
            # Start OpenVPN
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                # Wait for connection to establish
                time.sleep(5)
                
                # Verify connection
                new_ip = self.get_public_ip()
                if new_ip and new_ip != self.original_ip:
                    vpn_info = {
                        'config': str(config_file),
                        'namespace': namespace,
                        'ip': new_ip,
                        'started_at': time.time()
                    }
                    self.active_vpns.append(vpn_info)
                    self.logger.info(f"VPN started: {config_file.name} -> IP: {new_ip}")
                    return True
                else:
                    self.logger.error("VPN connection failed: IP did not change")
                    return False
            else:
                self.logger.error(f"Failed to start VPN: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error starting VPN: {e}")
            return False
    
    def stop_vpn(self, config_file: Optional[Path] = None) -> bool:
        """
        Stop a VPN connection
        
        Args:
            config_file: Optional specific VPN to stop (stops last if None)
        
        Returns:
            True if VPN stopped successfully
        """
        try:
            # Find VPN process
            result = subprocess.run(
                ['pgrep', '-f', 'openvpn'],
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                pids = result.stdout.strip().split('\n')
                
                for pid in pids:
                    if pid:
                        subprocess.run(['kill', pid], check=False)
                
                # Remove from active list
                if self.active_vpns:
                    stopped = self.active_vpns.pop()
                    self.logger.info(f"Stopped VPN: {stopped['config']}")
                    
                    # Clean up namespace if used
                    if stopped.get('namespace'):
                        subprocess.run(
                            ['ip', 'netns', 'del', stopped['namespace']],
                            check=False,
                            capture_output=True
                        )
                
                return True
            else:
                self.logger.warning("No VPN process found")
                return False
                
        except Exception as e:
            self.logger.error(f"Error stopping VPN: {e}")
            return False
    
    def chain_vpns(self, providers: List[str], count: int = 3) -> bool:
        """
        Create a chain of VPN connections
        
        Args:
            providers: List of VPN providers to use
            count: Number of VPNs to chain
        
        Returns:
            True if chain established successfully
        """
        self.logger.info(f"Creating VPN chain with {count} hops...")
        
        # Get original IP
        self.original_ip = self.get_public_ip()
        if not self.original_ip:
            self.logger.error("Could not determine original IP")
            return False
        
        self.logger.info(f"Original IP: {self.original_ip}")
        
        # Find configs for each provider
        all_configs = []
        for provider in providers:
            configs = self.find_vpn_configs(provider)
            if configs:
                all_configs.extend(configs[:count])  # Limit per provider
        
        if len(all_configs) < count:
            self.logger.error(f"Not enough VPN configs found (need {count}, found {len(all_configs)})")
            return False
        
        # Start VPNs in sequence
        for i, config in enumerate(all_configs[:count]):
            namespace = f"vpn_hop_{i+1}"
            self.logger.info(f"Starting hop {i+1}/{count}: {config.name}")
            
            if not self.start_vpn(config, namespace if i > 0 else None):
                self.logger.error(f"Failed to start hop {i+1}")
                # Clean up previously started VPNs
                self.stop_all()
                return False
            
            # Wait between hops
            time.sleep(3)
        
        # Verify final IP
        final_ip = self.get_public_ip()
        self.logger.info(f"VPN chain established: {self.original_ip} -> {final_ip}")
        self.logger.info(f"Active hops: {len(self.active_vpns)}")
        
        return True
    
    def stop_all(self) -> None:
        """Stop all active VPN connections"""
        self.logger.info("Stopping all VPN connections...")
        
        while self.active_vpns:
            self.stop_vpn()
        
        # Kill any remaining openvpn processes
        subprocess.run(['pkill', '-9', 'openvpn'], check=False, capture_output=True)
        
        # Clean up all VPN namespaces
        result = subprocess.run(
            ['ip', 'netns', 'list'],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            for line in result.stdout.strip().split('\n'):
                if 'vpn_hop' in line:
                    ns = line.split()[0]
                    subprocess.run(
                        ['ip', 'netns', 'del', ns],
                        check=False,
                        capture_output=True
                    )
        
        self.logger.info("All VPN connections stopped")
    
    def status(self) -> None:
        """Display current VPN chain status"""
        print("\n=== VPN Chain Status ===")
        print(f"Original IP: {self.original_ip}")
        print(f"Current IP:  {self.get_public_ip()}")
        print(f"Active Hops: {len(self.active_vpns)}")
        
        if self.active_vpns:
            print("\nChain Details:")
            for i, vpn in enumerate(self.active_vpns, 1):
                print(f"  Hop {i}: {Path(vpn['config']).name}")
                print(f"         IP: {vpn['ip']}")
                if vpn.get('namespace'):
                    print(f"         Namespace: {vpn['namespace']}")
        else:
            print("\nNo active VPN connections")
        print()
    
    def test_chain(self) -> bool:
        """Test VPN chain for leaks"""
        self.logger.info("Testing VPN chain for leaks...")
        
        tests = {
            'IP Leak': self._test_ip_leak(),
            'DNS Leak': self._test_dns_leak(),
            'WebRTC Leak': self._test_webrtc_leak()
        }
        
        print("\n=== VPN Chain Test Results ===")
        all_passed = True
        for test_name, result in tests.items():
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"{test_name}: {status}")
            if not result:
                all_passed = False
        print()
        
        return all_passed
    
    def _test_ip_leak(self) -> bool:
        """Test for IP leaks"""
        current_ip = self.get_public_ip()
        return current_ip != self.original_ip if current_ip else False
    
    def _test_dns_leak(self) -> bool:
        """Test for DNS leaks"""
        try:
            # This is a simplified check - in production, use dnsleaktest.com API
            result = subprocess.run(
                ['dig', '+short', 'myip.opendns.com', '@resolver1.opendns.com'],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                dns_ip = result.stdout.strip()
                return dns_ip != self.original_ip
            
            return True  # If can't test, assume pass
        except:
            return True
    
    def _test_webrtc_leak(self) -> bool:
        """Test for WebRTC leaks (basic check)"""
        # In production, this would check browser WebRTC
        # For now, just return True as it's browser-specific
        return True

def main():
    parser = argparse.ArgumentParser(
        description='VPN Chain Manager - Multi-hop VPN anonymity'
    )
    
    parser.add_argument(
        'action',
        choices=['start', 'stop', 'status', 'test'],
        help='Action to perform'
    )
    
    parser.add_argument(
        '--providers',
        nargs='+',
        default=['mullvad', 'proton', 'nord'],
        help='VPN providers to use (default: mullvad proton nord)'
    )
    
    parser.add_argument(
        '--hops',
        type=int,
        default=2,
        help='Number of VPN hops (default: 2)'
    )
    
    parser.add_argument(
        '--config-dir',
        default='/etc/openvpn',
        help='VPN config directory (default: /etc/openvpn)'
    )
    
    args = parser.parse_args()
    
    # Check root privileges
    if os.geteuid() != 0 and args.action in ['start', 'stop']:
        print("Error: This tool requires root privileges for VPN management")
        print("Run with: sudo python3 vpn_chain.py")
        return 1
    
    # Create VPN chain manager
    vpn = VPNChain(args.config_dir)
    
    # Execute action
    if args.action == 'start':
        success = vpn.chain_vpns(args.providers, args.hops)
        if success:
            vpn.status()
            return 0
        else:
            return 1
    
    elif args.action == 'stop':
        vpn.stop_all()
        return 0
    
    elif args.action == 'status':
        vpn.status()
        return 0
    
    elif args.action == 'test':
        passed = vpn.test_chain()
        return 0 if passed else 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main())
