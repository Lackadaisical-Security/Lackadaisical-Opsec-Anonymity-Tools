#!/usr/bin/env python3
"""
DNS Leak Tester - Detect DNS leaks in anonymity configurations
Part of Lackadaisical Anonymity Toolkit
"""

import socket
import sys
import argparse
import dns.resolver
import dns.query
import dns.message
from typing import List, Dict, Optional, Tuple
import requests
import json
import time

class DNSLeakTester:
    """Test for DNS leaks that could compromise anonymity"""
    
    def __init__(self):
        self.test_domains = [
            'www.google.com',
            'www.github.com',
            'www.cloudflare.com',
            'www.amazon.com'
        ]
        
        # Public DNS servers for comparison
        self.public_dns = {
            'Google': ['8.8.8.8', '8.8.4.4'],
            'Cloudflare': ['1.1.1.1', '1.0.0.1'],
            'Quad9': ['9.9.9.9', '149.112.112.112'],
            'OpenDNS': ['208.67.222.222', '208.67.220.220']
        }
        
    def get_system_dns(self) -> List[str]:
        """Get system DNS servers from resolv.conf or system settings"""
        dns_servers = []
        
        try:
            # Try reading resolv.conf (Linux/macOS)
            with open('/etc/resolv.conf', 'r') as f:
                for line in f:
                    if line.strip().startswith('nameserver'):
                        dns_servers.append(line.split()[1])
        except FileNotFoundError:
            # Try using DNS resolver module
            try:
                resolver = dns.resolver.Resolver()
                dns_servers = [str(ns) for ns in resolver.nameservers]
            except:
                pass
        
        return dns_servers
    
    def query_dns_server(self, domain: str, dns_server: str) -> Optional[List[str]]:
        """Query a specific DNS server"""
        try:
            query = dns.message.make_query(domain, dns.rdatatype.A)
            response = dns.query.udp(query, dns_server, timeout=3)
            
            ips = []
            for answer in response.answer:
                for item in answer:
                    if hasattr(item, 'address'):
                        ips.append(str(item.address))
            
            return ips if ips else None
        except Exception as e:
            return None
    
    def test_dns_servers(self) -> Dict[str, List]:
        """Test which DNS servers are being used"""
        results = {}
        system_dns = self.get_system_dns()
        
        print(f"System DNS servers: {', '.join(system_dns) if system_dns else 'None found'}\n")
        
        # Test system DNS
        for domain in self.test_domains:
            for dns_server in system_dns:
                result = self.query_dns_server(domain, dns_server)
                if result:
                    if dns_server not in results:
                        results[dns_server] = []
                    results[dns_server].append({
                        'domain': domain,
                        'ips': result
                    })
        
        return results
    
    def detect_isp_dns(self, dns_servers: List[str]) -> Dict[str, bool]:
        """Detect if DNS servers belong to common ISPs"""
        isp_detection = {}
        
        for dns in dns_servers:
            # Check if it's a public DNS
            is_public = False
            provider = None
            
            for name, servers in self.public_dns.items():
                if dns in servers:
                    is_public = True
                    provider = name
                    break
            
            if is_public:
                isp_detection[dns] = {
                    'is_isp': False,
                    'provider': provider,
                    'risk': 'LOW'
                }
            else:
                # Likely ISP DNS (private IP or unknown)
                isp_detection[dns] = {
                    'is_isp': True,
                    'provider': 'Unknown/ISP',
                    'risk': 'HIGH'
                }
        
        return isp_detection
    
    def test_webrtc_leak(self) -> Dict[str, any]:
        """Check for WebRTC leaks (requires browser)"""
        # This is a basic check - full WebRTC testing requires browser automation
        print("Note: WebRTC leak testing requires browser. Use browser extension for full test.")
        return {
            'tested': False,
            'info': 'Use browserleaks.com/webrtc or browser extension for WebRTC testing'
        }
    
    def test_transparent_proxy(self) -> bool:
        """Test if using transparent DNS proxy"""
        # Try to query a DNS server directly vs through system
        test_domain = 'test.example.com'
        
        try:
            # Query Cloudflare directly
            direct_result = self.query_dns_server(test_domain, '1.1.1.1')
            
            # Query through system
            try:
                system_result = socket.gethostbyname(test_domain)
                
                # If we get results despite querying non-existent domain, 
                # might be transparent proxy or DNS hijacking
                return True
            except socket.gaierror:
                # Expected for non-existent domain
                return False
        except:
            return False
    
    def get_public_ip(self) -> Optional[str]:
        """Get public IP address"""
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
    
    def full_leak_test(self) -> Dict:
        """Run comprehensive DNS leak test"""
        print("=" * 60)
        print("DNS LEAK TEST")
        print("=" * 60)
        print()
        
        results = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'public_ip': None,
            'dns_servers': {},
            'isp_detection': {},
            'transparent_proxy': False,
            'webrtc_info': {},
            'overall_status': 'UNKNOWN'
        }
        
        # Get public IP
        print("Getting public IP...")
        results['public_ip'] = self.get_public_ip()
        print(f"Public IP: {results['public_ip']}\n")
        
        # Test DNS servers
        print("Testing DNS servers...")
        results['dns_servers'] = self.test_dns_servers()
        
        system_dns = self.get_system_dns()
        results['isp_detection'] = self.detect_isp_dns(system_dns)
        
        # Print DNS results
        for dns, info in results['isp_detection'].items():
            risk_color = '✗' if info['risk'] == 'HIGH' else '✓'
            print(f"  {risk_color} {dns} - {info['provider']} ({info['risk']} risk)")
        print()
        
        # Test for transparent proxy
        print("Testing for transparent DNS proxy...")
        results['transparent_proxy'] = self.test_transparent_proxy()
        if results['transparent_proxy']:
            print("  ✗ WARNING: Possible transparent DNS proxy detected\n")
        else:
            print("  ✓ No transparent proxy detected\n")
        
        # WebRTC info
        results['webrtc_info'] = self.test_webrtc_leak()
        
        # Determine overall status
        has_isp_dns = any(info['is_isp'] for info in results['isp_detection'].values())
        
        if has_isp_dns or results['transparent_proxy']:
            results['overall_status'] = 'LEAK DETECTED'
        else:
            results['overall_status'] = 'NO LEAKS DETECTED'
        
        return results
    
    def print_report(self, results: Dict):
        """Print comprehensive report"""
        print("=" * 60)
        print("DNS LEAK TEST REPORT")
        print("=" * 60)
        print()
        
        print(f"Timestamp: {results['timestamp']}")
        print(f"Public IP: {results['public_ip']}")
        print()
        
        print("DNS Servers:")
        for dns, info in results['isp_detection'].items():
            status = '✗ LEAK' if info['is_isp'] else '✓ OK'
            print(f"  {status} {dns} ({info['provider']}) - Risk: {info['risk']}")
        print()
        
        if results['transparent_proxy']:
            print("⚠ WARNING: Transparent DNS proxy detected!")
            print("  Your ISP may be intercepting DNS queries")
            print()
        
        print("Overall Status: " + results['overall_status'])
        print()
        
        if results['overall_status'] == 'LEAK DETECTED':
            print("RECOMMENDATIONS:")
            print("  1. Configure your VPN/Tor to handle DNS")
            print("  2. Use DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)")
            print("  3. Manually set DNS to privacy-focused servers")
            print("     - Cloudflare: 1.1.1.1")
            print("     - Quad9: 9.9.9.9")
            print("  4. Enable DNS leak protection in VPN client")
            print("  5. Test again after applying fixes")
        else:
            print("✓ No DNS leaks detected")
            print("  Your DNS queries appear to be protected")
        
        print()
        print("=" * 60)

def main():
    parser = argparse.ArgumentParser(
        description='DNS Leak Tester - Detect DNS leaks'
    )
    
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output results as JSON'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Save report to file'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    args = parser.parse_args()
    
    tester = DNSLeakTester()
    
    try:
        results = tester.full_leak_test()
        
        if args.json:
            output = json.dumps(results, indent=2)
            print(output)
        else:
            tester.print_report(results)
        
        if args.output:
            with open(args.output, 'w') as f:
                if args.json:
                    f.write(json.dumps(results, indent=2))
                else:
                    f.write(str(results))
            print(f"\nReport saved to: {args.output}")
        
        # Exit with error code if leaks detected
        if results['overall_status'] == 'LEAK DETECTED':
            return 1
        
        return 0
        
    except KeyboardInterrupt:
        print("\nTest interrupted by user")
        return 130
    except Exception as e:
        print(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == '__main__':
    sys.exit(main())
