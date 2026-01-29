"""
DNS-over-HTTPS Client with Anonymization
Part of Lackadaisical Anonymity Toolkit
"""

import base64
import json
import random
import socket
import struct
import time
import threading
from typing import List, Tuple, Optional, Dict
import requests
import socks
from cryptography.fernet import Fernet

class DoHClient:
    """DNS-over-HTTPS client class"""
    
    PROVIDERS = {
        'cloudflare': 'https://cloudflare-dns.com/dns-query',
        'google': 'https://dns.google/dns-query',
        'quad9': 'https://dns.quad9.net/dns-query',
        'adguard': 'https://dns.adguard.com/dns-query',
        # Add more providers as needed
    }
    
    def __init__(self, provider='cloudflare', use_tor=False):
        self.provider = provider
        self.use_tor = use_tor
        self.session = requests.Session()
        
        # Configure Tor if requested
        if self.use_tor:
            self._configure_tor()
    
    def _configure_tor(self):
        """Configure Tor settings"""
        # Set Tor as the proxy for requests
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket
    
    def resolve(self, domain: str, record_type: str = 'A') -> Optional[List[str]]:
        """Resolve a domain using DNS-over-HTTPS"""
        url = self.PROVIDERS[self.provider]
        headers = {'Accept': 'application/dns-json'}
        
        # Build the DNS query
        query = {
            'name': domain,
            'type': record_type
        }
        
        try:
            response = self.session.get(url, headers=headers, params=query)
            response.raise_for_status()
            
            # Parse the JSON response
            data = response.json()
            if 'Answer' in data:
                # Extract IP addresses from the answer section
                return [answer['data'] for answer in data['Answer']]
        
        except Exception as e:
            print(f"Error resolving {domain}: {e}")
        
        return None

class DNSProxy:
    """DNS proxy server class"""
    
    def __init__(self, listen_port: int, doh_client: DoHClient):
        self.listen_port = listen_port
        self.doh_client = doh_client
        self.server = None
    
    def start(self):
        """Start the DNS proxy server"""
        import dns.message
        import dns.query
        import dns.resolver
        
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('', self.listen_port))
        print(f"Listening for DNS queries on port {self.listen_port}...")
        
        while True:
            try:
                # Receive DNS query
                data, addr = sock.recvfrom(512)
                
                # Parse the DNS query
                query = dns.message.from_wire(data)
                
                # Extract the domain name from the query
                domain = str(query.question[0].name)
                record_type = dns.rdatatype.to_text(query.question[0].rdtype)
                
                print(f"Received query for {domain} ({record_type})")
                
                # Resolve the domain using DoH
                result = self.doh_client.resolve(domain, record_type)
                
                # Build the DNS response
                response = dns.message.make_response(query)
                if result:
                    # Add the resolved IP addresses to the response
                    for ip in result:
                        response.answer.append(
                            dns.rrset.from_text(domain, 300, dns.rdataclass.IN, record_type, ip)
                        )
                else:
                    # No result found, return NXDOMAIN
                    response.set_rcode(dns.rcode.NXDOMAIN)
                
                # Send the DNS response
                sock.sendto(response.to_wire(), addr)
            
            except Exception as e:
                print(f"Error processing query: {e}")
    
    def stop(self):
        """Stop the DNS proxy server"""
        if self.server:
            self.server.shutdown()
            self.server = None
            print("DNS proxy stopped.")

def main():
    """CLI interface"""
    import argparse
    import threading
    
    parser = argparse.ArgumentParser(description='DNS-over-HTTPS Client')
    parser.add_argument('domain', nargs='?', help='Domain to resolve')
    parser.add_argument('-t', '--type', default='A', help='Record type (A, AAAA, MX, etc.)')
    parser.add_argument('-p', '--provider', default='cloudflare', 
                        choices=list(DoHClient.PROVIDERS.keys()), help='DoH provider')
    parser.add_argument('--tor', action='store_true', help='Use Tor for queries')
    parser.add_argument('--proxy', action='store_true', help='Start DNS proxy server')
    parser.add_argument('--port', type=int, default=5353, help='DNS proxy port')
    
    args = parser.parse_args()
    
    # Create DoH client
    doh = DoHClient(provider=args.provider, use_tor=args.tor)
    
    if args.proxy:
        # Start DNS proxy
        proxy = DNSProxy(listen_port=args.port, doh_client=doh)
        try:
            proxy.start()
        except KeyboardInterrupt:
            print("\nStopping DNS proxy...")
            proxy.stop()
    
    elif args.domain:
        # Resolve single domain
        print(f"Resolving {args.domain} via {args.provider}...")
        
        result = doh.resolve(args.domain, args.type)
        if result:
            print(f"\nResults for {args.domain}:")
            for ip in result:
                print(f"  {ip}")
        else:
            print(f"Failed to resolve {args.domain}")
    
    else:
        parser.print_help()

if __name__ == '__main__':
    import threading
    main()