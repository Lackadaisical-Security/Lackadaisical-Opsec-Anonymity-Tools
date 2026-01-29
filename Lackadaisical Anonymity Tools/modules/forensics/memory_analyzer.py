#!/usr/bin/env python3
"""
Memory Analyzer - Analyze memory for forensic artifacts and threats
Part of Lackadaisical Anonymity Toolkit
"""

import os
import sys
import re
import struct
import mmap
import psutil
from typing import List, Dict, Tuple, Optional
from collections import defaultdict

class MemoryAnalyzer:
    """Analyze system memory for threats and artifacts"""
    
    def __init__(self):
        self.patterns = self._load_patterns()
        self.yara_rules = self._load_yara_rules()
        
    def _load_patterns(self) -> Dict[str, List[bytes]]:
        """Load search patterns"""
        return {
            'urls': [
                b'http://',
                b'https://',
                b'ftp://',
                b'ssh://'
            ],
            'emails': [
                # Email pattern regex would be compiled here
            ],
            'passwords': [
                b'password=',
                b'passwd=',
                b'pwd=',
                b'pass=',
                b'secret=',
                b'api_key=',
                b'token='
            ],
            'credit_cards': [
                # Credit card patterns
            ],
            'crypto_wallets': [
                b'bitcoin:',
                b'ethereum:',
                b'BC1',  # Bitcoin Bech32
                b'0x'    # Ethereum
            ],
            'commands': [
                b'cmd.exe',
                b'powershell.exe',
                b'/bin/bash',
                b'/bin/sh',
                b'wget ',
                b'curl ',
                b'nc -e'
            ],
            'malware_indicators': [
                b'INJECTED',
                b'Reflective',
                b'\\x00\\x00\\x00\\x00MZ',  # PE header in memory
                b'This program cannot be run in DOS mode',
                b'kernel32.dll',
                b'ntdll.dll'
            ]
        }
    
    def _load_yara_rules(self) -> Optional[object]:
        """Load YARA rules if available"""
        try:
            import yara
            
            rules_path = os.path.expanduser("~/.lackadaisical/yara_rules")
            if os.path.exists(rules_path):
                return yara.compile(filepath=rules_path)
            return None
        except ImportError:
            return None
    
    def scan_process_memory(self, pid: int) -> Dict[str, List]:
        """Scan specific process memory"""
        findings = defaultdict(list)
        
        try:
            process = psutil.Process(pid)
            
            # Get process info
            proc_info = {
                'name': process.name(),
                'exe': process.exe(),
                'cmdline': process.cmdline(),
                'connections': process.connections()
            }
            
            # Platform-specific memory reading
            if sys.platform == 'win32':
                findings.update(self._scan_windows_process(pid))
            else:
                findings.update(self._scan_linux_process(pid))
            
            # Scan for patterns
            # Note: Actual implementation would read process memory
            # This is a simplified version
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            findings['errors'].append(str(e))
        
        return dict(findings)
    
    def _scan_windows_process(self, pid: int) -> Dict[str, List]:
        """Scan Windows process memory"""
        findings = defaultdict(list)
        
        try:
            import ctypes
            import ctypes.wintypes
            
            # Windows API constants
            PROCESS_VM_READ = 0x0010
            PROCESS_QUERY_INFORMATION = 0x0400
            
            # Open process
            kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            process_handle = kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                False,
                pid
            )
            
            if not process_handle:
                findings['errors'].append("Failed to open process")
                return dict(findings)
            
            # Memory scanning would go here
            # This is a simplified placeholder
            
            kernel32.CloseHandle(process_handle)
            
        except Exception as e:
            findings['errors'].append(f"Windows scan error: {e}")
        
        return dict(findings)
    
    def _scan_linux_process(self, pid: int) -> Dict[str, List]:
        """Scan Linux process memory"""
        findings = defaultdict(list)
        
        try:
            # Read process maps
            maps_file = f"/proc/{pid}/maps"
            mem_file = f"/proc/{pid}/mem"
            
            if not os.path.exists(maps_file):
                findings['errors'].append("Process not found")
                return dict(findings)
            
            with open(maps_file, 'r') as f:
                maps = f.readlines()
            
            # Parse memory regions
            for line in maps:
                parts = line.split()
                if len(parts) < 6:
                    continue
                
                # Parse address range
                addr_range = parts[0].split('-')
                start_addr = int(addr_range[0], 16)
                end_addr = int(addr_range[1], 16)
                
                # Check permissions (must be readable)
                perms = parts[1]
                if 'r' not in perms:
                    continue
                
                # Read memory region
                try:
                    with open(mem_file, 'rb') as mem:
                        mem.seek(start_addr)
                        data = mem.read(end_addr - start_addr)
                        
                        # Scan for patterns
                        self._scan_memory_region(data, findings)
                        
                except Exception:
                    # Memory region not accessible
                    continue
            
        except Exception as e:
            findings['errors'].append(f"Linux scan error: {e}")
        
        return dict(findings)
    
    def _scan_memory_region(self, data: bytes, findings: Dict[str, List]):
        """Scan memory region for patterns"""
        # URL extraction
        url_pattern = rb'https?://[^\s<>"{}|\\^`\[\]]+' 
        for match in re.finditer(url_pattern, data):
            url = match.group(0).decode('utf-8', errors='ignore')
            findings['urls'].append(url)
        
        # Password detection
        for pattern in self.patterns['passwords']:
            if pattern in data:
                # Extract context around password
                idx = data.find(pattern)
                context = data[max(0, idx-20):idx+50]
                findings['passwords'].append({
                    'pattern': pattern.decode('utf-8', errors='ignore'),
                    'context': context.decode('utf-8', errors='ignore')
                })
        
        # Command detection
        for pattern in self.patterns['commands']:
            if pattern in data:
                findings['commands'].append(pattern.decode('utf-8', errors='ignore'))
        
        # Malware indicators
        for pattern in self.patterns['malware_indicators']:
            if pattern in data:
                findings['malware_indicators'].append(
                    pattern.decode('utf-8', errors='ignore')
                )
    
    def detect_injection(self) -> List[Dict]:
        """Detect process injection"""
        injections = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                pid = proc.info['pid']
                
                # Check for common injection indicators
                # 1. Process hollowing - process path mismatch
                if proc.info['exe'] and proc.info['name']:
                    expected_name = os.path.basename(proc.info['exe'])
                    if expected_name.lower() != proc.info['name'].lower():
                        injections.append({
                            'type': 'PROCESS_HOLLOWING',
                            'pid': pid,
                            'name': proc.info['name'],
                            'exe': proc.info['exe']
                        })
                
                # 2. Check for suspicious memory regions
                # This would require platform-specific implementation
                
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        return injections
    
    def find_hidden_processes(self) -> List[Dict]:
        """Find potentially hidden processes"""
        hidden = []
        
        # Method 1: Compare different process enumeration methods
        psutil_pids = set(psutil.pids())
        
        # Platform-specific enumeration
        if sys.platform == 'win32':
            # Windows: Compare with WMI
            try:
                import wmi
                c = wmi.WMI()
                wmi_pids = set(int(p.ProcessId) for p in c.Win32_Process())
                
                # PIDs in WMI but not psutil might be hidden
                hidden_pids = wmi_pids - psutil_pids
                for pid in hidden_pids:
                    hidden.append({
                        'pid': pid,
                        'detection_method': 'WMI comparison'
                    })
            except:
                pass
        
        else:
            # Linux: Check /proc directly
            try:
                proc_pids = set()
                for entry in os.listdir('/proc'):
                    if entry.isdigit():
                        proc_pids.add(int(entry))
                
                hidden_pids = proc_pids - psutil_pids
                for pid in hidden_pids:
                    hidden.append({
                        'pid': pid,
                        'detection_method': '/proc comparison'
                    })
            except:
                pass
        
        return hidden
    
    def extract_strings(self, pid: int, min_length: int = 4) -> List[str]:
        """Extract readable strings from process memory"""
        strings = []
        
        # This is a simplified version
        # Real implementation would read actual process memory
        
        try:
            process = psutil.Process(pid)
            
            # Add some basic strings from process info
            strings.append(process.name())
            strings.extend(process.cmdline())
            
            # Note: Actual string extraction would scan memory regions
            
        except Exception:
            pass
        
        return strings
    
    def volatility_analysis(self, memory_dump: str) -> Dict:
        """Analyze memory dump using Volatility-like techniques"""
        analysis = {
            'processes': [],
            'network_connections': [],
            'registry_keys': [],
            'dlls': [],
            'handles': []
        }
        
        # This would integrate with Volatility framework
        # Placeholder for demonstration
        
        return analysis
    
    def generate_memory_report(self) -> str:
        """Generate comprehensive memory analysis report"""
        report = []
        report.append("Memory Analysis Report")
        report.append("=" * 50)
        report.append(f"Generated: {datetime.now()}")
        report.append("")
        
        # Check for injections
        injections = self.detect_injection()
        if injections:
            report.append("Process Injection Detected:")
            report.append("-" * 30)
            for inj in injections:
                report.append(f"- {inj['type']}: PID {inj['pid']} ({inj['name']})")
            report.append("")
        
        # Check for hidden processes
        hidden = self.find_hidden_processes()
        if hidden:
            report.append("Hidden Processes Detected:")
            report.append("-" * 30)
            for h in hidden:
                report.append(f"- PID {h['pid']} (found via {h['detection_method']})")
            report.append("")
        
        # Scan all processes for threats
        report.append("Process Memory Scan Results:")
        report.append("-" * 30)
        
        threat_count = 0
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                findings = self.scan_process_memory(proc.info['pid'])
                
                if any(findings.values()):
                    threat_count += 1
                    report.append(f"\nProcess: {proc.info['name']} (PID: {proc.info['pid']})")
                    
                    for category, items in findings.items():
                        if items and category != 'errors':
                            report.append(f"  {category}: {len(items)} found")
                
            except:
                continue
        
        report.append(f"\nTotal suspicious processes: {threat_count}")
        
        return "\n".join(report)


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Memory Analyzer - Detect threats in memory'
    )
    parser.add_argument('--scan-pid', type=int, help='Scan specific process')
    parser.add_argument('--scan-all', action='store_true', 
                       help='Scan all processes')
    parser.add_argument('--detect-injection', action='store_true',
                       help='Detect process injection')
    parser.add_argument('--find-hidden', action='store_true',
                       help='Find hidden processes')
    parser.add_argument('--report', action='store_true',
                       help='Generate full report')
    
    args = parser.parse_args()
    
    # Check for appropriate privileges
    if sys.platform != 'win32' and os.geteuid() != 0:
        print("Warning: Root privileges recommended for memory analysis")
    
    analyzer = MemoryAnalyzer()
    
    if args.scan_pid:
        print(f"Scanning process {args.scan_pid}...")
        findings = analyzer.scan_process_memory(args.scan_pid)
        
        if findings:
            print("\nFindings:")
            for category, items in findings.items():
                if items:
                    print(f"\n{category}:")
                    for item in items[:10]:  # Limit output
                        print(f"  - {item}")
        else:
            print("No findings")
    
    elif args.scan_all:
        print("Scanning all processes...")
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                findings = analyzer.scan_process_memory(proc.info['pid'])
                if any(findings.values()):
                    print(f"\n{proc.info['name']} (PID: {proc.info['pid']}):")
                    for category, items in findings.items():
                        if items:
                            print(f"  {category}: {len(items)} items")
            except:
                continue
    
    elif args.detect_injection:
        injections = analyzer.detect_injection()
        if injections:
            print("Process injection detected:")
            for inj in injections:
                print(f"- {inj}")
        else:
            print("No process injection detected")
    
    elif args.find_hidden:
        hidden = analyzer.find_hidden_processes()
        if hidden:
            print("Hidden processes found:")
            for h in hidden:
                print(f"- PID {h['pid']} ({h['detection_method']})")
        else:
            print("No hidden processes found")
    
    elif args.report:
        report = analyzer.generate_memory_report()
        print(report)
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
