#!/usr/bin/env python3
"""
Digital Footprint Analyzer - Analyze privacy exposure
Part of Lackadaisical Anonymity Toolkit

This tool scans for privacy-leaking artifacts across browsers, system,
network, applications, filesystem, and cloud services.
"""

import os
import sys
import json
import sqlite3
import platform
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import subprocess

class DigitalFootprintAnalyzer:
    def __init__(self):
        self.findings = {
            'browsers': [],
            'system': [],
            'network': [],
            'applications': [],
            'filesystem': [],
            'cloud': []
        }
        self.risk_score = 0
        self.platform = platform.system()
    
    def analyze_browsers(self):
        """Analyze browser-related artifacts"""
        browser_paths = self._get_browser_paths()
        
        for browser_name, paths in browser_paths.items():
            for path_type, path in paths.items():
                if path.exists():
                    finding = {
                        'browser': browser_name,
                        'artifact': path_type,
                        'path': str(path),
                        'risk': 'MEDIUM'
                    }
                    
                    # Check specific artifacts
                    if path_type == 'history':
                        count = self._count_browser_history(path)
                        finding['details'] = f"{count} history entries found"
                        finding['risk'] = 'HIGH' if count > 10000 else 'MEDIUM'
                    
                    elif path_type == 'cookies':
                        count = self._count_browser_cookies(path)
                        finding['details'] = f"{count} cookies found"
                        finding['risk'] = 'HIGH' if count > 500 else 'MEDIUM'
                    
                    elif path_type == 'cache':
                        size = self._get_dir_size(path)
                        finding['details'] = f"{size / (1024*1024):.1f} MB cache"
                        finding['risk'] = 'MEDIUM' if size > 100*1024*1024 else 'LOW'
                    
                    self.findings['browsers'].append(finding)
    
    def analyze_system_artifacts(self):
        """Analyze system-related artifacts"""
        # Check system logs
        if self.platform == 'Linux':
            log_paths = [
                '/var/log/auth.log',
                '/var/log/syslog',
                '~/.bash_history',
                '~/.zsh_history',
                '~/.python_history'
            ]
        elif self.platform == 'Darwin':  # macOS
            log_paths = [
                '~/Library/Logs',
                '~/.bash_history',
                '~/.zsh_history'
            ]
        elif self.platform == 'Windows':
            log_paths = [
                os.path.expandvars(r'%APPDATA%\Microsoft\Windows\Recent'),
                os.path.expandvars(r'%APPDATA%\Microsoft\Windows\PowerShell\PSReadline')
            ]
        else:
            log_paths = []
        
        for log_path in log_paths:
            path = Path(log_path).expanduser()
            if path.exists():
                if path.is_file():
                    size = path.stat().st_size
                    self.findings['system'].append({
                        'artifact': 'log_file',
                        'path': str(path),
                        'size_kb': size // 1024,
                        'risk': 'HIGH' if size > 1024*1024 else 'MEDIUM'
                    })
                elif path.is_dir():
                    count = len(list(path.rglob('*')))
                    self.findings['system'].append({
                        'artifact': 'log_directory',
                        'path': str(path),
                        'file_count': count,
                        'risk': 'MEDIUM'
                    })
        
        # Check temporary files
        temp_dirs = [
            Path('/tmp'),
            Path('~/.cache').expanduser(),
            Path('/var/tmp')
        ]
        
        for temp_dir in temp_dirs:
            if temp_dir.exists():
                size = self._get_dir_size(temp_dir)
                if size > 0:
                    self.findings['system'].append({
                        'artifact': 'temporary_files',
                        'path': str(temp_dir),
                        'size_mb': size // (1024*1024),
                        'risk': 'MEDIUM' if size > 100*1024*1024 else 'LOW'
                    })
    
    def analyze_network_artifacts(self):
        """Analyze network-related artifacts"""
        # Check DNS cache
        try:
            if self.platform == 'Linux':
                # Check systemd-resolved cache
                result = subprocess.run(
                    ['systemd-resolve', '--statistics'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    self.findings['network'].append({
                        'artifact': 'dns_cache',
                        'details': 'DNS cache active',
                        'risk': 'MEDIUM'
                    })
        except:
            pass
        
        # Check network connection history
        known_hosts = Path('~/.ssh/known_hosts').expanduser()
        if known_hosts.exists():
            lines = len(known_hosts.read_text().strip().split('\n'))
            self.findings['network'].append({
                'artifact': 'ssh_known_hosts',
                'path': str(known_hosts),
                'host_count': lines,
                'risk': 'MEDIUM' if lines > 10 else 'LOW'
            })
        
        # Check for network manager connections
        nm_connections = Path('/etc/NetworkManager/system-connections')
        if nm_connections.exists():
            count = len(list(nm_connections.glob('*')))
            if count > 0:
                self.findings['network'].append({
                    'artifact': 'network_connections',
                    'count': count,
                    'risk': 'MEDIUM'
                })
    
    def analyze_applications(self):
        """Analyze application-related artifacts"""
        # Check recently used files
        recent_dirs = [
            Path('~/.local/share/recently-used.xbel').expanduser(),
            Path('~/Library/Application Support/com.apple.sharedfilelist').expanduser(),
        ]
        
        for recent in recent_dirs:
            if recent.exists():
                if recent.is_file():
                    size = recent.stat().st_size
                    self.findings['applications'].append({
                        'artifact': 'recent_files',
                        'path': str(recent),
                        'size_kb': size // 1024,
                        'risk': 'HIGH' if size > 100*1024 else 'MEDIUM'
                    })
        
        # Check application caches
        cache_dirs = [
            Path('~/.cache').expanduser(),
            Path('~/Library/Caches').expanduser(),
            Path(os.path.expandvars(r'%LOCALAPPDATA%\Temp')).expanduser()
        ]
        
        for cache_dir in cache_dirs:
            if cache_dir.exists():
                size = self._get_dir_size(cache_dir)
                if size > 10*1024*1024:  # > 10MB
                    self.findings['applications'].append({
                        'artifact': 'application_cache',
                        'path': str(cache_dir),
                        'size_mb': size // (1024*1024),
                        'risk': 'MEDIUM'
                    })
    
    def analyze_filesystem(self):
        """Analyze filesystem-related artifacts"""
        # Check for sensitive file patterns
        home = Path.home()
        sensitive_patterns = [
            '*.key',
            '*.pem',
            '*.p12',
            '*.pfx',
            '*password*',
            '*credential*',
            '.env',
            'id_rsa',
            'id_ed25519'
        ]
        
        sensitive_dirs = [
            home / '.ssh',
            home / '.gnupg',
            home / '.aws',
            home / '.config'
        ]
        
        for check_dir in sensitive_dirs:
            if not check_dir.exists():
                continue
            
            for pattern in sensitive_patterns:
                for file_path in check_dir.rglob(pattern):
                    if file_path.is_file():
                        perms = oct(file_path.stat().st_mode)[-3:]
                        risk = 'HIGH' if perms != '600' else 'MEDIUM'
                        
                        self.findings['filesystem'].append({
                            'artifact': 'sensitive_file',
                            'path': str(file_path),
                            'permissions': perms,
                            'risk': risk
                        })
    
    def analyze_cloud_services(self):
        """Analyze cloud service-related artifacts"""
        # Check for cloud service configs
        cloud_configs = [
            Path('~/.aws/credentials').expanduser(),
            Path('~/.azure').expanduser(),
            Path('~/.config/gcloud').expanduser(),
            Path('~/Library/Application Support/Dropbox').expanduser(),
            Path('~/.dropbox').expanduser()
        ]
        
        for config_path in cloud_configs:
            if config_path.exists():
                service = config_path.name
                self.findings['cloud'].append({
                    'artifact': 'cloud_credentials',
                    'service': service,
                    'path': str(config_path),
                    'risk': 'HIGH'
                })
    
    def calculate_risk_score(self):
        """Calculate risk score based on findings (0-100)"""
        risk_weights = {
            'LOW': 1,
            'MEDIUM': 3,
            'HIGH': 5,
            'CRITICAL': 10
        }
        
        total_score = 0
        max_score = 0
        
        for category, findings_list in self.findings.items():
            for finding in findings_list:
                risk = finding.get('risk', 'LOW')
                total_score += risk_weights.get(risk, 0)
                max_score += risk_weights['HIGH']
        
        if max_score == 0:
            return 0
        
        # Normalize to 0-100
        self.risk_score = min(100, int((total_score / max_score) * 100))
        return self.risk_score
    
    def _get_browser_paths(self) -> Dict[str, Dict[str, Path]]:
        """Get browser data paths for different platforms"""
        home = Path.home()
        
        if self.platform == 'Linux':
            return {
                'Firefox': {
                    'history': home / '.mozilla/firefox/*.default*/places.sqlite',
                    'cookies': home / '.mozilla/firefox/*.default*/cookies.sqlite',
                    'cache': home / '.cache/mozilla/firefox'
                },
                'Chrome': {
                    'history': home / '.config/google-chrome/Default/History',
                    'cookies': home / '.config/google-chrome/Default/Cookies',
                    'cache': home / '.cache/google-chrome'
                },
                'Chromium': {
                    'history': home / '.config/chromium/Default/History',
                    'cookies': home / '.config/chromium/Default/Cookies',
                    'cache': home / '.cache/chromium'
                }
            }
        elif self.platform == 'Darwin':
            return {
                'Safari': {
                    'history': home / 'Library/Safari/History.db',
                    'cookies': home / 'Library/Cookies/Cookies.binarycookies',
                    'cache': home / 'Library/Caches/com.apple.Safari'
                },
                'Chrome': {
                    'history': home / 'Library/Application Support/Google/Chrome/Default/History',
                    'cookies': home / 'Library/Application Support/Google/Chrome/Default/Cookies',
                    'cache': home / 'Library/Caches/Google/Chrome'
                },
                'Firefox': {
                    'history': home / 'Library/Application Support/Firefox/Profiles/*.default*/places.sqlite',
                    'cookies': home / 'Library/Application Support/Firefox/Profiles/*.default*/cookies.sqlite',
                    'cache': home / 'Library/Caches/Firefox'
                }
            }
        elif self.platform == 'Windows':
            appdata = Path(os.environ.get('APPDATA', ''))
            localappdata = Path(os.environ.get('LOCALAPPDATA', ''))
            
            return {
                'Chrome': {
                    'history': localappdata / 'Google/Chrome/User Data/Default/History',
                    'cookies': localappdata / 'Google/Chrome/User Data/Default/Cookies',
                    'cache': localappdata / 'Google/Chrome/User Data/Default/Cache'
                },
                'Firefox': {
                    'history': appdata / 'Mozilla/Firefox/Profiles/*.default*/places.sqlite',
                    'cookies': appdata / 'Mozilla/Firefox/Profiles/*.default*/cookies.sqlite',
                    'cache': localappdata / 'Mozilla/Firefox/Profiles/*.default*/cache2'
                },
                'Edge': {
                    'history': localappdata / 'Microsoft/Edge/User Data/Default/History',
                    'cookies': localappdata / 'Microsoft/Edge/User Data/Default/Cookies',
                    'cache': localappdata / 'Microsoft/Edge/User Data/Default/Cache'
                }
            }
        else:
            return {}
    
    def _count_browser_history(self, db_path: Path) -> int:
        """Count entries in browser history database"""
        try:
            if '*' in str(db_path):
                matches = list(db_path.parent.parent.glob(db_path.name))
                if not matches:
                    return 0
                db_path = matches[0]
            
            if not db_path.exists():
                return 0
            
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            for table in ['moz_places', 'urls', 'history']:
                try:
                    cursor.execute(f'SELECT COUNT(*) FROM {table}')
                    count = cursor.fetchone()[0]
                    conn.close()
                    return count
                except:
                    continue
            
            conn.close()
            return 0
        except:
            return 0
    
    def _count_browser_cookies(self, db_path: Path) -> int:
        """Count cookies in browser cookie database"""
        try:
            if '*' in str(db_path):
                matches = list(db_path.parent.parent.glob(db_path.name))
                if not matches:
                    return 0
                db_path = matches[0]
            
            if not db_path.exists():
                return 0
            
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            for table in ['moz_cookies', 'cookies']:
                try:
                    cursor.execute(f'SELECT COUNT(*) FROM {table}')
                    count = cursor.fetchone()[0]
                    conn.close()
                    return count
                except:
                    continue
            
            conn.close()
            return 0
        except:
            return 0
    
    def _get_dir_size(self, path: Path) -> int:
        """Get total size of directory in bytes"""
        total = 0
        try:
            for entry in path.rglob('*'):
                if entry.is_file():
                    try:
                        total += entry.stat().st_size
                    except:
                        pass
        except:
            pass
        return total
    
    def analyze_all(self):
        """Run analysis on all categories"""
        print("Analyzing browsers...")
        self.analyze_browsers()
        
        print("Analyzing system artifacts...")
        self.analyze_system_artifacts()
        
        print("Analyzing network artifacts...")
        self.analyze_network_artifacts()
        
        print("Analyzing applications...")
        self.analyze_applications()
        
        print("Analyzing filesystem...")
        self.analyze_filesystem()
        
        print("Analyzing cloud services...")
        self.analyze_cloud_services()
        
        findings = {
            'findings': dict(self.findings),
            'risk_score': self.calculate_risk_score(),
            'timestamp': datetime.now().isoformat()
        }
        
        return findings
    
    def generate_report(self, findings: Dict) -> str:
        """Generate human-readable report from findings"""
        report = []
        report.append("=" * 60)
        report.append("DIGITAL FOOTPRINT ANALYSIS REPORT")
        report.append("=" * 60)
        report.append(f"Generated: {findings['timestamp']}")
        report.append(f"Risk Score: {findings['risk_score']}/100")
        report.append("")
        
        for category, items in findings['findings'].items():
            if items:
                report.append(f"\n{category.upper()}")
                report.append("-" * 60)
                for item in items:
                    risk = item.get('risk', 'UNKNOWN')
                    report.append(f"\n  [{risk}] {item.get('artifact', 'Unknown')}")
                    for key, value in item.items():
                        if key not in ['artifact', 'risk']:
                            report.append(f"    {key}: {value}")
        
        report.append("\n" + "=" * 60)
        report.append("END OF REPORT")
        report.append("=" * 60)
        
        return "\n".join(report)

def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Digital Footprint Analyzer - Analyze your privacy exposure'
    )
    parser.add_argument('--output', '-o', help='Output file for report')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--category', choices=[
        'browsers', 'system', 'network', 'applications', 'filesystem', 'cloud'
    ], help='Analyze specific category only')
    
    args = parser.parse_args()
    
    analyzer = DigitalFootprintAnalyzer()
    
    print("Lackadaisical Digital Footprint Analyzer")
    print("=" * 40)
    
    # Run analysis
    if args.category:
        print(f"Analyzing {args.category} only...")
        if args.category == 'browsers':
            analyzer.analyze_browsers()
        elif args.category == 'system':
            analyzer.analyze_system_artifacts()
        elif args.category == 'network':
            analyzer.analyze_network_artifacts()
        elif args.category == 'applications':
            analyzer.analyze_applications()
        elif args.category == 'filesystem':
            analyzer.analyze_filesystem()
        elif args.category == 'cloud':
            analyzer.analyze_cloud_services()
        
        findings = {
            'findings': dict(analyzer.findings),
            'risk_score': analyzer.calculate_risk_score(),
            'timestamp': datetime.now().isoformat()
        }
    else:
        findings = analyzer.analyze_all()
    
    # Output results
    if args.json:
        output = json.dumps(findings, indent=2)
    else:
        output = analyzer.generate_report(findings)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(output)
        print(f"\nReport saved to: {args.output}")
    else:
        print("\n" + output)

if __name__ == '__main__':
    main()
