#!/usr/bin/env python3
"""
Filesystem Monitor - Detect unauthorized access and surveillance
Part of Lackadaisical Anonymity Toolkit
"""

import os
import sys
import time
import json
import hashlib
import sqlite3
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil

class FilesystemMonitor:
    """Monitor filesystem for unauthorized access and changes"""
    
    def __init__(self, db_path: str = "~/.lackadaisical/fs_monitor.db"):
        self.db_path = os.path.expanduser(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self.conn = self._init_database()
        self.monitored_paths = set()
        self.alerts = []
        self.process_whitelist = self._load_process_whitelist()
        
    def _init_database(self) -> sqlite3.Connection:
        """Initialize monitoring database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_baseline (
                path TEXT PRIMARY KEY,
                hash TEXT,
                size INTEGER,
                mtime REAL,
                atime REAL,
                permissions INTEGER,
                owner TEXT,
                last_checked TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT,
                event_type TEXT,
                process_name TEXT,
                process_pid INTEGER,
                timestamp TIMESTAMP,
                details TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT,
                severity TEXT,
                path TEXT,
                message TEXT,
                timestamp TIMESTAMP
            )
        ''')
        
        conn.commit()
        return conn
    
    def _load_process_whitelist(self) -> Set[str]:
        """Load trusted processes"""
        whitelist = {
            'kernel', 'systemd', 'init', 'kworker',
            'python', 'python3', 'bash', 'sh',
            # Add system-specific processes
        }
        
        # Load user whitelist
        whitelist_file = os.path.expanduser("~/.lackadaisical/process_whitelist.txt")
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r') as f:
                whitelist.update(line.strip() for line in f if line.strip())
        
        return whitelist
    
    def add_monitored_path(self, path: str, recursive: bool = True):
        """Add path to monitoring"""
        path = os.path.abspath(path)
        
        if not os.path.exists(path):
            print(f"Path does not exist: {path}")
            return
        
        self.monitored_paths.add(path)
        
        # Create baseline
        if os.path.isdir(path):
            self._baseline_directory(path, recursive)
        else:
            self._baseline_file(path)
        
        print(f"Added to monitoring: {path}")
    
    def _baseline_file(self, filepath: str):
        """Create baseline for single file"""
        try:
            stat = os.stat(filepath)
            
            # Calculate file hash
            file_hash = self._calculate_file_hash(filepath)
            
            # Get owner info
            try:
                import pwd
                owner = pwd.getpwuid(stat.st_uid).pw_name
            except:
                owner = str(stat.st_uid)
            
            # Store in database
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO file_baseline 
                (path, hash, size, mtime, atime, permissions, owner, last_checked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                filepath, file_hash, stat.st_size,
                stat.st_mtime, stat.st_atime,
                stat.st_mode, owner,
                datetime.now()
            ))
            self.conn.commit()
            
        except Exception as e:
            print(f"Error baselining {filepath}: {e}")
    
    def _baseline_directory(self, dirpath: str, recursive: bool):
        """Create baseline for directory"""
        for root, dirs, files in os.walk(dirpath):
            for filename in files:
                filepath = os.path.join(root, filename)
                self._baseline_file(filepath)
            
            if not recursive:
                break
    
    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except:
            return "INACCESSIBLE"
    
    def check_integrity(self) -> List[Dict]:
        """Check all monitored files for changes"""
        violations = []
        cursor = self.conn.cursor()
        
        # Get all baseline entries
        cursor.execute("SELECT * FROM file_baseline")
        baselines = cursor.fetchall()
        
        for baseline in baselines:
            path = baseline[0]
            
            if not os.path.exists(path):
                violations.append({
                    'type': 'DELETED',
                    'path': path,
                    'message': 'File has been deleted'
                })
                continue
            
            # Check current state
            try:
                stat = os.stat(path)
                current_hash = self._calculate_file_hash(path)
                
                # Check for modifications
                if current_hash != baseline[1] and current_hash != "INACCESSIBLE":
                    violations.append({
                        'type': 'MODIFIED',
                        'path': path,
                        'message': 'File content has been modified',
                        'old_hash': baseline[1],
                        'new_hash': current_hash
                    })
                
                # Check permissions
                if stat.st_mode != baseline[5]:
                    violations.append({
                        'type': 'PERMISSION_CHANGE',
                        'path': path,
                        'message': 'File permissions changed',
                        'old_perms': oct(baseline[5]),
                        'new_perms': oct(stat.st_mode)
                    })
                
                # Check suspicious access patterns
                if stat.st_atime > baseline[4] + 1:  # Accessed after baseline
                    # Find what process accessed it
                    accessing_process = self._find_accessing_process(path)
                    if accessing_process and accessing_process not in self.process_whitelist:
                        violations.append({
                            'type': 'SUSPICIOUS_ACCESS',
                            'path': path,
                            'message': f'Accessed by suspicious process: {accessing_process}',
                            'access_time': datetime.fromtimestamp(stat.st_atime)
                        })
                
            except Exception as e:
                violations.append({
                    'type': 'ERROR',
                    'path': path,
                    'message': f'Error checking file: {e}'
                })
        
        # Log violations
        for violation in violations:
            self._create_alert(
                violation['type'],
                'HIGH' if violation['type'] in ['MODIFIED', 'SUSPICIOUS_ACCESS'] else 'MEDIUM',
                violation['path'],
                violation['message']
            )
        
        return violations
    
    def _find_accessing_process(self, filepath: str) -> Optional[str]:
        """Find process that has file open"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                try:
                    for file in proc.open_files():
                        if file.path == filepath:
                            return proc.info['name']
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except:
            pass
        return None
    
    def monitor_realtime(self):
        """Start real-time filesystem monitoring"""
        event_handler = FileEventHandler(self)
        observer = Observer()
        
        for path in self.monitored_paths:
            observer.schedule(event_handler, path, recursive=True)
        
        observer.start()
        print("Real-time monitoring started. Press Ctrl+C to stop.")
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            print("\nMonitoring stopped.")
        
        observer.join()
    
    def detect_surveillance_indicators(self) -> List[Dict]:
        """Detect potential surveillance software indicators"""
        indicators = []
        
        # Known surveillance software paths
        surveillance_paths = [
            # Windows
            "C:\\Windows\\System32\\LogFiles",
            "C:\\Windows\\Prefetch",
            "C:\\ProgramData\\Microsoft\\Windows\\WER",
            # Linux
            "/var/log/auth.log",
            "/var/log/secure",
            "/var/log/audit",
            # Common keylogger locations
            "*/keylogs*",
            "*/keylogger*",
            "*/.hidden/*"
        ]
        
        # Check for suspicious processes
        suspicious_processes = [
            'keylogger', 'screenshot', 'recorder', 'monitor',
            'spy', 'track', 'watch', 'capture', 'grab'
        ]
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                proc_name = proc.info['name'].lower()
                for suspicious in suspicious_processes:
                    if suspicious in proc_name:
                        indicators.append({
                            'type': 'SUSPICIOUS_PROCESS',
                            'name': proc.info['name'],
                            'pid': proc.info['pid'],
                            'exe': proc.info['exe']
                        })
            except:
                pass
        
        # Check for packet capture
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] in ['tcpdump', 'wireshark', 'tshark']:
                    indicators.append({
                        'type': 'PACKET_CAPTURE',
                        'process': proc.info['name']
                    })
        except:
            pass
        
        # Check for surveillance files
        home_dir = os.path.expanduser("~")
        suspicious_files = []
        
        for pattern in ['*.pcap', '*.cap', 'keylog*', '*.kl', 'screenshot*']:
            for file in Path(home_dir).rglob(pattern):
                if file.is_file():
                    suspicious_files.append(str(file))
        
        if suspicious_files:
            indicators.append({
                'type': 'SUSPICIOUS_FILES',
                'files': suspicious_files[:10]  # Limit to 10
            })
        
        return indicators
    
    def _create_alert(self, alert_type: str, severity: str, 
                     path: str, message: str):
        """Create security alert"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO alerts (alert_type, severity, path, message, timestamp)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert_type, severity, path, message, datetime.now()))
        self.conn.commit()
        
        # Also append to memory
        self.alerts.append({
            'type': alert_type,
            'severity': severity,
            'path': path,
            'message': message,
            'timestamp': datetime.now()
        })
    
    def get_alerts(self, severity: Optional[str] = None) -> List[Dict]:
        """Get security alerts"""
        cursor = self.conn.cursor()
        
        if severity:
            cursor.execute(
                "SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC",
                (severity,)
            )
        else:
            cursor.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
        
        alerts = []
        for row in cursor.fetchall():
            alerts.append({
                'id': row[0],
                'type': row[1],
                'severity': row[2],
                'path': row[3],
                'message': row[4],
                'timestamp': row[5]
            })
        
        return alerts
    
    def generate_report(self) -> str:
        """Generate security report"""
        report = []
        report.append("Filesystem Security Report")
        report.append("=" * 50)
        report.append(f"Generated: {datetime.now()}")
        report.append("")
        
        # Summary
        cursor = self.conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM file_baseline")
        total_files = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM alerts WHERE severity = 'HIGH'")
        high_alerts = cursor.fetchone()[0]
        
        report.append(f"Monitored files: {total_files}")
        report.append(f"High severity alerts: {high_alerts}")
        report.append("")
        
        # Recent alerts
        report.append("Recent Alerts:")
        report.append("-" * 30)
        
        recent_alerts = self.get_alerts()[:10]
        for alert in recent_alerts:
            report.append(f"[{alert['severity']}] {alert['type']}: {alert['path']}")
            report.append(f"  {alert['message']}")
            report.append(f"  Time: {alert['timestamp']}")
            report.append("")
        
        # Surveillance indicators
        indicators = self.detect_surveillance_indicators()
        if indicators:
            report.append("Surveillance Indicators Detected:")
            report.append("-" * 30)
            for indicator in indicators:
                report.append(f"- {indicator['type']}: {indicator}")
            report.append("")
        
        return "\n".join(report)


class FileEventHandler(FileSystemEventHandler):
    """Handle filesystem events"""
    
    def __init__(self, monitor: FilesystemMonitor):
        self.monitor = monitor
    
    def on_modified(self, event):
        if not event.is_directory:
            self.monitor._create_alert(
                'FILE_MODIFIED',
                'MEDIUM',
                event.src_path,
                f'File modified in real-time'
            )
    
    def on_created(self, event):
        if not event.is_directory:
            # Check if it's a suspicious file
            filename = os.path.basename(event.src_path).lower()
            if any(susp in filename for susp in ['keylog', 'screenshot', 'capture']):
                severity = 'HIGH'
                message = 'Suspicious file created'
            else:
                severity = 'LOW'
                message = 'File created'
            
            self.monitor._create_alert(
                'FILE_CREATED',
                severity,
                event.src_path,
                message
            )
    
    def on_deleted(self, event):
        if not event.is_directory:
            self.monitor._create_alert(
                'FILE_DELETED',
                'MEDIUM',
                event.src_path,
                'File deleted'
            )


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Filesystem Monitor - Detect unauthorized access'
    )
    parser.add_argument('--add', metavar='PATH', help='Add path to monitoring')
    parser.add_argument('--check', action='store_true', 
                       help='Check integrity of monitored files')
    parser.add_argument('--monitor', action='store_true',
                       help='Start real-time monitoring')
    parser.add_argument('--detect', action='store_true',
                       help='Detect surveillance indicators')
    parser.add_argument('--alerts', action='store_true',
                       help='Show recent alerts')
    parser.add_argument('--report', action='store_true',
                       help='Generate security report')
    
    args = parser.parse_args()
    
    monitor = FilesystemMonitor()
    
    if args.add:
        monitor.add_monitored_path(args.add)
    
    elif args.check:
        print("Checking file integrity...")
        violations = monitor.check_integrity()
        
        if violations:
            print(f"\nFound {len(violations)} integrity violations:")
            for v in violations:
                print(f"- {v['type']}: {v['path']}")
                print(f"  {v['message']}")
        else:
            print("No integrity violations found.")
    
    elif args.monitor:
        monitor.monitor_realtime()
    
    elif args.detect:
        indicators = monitor.detect_surveillance_indicators()
        
        if indicators:
            print("Surveillance indicators detected:")
            for ind in indicators:
                print(f"- {ind}")
        else:
            print("No surveillance indicators detected.")
    
    elif args.alerts:
        alerts = monitor.get_alerts()
        
        if alerts:
            print(f"Recent alerts ({len(alerts)} total):")
            for alert in alerts[:20]:
                print(f"[{alert['severity']}] {alert['type']}: {alert['path']}")
                print(f"  {alert['message']}")
                print(f"  {alert['timestamp']}")
                print()
        else:
            print("No alerts found.")
    
    elif args.report:
        report = monitor.generate_report()
        print(report)
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
