#!/usr/bin/env python3
"""
Activity Monitor - Real-time OPSEC monitoring and alerts
Part of Lackadaisical Anonymity Toolkit
"""

import os
import sys
import time
import json
import psutil
import socket
import threading
import subprocess
from datetime import datetime
from collections import defaultdict
import logging

class ActivityMonitor:
    def __init__(self, config_file=None):
        self.running = False
        self.alerts = []
        self.config = self.load_config(config_file)
        self.setup_logging()
        
        # Monitoring states
        self.baseline = {
            'processes': set(),
            'connections': set(),
            'files': {},
            'registry': {}
        }
        
        # Alert thresholds
        self.thresholds = {
            'new_connections': 10,
            'cpu_usage': 80,
            'memory_usage': 80,
            'disk_io': 100 * 1024 * 1024,  # 100 MB/s
            'network_io': 10 * 1024 * 1024   # 10 MB/s
        }
        
    def load_config(self, config_file):
        """Load configuration from file"""
        default_config = {
            'monitoring': {
                'processes': True,
                'network': True,
                'filesystem': True,
                'registry': sys.platform == 'win32'
            },
            'alerts': {
                'console': True,
                'log_file': True,
                'sound': False
            },
            'whitelist': {
                'processes': [],
                'ips': [],
                'domains': []
            }
        }
        
        if config_file and os.path.exists(config_file):
            with open(config_file, 'r') as f:
                config = json.load(f)
                default_config.update(config)
        
        return default_config
    
    def setup_logging(self):
        """Setup logging configuration"""
        log_dir = os.path.expanduser('~/.lackadaisical/logs')
        os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(os.path.join(log_dir, 'activity_monitor.log')),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
    def start(self):
        """Start monitoring"""
        self.running = True
        self.logger.info("Activity Monitor started")
        
        # Create baseline
        self.create_baseline()
        
        # Start monitoring threads
        threads = []
        
        if self.config['monitoring']['processes']:
            threads.append(threading.Thread(target=self.monitor_processes))
        
        if self.config['monitoring']['network']:
            threads.append(threading.Thread(target=self.monitor_network))
        
        if self.config['monitoring']['filesystem']:
            threads.append(threading.Thread(target=self.monitor_filesystem))
        
        if self.config['monitoring']['registry'] and sys.platform == 'win32':
            threads.append(threading.Thread(target=self.monitor_registry))
        
        # Start system resource monitoring
        threads.append(threading.Thread(target=self.monitor_resources))
        
        for thread in threads:
            thread.daemon = True
            thread.start()
        
        # Main monitoring loop
        try:
            while self.running:
                time.sleep(1)
                self.process_alerts()
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        self.logger.info("Activity Monitor stopped")
    
    def create_baseline(self):
        """Create baseline for comparison"""
        # Baseline processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                self.baseline['processes'].add(proc.info['name'])
            except:
                pass
        
        # Baseline connections
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED':
                self.baseline['connections'].add((conn.raddr.ip, conn.raddr.port) if conn.raddr else None)
    
    def monitor_processes(self):
        """Monitor process creation"""
        known_processes = self.baseline['processes'].copy()
        
        while self.running:
            try:
                current_processes = set()
                
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
                    try:
                        proc_name = proc.info['name']
                        current_processes.add(proc_name)
                        
                        # Check for new processes
                        if proc_name not in known_processes:
                            if proc_name not in self.config['whitelist']['processes']:
                                self.create_alert(
                                    'PROCESS',
                                    f'New process detected: {proc_name}',
                                    {
                                        'pid': proc.info['pid'],
                                        'name': proc_name,
                                        'cmdline': proc.info['cmdline'],
                                        'created': datetime.fromtimestamp(proc.info['create_time']).isoformat()
                                    }
                                )
                            known_processes.add(proc_name)
                        
                        # Check for suspicious process names
                        suspicious_patterns = [
                            'mimikatz', 'pwdump', 'procdump', 'lsass',
                            'keylogger', 'wireshark', 'tcpdump', 'nmap'
                        ]
                        
                        for pattern in suspicious_patterns:
                            if pattern.lower() in proc_name.lower():
                                self.create_alert(
                                    'SUSPICIOUS',
                                    f'Suspicious process detected: {proc_name}',
                                    {'pid': proc.info['pid'], 'pattern': pattern}
                                )
                    except:
                        pass
                
                time.sleep(1)
                
            except Exception as e:
                self.logger.error(f"Process monitoring error: {e}")
                time.sleep(5)
    
    def monitor_network(self):
        """Monitor network connections"""
        known_connections = self.baseline['connections'].copy()
        connection_counts = defaultdict(int)
        
        while self.running:
            try:
                current_connections = set()
                new_connection_count = 0
                
                for conn in psutil.net_connections():
                    if conn.status == 'ESTABLISHED' and conn.raddr:
                        endpoint = (conn.raddr.ip, conn.raddr.port)
                        current_connections.add(endpoint)
                        
                        # Check for new connections
                        if endpoint not in known_connections:
                            new_connection_count += 1
                            
                            # Check if IP is whitelisted
                            if conn.raddr.ip not in self.config['whitelist']['ips']:
                                # Resolve hostname if possible
                                try:
                                    hostname = socket.gethostbyaddr(conn.raddr.ip)[0]
                                except:
                                    hostname = 'Unknown'
                                
                                self.create_alert(
                                    'NETWORK',
                                    f'New connection to {conn.raddr.ip}:{conn.raddr.port}',
                                    {
                                        'ip': conn.raddr.ip,
                                        'port': conn.raddr.port,
                                        'hostname': hostname,
                                        'process': self.get_process_by_connection(conn)
                                    }
                                )
                            
                            known_connections.add(endpoint)
                        
                        # Track connection frequency
                        connection_counts[conn.raddr.ip] += 1
                
                # Check for connection burst
                if new_connection_count > self.thresholds['new_connections']:
                    self.create_alert(
                        'ANOMALY',
                        f'Unusual number of new connections: {new_connection_count}',
                        {'count': new_connection_count}
                    )
                
                # Check for suspicious ports
                suspicious_ports = [22, 23, 3389, 5900, 5901]  # SSH, Telnet, RDP, VNC
                for conn in psutil.net_connections():
                    if conn.laddr and conn.laddr.port in suspicious_ports and conn.status == 'LISTEN':
                        self.create_alert(
                            'SUSPICIOUS',
                            f'Suspicious port listening: {conn.laddr.port}',
                            {'port': conn.laddr.port, 'service': self.get_service_name(conn.laddr.port)}
                        )
                
                time.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Network monitoring error: {e}")
                time.sleep(5)
    
    def monitor_filesystem(self):
        """Monitor filesystem changes"""
        if sys.platform == 'win32':
            self.monitor_filesystem_windows()
        else:
            self.monitor_filesystem_unix()
    
    def monitor_filesystem_unix(self):
        """Monitor filesystem on Unix systems"""
        sensitive_paths = [
            os.path.expanduser('~/.ssh'),
            os.path.expanduser('~/.gnupg'),
            '/etc/passwd',
            '/etc/shadow',
            os.path.expanduser('~/.bash_history')
        ]
        
        file_states = {}
        
        while self.running:
            try:
                for path in sensitive_paths:
                    if os.path.exists(path):
                        stat = os.stat(path)
                        current_state = (stat.st_mtime, stat.st_size)
                        
                        if path in file_states and file_states[path] != current_state:
                            self.create_alert(
                                'FILESYSTEM',
                                f'Sensitive file modified: {path}',
                                {
                                    'path': path,
                                    'old_mtime': datetime.fromtimestamp(file_states[path][0]).isoformat(),
                                    'new_mtime': datetime.fromtimestamp(current_state[0]).isoformat(),
                                    'size_change': current_state[1] - file_states[path][1]
                                }
                            )
                        
                        file_states[path] = current_state
                
                time.sleep(10)
                
            except Exception as e:
                self.logger.error(f"Filesystem monitoring error: {e}")
                time.sleep(10)
    
    def monitor_filesystem_windows(self):
        """Monitor filesystem on Windows"""
        # Similar implementation for Windows
        pass
    
    def monitor_registry(self):
        """Monitor Windows registry changes"""
        if sys.platform != 'win32':
            return
        
        import winreg
        
        sensitive_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce")
        ]
        
        registry_states = {}
        
        while self.running:
            try:
                for hive, key_path in sensitive_keys:
                    try:
                        key = winreg.OpenKey(hive, key_path)
                        values = []
                        
                        i = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(key, i)
                                values.append((name, value))
                                i += 1
                            except WindowsError:
                                break
                        
                        winreg.CloseKey(key)
                        
                        key_id = f"{hive}\\{key_path}"
                        if key_id in registry_states:
                            old_values = set(registry_states[key_id])
                            new_values = set(values)
                            
                            added = new_values - old_values
                            removed = old_values - new_values
                            
                            for name, value in added:
                                self.create_alert(
                                    'REGISTRY',
                                    f'Registry autorun added: {name}',
                                    {
                                        'key': key_path,
                                        'name': name,
                                        'value': value
                                    }
                                )
                        
                        registry_states[key_id] = values
                        
                    except Exception as e:
                        pass
                
                time.sleep(30)
                
            except Exception as e:
                self.logger.error(f"Registry monitoring error: {e}")
                time.sleep(30)
    
    def monitor_resources(self):
        """Monitor system resource usage"""
        while self.running:
            try:
                # CPU usage
                cpu_percent = psutil.cpu_percent(interval=1)
                if cpu_percent > self.thresholds['cpu_usage']:
                    self.create_alert(
                        'RESOURCE',
                        f'High CPU usage: {cpu_percent}%',
                        {'cpu_percent': cpu_percent}
                    )
                
                # Memory usage
                memory = psutil.virtual_memory()
                if memory.percent > self.thresholds['memory_usage']:
                    self.create_alert(
                        'RESOURCE',
                        f'High memory usage: {memory.percent}%',
                        {
                            'memory_percent': memory.percent,
                            'used': memory.used,
                            'total': memory.total
                        }
                    )
                
                # Disk I/O
                disk_io = psutil.disk_io_counters()
                if disk_io:
                    read_speed = disk_io.read_bytes
                    write_speed = disk_io.write_bytes
                    
                    if read_speed > self.thresholds['disk_io'] or write_speed > self.thresholds['disk_io']:
                        self.create_alert(
                            'RESOURCE',
                            'High disk I/O detected',
                            {
                                'read_speed': read_speed,
                                'write_speed': write_speed
                            }
                        )
                
                # Network I/O
                net_io = psutil.net_io_counters()
                if net_io:
                    bytes_sent = net_io.bytes_sent
                    bytes_recv = net_io.bytes_recv
                    
                    if bytes_sent > self.thresholds['network_io'] or bytes_recv > self.thresholds['network_io']:
                        self.create_alert(
                            'RESOURCE',
                            'High network I/O detected',
                            {
                                'bytes_sent': bytes_sent,
                                'bytes_recv': bytes_recv
                            }
                        )
                
                time.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Resource monitoring error: {e}")
                time.sleep(5)
    
    def create_alert(self, alert_type, message, details=None):
        """Create and store alert"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'message': message,
            'details': details or {}
        }
        
        self.alerts.append(alert)
        
        # Log alert
        self.logger.warning(f"[{alert_type}] {message}")
        
        # Sound alert if configured
        if self.config['alerts']['sound']:
            self.play_alert_sound()
    
    def process_alerts(self):
        """Process and display alerts"""
        while self.alerts:
            alert = self.alerts.pop(0)
            
            if self.config['alerts']['console']:
                self.display_alert(alert)
            
            if self.config['alerts']['log_file']:
                self.log_alert(alert)
    
    def display_alert(self, alert):
        """Display alert to console"""
        print(f"\n[{alert['timestamp']}] {alert['type']}: {alert['message']}")
        if alert['details']:
            for key, value in alert['details'].items():
                print(f"  {key}: {value}")
    
    def log_alert(self, alert):
        """Log alert to file"""
        log_file = os.path.expanduser('~/.lackadaisical/logs/alerts.json')
        
        alerts = []
        if os.path.exists(log_file):
            with open(log_file, 'r') as f:
                try:
                    alerts = json.load(f)
                except:
                    alerts = []
        
        alerts.append(alert)
        
        with open(log_file, 'w') as f:
            json.dump(alerts, f, indent=2)
    
    def play_alert_sound(self):
        """Play alert sound"""
        if sys.platform == 'win32':
            import winsound
            winsound.Beep(1000, 200)
        else:
            print('\a')  # Terminal bell
    
    def get_process_by_connection(self, conn):
        """Get process name for connection"""
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                connections = proc.connections()
                for c in connections:
                    if c.laddr == conn.laddr and c.raddr == conn.raddr:
                        return proc.info['name']
        except:
            pass
        return 'Unknown'
    
    def get_service_name(self, port):
        """Get common service name for port"""
        services = {
            22: 'SSH',
            23: 'Telnet',
            80: 'HTTP',
            443: 'HTTPS',
            3389: 'RDP',
            5900: 'VNC',
            5901: 'VNC',
            8080: 'HTTP-ALT'
        }
        return services.get(port, 'Unknown')

def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Activity Monitor - OPSEC monitoring')
    parser.add_argument('-c', '--config', help='Configuration file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    monitor = ActivityMonitor(args.config)
    
    try:
        monitor.start()
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        monitor.stop()

if __name__ == '__main__':
    main()
