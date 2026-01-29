#!/usr/bin/env python3
"""
Anti-Forensics Toolkit - Defeat forensic analysis
Part of Lackadaisical Anonymity Toolkit
"""

import os
import sys
import time
import shutil
import struct
import random
import hashlib
import platform
import subprocess
from datetime import datetime, timedelta
from typing import List, Dict, Optional
import ctypes

class AntiForensics:
    """Comprehensive anti-forensics toolkit"""
    
    def __init__(self):
        self.os_type = platform.system().lower()
        self.is_admin = self._check_admin()
        
    def _check_admin(self):
        """Check if running with admin privileges"""
        if self.os_type == 'windows':
            try:
                return ctypes.windll.shell32.IsUserAnAdmin()
            except:
                return False
        else:
            return os.geteuid() == 0
    
    def timestamp_manipulation(self, file_path: str, 
                             created: Optional[datetime] = None,
                             modified: Optional[datetime] = None,
                             accessed: Optional[datetime] = None):
        """Manipulate file timestamps"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Generate random timestamps if not provided
        if not any([created, modified, accessed]):
            base_time = datetime.now() - timedelta(days=random.randint(30, 365))
            created = created or base_time - timedelta(days=random.randint(1, 30))
            modified = modified or base_time - timedelta(days=random.randint(0, 7))
            accessed = accessed or base_time
        
        if self.os_type == 'windows':
            self._set_windows_timestamps(file_path, created, modified, accessed)
        else:
            self._set_unix_timestamps(file_path, modified, accessed)
    
    def _set_windows_timestamps(self, file_path, created, modified, accessed):
        """Set timestamps on Windows"""
        import win32file
        import win32con
        import pywintypes
        
        def datetime_to_filetime(dt):
            if dt:
                return pywintypes.Time(dt)
            return None
        
        handle = win32file.CreateFile(
            file_path,
            win32con.GENERIC_WRITE,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_ATTRIBUTE_NORMAL,
            None
        )
        
        win32file.SetFileTime(
            handle,
            datetime_to_filetime(created),
            datetime_to_filetime(accessed),
            datetime_to_filetime(modified)
        )
        
        win32file.CloseHandle(handle)
    
    def _set_unix_timestamps(self, file_path, modified, accessed):
        """Set timestamps on Unix-like systems"""
        if modified and accessed:
            os.utime(file_path, (accessed.timestamp(), modified.timestamp()))
    
    def slack_space_wipe(self, directory: str):
        """Wipe slack space in filesystem"""
        if not self.is_admin:
            print("Warning: Admin privileges required for complete slack space wiping")
        
        # Create temporary file to fill free space
        temp_file = os.path.join(directory, f'.wipe_{random.randint(1000, 9999)}')
        
        try:
            with open(temp_file, 'wb') as f:
                chunk_size = 1024 * 1024  # 1MB chunks
                random_data = os.urandom(chunk_size)
                
                while True:
                    try:
                        f.write(random_data)
                        f.flush()
                        os.fsync(f.fileno())
                    except (OSError, IOError):
                        # Disk full
                        break
            
            # Overwrite with zeros
            with open(temp_file, 'r+b') as f:
                f.seek(0)
                file_size = f.seek(0, 2)
                f.seek(0)
                
                zeros = b'\x00' * chunk_size
                written = 0
                
                while written < file_size:
                    to_write = min(chunk_size, file_size - written)
                    f.write(zeros[:to_write])
                    written += to_write
                
                f.flush()
                os.fsync(f.fileno())
        
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)
    
    def mft_manipulation(self, target_file: str):
        """Manipulate MFT entries (Windows only)"""
        if self.os_type != 'windows':
            print("MFT manipulation is Windows-specific")
            return
        
        if not self.is_admin:
            raise PermissionError("Admin privileges required for MFT manipulation")
        
        # Direct MFT manipulation requires low-level disk access
        # This is a simplified approach using fsutil
        try:
            # Create alternate data streams
            ads_name = f"{target_file}:hidden_{random.randint(1000, 9999)}"
            with open(ads_name, 'w') as f:
                f.write("Decoy data to confuse forensics\n")
            
            # Manipulate file attributes
            subprocess.run([
                'attrib', '+H', '+S', '+A', target_file
            ], capture_output=True)
            
        except Exception as e:
            print(f"MFT manipulation error: {e}")
    
    def process_hollowing_detector_evasion(self):
        """Evade process hollowing detection"""
        if self.os_type == 'windows':
            # Modify process memory patterns
            import psutil
            
            current_process = psutil.Process()
            
            # Randomize memory regions
            for child in current_process.children():
                try:
                    # Inject benign patterns
                    pass  # Actual implementation would require ctypes/win32api
                except:
                    pass
    
    def registry_timestamp_manipulation(self, key_path: str):
        """Manipulate Windows registry timestamps"""
        if self.os_type != 'windows':
            return
        
        try:
            import winreg
            
            # Open registry key
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, 
                                winreg.KEY_ALL_ACCESS)
            
            # Registry timestamp manipulation requires kernel-level access
            # This is a placeholder for the concept
            
            winreg.CloseKey(key)
            
        except Exception as e:
            print(f"Registry manipulation error: {e}")
    
    def memory_artifacts_removal(self):
        """Remove artifacts from memory"""
        import gc
        
        # Force garbage collection
        gc.collect()
        
        if self.os_type == 'windows':
            # Clear working set
            try:
                kernel32 = ctypes.windll.kernel32
                handle = kernel32.GetCurrentProcess()
                kernel32.SetProcessWorkingSetSize(handle, -1, -1)
            except:
                pass
        else:
            # Drop caches on Linux
            if self.is_admin:
                try:
                    with open('/proc/sys/vm/drop_caches', 'w') as f:
                        f.write('3')
                except:
                    pass
    
    def pagefile_swap_cleaner(self):
        """Clean pagefile and swap space"""
        if self.os_type == 'windows':
            if self.is_admin:
                # Clear pagefile on shutdown
                subprocess.run([
                    'reg', 'add',
                    'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management',
                    '/v', 'ClearPageFileAtShutdown',
                    '/t', 'REG_DWORD',
                    '/d', '1',
                    '/f'
                ], capture_output=True)
        else:
            # Clear swap on Linux/Unix
            if self.is_admin:
                try:
                    subprocess.run(['swapoff', '-a'], capture_output=True)
                    subprocess.run(['swapon', '-a'], capture_output=True)
                except:
                    pass
    
    def hibernation_file_removal(self):
        """Remove hibernation file"""
        if self.os_type == 'windows':
            if self.is_admin:
                subprocess.run(['powercfg', '-h', 'off'], capture_output=True)
        else:
            # Remove hibernation file on Linux
            hibfile = '/var/swap/hibernation'
            if os.path.exists(hibfile) and self.is_admin:
                os.unlink(hibfile)
    
    def usn_journal_manipulation(self):
        """Manipulate USN Journal (Windows)"""
        if self.os_type != 'windows' or not self.is_admin:
            return
        
        try:
            # Delete USN Journal
            subprocess.run([
                'fsutil', 'usn', 'deletejournal', '/n', 'C:'
            ], capture_output=True)
            
            # Recreate with minimal size
            subprocess.run([
                'fsutil', 'usn', 'createjournal', 'm=1000', 'a=100', 'C:'
            ], capture_output=True)
            
        except Exception as e:
            print(f"USN Journal manipulation error: {e}")
    
    def event_log_manipulation(self):
        """Manipulate system event logs"""
        if self.os_type == 'windows':
            if self.is_admin:
                # Clear specific event logs
                logs = ['System', 'Security', 'Application']
                for log in logs:
                    subprocess.run([
                        'wevtutil', 'cl', log
                    ], capture_output=True)
        else:
            # Clear logs on Linux
            if self.is_admin:
                log_files = [
                    '/var/log/auth.log',
                    '/var/log/syslog',
                    '/var/log/kern.log',
                    '/var/log/messages'
                ]
                
                for log_file in log_files:
                    if os.path.exists(log_file):
                        open(log_file, 'w').close()
    
    def prefetch_manipulation(self):
        """Manipulate Windows Prefetch"""
        if self.os_type != 'windows':
            return
        
        prefetch_dir = 'C:\\Windows\\Prefetch'
        
        if os.path.exists(prefetch_dir) and self.is_admin:
            # Clear prefetch files
            for file in os.listdir(prefetch_dir):
                if file.endswith('.pf'):
                    try:
                        os.unlink(os.path.join(prefetch_dir, file))
                    except:
                        pass
    
    def browser_artifacts_removal(self):
        """Remove browser forensic artifacts"""
        # Common browser paths
        browser_paths = {
            'chrome': {
                'windows': os.path.expandvars('%LOCALAPPDATA%\\Google\\Chrome\\User Data'),
                'linux': os.path.expanduser('~/.config/google-chrome'),
                'darwin': os.path.expanduser('~/Library/Application Support/Google/Chrome')
            },
            'firefox': {
                'windows': os.path.expandvars('%APPDATA%\\Mozilla\\Firefox\\Profiles'),
                'linux': os.path.expanduser('~/.mozilla/firefox'),
                'darwin': os.path.expanduser('~/Library/Application Support/Firefox/Profiles')
            }
        }
        
        # Artifacts to remove
        artifacts = [
            'History', 'Cookies', 'Cache', 'Thumbnails',
            'Session Storage', 'Local Storage', 'IndexedDB'
        ]
        
        for browser, paths in browser_paths.items():
            browser_path = paths.get(self.os_type)
            if browser_path and os.path.exists(browser_path):
                self._clean_browser_artifacts(browser_path, artifacts)
    
    def _clean_browser_artifacts(self, browser_path: str, artifacts: List[str]):
        """Clean specific browser artifacts"""
        for root, dirs, files in os.walk(browser_path):
            for artifact in artifacts:
                # Remove matching files
                for file in files:
                    if artifact.lower() in file.lower():
                        try:
                            os.unlink(os.path.join(root, file))
                        except:
                            pass
                
                # Remove matching directories
                for dir in dirs:
                    if artifact.lower() in dir.lower():
                        try:
                            shutil.rmtree(os.path.join(root, dir))
                        except:
                            pass
    
    def full_anti_forensics_wipe(self):
        """Perform comprehensive anti-forensics wipe"""
        print("Starting comprehensive anti-forensics wipe...")
        
        tasks = [
            ("Memory artifacts", self.memory_artifacts_removal),
            ("Browser artifacts", self.browser_artifacts_removal),
            ("Event logs", self.event_log_manipulation),
            ("Prefetch data", self.prefetch_manipulation),
            ("USN Journal", self.usn_journal_manipulation),
            ("Hibernation file", self.hibernation_file_removal),
            ("Pagefile/Swap", self.pagefile_swap_cleaner)
        ]
        
        for task_name, task_func in tasks:
            try:
                print(f"Cleaning {task_name}...")
                task_func()
                print(f"  ✓ {task_name} cleaned")
            except Exception as e:
                print(f"  ✗ {task_name} failed: {e}")
        
        print("\nAnti-forensics wipe completed")


def main():
    """CLI interface"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Anti-Forensics Toolkit')
    parser.add_argument('--timestamp', metavar='FILE', help='Manipulate file timestamps')
    parser.add_argument('--slack-wipe', metavar='DIR', help='Wipe filesystem slack space')
    parser.add_argument('--full-wipe', action='store_true', help='Perform full anti-forensics wipe')
    parser.add_argument('--memory-clean', action='store_true', help='Clean memory artifacts')
    parser.add_argument('--browser-clean', action='store_true', help='Clean browser artifacts')
    
    args = parser.parse_args()
    
    af = AntiForensics()
    
    if not af.is_admin:
        print("Warning: Some operations require administrator privileges")
    
    if args.timestamp:
        af.timestamp_manipulation(args.timestamp)
        print(f"Timestamps manipulated for: {args.timestamp}")
    
    elif args.slack_wipe:
        print(f"Wiping slack space in: {args.slack_wipe}")
        af.slack_space_wipe(args.slack_wipe)
        print("Slack space wiped")
    
    elif args.full_wipe:
        af.full_anti_forensics_wipe()
    
    elif args.memory_clean:
        af.memory_artifacts_removal()
        print("Memory artifacts cleaned")
    
    elif args.browser_clean:
        af.browser_artifacts_removal()
        print("Browser artifacts cleaned")
    
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
