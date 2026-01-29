#!/usr/bin/env python3
"""
Secure File Shredder - Military-grade file deletion
Part of Lackadaisical Anonymity Toolkit

Implements multiple secure deletion standards:
- DoD 5220.22-M (3-pass, 7-pass)
- Gutmann method (35-pass)
- Random overwrite
- Zero-fill
"""

import os
import sys
import argparse
import random
import hashlib
from pathlib import Path
from typing import List, Optional
import time

class SecureShredder:
    """Secure file deletion with multiple methods"""
    
    # DoD 5220.22-M patterns
    DOD_PATTERNS = [
        lambda size: bytes([0x00] * size),  # All zeros
        lambda size: bytes([0xFF] * size),  # All ones
        lambda size: os.urandom(size)       # Random
    ]
    
    # Gutmann patterns (simplified - full method has 35 passes)
    GUTMANN_PATTERNS = [
        lambda size: bytes([0x00] * size),
        lambda size: bytes([0xFF] * size),
        lambda size: bytes([0x55] * size),  # 01010101
        lambda size: bytes([0xAA] * size),  # 10101010
    ] + [lambda size: os.urandom(size)] * 31  # 31 random passes
    
    def __init__(self, verify: bool = True, verbose: bool = False):
        self.verify = verify
        self.verbose = verbose
        self.block_size = 64 * 1024  # 64KB blocks
    
    def log(self, message: str):
        """Log message if verbose"""
        if self.verbose:
            print(f"  {message}")
    
    def get_file_size(self, file_path: Path) -> int:
        """Get file size in bytes"""
        return file_path.stat().st_size
    
    def overwrite_pass(self, file_path: Path, pattern_func, pass_num: int = 0) -> bool:
        """Perform single overwrite pass"""
        try:
            file_size = self.get_file_size(file_path)
            
            with open(file_path, 'r+b', buffering=0) as f:
                offset = 0
                
                while offset < file_size:
                    # Calculate block size for this iteration
                    remaining = file_size - offset
                    current_block = min(self.block_size, remaining)
                    
                    # Generate pattern
                    pattern = pattern_func(current_block)
                    
                    # Write pattern
                    f.seek(offset)
                    f.write(pattern)
                    f.flush()
                    os.fsync(f.fileno())
                    
                    offset += current_block
                
                # Verify if requested
                if self.verify:
                    f.seek(0)
                    verify_offset = 0
                    
                    while verify_offset < file_size:
                        remaining = file_size - verify_offset
                        current_block = min(self.block_size, remaining)
                        
                        expected = pattern_func(current_block)
                        actual = f.read(current_block)
                        
                        if actual != expected:
                            self.log(f"✗ Verification failed at offset {verify_offset}")
                            return False
                        
                        verify_offset += current_block
            
            return True
            
        except Exception as e:
            self.log(f"✗ Overwrite error: {e}")
            return False
    
    def shred_file_dod_3pass(self, file_path: Path) -> bool:
        """DoD 5220.22-M 3-pass method"""
        self.log("Using DoD 5220.22-M (3-pass) method")
        
        for i, pattern_func in enumerate(self.DOD_PATTERNS, 1):
            self.log(f"Pass {i}/3...")
            if not self.overwrite_pass(file_path, pattern_func, i):
                return False
        
        return True
    
    def shred_file_dod_7pass(self, file_path: Path) -> bool:
        """DoD 5220.22-M 7-pass method"""
        self.log("Using DoD 5220.22-M (7-pass) method")
        
        patterns = (
            self.DOD_PATTERNS * 2  # First 3 patterns twice
            + [lambda size: os.urandom(size)]  # Final random pass
        )
        
        for i, pattern_func in enumerate(patterns, 1):
            self.log(f"Pass {i}/7...")
            if not self.overwrite_pass(file_path, pattern_func, i):
                return False
        
        return True
    
    def shred_file_gutmann(self, file_path: Path) -> bool:
        """Gutmann 35-pass method"""
        self.log("Using Gutmann (35-pass) method")
        
        for i, pattern_func in enumerate(self.GUTMANN_PATTERNS, 1):
            self.log(f"Pass {i}/35...")
            if not self.overwrite_pass(file_path, pattern_func, i):
                return False
        
        return True
    
    def shred_file_random(self, file_path: Path, passes: int = 3) -> bool:
        """Random overwrite method"""
        self.log(f"Using random overwrite ({passes}-pass) method")
        
        for i in range(passes):
            self.log(f"Pass {i+1}/{passes}...")
            if not self.overwrite_pass(file_path, lambda size: os.urandom(size), i+1):
                return False
        
        return True
    
    def shred_file_zero(self, file_path: Path) -> bool:
        """Simple zero-fill method"""
        self.log("Using zero-fill method")
        
        return self.overwrite_pass(file_path, lambda size: bytes([0x00] * size), 1)
    
    def rename_file_random(self, file_path: Path) -> Path:
        """Rename file to random name to obscure original"""
        try:
            new_name = ''.join(random.choices('0123456789abcdef', k=16))
            new_path = file_path.parent / new_name
            
            file_path.rename(new_path)
            self.log(f"Renamed to: {new_name}")
            
            return new_path
        except Exception as e:
            self.log(f"Rename error: {e}")
            return file_path
    
    def truncate_file(self, file_path: Path) -> bool:
        """Truncate file to zero length"""
        try:
            with open(file_path, 'wb') as f:
                f.truncate(0)
            return True
        except Exception as e:
            self.log(f"Truncate error: {e}")
            return False
    
    def delete_file(self, file_path: Path) -> bool:
        """Delete file from filesystem"""
        try:
            file_path.unlink()
            self.log("File deleted from filesystem")
            return True
        except Exception as e:
            self.log(f"Delete error: {e}")
            return False
    
    def shred_file(self, file_path: str, method: str = 'dod3', 
                   rename: bool = True, delete: bool = True) -> bool:
        """
        Securely shred a file
        
        Args:
            file_path: Path to file to shred
            method: Shredding method (dod3, dod7, gutmann, random, zero)
            rename: Rename file before deletion
            delete: Delete file after shredding
        
        Returns:
            True if successful
        """
        path = Path(file_path)
        
        if not path.exists():
            print(f"✗ File not found: {file_path}")
            return False
        
        if not path.is_file():
            print(f"✗ Not a file: {file_path}")
            return False
        
        file_size = self.get_file_size(path)
        
        print(f"Shredding: {file_path}")
        print(f"Size: {file_size:,} bytes ({file_size / (1024**2):.2f} MB)")
        print(f"Method: {method}")
        
        start_time = time.time()
        
        # Perform shredding
        success = False
        
        if method == 'dod3':
            success = self.shred_file_dod_3pass(path)
        elif method == 'dod7':
            success = self.shred_file_dod_7pass(path)
        elif method == 'gutmann':
            success = self.shred_file_gutmann(path)
        elif method == 'random':
            success = self.shred_file_random(path, passes=7)
        elif method == 'zero':
            success = self.shred_file_zero(path)
        else:
            print(f"✗ Unknown method: {method}")
            return False
        
        if not success:
            print(f"✗ Shredding failed")
            return False
        
        # Rename file
        if rename:
            path = self.rename_file_random(path)
        
        # Truncate
        if not self.truncate_file(path):
            print(f"✗ Failed to truncate file")
        
        # Delete
        if delete:
            if not self.delete_file(path):
                print(f"✗ Failed to delete file")
                return False
        
        elapsed = time.time() - start_time
        print(f"✓ File shredded successfully in {elapsed:.2f}s")
        
        return True
    
    def shred_directory(self, dir_path: str, method: str = 'dod3',
                       recursive: bool = False) -> Tuple[int, int]:
        """
        Shred all files in a directory
        
        Returns:
            Tuple of (successful, failed) counts
        """
        path = Path(dir_path)
        
        if not path.exists() or not path.is_dir():
            print(f"✗ Directory not found: {dir_path}")
            return (0, 0)
        
        pattern = '**/*' if recursive else '*'
        files = [f for f in path.glob(pattern) if f.is_file()]
        
        print(f"Shredding {len(files)} files in: {dir_path}")
        
        successful = 0
        failed = 0
        
        for file_path in files:
            if self.shred_file(str(file_path), method=method):
                successful += 1
            else:
                failed += 1
        
        print(f"\n✓ Shredded {successful} files")
        if failed > 0:
            print(f"✗ Failed to shred {failed} files")
        
        return (successful, failed)

def main():
    parser = argparse.ArgumentParser(
        description='Secure File Shredder - Military-grade file deletion',
        epilog='WARNING: Shredded files CANNOT be recovered!'
    )
    
    parser.add_argument(
        'files',
        nargs='+',
        help='Files or directories to shred'
    )
    
    parser.add_argument(
        '--method', '-m',
        choices=['dod3', 'dod7', 'gutmann', 'random', 'zero'],
        default='dod3',
        help='Shredding method (default: dod3)'
    )
    
    parser.add_argument(
        '--no-verify',
        action='store_true',
        help='Skip verification pass'
    )
    
    parser.add_argument(
        '--no-rename',
        action='store_true',
        help='Do not rename file before deletion'
    )
    
    parser.add_argument(
        '--no-delete',
        action='store_true',
        help='Do not delete file after shredding'
    )
    
    parser.add_argument(
        '--recursive', '-r',
        action='store_true',
        help='Recursively shred directories'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Skip confirmation prompt'
    )
    
    args = parser.parse_args()
    
    # Warning and confirmation
    if not args.force:
        print("⚠  WARNING: This will PERMANENTLY DESTROY data!")
        print("⚠  Shredded files CANNOT be recovered!")
        print()
        response = input("Continue? (yes/no): ")
        if response.lower() != 'yes':
            print("Cancelled")
            return 0
        print()
    
    # Create shredder
    shredder = SecureShredder(
        verify=not args.no_verify,
        verbose=args.verbose
    )
    
    # Process each file/directory
    total_success = 0
    total_failed = 0
    
    for target in args.files:
        path = Path(target)
        
        if path.is_file():
            if shredder.shred_file(
                target,
                method=args.method,
                rename=not args.no_rename,
                delete=not args.no_delete
            ):
                total_success += 1
            else:
                total_failed += 1
        
        elif path.is_dir():
            success, failed = shredder.shred_directory(
                target,
                method=args.method,
                recursive=args.recursive
            )
            total_success += success
            total_failed += failed
        
        else:
            print(f"✗ Not found: {target}")
            total_failed += 1
        
        print()
    
    # Summary
    print("=" * 60)
    print(f"Shredding complete: {total_success} succeeded, {total_failed} failed")
    
    return 0 if total_failed == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
