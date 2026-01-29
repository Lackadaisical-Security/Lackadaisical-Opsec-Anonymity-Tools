```python
import unittest
import os
import tempfile
from core.secure_delete import secure_delete_file
from core.identity import PseudonymGenerator
from modules.tor_controller import TestTorController
from modules.doh_client import TestDoHClient
from modules.secure_delete import TestSecureDelete
from modules.identity import TestPseudonymGenerator
from modules.activity_monitor import TestActivityMonitor
from modules.anti_forensics import TestAntiForensics
from integration_tests import TestIntegration

class TestSecurity(unittest.TestCase):
    """Security-specific tests"""
    
    def test_no_hardcoded_credentials(self):
        """Ensure no hardcoded credentials in source"""
        # Scan all Python files for potential credentials
        root_dir = Path(__file__).parent.parent
        
        suspicious_patterns = [
            r'password\s*=\s*["\'][^"\']+["\']',
            r'api_key\s*=\s*["\'][^"\']+["\']',
            r'secret\s*=\s*["\'][^"\']+["\']',
            r'token\s*=\s*["\'][^"\']+["\']'
        ]
        
        violations = []
        
        for py_file in root_dir.rglob('*.py'):
            if 'test' in str(py_file):
                continue
                
            with open(py_file, 'r') as f:
                content = f.read()
                
            for pattern in suspicious_patterns:
                import re
                if re.search(pattern, content, re.IGNORECASE):
                    violations.append(str(py_file))
        
        self.assertEqual(len(violations), 0, 
                        f"Potential hardcoded credentials in: {violations}")
    
    def test_secure_random(self):
        """Test secure random generation"""
        import secrets
        
        # Test randomness quality
        random_bytes = secrets.token_bytes(32)
        self.assertEqual(len(random_bytes), 32, "Random generation failed")
        
        # Ensure different values
        random_bytes2 = secrets.token_bytes(32)
        self.assertNotEqual(random_bytes, random_bytes2, 
                           "Random generation not random")

class TestPerformance(unittest.TestCase):
    """Performance tests"""
    
    def test_secure_delete_performance(self):
        """Test secure deletion performance"""
        import time
        
        # Create 1MB test file
        test_file = tempfile.mktemp()
        with open(test_file, 'wb') as f:
            f.write(os.urandom(1024 * 1024))  # 1MB
        
        start_time = time.time()
        secure_delete_file(test_file, passes=3)
        elapsed_time = time.time() - start_time
        
        # Should complete within reasonable time (10 seconds for 1MB)
        self.assertLess(elapsed_time, 10, 
                       f"Secure delete too slow: {elapsed_time:.2f}s")
    
    def test_identity_generation_performance(self):
        """Test identity generation performance"""
        import time
        
        generator = PseudonymGenerator()
        
        start_time = time.time()
        identities = [generator.generate_identity() for _ in range(100)]
        elapsed_time = time.time() - start_time
        
        # Should generate 100 identities in under 1 second
        self.assertLess(elapsed_time, 1, 
                       f"Identity generation too slow: {elapsed_time:.2f}s")

def run_tests():
    """Run all tests with detailed output"""
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestTorController,
        TestDoHClient,
        TestSecureDelete,
        TestPseudonymGenerator,
        TestActivityMonitor,
        TestAntiForensics,
        TestIntegration,
        TestSecurity,
        TestPerformance
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return success/failure
    return result.wasSuccessful()

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Run Lackadaisical Toolkit Tests')
    parser.add_argument('--module', help='Test specific module only')
    parser.add_argument('--integration', action='store_true', 
                       help='Run integration tests only')
    parser.add_argument('--security', action='store_true',
                       help='Run security tests only')
    
    args = parser.parse_args()
    
    if args.module:
        # Run specific module tests
        module_test = f'Test{args.module.title()}'
        if module_test in globals():
            suite = unittest.TestLoader().loadTestsFromTestCase(globals()[module_test])
            runner = unittest.TextTestRunner(verbosity=2)
            runner.run(suite)
        else:
            print(f"Test class {module_test} not found")
    elif args.integration:
        suite = unittest.TestLoader().loadTestsFromTestCase(TestIntegration)
        runner = unittest.TextTestRunner(verbosity=2)
        runner.run(suite)
    elif args.security:
        suite = unittest.TestLoader().loadTestsFromTestCase(TestSecurity)
        runner = unittest.TextTestRunner(verbosity=2)
        runner.run(suite)
    else:
        # Run all tests
        success = run_tests()
        sys.exit(0 if success else 1)
```