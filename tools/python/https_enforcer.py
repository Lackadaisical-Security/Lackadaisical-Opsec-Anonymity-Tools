#!/usr/bin/env python3
"""
HTTPS Enforcer - Force HTTPS connections and detect downgrades
Part of Lackadaisical Anonymity Toolkit
"""

import sys
import argparse
import urllib.parse
import requests
from typing import List, Dict, Optional
import socket
import ssl
from datetime import datetime

class HTTPSEnforcer:
    """Enforce HTTPS connections and detect SSL/TLS issues"""
    
    def __init__(self, timeout: int = 5):
        self.timeout = timeout
        self.session = requests.Session()
        # Force HTTPS adapter
        self.session.mount('http://', requests.adapters.HTTPAdapter())
    
    def check_https_available(self, domain: str) -> Dict:
        """Check if HTTPS is available for a domain"""
        result = {
            'domain': domain,
            'https_available': False,
            'https_redirect': False,
            'http_works': False,
            'cert_valid': False,
            'hsts_enabled': False,
            'tls_version': None,
            'issues': []
        }
        
        # Test HTTP
        try:
            response = requests.get(
                f'http://{domain}',
                timeout=self.timeout,
                allow_redirects=True
            )
            result['http_works'] = True
            
            # Check if redirected to HTTPS
            if response.url.startswith('https://'):
                result['https_redirect'] = True
        except:
            result['issues'].append('HTTP connection failed')
        
        # Test HTTPS
        try:
            response = requests.get(
                f'https://{domain}',
                timeout=self.timeout,
                verify=True
            )
            result['https_available'] = True
            result['cert_valid'] = True
            
            # Check HSTS header
            if 'Strict-Transport-Security' in response.headers:
                result['hsts_enabled'] = True
                result['hsts_header'] = response.headers['Strict-Transport-Security']
            else:
                result['issues'].append('HSTS not enabled')
            
        except requests.exceptions.SSLError as e:
            result['https_available'] = True
            result['cert_valid'] = False
            result['issues'].append(f'SSL certificate invalid: {str(e)}')
        except:
            result['issues'].append('HTTPS connection failed')
        
        # Get TLS version
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    result['tls_version'] = ssock.version()
                    
                    # Check for weak protocols
                    if ssock.version() in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                        result['issues'].append(f'Weak TLS version: {ssock.version()}')
        except:
            pass
        
        return result
    
    def enforce_https_url(self, url: str) -> str:
        """Convert HTTP URL to HTTPS"""
        parsed = urllib.parse.urlparse(url)
        
        if parsed.scheme == 'http':
            # Replace http with https
            return url.replace('http://', 'https://', 1)
        
        return url
    
    def check_mixed_content(self, url: str) -> List[str]:
        """Check for mixed content (HTTP resources on HTTPS page)"""
        if not url.startswith('https://'):
            return []
        
        mixed_content = []
        
        try:
            response = requests.get(url, timeout=self.timeout)
            content = response.text.lower()
            
            # Look for http:// references (excluding https://)
            import re
            http_refs = re.findall(r'http://[^\s<>"\']+', content)
            
            for ref in set(http_refs):
                if not ref.startswith('http://localhost') and not ref.startswith('http://127.0.0.1'):
                    mixed_content.append(ref)
        except:
            pass
        
        return mixed_content
    
    def test_ssl_labs(self, domain: str) -> Optional[str]:
        """Get SSL Labs rating (if available)"""
        # This would require SSL Labs API - simplified version
        print(f"  SSL Labs: https://www.ssllabs.com/ssltest/analyze.html?d={domain}")
        return None
    
    def generate_report(self, results: List[Dict]) -> str:
        """Generate comprehensive HTTPS report"""
        report = []
        report.append("=" * 60)
        report.append("HTTPS ENFORCEMENT REPORT")
        report.append("=" * 60)
        report.append(f"Tested: {len(results)} domains")
        report.append(f"Timestamp: {datetime.now().isoformat()}")
        report.append("")
        
        for result in results:
            domain = result['domain']
            report.append(f"\n{domain}")
            report.append("-" * 60)
            
            # HTTPS availability
            if result['https_available']:
                report.append("  ✓ HTTPS available")
            else:
                report.append("  ✗ HTTPS NOT available")
            
            # Certificate validity
            if result['cert_valid']:
                report.append("  ✓ Certificate valid")
            else:
                report.append("  ✗ Certificate INVALID")
            
            # HTTP redirect
            if result['https_redirect']:
                report.append("  ✓ HTTP redirects to HTTPS")
            elif result['http_works']:
                report.append("  ✗ HTTP does NOT redirect to HTTPS")
            
            # HSTS
            if result['hsts_enabled']:
                report.append("  ✓ HSTS enabled")
            else:
                report.append("  ⚠ HSTS NOT enabled")
            
            # TLS version
            if result['tls_version']:
                if result['tls_version'] in ['TLSv1.2', 'TLSv1.3']:
                    report.append(f"  ✓ TLS version: {result['tls_version']}")
                else:
                    report.append(f"  ⚠ TLS version: {result['tls_version']} (outdated)")
            
            # Issues
            if result['issues']:
                report.append("\n  Issues:")
                for issue in result['issues']:
                    report.append(f"    - {issue}")
        
        report.append("\n" + "=" * 60)
        report.append("RECOMMENDATIONS")
        report.append("=" * 60)
        
        # Generate recommendations
        no_https = [r['domain'] for r in results if not r['https_available']]
        no_redirect = [r['domain'] for r in results if r['http_works'] and not r['https_redirect']]
        no_hsts = [r['domain'] for r in results if r['https_available'] and not r['hsts_enabled']]
        invalid_cert = [r['domain'] for r in results if not r['cert_valid']]
        
        if no_https:
            report.append(f"\n✗ {len(no_https)} domain(s) do not support HTTPS:")
            for domain in no_https[:5]:
                report.append(f"    - {domain}")
            report.append("  Recommendation: Enable HTTPS with valid certificate")
        
        if invalid_cert:
            report.append(f"\n✗ {len(invalid_cert)} domain(s) have invalid certificates:")
            for domain in invalid_cert[:5]:
                report.append(f"    - {domain}")
            report.append("  Recommendation: Renew/fix SSL certificates")
        
        if no_redirect:
            report.append(f"\n⚠ {len(no_redirect)} domain(s) don't redirect HTTP to HTTPS:")
            for domain in no_redirect[:5]:
                report.append(f"    - {domain}")
            report.append("  Recommendation: Configure HTTP->HTTPS redirect (301)")
        
        if no_hsts:
            report.append(f"\n⚠ {len(no_hsts)} domain(s) don't have HSTS enabled:")
            for domain in no_hsts[:5]:
                report.append(f"    - {domain}")
            report.append("  Recommendation: Add HSTS header")
            report.append("  Header: Strict-Transport-Security: max-age=31536000; includeSubDomains")
        
        report.append("\n" + "=" * 60)
        
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(
        description='HTTPS Enforcer - Detect and enforce HTTPS connections'
    )
    
    parser.add_argument(
        'domains',
        nargs='+',
        help='Domains to check'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=5,
        help='Connection timeout in seconds (default: 5)'
    )
    
    parser.add_argument(
        '--output', '-o',
        help='Save report to file'
    )
    
    parser.add_argument(
        '--enforce',
        action='store_true',
        help='Convert HTTP URLs to HTTPS'
    )
    
    parser.add_argument(
        '--check-mixed-content',
        action='store_true',
        help='Check for mixed content on HTTPS pages'
    )
    
    args = parser.parse_args()
    
    enforcer = HTTPSEnforcer(timeout=args.timeout)
    
    # Process domains
    results = []
    
    for domain in args.domains:
        # Remove protocol if provided
        domain = domain.replace('https://', '').replace('http://', '').split('/')[0]
        
        print(f"Checking {domain}...")
        result = enforcer.check_https_available(domain)
        results.append(result)
        
        # Check mixed content if requested
        if args.check_mixed_content and result['https_available']:
            mixed = enforcer.check_mixed_content(f'https://{domain}')
            if mixed:
                result['issues'].append(f'Mixed content detected: {len(mixed)} HTTP resources')
                print(f"  Found {len(mixed)} HTTP resources on HTTPS page")
    
    # Generate report
    report = enforcer.generate_report(results)
    print("\n" + report)
    
    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"\nReport saved to: {args.output}")
    
    # Return error code if issues found
    has_issues = any(r['issues'] for r in results)
    return 1 if has_issues else 0

if __name__ == '__main__':
    sys.exit(main())
