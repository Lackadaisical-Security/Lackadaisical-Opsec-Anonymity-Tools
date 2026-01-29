# Lackadaisical Anonymity Toolkit - API Reference

## Overview

The Lackadaisical Anonymity Toolkit provides both command-line interfaces and programmable APIs for all modules. This document covers the Python API, but similar APIs exist for other supported languages.

## Table of Contents

1. [Core API](#core-api)
2. [Network Module](#network-module)
3. [Identity Module](#identity-module)
4. [Data Security Module](#data-security-module)
5. [System Protection Module](#system-protection-module)
6. [Communication Module](#communication-module)
7. [Forensics Module](#forensics-module)
8. [OPSEC Module](#opsec-module)

## Core API

### Installation

```python
from lackadaisical import core

# Initialize toolkit
toolkit = core.LackadaisicalToolkit()

# Check version
print(toolkit.version)

# Get available modules
modules = toolkit.list_modules()
```

### Configuration

```python
# Load configuration
config = core.Config.load('/etc/lackadaisical/config.json')

# Modify settings
config.set('network.proxy_chains', True)
config.set('privacy.paranoid_mode', True)

# Save configuration
config.save()
```

### Logging

```python
from lackadaisical.core import Logger

# Initialize logger
logger = Logger('my_module', level='DEBUG')

# Log messages
logger.info('Starting anonymization')
logger.warning('Potential leak detected')
logger.error('Connection failed')
```

## Network Module

### Tor Controller

```python
from lackadaisical.modules.network import TorController

# Initialize controller
tor = TorController()

# Connect to Tor
tor.connect(control_port=9051, password='mypassword')

# Get current IP
current_ip = tor.get_ip()
print(f"Current Tor IP: {current_ip}")

# Get new identity
tor.new_identity()

# Get circuit info
circuit = tor.get_circuit_info()
print(f"Circuit: {' -> '.join(circuit)}")

# Configure exit nodes
tor.set_exit_nodes(['CH', 'IS', 'RO'])

# Use bridges
tor.use_bridges([
    'obfs4 1.2.3.4:443 FINGERPRINT cert=CERT iat-mode=0'
])

# Monitor bandwidth
tor.monitor_bandwidth(callback=lambda bw: print(f"Bandwidth: {bw}"))

# Close connection
tor.close()
```

### DNS over HTTPS

```python
from lackadaisical.modules.network import DoHClient

# Initialize DoH client
doh = DoHClient(provider='cloudflare')

# Resolve domain
ips = doh.resolve('example.com', record_type='A')
print(f"IPs: {ips}")

# Use custom server
doh_custom = DoHClient(server='https://dns.example.com/dns-query')

# Resolve with Tor
doh_tor = DoHClient(use_tor=True)
ips = doh_tor.resolve('example.com')

# Batch resolution
domains = ['example.com', 'test.com', 'demo.com']
results = doh.resolve_batch(domains)
```

### Network Anonymizer

```python
from lackadaisical.modules.network import NetworkAnonymizer

# Initialize anonymizer
anon = NetworkAnonymizer()

# Apply full anonymization
anon.apply_full_anonymity(paranoid=True)

# Individual components
anon.randomize_mac_address('wlan0')
anon.change_hostname(random=True)
anon.setup_dns_privacy(method='dnscrypt')
anon.setup_tor(bridges=True, exit_countries=['CH', 'IS'])
anon.setup_vpn(provider='protonvpn', server='ch-01')

# Monitor status
status = anon.get_status()
print(f"Active layers: {status['active_layers']}")
print(f"Current IP: {status['current_ip']}")

# Restore original settings
anon.restore_original_settings()
```

## Identity Module

### Pseudonym Generator

```python
from lackadaisical.modules.identity import PseudonymGenerator

# Initialize generator
gen = PseudonymGenerator(locale='en')

# Generate basic identity
identity = gen.generate_identity()
print(f"Name: {identity['name']}")
print(f"Email: {identity['email']}")
print(f"Phone: {identity['phone']}")

# Generate full persona
persona = gen.generate_full_persona(
    include_backstory=True,
    include_social_media=True,
    include_financial=True
)

# Generate consistent identity
seed = "my_secret_seed"
consistent_identity = gen.generate_identity(seed=seed)

# Batch generation
identities = gen.generate_batch(count=10)

# Export to file
gen.export_identity(identity, 'persona.json', encrypt=True)
```

### Biometric Spoofer

```python
from lackadaisical.modules.identity import BiometricSpoofer

# Initialize spoofer
spoofer = BiometricSpoofer()

# Generate fingerprint
fingerprint = spoofer.generate_fingerprint(
    pattern_type='whorl',
    quality='high'
)
fingerprint.save('fake_fingerprint.png')

# Generate face
face = spoofer.generate_face(
    age=30,
    gender='female',
    ethnicity='asian'
)
face.save('fake_face.jpg')

# Voice synthesis
voice = spoofer.synthesize_voice(
    text="Hello, this is a test",
    voice_profile='adult_male'
)
voice.save('fake_voice.wav')

# Handwriting
handwriting = spoofer.generate_handwriting(
    text="Sample signature",
    style='cursive'
)
handwriting.save('fake_signature.png')
```

## Data Security Module

### Secure Delete

```python
from lackadaisical.modules.data import SecureDelete

# Initialize
shredder = SecureDelete()

# Delete file
shredder.delete_file('/path/to/file', passes=7)

# Delete directory
shredder.delete_directory('/path/to/dir', recursive=True)

# Wipe free space
shredder.wipe_free_space('/dev/sda1')

# Verify deletion
is_deleted = shredder.verify_deletion('/path/to/file')
```

### Metadata Cleaner

```python
from lackadaisical.modules.data import MetadataCleaner

# Initialize cleaner
cleaner = MetadataCleaner()

# Clean single file
cleaner.clean_file('photo.jpg', preserve_dates=False)

# Batch cleaning
cleaner.clean_directory('/photos', recursive=True, file_types=['.jpg', '.png'])

# Get metadata
metadata = cleaner.extract_metadata('document.pdf')
print(f"Metadata: {metadata}")

# Verify cleaning
is_clean = cleaner.verify_clean('photo.jpg')
```

### Encryption

```python
from lackadaisical.modules.data import Encryption

# Initialize encryption
crypto = Encryption()

# Encrypt file
crypto.encrypt_file('document.txt', password='mysecret')

# Decrypt file
crypto.decrypt_file('document.txt.enc', password='mysecret')

# Encrypt directory
crypto.encrypt_directory('/sensitive', password='mysecret')

# Use key file
crypto.generate_keyfile('mykey.key')
crypto.encrypt_file('data.txt', keyfile='mykey.key')

# Secure communication
public_key, private_key = crypto.generate_keypair()
encrypted = crypto.encrypt_asymmetric(data, public_key)
decrypted = crypto.decrypt_asymmetric(encrypted, private_key)
```

## System Protection Module

### Process Hider

```python
from lackadaisical.modules.system import ProcessHider

# Initialize (requires root)
hider = ProcessHider()

# Hide process by PID
hider.hide_process(1234)

# Hide by name
hider.hide_by_name('myapp')

# Hide current process
hider.hide_current()

# List hidden processes
hidden = hider.list_hidden()

# Unhide process
hider.unhide_process(1234)
```

### Anti-Forensics

```python
from lackadaisical.modules.system import AntiForensics

# Initialize
af = AntiForensics()

# Timestamp manipulation
af.change_timestamps(
    '/path/to/file',
    accessed='2020-01-01 12:00:00',
    modified='2020-01-01 12:00:00',
    created='2020-01-01 12:00:00'
)

# Clear system artifacts
af.clear_artifacts(
    clear_logs=True,
    clear_history=True,
    clear_temp=True,
    clear_cache=True
)

# Wipe memory
af.wipe_memory(passes=3)

# Defeat forensic tools
af.anti_forensic_measures(
    disable_hibernation=True,
    disable_crash_dumps=True,
    disable_prefetch=True
)
```

## Communication Module

### Secure Messenger

```python
from lackadaisical.modules.communication import SecureMessenger

# Initialize messenger
messenger = SecureMessenger('myusername')

# Get public key
pub_key = messenger.get_public_key_string()

# Add contact
messenger.add_contact('friend', 'their_public_key_base64')

# Send message
messenger.send_message('friend', 'Hello, secure world!', 
                      host='192.168.1.100', port=8888)

# Start server
messenger.start_server(port=8888)

# Create group
messenger.create_group('team', ['alice', 'bob', 'charlie'])

# Send to group
messenger.send_group_message('team', 'Team meeting at 3pm')
```

### Anonymous Email

```python
from lackadaisical.modules.communication import AnonymousEmail

# Initialize
anon_email = AnonymousEmail(use_tor=True)

# Create temporary email
temp_email = anon_email.create_temporary()
print(f"Temporary email: {temp_email['address']}")

# Check inbox
messages = anon_email.check_inbox(temp_email['address'])

# Send anonymous email
anon_email.send(
    to='recipient@example.com',
    subject='Anonymous Message',
    body='This is an anonymous message',
    attachments=['file.pdf']
)

# Use guerrilla mail
gm = AnonymousEmail(provider='guerrilla')
email = gm.create_temporary(custom_name='myalias')
```

## Forensics Module

### Memory Analyzer

```python
from lackadaisical.modules.forensics import MemoryAnalyzer

# Initialize analyzer
analyzer = MemoryAnalyzer()

# Scan process memory
findings = analyzer.scan_process_memory(pid=1234)
print(f"URLs found: {findings['urls']}")
print(f"Passwords found: {len(findings['passwords'])}")

# Detect injection
injections = analyzer.detect_injection()
for inj in injections:
    print(f"Injection detected: {inj['type']} in PID {inj['pid']}")

# Find hidden processes
hidden = analyzer.find_hidden_processes()

# Extract strings
strings = analyzer.extract_strings(pid=1234, min_length=8)

# Generate report
report = analyzer.generate_memory_report()
```

### Filesystem Monitor

```python
from lackadaisical.modules.forensics import FilesystemMonitor

# Initialize monitor
monitor = FilesystemMonitor()

# Add paths to monitor
monitor.add_monitored_path('/home/user/documents', recursive=True)
monitor.add_monitored_path('/etc/passwd', recursive=False)

# Check integrity
violations = monitor.check_integrity()
for v in violations:
    print(f"{v['type']}: {v['path']} - {v['message']}")

# Real-time monitoring
monitor.monitor_realtime()  # Blocks until Ctrl+C

# Detect surveillance
indicators = monitor.detect_surveillance_indicators()

# Get alerts
alerts = monitor.get_alerts(severity='HIGH')

# Generate report
report = monitor.generate_report()
```

## OPSEC Module

### Activity Monitor

```python
from lackadaisical.modules.opsec import ActivityMonitor

# Initialize monitor
monitor = ActivityMonitor()

# Start monitoring
monitor.start()

# Set alert callback
def alert_handler(alert):
    print(f"ALERT: {alert['type']} - {alert['message']}")

monitor.set_alert_handler(alert_handler)

# Configure monitoring
monitor.configure(
    network_monitoring=True,
    process_monitoring=True,
    file_monitoring=True,
    threshold='medium'
)

# Get statistics
stats = monitor.get_statistics()
print(f"Alerts triggered: {stats['alerts_count']}")

# Export alerts
monitor.export_alerts('alerts.json')

# Stop monitoring
monitor.stop()
```

### Digital Footprint Analyzer

```python
from lackadaisical.modules.opsec import DigitalFootprintAnalyzer

# Initialize analyzer
analyzer = DigitalFootprintAnalyzer()

# Analyze all
results = analyzer.analyze_all()
print(f"Risk score: {results['risk_score']}/100")

# Analyze specific category
browser_findings = analyzer.analyze_browsers()
for finding in browser_findings:
    print(f"{finding['browser']}: {finding['risk_level']}")

# Get recommendations
recommendations = analyzer.get_recommendations()
for rec in recommendations:
    print(f"- {rec['action']}: {rec['description']}")

# Generate report
report = analyzer.generate_report(results)
with open('footprint_report.html', 'w') as f:
    f.write(report)

# Continuous monitoring
analyzer.monitor_footprint(interval=3600)  # Check every hour
```

## Advanced Usage

### Custom Modules

```python
from lackadaisical.core import BaseModule

class MyCustomModule(BaseModule):
    """Custom anonymity module"""
    
    def __init__(self):
        super().__init__('my_module')
        
    def anonymize_data(self, data):
        # Custom anonymization logic
        return self._apply_transformations(data)
    
    def verify_anonymity(self, data):
        # Verification logic
        return True

# Register module
toolkit = core.LackadaisicalToolkit()
toolkit.register_module(MyCustomModule())
```

### Event Handling

```python
from lackadaisical.core import EventBus

# Subscribe to events
bus = EventBus()

@bus.on('anonymization.started')
def on_anonymization_start(event):
    print(f"Anonymization started: {event.data}")

@bus.on('security.alert')
def on_security_alert(event):
    print(f"SECURITY ALERT: {event.data['message']}")
    # Take action...

# Emit custom events
bus.emit('custom.event', {'data': 'value'})
```

### Batch Operations

```python
from lackadaisical import batch

# Batch file operations
batch.clean_metadata('/photos/*.jpg')
batch.encrypt_files('/documents/*.pdf', password='secret')
batch.secure_delete('/temp/*', passes=7)

# Batch identity generation
identities = batch.generate_identities(
    count=100,
    locale='en',
    export_format='csv',
    output='identities.csv'
)
```

### Integration Examples

```python
# Flask integration
from flask import Flask
from lackadaisical.integrations import FlaskAnonymizer

app = Flask(__name__)
anonymizer = FlaskAnonymizer(app)

@app.route('/api/data')
@anonymizer.anonymize_response
def get_data():
    return {'sensitive': 'data'}

# Django integration
from lackadaisical.integrations.django import AnonymityMiddleware

MIDDLEWARE = [
    'lackadaisical.integrations.django.AnonymityMiddleware',
    # ... other middleware
]

# Requests integration
import requests
from lackadaisical.integrations import AnonymousSession

session = AnonymousSession()
response = session.get('https://example.com')
```

## Error Handling

```python
from lackadaisical.exceptions import (
    TorConnectionError,
    AnonymizationError,
    PrivacyLeakError
)

try:
    tor.connect()
except TorConnectionError as e:
    print(f"Failed to connect to Tor: {e}")
    # Fallback logic

try:
    anon.apply_full_anonymity()
except AnonymizationError as e:
    print(f"Anonymization failed: {e}")
    # Restore original settings
    anon.restore_original_settings()

try:
    # Risky operation
    pass
except PrivacyLeakError as e:
    print(f"PRIVACY LEAK DETECTED: {e}")
    # Emergency shutdown
    toolkit.panic()
```

## Testing

```python
from lackadaisical.testing import TestSuite

# Run all tests
suite = TestSuite()
results = suite.run_all()

# Test specific module
results = suite.test_module('network.tor_controller')

# Privacy leak testing
from lackadaisical.testing import LeakTest

leak_test = LeakTest()
leak_test.test_dns_leaks()
leak_test.test_webrtc_leaks()
leak_test.test_ip_leaks()

# Performance testing
from lackadaisical.testing import PerformanceTest

perf = PerformanceTest()
perf.benchmark_encryption()
perf.benchmark_anonymization()
```

## Best Practices

1. **Always handle errors gracefully**
2. **Use context managers for resource cleanup**
3. **Implement proper logging**
4. **Validate all inputs**
5. **Use type hints for better code clarity**
6. **Follow the principle of least privilege**
7. **Regularly update dependencies**
8. **Test your implementation thoroughly**

For more examples and advanced usage, see the `/examples` directory in the repository.
