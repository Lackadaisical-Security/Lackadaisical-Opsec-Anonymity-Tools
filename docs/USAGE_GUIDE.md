# Lackadaisical Anonymity Toolkit - Usage Guide

## Table of Contents

1. [Getting Started](#getting-started)
2. [Core Modules](#core-modules)
3. [Network Anonymization](#network-anonymization)
4. [Identity Management](#identity-management)
5. [Data Security](#data-security)
6. [System Protection](#system-protection)
7. [Communication Security](#communication-security)
8. [Advanced Features](#advanced-features)
9. [Troubleshooting](#troubleshooting)

## Getting Started

### Installation

```bash
# Clone repository
git clone https://github.com/lackadaisical-security/anonymity-toolkit
cd anonymity-toolkit

# Install with deployment script
sudo ./scripts/deploy.sh install

# Or manual installation
pip3 install -r requirements.txt
./scripts/setup.sh
```

### Basic Commands

```bash
# List all modules
lackadaisical --list

# Get help for specific module
lackadaisical <module> --help

# Check system privacy status
lackadaisical privacy-check

# Apply full anonymization
sudo lackadaisical anonymize --full
```

## Core Modules

### Tor Controller

Control and monitor Tor connections:

```bash
# Start Tor with specific exit country
lackadaisical tor-control --exit-country CH,IS

# Get new identity
lackadaisical tor-control --new-identity

# Monitor Tor status
lackadaisical tor-control --monitor

# Use bridges
lackadaisical tor-control --bridges --bridge-file bridges.txt
```

### DNS Privacy

Secure DNS resolution:

```bash
# Configure DNS-over-HTTPS
lackadaisical dns-over-https --provider cloudflare

# Test DNS privacy
lackadaisical dns-over-https --test

# Use custom DoH server
lackadaisical dns-over-https --server https://dns.example.com/dns-query
```

## Network Anonymization

### Complete Network Anonymization

```bash
# Standard anonymization
sudo lackadaisical anonymize --full

# Paranoid mode (maximum security)
sudo lackadaisical anonymize --paranoid

# Monitor anonymization status
lackadaisical anonymize --monitor

# Custom configuration
sudo lackadaisical anonymize --tor --vpn protonvpn --proxy
```

### MAC Address Spoofing

```bash
# Randomize all interfaces
sudo lackadaisical mac-spoof --all

# Specific interface
sudo lackadaisical mac-spoof --interface wlan0

# Custom MAC
sudo lackadaisical mac-spoof --interface eth0 --mac 00:11:22:33:44:55

# Restore original
sudo lackadaisical mac-spoof --restore
```

### Traffic Obfuscation

```bash
# Start obfuscated tunnel
lackadaisical traffic-obfuscate --mode https --port 443

# Use meek transport
lackadaisical traffic-obfuscate --mode meek --front www.google.com

# Custom obfuscation
lackadaisical traffic-obfuscate --mode custom --config obfs.conf
```

## Identity Management

### Pseudonym Generation

```bash
# Generate single identity
lackadaisical pseudonym

# Generate with specific locale
lackadaisical pseudonym --locale de

# Generate multiple identities
lackadaisical pseudonym --count 5 --output identities.json

# Full persona with backstory
lackadaisical pseudonym --full --with-backstory
```

### Credential Management

```bash
# Store credentials securely
lackadaisical cred-manager store --name "persona1"

# Retrieve credentials
lackadaisical cred-manager get --name "persona1"

# List all personas
lackadaisical cred-manager list

# Switch persona
lackadaisical cred-manager switch --name "persona2"
```

### Browser Fingerprinting

```bash
# Spoof browser fingerprint
lackadaisical browser-spoof --profile firefox

# Random fingerprint
lackadaisical browser-spoof --random

# Custom user agent
lackadaisical browser-spoof --user-agent "Mozilla/5.0..."

# Test fingerprint
lackadaisical browser-spoof --test
```

## Data Security

### Metadata Removal

```bash
# Clean single file
lackadaisical metadata-clean image.jpg

# Batch processing
lackadaisical metadata-clean *.jpg --recursive

# Verify cleaning
lackadaisical metadata-clean --verify image.jpg

# Preserve timestamps
lackadaisical metadata-clean image.jpg --preserve-dates
```

### Secure Deletion

```bash
# Delete file securely
lackadaisical secure-delete sensitive.txt

# Delete directory
lackadaisical secure-delete -r sensitive_folder/

# Custom passes
lackadaisical secure-delete --passes 10 file.txt

# Verify deletion
lackadaisical secure-delete --verify file.txt
```

### File Encryption

```bash
# Encrypt file
lackadaisical encrypt file.txt

# Decrypt file
lackadaisical decrypt file.txt.enc

# Encrypt directory
lackadaisical encrypt -r folder/

# Use specific algorithm
lackadaisical encrypt --algorithm aes256 file.txt
```

### Steganography

```bash
# Hide data in image
lackadaisical stego hide --cover image.jpg --data secret.txt --output stego.jpg

# Extract hidden data
lackadaisical stego extract --image stego.jpg

# Hide in audio
lackadaisical stego hide --cover audio.mp3 --data secret.txt

# Advanced hiding
lackadaisical stego hide --cover video.mp4 --data file.zip --method lsb
```

## System Protection

### Process Hiding

```bash
# Hide current process
sudo lackadaisical process-hide --pid $$

# Hide by name
sudo lackadaisical process-hide --name myapp

# Unhide process
sudo lackadaisical process-hide --unhide --pid 1234

# List hidden processes
sudo lackadaisical process-hide --list
```

### Anti-Forensics

```bash
# Full anti-forensics suite
sudo lackadaisical anti-forensics --full

# Timestamp manipulation
lackadaisical anti-forensics --timestamps file.txt --date "2020-01-01"

# Clear system artifacts
sudo lackadaisical anti-forensics --clear-artifacts

# Memory wiping
sudo lackadaisical anti-forensics --wipe-memory
```

### Activity Monitoring

```bash
# Start monitoring
lackadaisical activity-monitor

# Set alert level
lackadaisical activity-monitor --alert-level high

# Monitor specific paths
lackadaisical activity-monitor --watch /home/user/sensitive

# Export alerts
lackadaisical activity-monitor --export alerts.json
```

### Filesystem Monitor

```bash
# Add path to monitoring
lackadaisical fs-monitor --add /path/to/monitor

# Check integrity
lackadaisical fs-monitor --check

# Real-time monitoring
lackadaisical fs-monitor --realtime

# Generate report
lackadaisical fs-monitor --report
```

## Communication Security

### Encrypted Messaging

```bash
# Start messenger
lackadaisical secure-messenger myusername --listen

# Add contact
lackadaisical secure-messenger myusername add-contact friend their_public_key

# Send message
lackadaisical secure-messenger myusername send friend "Hello"

# Create group
lackadaisical secure-messenger myusername create-group team alice bob charlie
```

### Anonymous Email

```bash
# Create temporary email
lackadaisical anon-email create

# Check inbox
lackadaisical anon-email check --address temp123@example.com

# Send anonymous email
lackadaisical anon-email send --to target@example.com --subject "Test"

# Use with Tor
lackadaisical anon-email create --use-tor
```

### Covert Channels

```bash
# DNS tunneling
lackadaisical covert-channel dns --data "secret message" --domain example.com

# HTTP headers
lackadaisical covert-channel http --data "secret" --target 192.168.1.1

# Timing channel
lackadaisical covert-channel timing --data "secret" --delay 100

# Image steganography channel
lackadaisical covert-channel image --data file.txt --cover image.jpg
```

## Advanced Features

### Network Scanning

```bash
# Stealthy scan
lackadaisical network-scan --stealth 192.168.1.0/24

# Service detection
lackadaisical network-scan --services 192.168.1.1

# OS fingerprinting
lackadaisical network-scan --os-detect 192.168.1.1

# Custom timing
lackadaisical network-scan --timing paranoid 192.168.1.0/24
```

### Traffic Analysis

```bash
# Capture and analyze
sudo lackadaisical traffic-analyze --interface eth0

# Detect surveillance
sudo lackadaisical traffic-analyze --detect-surveillance

# Export pcap
sudo lackadaisical traffic-analyze --export traffic.pcap

# Real-time analysis
sudo lackadaisical traffic-analyze --realtime
```

### Digital Footprint Analysis

```bash
# Full analysis
lackadaisical footprint-analyze

# Specific category
lackadaisical footprint-analyze --category browsers

# Generate report
lackadaisical footprint-analyze --report footprint.html

# Continuous monitoring
lackadaisical footprint-analyze --monitor
```

### Memory Analysis

```bash
# Scan current process
lackadaisical memory-analyze --pid $$

# Scan all processes
sudo lackadaisical memory-analyze --all

# Detect injection
sudo lackadaisical memory-analyze --detect-injection

# Find hidden processes
sudo lackadaisical memory-analyze --find-hidden
```

### Counter-Surveillance

```bash
# Full sweep
sudo lackadaisical counter-surveillance --full

# Check for cameras
lackadaisical counter-surveillance --cameras

# RF detection
lackadaisical counter-surveillance --rf-scan

# Network monitoring detection
lackadaisical counter-surveillance --network
```

## Privacy Profiles

### Creating Profiles

```bash
# Create new profile
lackadaisical profile create --name journalist

# Import profile
lackadaisical profile import --file profile.json

# Export profile
lackadaisical profile export --name journalist --output journalist.json
```

### Using Profiles

```bash
# Activate profile
lackadaisical profile activate --name journalist

# Switch profiles
lackadaisical profile switch --from personal --to work

# List profiles
lackadaisical profile list

# Delete profile
lackadaisical profile delete --name old_profile
```

## Automation

### Scheduled Tasks

```bash
# Schedule privacy checks
lackadaisical schedule --task privacy-check --interval daily

# Auto-cleanup
lackadaisical schedule --task cleanup --time "02:00"

# Random MAC changes
lackadaisical schedule --task mac-randomize --interval 4h
```

### Scripts and Hooks

```bash
# Run custom script
lackadaisical run-script cleanup.sh

# Set pre-connect hook
lackadaisical hooks set --event pre-connect --script prepare.sh

# Set post-disconnect hook
lackadaisical hooks set --event post-disconnect --script cleanup.sh
```

## Emergency Procedures

### Quick Anonymization

```bash
# Emergency mode
sudo lackadaisical emergency --anonymize

# Panic button
sudo lackadaisical panic

# Quick cleanup
sudo lackadaisical emergency --cleanup

# Destroy traces
sudo lackadaisical emergency --destroy
```

### Data Protection

```bash
# Emergency encryption
lackadaisical emergency --encrypt-all /home/user

# Secure wipe
sudo lackadaisical emergency --wipe /sensitive

# Hidden volume
lackadaisical emergency --hide-volume /secret
```

## Troubleshooting

### Common Issues

#### Tor Connection Failed
```bash
# Check Tor status
systemctl status tor

# Reset Tor
sudo systemctl restart tor

# Use bridges
lackadaisical tor-control --bridges
```

#### VPN Not Connecting
```bash
# Check logs
lackadaisical logs --module vpn

# Try different server
lackadaisical anonymize --vpn-server ch-01

# Fallback mode
lackadaisical anonymize --fallback
```

#### Permission Denied
```bash
# Run with sudo for system operations
sudo lackadaisical <command>

# Check permissions
lackadaisical check-permissions

# Fix permissions
sudo lackadaisical fix-permissions
```

### Diagnostics

```bash
# Full system diagnostic
lackadaisical diagnose

# Network diagnostic
lackadaisical diagnose --network

# Module diagnostic
lackadaisical diagnose --module tor-control

# Generate diagnostic report
lackadaisical diagnose --report diag.txt
```

### Getting Help

```bash
# General help
lackadaisical --help

# Module help
lackadaisical <module> --help

# Online documentation
lackadaisical docs

# Community support
lackadaisical support
```

## Best Practices

1. **Always verify anonymization**
   ```bash
   lackadaisical verify-anonymity
   ```

2. **Regular security audits**
   ```bash
   lackadaisical audit --full
   ```

3. **Keep toolkit updated**
   ```bash
   sudo ./scripts/deploy.sh update
   ```

4. **Use profiles for different activities**
   ```bash
   lackadaisical profile activate --name <activity>
   ```

5. **Monitor for leaks**
   ```bash
   lackadaisical monitor-leaks
   ```

Remember: No tool provides perfect anonymity. Always use multiple layers of protection and stay informed about current threats.
