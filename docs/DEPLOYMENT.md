# Lackadaisical Anonymity Toolkit - Deployment Guide

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation Methods](#installation-methods)
3. [Platform-Specific Instructions](#platform-specific-instructions)
4. [Configuration](#configuration)
5. [Security Hardening](#security-hardening)
6. [Troubleshooting](#troubleshooting)
7. [Updating](#updating)
8. [Uninstallation](#uninstallation)

## System Requirements

### Minimum Requirements

- **CPU**: 2+ cores (4+ recommended)
- **RAM**: 4GB (8GB+ recommended)
- **Storage**: 2GB free space
- **Network**: Broadband internet connection

### Operating Systems

- **Linux**: Ubuntu 20.04+, Debian 10+, Fedora 32+, Arch
- **Windows**: Windows 10 version 1909+ (WSL2 recommended)
- **macOS**: 10.15 Catalina+
- **BSD**: FreeBSD 12+, OpenBSD 6.8+

### Dependencies

Required software:
- Python 3.8+
- Git
- GCC/Clang
- Make
- OpenSSL
- Tor

Optional software:
- Go 1.16+
- Ruby 2.7+
- Node.js 14+
- Rust 1.50+
- Docker

## Installation Methods

### Quick Install (Recommended)

```bash
# Download and run installer
curl -sSL https://lackadaisical-security.com/install.sh | bash

# Or with wget
wget -qO- https://lackadaisical-security.com/install.sh | bash
```

### Git Installation

```bash
# Clone repository
git clone https://github.com/lackadaisical-security/anonymity-toolkit
cd anonymity-toolkit

# Run deployment script
sudo ./scripts/deploy.sh install
```

### Docker Installation

```bash
# Pull official image
docker pull lackadaisical/anonymity-toolkit:latest

# Run container
docker run -it --rm \
  --name lackadaisical \
  --cap-add=NET_ADMIN \
  --device /dev/net/tun \
  lackadaisical/anonymity-toolkit:latest
```

### Manual Installation

```bash
# Install system dependencies
sudo apt update && sudo apt install -y \
  python3 python3-pip python3-venv \
  git build-essential tor \
  golang ruby nodejs npm

# Clone and setup
git clone https://github.com/lackadaisical-security/anonymity-toolkit
cd anonymity-toolkit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Build native components
make all

# Install system-wide
sudo make install
```

## Platform-Specific Instructions

### Linux

#### Debian/Ubuntu

```bash
# Add repository
sudo add-apt-repository ppa:lackadaisical/toolkit
sudo apt update

# Install
sudo apt install lackadaisical-toolkit

# Enable services
sudo systemctl enable lackadaisical-monitor
sudo systemctl start lackadaisical-monitor
```

#### Fedora/RHEL

```bash
# Add repository
sudo dnf config-manager --add-repo https://lackadaisical-security.com/fedora/lackadaisical.repo

# Install
sudo dnf install lackadaisical-toolkit

# SELinux configuration
sudo setsebool -P lackadaisical_use_tor on
```

#### Arch Linux

```bash
# Install from AUR
yay -S lackadaisical-toolkit

# Or with makepkg
git clone https://aur.archlinux.org/lackadaisical-toolkit.git
cd lackadaisical-toolkit
makepkg -si
```

### Windows

#### WSL2 (Recommended)

```powershell
# Enable WSL2
wsl --install

# Install Ubuntu
wsl --install -d Ubuntu

# In WSL2 terminal, follow Linux instructions
```

#### Native Windows

```powershell
# Install with Chocolatey
choco install lackadaisical-toolkit

# Or download installer
Invoke-WebRequest -Uri "https://lackadaisical-security.com/windows/installer.exe" -OutFile "installer.exe"
.\installer.exe
```

### macOS

```bash
# Install with Homebrew
brew tap lackadaisical/toolkit
brew install lackadaisical-toolkit

# Start services
brew services start lackadaisical-monitor

# Grant permissions
sudo security authorizationdb write com.lackadaisical.toolkit allow
```

### BSD

```bash
# FreeBSD
pkg install lackadaisical-toolkit

# OpenBSD
pkg_add lackadaisical-toolkit

# Enable at boot
echo 'lackadaisical_enable="YES"' >> /etc/rc.conf
```

## Configuration

### Initial Setup

```bash
# Run setup wizard
lackadaisical setup

# Or configure manually
lackadaisical config set network.use_tor true
lackadaisical config set privacy.paranoid_mode false
lackadaisical config set log.level INFO
```

### Configuration Files

Main configuration: `/etc/lackadaisical/config.json`

```json
{
  "general": {
    "auto_update": true,
    "telemetry": false,
    "language": "en"
  },
  "network": {
    "use_tor": true,
    "tor_bridges": false,
    "dns_over_https": true,
    "vpn_provider": null
  },
  "privacy": {
    "clear_on_exit": true,
    "auto_shred": true,
    "paranoid_mode": false
  }
}
```

### Environment Variables

```bash
# Set runtime options
export LACKADAISICAL_CONFIG=/path/to/config.json
export LACKADAISICAL_LOG_LEVEL=DEBUG
export LACKADAISICAL_TOR_PORT=9050
export LACKADAISICAL_USE_PROXY=true
```

## Security Hardening

### System Hardening

```bash
# Run hardening script
sudo ./scripts/security_hardening.sh

# Individual hardening steps
lackadaisical harden --kernel
lackadaisical harden --network
lackadaisical harden --filesystem
lackadaisical harden --services
```

### Firewall Configuration

```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 9050/tcp  # Tor SOCKS
sudo ufw allow 9051/tcp  # Tor Control
sudo ufw allow 8888/tcp  # Secure Messenger
sudo ufw enable

# iptables
sudo iptables -A INPUT -p tcp --dport 9050 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 9051 -j ACCEPT
sudo iptables -A OUTPUT -m owner --uid-owner tor -j ACCEPT
sudo iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT
sudo iptables -P OUTPUT DROP
```

### AppArmor/SELinux

```bash
# AppArmor
sudo aa-enforce /etc/apparmor.d/usr.bin.lackadaisical

# SELinux
sudo semanage fcontext -a -t lackadaisical_exec_t '/usr/bin/lackadaisical'
sudo restorecon -v '/usr/bin/lackadaisical'
```

## Troubleshooting

### Common Issues

#### Permission Denied

```bash
# Fix permissions
sudo chown -R $USER:$USER ~/.lackadaisical
chmod 700 ~/.lackadaisical
chmod 600 ~/.lackadaisical/keys/*
```

#### Tor Connection Failed

```bash
# Check Tor status
systemctl status tor

# Restart Tor
sudo systemctl restart tor

# Use bridges
lackadaisical tor-control --bridges --bridge-type obfs4
```

#### Module Not Found

```bash
# Rebuild modules
cd /opt/lackadaisical
make clean && make all

# Reinstall
sudo make install
```

### Debug Mode

```bash
# Enable debug logging
lackadaisical --debug <command>

# Check logs
tail -f ~/.lackadaisical/logs/debug.log

# System logs
journalctl -u lackadaisical-monitor -f
```

### Health Check

```bash
# Run diagnostics
lackadaisical diagnose

# Check specific component
lackadaisical diagnose --component tor
lackadaisical diagnose --component network
lackadaisical diagnose --component modules
```

## Updating

### Automatic Updates

```bash
# Enable auto-updates
lackadaisical config set general.auto_update true

# Check for updates
lackadaisical update --check

# Update now
sudo lackadaisical update --now
```

### Manual Update

```bash
cd /opt/lackadaisical
git pull origin main
pip install -r requirements.txt --upgrade
make clean && make all
sudo make install
```

### Major Version Upgrade

```bash
# Backup configuration
lackadaisical backup --config --keys

# Perform upgrade
sudo ./scripts/upgrade.sh

# Restore configuration
lackadaisical restore --config --keys
```

## Uninstallation

### Complete Removal

```bash
# Run uninstaller
sudo ./scripts/uninstall.sh

# Or manually
sudo systemctl stop lackadaisical-monitor
sudo systemctl disable lackadaisical-monitor
sudo rm -rf /opt/lackadaisical
sudo rm -rf /etc/lackadaisical
sudo rm -f /usr/bin/lackadaisical
rm -rf ~/.lackadaisical
```

### Secure Removal

```bash
# Securely wipe all data
sudo ./scripts/secure_uninstall.sh

# This will:
# - Shred all configuration files
# - Wipe all logs
# - Remove all keys
# - Clear all caches
```

## Post-Installation

### Verification

```bash
# Verify installation
lackadaisical --version
lackadaisical verify-install

# Test core functionality
lackadaisical test --core
lackadaisical test --network
lackadaisical test --security
```

### First Run

```bash
# Initialize toolkit
lackadaisical init

# Run privacy check
lackadaisical privacy-check

# Apply recommended settings
lackadaisical apply-recommendations
```

### Integration

```bash
# Shell integration
echo 'source /opt/lackadaisical/shell/completion.bash' >> ~/.bashrc

# Cron jobs
lackadaisical schedule --task privacy-check --interval daily
lackadaisical schedule --task update-check --interval weekly

# System services
sudo systemctl enable lackadaisical-monitor
sudo systemctl enable lackadaisical-tor-watcher
```

## Support

- Documentation: https://docs.lackadaisical-security.com
- Issues: https://github.com/lackadaisical-security/anonymity-toolkit/issues
- Community: https://community.lackadaisical-security.com
- Email: support@lackadaisical-security.com

## License

The Lackadaisical Anonymity Toolkit is released under the MIT License. See [LICENSE](../LICENSE) for details.
