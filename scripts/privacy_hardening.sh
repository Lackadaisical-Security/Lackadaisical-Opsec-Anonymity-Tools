#!/bin/bash
# Privacy Hardening Script
# Part of Lackadaisical Anonymity Toolkit
# Hardens Linux system for maximum privacy

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging
LOG_FILE="/var/log/privacy_hardening.log"
BACKUP_DIR="/root/privacy_hardening_backup_$(date +%Y%m%d_%H%M%S)"

# Functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1" | tee -a "$LOG_FILE"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        error "Cannot detect OS distribution"
    fi
    log "Detected OS: $OS $VER"
}

backup_config() {
    log "Creating backup of system configurations..."
    mkdir -p "$BACKUP_DIR"
    
    # Backup important configs
    configs=(
        "/etc/sysctl.conf"
        "/etc/hosts"
        "/etc/hostname"
        "/etc/resolv.conf"
        "/etc/fstab"
        "/etc/ssh/sshd_config"
        "/etc/tor/torrc"
    )
    
    for config in "${configs[@]}"; do
        if [ -f "$config" ]; then
            cp -p "$config" "$BACKUP_DIR/" 2>/dev/null || true
        fi
    done
    
    log "Backup created at: $BACKUP_DIR"
}

# Network Hardening
harden_network() {
    log "Hardening network configuration..."
    
    # Disable IPv6 (can leak real IP)
    cat >> /etc/sysctl.d/99-privacy.conf << EOF
# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1

# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 1

# Ignore Directed pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable TCP timestamps
net.ipv4.tcp_timestamps = 0

# Enable TCP SYN cookies
net.ipv4.tcp_syncookies = 1

# Increase TCP SYN backlog
net.ipv4.tcp_max_syn_backlog = 4096

# Disable TCP SACK
net.ipv4.tcp_sack = 0
net.ipv4.tcp_dsack = 0
net.ipv4.tcp_fack = 0
EOF
    
    # Apply sysctl settings
    sysctl -p /etc/sysctl.d/99-privacy.conf
    
    # Configure firewall
    if command -v ufw &> /dev/null; then
        log "Configuring UFW firewall..."
        ufw --force reset
        ufw default deny incoming
        ufw default deny outgoing
        
        # Allow only essential outgoing
        ufw allow out 53/udp  # DNS
        ufw allow out 80/tcp  # HTTP
        ufw allow out 443/tcp # HTTPS
        ufw allow out 9050/tcp # Tor SOCKS
        ufw allow out 9051/tcp # Tor Control
        
        ufw --force enable
    elif command -v firewall-cmd &> /dev/null; then
        log "Configuring firewalld..."
        firewall-cmd --set-default-zone=drop
        firewall-cmd --permanent --zone=drop --add-service=dns
        firewall-cmd --permanent --zone=drop --add-service=https
        firewall-cmd --reload
    fi
}

# DNS Privacy
setup_dns_privacy() {
    log "Configuring DNS privacy..."
    
    # Backup original resolv.conf
    cp /etc/resolv.conf /etc/resolv.conf.backup
    
    # Use DNS-over-HTTPS
    if ! command -v dnscrypt-proxy &> /dev/null; then
        log "Installing dnscrypt-proxy..."
        case $OS in
            ubuntu|debian)
                apt-get update
                apt-get install -y dnscrypt-proxy
                ;;
            fedora|centos|rhel)
                dnf install -y dnscrypt-proxy
                ;;
            arch)
                pacman -S --noconfirm dnscrypt-proxy
                ;;
        esac
    fi
    
    # Configure dnscrypt-proxy
    cat > /etc/dnscrypt-proxy/dnscrypt-proxy.toml << 'EOF'
listen_addresses = ['127.0.0.1:53']
server_names = ['cloudflare', 'quad9-dnscrypt-ip4-nofilter-pri']
ipv4_servers = true
ipv6_servers = false
dnscrypt_servers = true
doh_servers = true
require_dnssec = true
require_nolog = true
require_nofilter = false
force_tcp = false
timeout = 2500
keepalive = 30
cert_refresh_delay = 240
tls_disable_session_tickets = true
tls_cipher_suite = [52392, 49199]
fallback_resolver = '9.9.9.9:53'
ignore_system_dns = true
netprobe_timeout = 60
netprobe_address = '9.9.9.9:53'
log_files_max_size = 10
log_files_max_age = 7
log_files_max_backups = 1

[query_log]
  file = '/var/log/dnscrypt-proxy/query.log'
  format = 'tsv'

[nx_log]
  file = '/var/log/dnscrypt-proxy/nx.log'
  format = 'tsv'

[sources]
  [sources.'public-resolvers']
  urls = ['https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/master/v3/public-resolvers.md']
  cache_file = '/var/cache/dnscrypt-proxy/public-resolvers.md'
  minisign_key = 'RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3'
EOF
    
    # Set localhost as DNS
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    chattr +i /etc/resolv.conf  # Make immutable
    
    # Start dnscrypt-proxy
    systemctl enable dnscrypt-proxy
    systemctl restart dnscrypt-proxy
}

# Browser Hardening
harden_browsers() {
    log "Hardening browser configurations..."
    
    # Firefox hardening
    firefox_profiles=$(find /home -name "*.default*" -type d -path "*/firefox/*" 2>/dev/null)
    
    for profile in $firefox_profiles; do
        if [ -d "$profile" ]; then
            log "Hardening Firefox profile: $profile"
            
            # Create user.js with privacy settings
            cat > "$profile/user.js" << 'EOF'
// Privacy Settings
user_pref("privacy.firstparty.isolate", true);
user_pref("privacy.resistFingerprinting", true);
user_pref("privacy.trackingprotection.enabled", true);
user_pref("privacy.trackingprotection.socialtracking.enabled", true);
user_pref("privacy.trackingprotection.cryptomining.enabled", true);
user_pref("privacy.trackingprotection.fingerprinting.enabled", true);

// Disable telemetry
user_pref("toolkit.telemetry.enabled", false);
user_pref("toolkit.telemetry.unified", false);
user_pref("toolkit.telemetry.archive.enabled", false);
user_pref("datareporting.healthreport.uploadEnabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("browser.ping-centre.telemetry", false);

// Disable WebRTC
user_pref("media.peerconnection.enabled", false);
user_pref("media.navigator.enabled", false);

// Disable geolocation
user_pref("geo.enabled", false);
user_pref("geo.wifi.uri", "");

// Disable battery API
user_pref("dom.battery.enabled", false);

// Disable clipboard events
user_pref("dom.event.clipboardevents.enabled", false);

// Disable device sensors
user_pref("device.sensors.enabled", false);

// DNS-over-HTTPS
user_pref("network.trr.mode", 3);
user_pref("network.trr.uri", "https://cloudflare-dns.com/dns-query");

// Disable prefetching
user_pref("network.dns.disablePrefetch", true);
user_pref("network.prefetch-next", false);
user_pref("network.predictor.enabled", false);

// Disable JavaScript in PDFs
user_pref("pdfjs.enableScripting", false);

// Clear data on shutdown
user_pref("privacy.sanitize.sanitizeOnShutdown", true);
user_pref("privacy.clearOnShutdown.cache", true);
user_pref("privacy.clearOnShutdown.cookies", true);
user_pref("privacy.clearOnShutdown.downloads", true);
user_pref("privacy.clearOnShutdown.formdata", true);
user_pref("privacy.clearOnShutdown.history", true);
user_pref("privacy.clearOnShutdown.sessions", true);
EOF
            
            # Set proper ownership
            owner=$(stat -c %U "$profile")
            chown -R "$owner:$owner" "$profile/user.js"
        fi
    done
}

# System Hardening
harden_system() {
    log "Hardening system configuration..."
    
    # Disable core dumps
    echo "* hard core 0" >> /etc/security/limits.conf
    echo "fs.suid_dumpable = 0" >> /etc/sysctl.d/99-privacy.conf
    
    # Restrict kernel logs
    echo "kernel.dmesg_restrict = 1" >> /etc/sysctl.d/99-privacy.conf
    
    # Hide kernel symbols
    echo "kernel.kptr_restrict = 2" >> /etc/sysctl.d/99-privacy.conf
    
    # Restrict ptrace
    echo "kernel.yama.ptrace_scope = 2" >> /etc/sysctl.d/99-privacy.conf
    
    # Disable kexec
    echo "kernel.kexec_load_disabled = 1" >> /etc/sysctl.d/99-privacy.conf
    
    # Enable ASLR
    echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/99-privacy.conf
    
    # Apply settings
    sysctl -p /etc/sysctl.d/99-privacy.conf
    
    # Disable unnecessary services
    services_to_disable=(
        "bluetooth"
        "cups"
        "avahi-daemon"
        "apache2"
        "nginx"
        "mysql"
        "postgresql"
    )
    
    for service in "${services_to_disable[@]}"; do
        if systemctl is-enabled "$service" &> /dev/null; then
            log "Disabling $service..."
            systemctl stop "$service"
            systemctl disable "$service"
        fi
    done
    
    # Remove unnecessary packages
    case $OS in
        ubuntu|debian)
            apt-get remove -y telnet nis yp-tools tftpd atftpd tftpd-hpa telnetd rsh-server rsh-redone-server 2>/dev/null || true
            ;;
        fedora|centos|rhel)
            dnf remove -y telnet telnet-server rsh rsh-server ypbind tftp tftp-server 2>/dev/null || true
            ;;
    esac
}

# SSH Hardening
harden_ssh() {
    if [ -f /etc/ssh/sshd_config ]; then
        log "Hardening SSH configuration..."
        
        # Backup original
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
        
        # Apply hardening
        cat >> /etc/ssh/sshd_config << EOF

# Privacy hardening
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowUsers ${SUDO_USER:-root}
LoginGraceTime 20
StrictModes yes
PubkeyAuthentication yes
IgnoreRhosts yes
HostbasedAuthentication no
UsePrivilegeSeparation yes
LogLevel VERBOSE
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256
EOF
        
        # Restart SSH
        systemctl restart sshd
    fi
}

# Install privacy tools
install_privacy_tools() {
    log "Installing privacy tools..."
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                tor \
                torsocks \
                proxychains4 \
                macchanger \
                bleachbit \
                secure-delete \
                scrub \
                mat2 \
                cryptsetup \
                gpa \
                gnupg2 \
                firejail
            ;;
        fedora|centos|rhel)
            dnf install -y \
                tor \
                torsocks \
                proxychains-ng \
                macchanger \
                bleachbit \
                scrub \
                cryptsetup \
                gnupg2 \
                firejail
            ;;
        arch)
            pacman -S --noconfirm \
                tor \
                torsocks \
                proxychains-ng \
                macchanger \
                bleachbit \
                cryptsetup \
                gnupg \
                firejail
            ;;
    esac
}

# Configure Tor
configure_tor() {
    log "Configuring Tor..."
    
    if [ -f /etc/tor/torrc ]; then
        cp /etc/tor/torrc /etc/tor/torrc.backup
        
        cat >> /etc/tor/torrc << EOF

# Privacy enhancements
AvoidDiskWrites 1
DisableDebuggerAttachment 1
Sandbox 1
SafeLogging 1
UseEntryGuards 1
NumEntryGuards 3
StrictNodes 1
EOF
        
        systemctl enable tor
        systemctl restart tor
    fi
}

# Setup MAC address randomization
setup_mac_randomization() {
    log "Setting up MAC address randomization..."
    
    # NetworkManager method
    if [ -d /etc/NetworkManager ]; then
        cat > /etc/NetworkManager/conf.d/30-mac-randomization.conf << EOF
[device-mac-randomization]
wifi.scan-rand-mac-address=yes
ethernet.scan-rand-mac-address=yes

[connection-mac-randomization]
wifi.cloned-mac-address=random
ethernet.cloned-mac-address=random
EOF
        
        systemctl restart NetworkManager
    fi
    
    # Systemd method
    cat > /etc/systemd/network/00-random-mac.link << EOF
[Match]
MACAddress=*

[Link]
MACAddressPolicy=random
NamePolicy=kernel database onboard slot path
EOF
}

# Create privacy aliases
create_privacy_aliases() {
    log "Creating privacy aliases..."
    
    cat >> /etc/bash.bashrc << 'EOF'

# Privacy aliases
alias shred='shred -vfz -n 7'
alias empty-trash='rm -rf ~/.local/share/Trash/*'
alias clear-history='history -c && history -w'
alias tor-check='curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip'
alias random-mac='sudo macchanger -r'
alias secure-delete='srm -vz'
alias anonymous='torsocks'
alias clear-swap='sudo swapoff -a && sudo swapon -a'
alias clear-memory='sudo sync && echo 3 | sudo tee /proc/sys/vm/drop_caches'

# Privacy functions
privacy-check() {
    echo "Privacy Status Check:"
    echo "===================="
    echo -n "Tor Status: "
    systemctl is-active tor
    echo -n "Current IP: "
    curl -s https://api.ipify.org
    echo -e "\nTor IP: "
    torsocks curl -s https://api.ipify.org
    echo -e "\nDNS Leak Test: "
    dig +short myip.opendns.com @resolver1.opendns.com
}

secure-rm() {
    find "$@" -type f -exec shred -vfz -n 7 {} \;
    find "$@" -type d -empty -delete
}
EOF
}

# Final report
generate_report() {
    log "Generating privacy hardening report..."
    
    report_file="/root/privacy_hardening_report_$(date +%Y%m%d_%H%M%S).txt"
    
    cat > "$report_file" << EOF
Privacy Hardening Report
========================
Date: $(date)
System: $OS $VER

Completed Tasks:
----------------
- Network hardening (IPv6 disabled, firewall configured)
- DNS privacy (DNS-over-HTTPS enabled)
- Browser hardening (Firefox privacy settings)
- System hardening (kernel parameters, service restrictions)
- SSH hardening (if applicable)
- Privacy tools installed
- Tor configured
- MAC randomization enabled

Backup Location: $BACKUP_DIR

Important Notes:
----------------
1. Reboot required for all changes to take effect
2. Some applications may not work with strict firewall rules
3. Review firewall rules and adjust as needed
4. Test all services after reboot

Next Steps:
-----------
1. Review this report
2. Test connectivity
3. Reboot system
4. Run 'privacy-check' to verify setup

EOF
    
    log "Report saved to: $report_file"
}

# Main execution
main() {
    cat << EOF
${BLUE}Lackadaisical Privacy Hardening Script${NC}
======================================

This script will harden your system for maximum privacy.
It will make significant changes to your system configuration.

${YELLOW}WARNING: This may break some applications!${NC}

EOF
    
    read -p "Continue? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
    
    check_root
    detect_distro
    backup_config
    
    # Execute hardening steps
    harden_network
    setup_dns_privacy
    harden_browsers
    harden_system
    harden_ssh
    install_privacy_tools
    configure_tor
    setup_mac_randomization
    create_privacy_aliases
    
    generate_report
    
    echo -e "\n${GREEN}Privacy hardening complete!${NC}"
    echo "Please review the report and reboot your system."
}

# Run main function
main "$@"
