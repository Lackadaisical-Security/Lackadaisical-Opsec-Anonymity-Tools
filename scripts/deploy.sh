#!/bin/bash
# Deployment Script for Lackadaisical Anonymity Toolkit
# Handles installation, updates, and configuration

set -euo pipefail

# Configuration
REPO_URL="https://github.com/lackadaisical-security/anonymity-toolkit"
INSTALL_DIR="/opt/lackadaisical-toolkit"
BIN_DIR="/usr/local/bin"
CONFIG_DIR="/etc/lackadaisical"
LOG_DIR="/var/log/lackadaisical"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        error "Cannot detect OS"
    fi
}

install_dependencies() {
    log "Installing dependencies..."
    
    case $OS in
        ubuntu|debian)
            apt-get update
            apt-get install -y \
                git build-essential python3 python3-pip python3-venv \
                golang ruby nodejs npm php perl lua5.3 \
                nasm gcc g++ make cmake \
                tor torsocks proxychains4 \
                macchanger dnsutils nmap tcpdump \
                gpg openssl cryptsetup \
                sqlite3 jq curl wget \
                libssl-dev libffi-dev python3-dev
            ;;
        fedora|centos|rhel)
            dnf install -y \
                git gcc gcc-c++ make cmake python3 python3-pip \
                golang ruby nodejs npm php perl lua \
                nasm tor torsocks proxychains-ng \
                macchanger bind-utils nmap tcpdump \
                gnupg2 openssl cryptsetup \
                sqlite jq curl wget \
                openssl-devel python3-devel
            ;;
        arch)
            pacman -Syu --noconfirm
            pacman -S --noconfirm \
                git base-devel python python-pip \
                go ruby nodejs npm php perl lua \
                nasm tor torsocks proxychains-ng \
                macchanger dnsutils nmap tcpdump \
                gnupg openssl cryptsetup \
                sqlite jq curl wget
            ;;
        *)
            error "Unsupported OS: $OS"
            ;;
    esac
    
    # Install Rust
    if ! command -v cargo &> /dev/null; then
        log "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source $HOME/.cargo/env
    fi
    
    # Install .NET Core SDK
    if ! command -v dotnet &> /dev/null; then
        log "Installing .NET Core SDK..."
        case $OS in
            ubuntu|debian)
                wget https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
                dpkg -i packages-microsoft-prod.deb
                apt-get update
                apt-get install -y dotnet-sdk-6.0
                rm packages-microsoft-prod.deb
                ;;
        esac
    fi
}

create_directories() {
    log "Creating directory structure..."
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "$BIN_DIR"
    
    # Set permissions
    chmod 755 "$INSTALL_DIR"
    chmod 755 "$CONFIG_DIR"
    chmod 755 "$LOG_DIR"
}

clone_repository() {
    log "Cloning repository..."
    
    if [ -d "$INSTALL_DIR/.git" ]; then
        log "Repository exists, updating..."
        cd "$INSTALL_DIR"
        git pull origin main
    else
        git clone "$REPO_URL" "$INSTALL_DIR"
    fi
}

build_tools() {
    log "Building tools..."
    
    cd "$INSTALL_DIR"
    
    # Build C tools
    log "Building C tools..."
    for c_file in core/c/*.c; do
        if [ -f "$c_file" ]; then
            output=$(basename "$c_file" .c)
            gcc -O2 -o "bin/$output" "$c_file" -lcrypto -lssl
        fi
    done
    
    # Build C++ tools
    log "Building C++ tools..."
    for cpp_file in core/cpp/*.cpp; do
        if [ -f "$cpp_file" ]; then
            output=$(basename "$cpp_file" .cpp)
            g++ -O2 -std=c++17 -o "bin/$output" "$cpp_file" -lcrypto -lssl -lpthread
        fi
    done
    
    # Build Go tools
    log "Building Go tools..."
    for go_file in tools/go/*.go modules/*/*.go; do
        if [ -f "$go_file" ] && grep -q "func main()" "$go_file"; then
            output=$(basename "$go_file" .go)
            go build -o "bin/$output" "$go_file"
        fi
    done
    
    # Build Rust tools
    if [ -d "modules/traffic" ] && [ -f "modules/traffic/Cargo.toml" ]; then
        log "Building Rust tools..."
        cd modules/traffic
        cargo build --release
        cp target/release/* "$INSTALL_DIR/bin/" 2>/dev/null || true
        cd "$INSTALL_DIR"
    fi
    
    # Build .NET tools
    if command -v dotnet &> /dev/null; then
        log "Building .NET tools..."
        for proj in tools/dotnet/*.csproj; do
            if [ -f "$proj" ]; then
                dotnet build "$proj" -c Release -o bin/
            fi
        done
    fi
    
    # Make scripts executable
    find scripts -name "*.sh" -exec chmod +x {} \;
    find tools -name "*.py" -exec chmod +x {} \;
    find tools -name "*.rb" -exec chmod +x {} \;
    find tools -name "*.pl" -exec chmod +x {} \;
}

install_python_packages() {
    log "Installing Python packages..."
    
    cd "$INSTALL_DIR"
    
    # Create virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [ -f requirements.txt ]; then
        pip install -r requirements.txt
    fi
    
    # Additional packages
    pip install stem pysocks requests[socks] scapy faker \
                cryptography pillow opencv-python psutil
    
    deactivate
}

create_symlinks() {
    log "Creating command symlinks..."
    
    # Main launcher
    ln -sf "$INSTALL_DIR/lackadaisical" "$BIN_DIR/lackadaisical"
    
    # Individual tools
    tools=(
        "tor-control:modules/network/tor_controller.py"
        "metadata-clean:bin/metadata_cleaner"
        "secure-delete:bin/secure_delete"
        "trace-remove:tools/powershell/Remove-Traces.ps1"
        "pseudonym:modules/identity/pseudonym_generator.rb"
        "network-scan:bin/NetworkScanner"
        "privacy-check:tools/bash/privacy_check.sh"
        "anonymize:tools/python/network_anonymizer.py"
    )
    
    for tool_info in "${tools[@]}"; do
        IFS=':' read -r name path <<< "$tool_info"
        if [ -f "$INSTALL_DIR/$path" ]; then
            ln -sf "$INSTALL_DIR/$path" "$BIN_DIR/lack-$name"
        fi
    done
}

configure_system() {
    log "Configuring system..."
    
    # Copy default configuration
    if [ ! -f "$CONFIG_DIR/config.json" ]; then
        cp "$INSTALL_DIR/config/default.conf" "$CONFIG_DIR/config.json"
    fi
    
    # Setup log rotation
    cat > /etc/logrotate.d/lackadaisical << EOF
$LOG_DIR/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0640 root root
}
EOF
    
    # Create systemd service for monitoring
    cat > /etc/systemd/system/lackadaisical-monitor.service << EOF
[Unit]
Description=Lackadaisical Activity Monitor
After=network.target

[Service]
Type=simple
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/modules/opsec/activity_monitor.py
Restart=on-failure
RestartSec=10
StandardOutput=append:$LOG_DIR/monitor.log
StandardError=append:$LOG_DIR/monitor-error.log

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
}

post_install() {
    log "Running post-installation tasks..."
    
    # Create desktop entries (if desktop environment exists)
    if [ -d /usr/share/applications ]; then
        cat > /usr/share/applications/lackadaisical-toolkit.desktop << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Lackadaisical Toolkit
Comment=Anonymity and Privacy Toolkit
Exec=gnome-terminal -- /usr/local/bin/lackadaisical
Icon=$INSTALL_DIR/assets/icon.png
Terminal=true
Categories=System;Security;
EOF
    fi
    
    # Setup bash completion
    cat > /etc/bash_completion.d/lackadaisical << 'EOF'
_lackadaisical() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    opts="tor-control metadata-clean secure-delete trace-remove pseudonym network-scan privacy-check anonymize"
    
    if [[ ${cur} == -* ]] ; then
        COMPREPLY=( $(compgen -W "--help --version --verbose" -- ${cur}) )
        return 0
    fi
    
    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}
complete -F _lackadaisical lackadaisical
EOF
}

verify_installation() {
    log "Verifying installation..."
    
    errors=0
    
    # Check main binary
    if [ ! -x "$BIN_DIR/lackadaisical" ]; then
        warning "Main launcher not found"
        ((errors++))
    fi
    
    # Check Python environment
    if [ ! -d "$INSTALL_DIR/venv" ]; then
        warning "Python virtual environment not created"
        ((errors++))
    fi
    
    # Check critical tools
    critical_tools=("tor" "macchanger" "proxychains4")
    for tool in "${critical_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            warning "Critical tool not installed: $tool"
            ((errors++))
        fi
    done
    
    if [ $errors -eq 0 ]; then
        log "Installation verified successfully!"
    else
        warning "Installation completed with $errors warnings"
    fi
}

uninstall() {
    log "Uninstalling Lackadaisical Toolkit..."
    
    # Stop services
    systemctl stop lackadaisical-monitor 2>/dev/null || true
    systemctl disable lackadaisical-monitor 2>/dev/null || true
    
    # Remove files
    rm -rf "$INSTALL_DIR"
    rm -rf "$CONFIG_DIR"
    rm -rf "$LOG_DIR"
    
    # Remove symlinks
    rm -f "$BIN_DIR"/lackadaisical
    rm -f "$BIN_DIR"/lack-*
    
    # Remove systemd service
    rm -f /etc/systemd/system/lackadaisical-monitor.service
    systemctl daemon-reload
    
    # Remove desktop entry
    rm -f /usr/share/applications/lackadaisical-toolkit.desktop
    
    # Remove bash completion
    rm -f /etc/bash_completion.d/lackadaisical
    
    # Remove logrotate config
    rm -f /etc/logrotate.d/lackadaisical
    
    log "Uninstallation complete"
}

show_banner() {
    cat << 'EOF'
    __               __             __      _      _           __
   / /   ____ ______/ /______ _____/ /___ _(_)____(_)_______ _/ /
  / /   / __ `/ ___/ //_/ __ `/ __  / __ `/ / ___/ / ___/ __ `/ / 
 / /___/ /_/ / /__/ ,< / /_/ / /_/ / /_/ / (__  ) / /__/ /_/ / /  
/_____/\__,_/\___/_/|_|\__,_/\__,_/\__,_/_/____/_/\___/\__,_/_/   
                                                                   
            Anonymity Toolkit - Installation Script
            
EOF
}

# Main installation flow
main() {
    show_banner
    
    case "${1:-install}" in
        install)
            log "Starting installation..."
            check_root
            detect_os
            install_dependencies
            create_directories
            clone_repository
            build_tools
            install_python_packages
            create_symlinks
            configure_system
            post_install
            verify_installation
            
            echo ""
            log "Installation complete!"
            echo ""
            echo "To get started:"
            echo "  lackadaisical --help"
            echo ""
            echo "Documentation: $INSTALL_DIR/docs/"
            echo "Configuration: $CONFIG_DIR/config.json"
            echo ""
            ;;
            
        update)
            log "Updating toolkit..."
            check_root
            clone_repository
            build_tools
            install_python_packages
            log "Update complete!"
            ;;
            
        uninstall)
            check_root
            read -p "Are you sure you want to uninstall? (y/N) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                uninstall
            fi
            ;;
            
        *)
            echo "Usage: $0 {install|update|uninstall}"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
