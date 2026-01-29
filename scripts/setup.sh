#!/bin/bash
# Lackadaisical Anonymity Toolkit Setup Script
# Installs dependencies and configures the environment

set -e

echo "====================================="
echo "Lackadaisical Anonymity Toolkit Setup"
echo "====================================="

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
    OS="windows"
else
    echo "Unsupported OS: $OSTYPE"
    exit 1
fi

echo "Detected OS: $OS"

# Check for required tools
echo -e "\nChecking prerequisites..."

check_command() {
    if ! command -v $1 &> /dev/null; then
        echo "  ✗ $1 not found"
        return 1
    else
        echo "  ✓ $1 found"
        return 0
    fi
}

# Core requirements
MISSING_DEPS=0
check_command git || ((MISSING_DEPS++))
check_command python3 || ((MISSING_DEPS++))
check_command gcc || ((MISSING_DEPS++))
check_command make || ((MISSING_DEPS++))

# Language-specific checks
check_command go || echo "  ! Go not found (optional)"
check_command ruby || echo "  ! Ruby not found (optional)"
check_command node || echo "  ! Node.js not found (optional)"
check_command php || echo "  ! PHP not found (optional)"

if [ $MISSING_DEPS -gt 0 ]; then
    echo -e "\nMissing required dependencies. Please install them first."
    exit 1
fi

# Create directory structure
echo -e "\nCreating directory structure..."
mkdir -p {core/{asm/x86_64,c,cpp,common},modules/{network,data,identity,traffic,system,communication,opsec},tools/{python,go,javascript,ruby,powershell,php},scripts,docs,tests,bin,lib,config}

# Install Python dependencies
echo -e "\nInstalling Python dependencies..."
cat > requirements.txt << EOF
stem>=1.8.0
requests[socks]>=2.25.0
pycryptodome>=3.10.0
scapy>=2.4.5
faker>=8.1.0
pillow>=8.2.0
cryptography>=3.4.7
colorama>=0.4.4
EOF

python3 -m pip install -r requirements.txt

# Install Go dependencies (if Go is available)
if command -v go &> /dev/null; then
    echo -e "\nInstalling Go dependencies..."
    go mod init lackadaisical-toolkit 2>/dev/null || true
    go get github.com/h2non/filetype
    go get github.com/rwcarlsen/goexif/exif
fi

# Install Ruby dependencies (if Ruby is available)
if command -v ruby &> /dev/null; then
    echo -e "\nInstalling Ruby dependencies..."
    gem install faker
    gem install securerandom
fi

# Build C/C++ components
echo -e "\nBuilding native components..."

# Build secure delete utility
if [ -f "core/c/secure_delete.c" ]; then
    gcc -O2 -o bin/secure_delete core/c/secure_delete.c
    echo "  ✓ Built secure_delete"
fi

# Build assembly components (x86_64 only)
if [[ $(uname -m) == "x86_64" ]] && command -v nasm &> /dev/null; then
    if [ -f "core/asm/x86_64/crypto_wipe.asm" ]; then
        nasm -f elf64 core/asm/x86_64/crypto_wipe.asm -o lib/crypto_wipe.o
        echo "  ✓ Built crypto_wipe"
    fi
fi

# Setup Tor (if not installed)
echo -e "\nChecking Tor installation..."
if ! command -v tor &> /dev/null; then
    echo "Tor is not installed. Would you like to install it? (y/n)"
    read -r response
    if [[ "$response" == "y" ]]; then
        case $OS in
            linux)
                if command -v apt-get &> /dev/null; then
                    sudo apt-get update && sudo apt-get install -y tor
                elif command -v yum &> /dev/null; then
                    sudo yum install -y tor
                elif command -v pacman &> /dev/null; then
                    sudo pacman -S tor
                fi
                ;;
            macos)
                if command -v brew &> /dev/null; then
                    brew install tor
                fi
                ;;
            *)
                echo "Please install Tor manually"
                ;;
        esac
    fi
else
    echo "  ✓ Tor found"
fi

# Create default configuration
echo -e "\nCreating default configuration..."
cat > config/default.conf << EOF
# Lackadaisical Anonymity Toolkit Configuration

[general]
verbose = false
log_level = INFO
data_dir = ~/.lackadaisical

[tor]
socks_port = 9050
control_port = 9051
use_bridges = false

[network]
proxy_chains = true
dns_over_https = true
preferred_dns = 1.1.1.1

[privacy]
clear_on_exit = true
randomize_mac = true
spoof_user_agent = true

[security]
use_encryption = true
shred_passes = 7
paranoid_mode = false
EOF

# Create launcher script
echo -e "\nCreating launcher script..."
cat > lackadaisical << 'EOF'
#!/bin/bash
# Lackadaisical Anonymity Toolkit Launcher

TOOLKIT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ $# -eq 0 ]; then
    echo "Lackadaisical Anonymity Toolkit"
    echo "Usage: ./lackadaisical <module> [options]"
    echo ""
    echo "Available modules:"
    echo "  tor-control    - Tor controller"
    echo "  secure-delete  - Secure file deletion"
    echo "  metadata-clean - Metadata removal"
    echo "  trace-remove   - System trace removal"
    echo "  pseudonym      - Identity generation"
    echo "  stego          - Steganography tools"
    echo ""
    echo "Run './lackadaisical <module> --help' for module-specific help"
    exit 0
fi

MODULE=$1
shift

case $MODULE in
    tor-control)
        python3 "$TOOLKIT_DIR/modules/network/tor_controller.py" "$@"
        ;;
    secure-delete)
        "$TOOLKIT_DIR/bin/secure_delete" "$@"
        ;;
    metadata-clean)
        "$TOOLKIT_DIR/bin/metadata_cleaner" "$@"
        ;;
    trace-remove)
        if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
            powershell -ExecutionPolicy Bypass -File "$TOOLKIT_DIR/tools/powershell/Remove-Traces.ps1" "$@"
        else
            echo "trace-remove is only available on Windows"
        fi
        ;;
    pseudonym)
        ruby "$TOOLKIT_DIR/modules/identity/pseudonym_generator.rb" "$@"
        ;;
    stego)
        php "$TOOLKIT_DIR/modules/communication/steganography.php" "$@"
        ;;
    *)
        echo "Unknown module: $MODULE"
        exit 1
        ;;
esac
EOF

chmod +x lackadaisical

# Final setup tasks
echo -e "\nFinalizing setup..."

# Set permissions
find . -type f -name "*.sh" -exec chmod +x {} \;
find bin -type f -exec chmod +x {} \;

# Create user data directory
mkdir -p ~/.lackadaisical/{logs,temp,cache}

echo -e "\n====================================="
echo "Setup completed successfully!"
echo ""
echo "To get started, run:"
echo "  ./lackadaisical"
echo ""
echo "For documentation, see the docs/ directory"
echo "====================================="
