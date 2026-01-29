#!/bin/bash
# Privacy Check Script
# Part of Lackadaisical Anonymity Toolkit

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Status icons
PASS="✓"
FAIL="✗"
WARN="⚠"

echo -e "${BLUE}Lackadaisical Privacy Check${NC}"
echo "=============================="
echo ""

# Function to check status
check_status() {
    local name=$1
    local command=$2
    local expected=$3
    local result
    
    printf "%-30s" "$name:"
    
    if eval "$command" &>/dev/null; then
        if [ -n "$expected" ]; then
            result=$(eval "$command" 2>/dev/null || echo "error")
            if [[ "$result" == *"$expected"* ]]; then
                echo -e "${GREEN}$PASS${NC} PASS"
                return 0
            else
                echo -e "${RED}$FAIL${NC} FAIL ($result)"
                return 1
            fi
        else
            echo -e "${GREEN}$PASS${NC} PASS"
            return 0
        fi
    else
        echo -e "${RED}$FAIL${NC} FAIL"
        return 1
    fi
}

# Network Privacy Checks
echo -e "${YELLOW}Network Privacy${NC}"
echo "---------------"

# Check Tor
check_status "Tor Service" "systemctl is-active tor" "active"

# Check Tor connectivity
if command -v tor &>/dev/null; then
    TOR_IP=$(curl -s --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip 2>/dev/null | grep -oP '"IP":"\K[^"]+' || echo "none")
    REAL_IP=$(curl -s https://api.ipify.org 2>/dev/null || echo "none")
    
    printf "%-30s" "Tor IP:"
    if [ "$TOR_IP" != "none" ] && [ "$TOR_IP" != "$REAL_IP" ]; then
        echo -e "${GREEN}$PASS${NC} $TOR_IP"
    else
        echo -e "${RED}$FAIL${NC} Not connected"
    fi
fi

# Check IPv6
check_status "IPv6 Disabled" "[ $(cat /proc/sys/net/ipv6/conf/all/disable_ipv6) -eq 1 ]" ""

# Check DNS
DNS_SERVER=$(grep -E "^nameserver" /etc/resolv.conf | head -1 | awk '{print $2}')
printf "%-30s" "DNS Server:"
if [[ "$DNS_SERVER" == "127.0.0.1" ]] || [[ "$DNS_SERVER" == "127.0.0.53" ]]; then
    echo -e "${GREEN}$PASS${NC} Local resolver"
else
    echo -e "${YELLOW}$WARN${NC} Using $DNS_SERVER"
fi

# Check firewall
if command -v ufw &>/dev/null; then
    check_status "UFW Firewall" "ufw status | grep -q 'Status: active'" ""
elif command -v firewall-cmd &>/dev/null; then
    check_status "Firewalld" "firewall-cmd --state" "running"
fi

echo ""

# System Privacy Checks
echo -e "${YELLOW}System Privacy${NC}"
echo "--------------"

# Check swappiness
SWAPPINESS=$(cat /proc/sys/vm/swappiness)
printf "%-30s" "Swappiness:"
if [ "$SWAPPINESS" -le 10 ]; then
    echo -e "${GREEN}$PASS${NC} $SWAPPINESS (low)"
else
    echo -e "${YELLOW}$WARN${NC} $SWAPPINESS (consider lowering)"
fi

# Check core dumps
check_status "Core Dumps Disabled" "[ $(ulimit -c) -eq 0 ]" ""

# Check ASLR
ASLR=$(cat /proc/sys/kernel/randomize_va_space)
printf "%-30s" "ASLR:"
if [ "$ASLR" -eq 2 ]; then
    echo -e "${GREEN}$PASS${NC} Fully enabled"
else
    echo -e "${RED}$FAIL${NC} Not fully enabled"
fi

# Check dmesg restriction
check_status "Kernel Log Restricted" "[ $(cat /proc/sys/kernel/dmesg_restrict) -eq 1 ]" ""

echo ""

# Browser Privacy Checks
echo -e "${YELLOW}Browser Privacy${NC}"
echo "---------------"

# Check for privacy browsers
for browser in "firefox" "tor-browser" "brave-browser"; do
    if command -v $browser &>/dev/null; then
        echo -e "$(printf "%-30s" "$browser:")${GREEN}$PASS${NC} Installed"
    fi
done

echo ""

# File System Privacy
echo -e "${YELLOW}File System Privacy${NC}"
echo "-------------------"

# Check encryption
if command -v lsblk &>/dev/null; then
    ENCRYPTED=$(lsblk -o NAME,FSTYPE | grep -c "crypto_LUKS" || true)
    printf "%-30s" "Encrypted Volumes:"
    if [ "$ENCRYPTED" -gt 0 ]; then
        echo -e "${GREEN}$PASS${NC} $ENCRYPTED found"
    else
        echo -e "${YELLOW}$WARN${NC} None found"
    fi
fi

# Check /tmp mount options
TMP_OPTIONS=$(findmnt -n /tmp | awk '{print $4}')
printf "%-30s" "/tmp Security:"
if [[ "$TMP_OPTIONS" == *"noexec"* ]] && [[ "$TMP_OPTIONS" == *"nosuid"* ]]; then
    echo -e "${GREEN}$PASS${NC} Secure mount"
else
    echo -e "${YELLOW}$WARN${NC} Consider noexec,nosuid"
fi

echo ""

# Privacy Tools Check
echo -e "${YELLOW}Privacy Tools${NC}"
echo "--------------"

tools=(
    "tor:Tor"
    "torsocks:Torsocks"
    "proxychains:Proxychains"
    "macchanger:MAC Changer"
    "bleachbit:BleachBit"
    "secure-delete:Secure Delete"
    "gpg:GnuPG"
    "cryptsetup:Disk Encryption"
    "firejail:Firejail"
    "dnscrypt-proxy:DNSCrypt"
)

for tool_info in "${tools[@]}"; do
    IFS=':' read -r cmd name <<< "$tool_info"
    if command -v "$cmd" &>/dev/null; then
        echo -e "$(printf "%-30s" "$name:")${GREEN}$PASS${NC} Installed"
    else
        echo -e "$(printf "%-30s" "$name:")${RED}$FAIL${NC} Not found"
    fi
done

echo ""

# Privacy Score
echo -e "${YELLOW}Privacy Score${NC}"
echo "-------------"

# Calculate score (simplified)
SCORE=0
MAX_SCORE=0

# Add up checks (this is simplified, real implementation would track all checks)
[ "$(systemctl is-active tor 2>/dev/null)" = "active" ] && ((SCORE+=10)) || true
[ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null)" = "1" ] && ((SCORE+=5)) || true
[ "$DNS_SERVER" = "127.0.0.1" ] && ((SCORE+=10)) || true
[ "$SWAPPINESS" -le 10 ] && ((SCORE+=5)) || true
[ "$(ulimit -c)" = "0" ] && ((SCORE+=5)) || true
[ "$ASLR" = "2" ] && ((SCORE+=10)) || true
[ "$ENCRYPTED" -gt 0 ] && ((SCORE+=15)) || true
command -v tor &>/dev/null && ((SCORE+=5)) || true
command -v gpg &>/dev/null && ((SCORE+=5)) || true

MAX_SCORE=70

PERCENTAGE=$((SCORE * 100 / MAX_SCORE))

echo -n "Overall Privacy Score: "
if [ "$PERCENTAGE" -ge 80 ]; then
    echo -e "${GREEN}$PERCENTAGE%${NC} - Excellent"
elif [ "$PERCENTAGE" -ge 60 ]; then
    echo -e "${YELLOW}$PERCENTAGE%${NC} - Good"
elif [ "$PERCENTAGE" -ge 40 ]; then
    echo -e "${YELLOW}$PERCENTAGE%${NC} - Fair"
else
    echo -e "${RED}$PERCENTAGE%${NC} - Poor"
fi

echo ""
echo "Run 'sudo ./privacy_hardening.sh' to improve your privacy score"
