#!/bin/bash
# Emergency Shutdown Script
# Part of Lackadaisical Anonymity Toolkit
# USE ONLY IN EMERGENCY SITUATIONS

set -euo pipefail

# This script performs immediate emergency shutdown and data destruction
# WARNING: This will destroy data and may damage the system

echo "EMERGENCY SHUTDOWN INITIATED"
echo "=========================="

# Kill all network connections immediately
echo "Killing network connections..."
# Flush all iptables rules
iptables -F 2>/dev/null || true
iptables -X 2>/dev/null || true
iptables -t nat -F 2>/dev/null || true
iptables -t nat -X 2>/dev/null || true
iptables -t mangle -F 2>/dev/null || true
iptables -t mangle -X 2>/dev/null || true

# Drop all traffic
iptables -P INPUT DROP 2>/dev/null || true
iptables -P FORWARD DROP 2>/dev/null || true
iptables -P OUTPUT DROP 2>/dev/null || true

# Disable network interfaces
for interface in $(ip link show | grep -E '^[0-9]+:' | cut -d: -f2 | grep -v lo); do
    ip link set $interface down 2>/dev/null || true
done

# Kill sensitive processes
echo "Terminating sensitive processes..."
killall -9 tor 2>/dev/null || true
killall -9 firefox 2>/dev/null || true
killall -9 chrome 2>/dev/null || true
killall -9 thunderbird 2>/dev/null || true
killall -9 gpg 2>/dev/null || true
killall -9 ssh 2>/dev/null || true
killall -9 openvpn 2>/dev/null || true

# Wipe memory
echo "Wiping memory..."
# Drop caches
sync
echo 3 > /proc/sys/vm/drop_caches 2>/dev/null || true

# Overwrite free memory
dd if=/dev/urandom of=/dev/shm/emergency_wipe bs=1M count=1000 2>/dev/null || true
rm -f /dev/shm/emergency_wipe

# Destroy swap
echo "Destroying swap..."
swapoff -a 2>/dev/null || true
# Find swap partitions and overwrite
for swap in $(cat /proc/swaps | tail -n +2 | cut -f1 -d' '); do
    dd if=/dev/urandom of=$swap bs=1M count=100 2>/dev/null || true
done

# Destroy sensitive files
echo "Destroying sensitive data..."
# SSH keys
find ~/.ssh -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true
# GPG keys
find ~/.gnupg -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true
# Lackadaisical data
find ~/.lackadaisical -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true
# Browser profiles
find ~/.mozilla -type f -name "*.sqlite" -exec shred -vfz -n 3 {} \; 2>/dev/null || true
find ~/.config/chromium -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true

# Clear logs
echo "Clearing logs..."
find /var/log -type f -exec sh -c '> {}' \; 2>/dev/null || true
> ~/.bash_history
> ~/.zsh_history 2>/dev/null || true
history -c

# Destroy encryption headers (WARNING: Makes encrypted volumes unrecoverable)
if [ "${DESTROY_ENCRYPTION:-0}" = "1" ]; then
    echo "DESTROYING ENCRYPTION HEADERS..."
    # LUKS headers
    for device in $(lsblk -o NAME,FSTYPE | grep crypto_LUKS | cut -d' ' -f1); do
        cryptsetup luksErase --batch-mode /dev/$device 2>/dev/null || true
    done
fi

# Final memory wipe
echo "Final memory wipe..."
# Fill all available memory to force overwrite
perl -e 'while(1){$a.="X"x1000000}' 2>/dev/null || true

# Power off immediately
echo "EMERGENCY SHUTDOWN COMPLETE"
echo "POWERING OFF IN 3 SECONDS..."
sleep 3

# Force immediate power off
echo o > /proc/sysrq-trigger 2>/dev/null || poweroff -f
