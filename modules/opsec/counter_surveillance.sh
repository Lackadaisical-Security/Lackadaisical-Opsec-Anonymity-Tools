#!/bin/bash
# Counter-Surveillance Script
# Part of Lackadaisical Anonymity Toolkit

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCAN_INTERVAL=60
LOG_DIR="$HOME/.lackadaisical/logs"
ALERT_SOUND="/usr/share/sounds/freedesktop/stereo/alarm-clock-elapsed.oga"

# Ensure log directory exists
mkdir -p "$LOG_DIR"

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}[$(date '+%Y-%m-%d %H:%M:%S')] ${message}${NC}"
}

# Check for required tools
check_requirements() {
    local tools=("iwlist" "airmon-ng" "tcpdump" "arp-scan" "nmap" "ss" "lsof")
    local missing=()
    
    for tool in "${tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing+=("$tool")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        print_status "$RED" "Missing required tools: ${missing[*]}"
        print_status "$YELLOW" "Install with: sudo apt-get install aircrack-ng tcpdump arp-scan nmap"
        exit 1
    fi
}

# Detect wireless cameras and hidden devices
detect_cameras() {
    print_status "$BLUE" "Scanning for wireless cameras..."
    
    # Common camera MAC prefixes
    local camera_vendors=(
        "00:12:5A" # Hikvision
        "00:0C:15" # Dahua
        "00:E0:4C" # Realtek (common in IP cameras)
        "B4:79:47" # Xiaomi
        "34:CE:00" # TP-Link
        "E8:AB:FA" # Shenzhen Reecam
        "C0:56:E3" # Hangzhou Xiongmai"
    )
    
    # Scan for devices
    local devices=$(sudo arp-scan --local 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+')
    
    while IFS= read -r line; do
        local mac=$(echo "$line" | awk '{print $2}')
        local ip=$(echo "$line" | awk '{print $1}')
        
        for vendor in "${camera_vendors[@]}"; do
            if [[ "$mac" == "$vendor"* ]]; then
                print_status "$RED" "ALERT: Potential camera detected! IP: $ip, MAC: $mac"
                echo "$(date),camera,$ip,$mac" >> "$LOG_DIR/surveillance_alerts.csv"
            fi
        done
    done <<< "$devices"
    
    # Scan for common camera ports
    local camera_ports="80,443,554,8080,8081,8082,8083,8084,8085"
    print_status "$BLUE" "Scanning for devices with camera ports..."
    
    local port_scan=$(sudo nmap -p "$camera_ports" --open -sS 192.168.1.0/24 2>/dev/null | grep -B2 "open")
    if [ -n "$port_scan" ]; then
        print_status "$YELLOW" "Devices with camera ports found:"
        echo "$port_scan"
    fi
}

# Detect GPS trackers
detect_gps_trackers() {
    print_status "$BLUE" "Scanning for GPS trackers..."
    
    # Check for suspicious Bluetooth devices
    if command -v hcitool &> /dev/null; then
        local bt_devices=$(sudo hcitool scan 2>/dev/null | tail -n +2)
        
        # Known tracker patterns
        local tracker_patterns=("GPS" "Tracker" "Tag" "Tile" "AirTag" "SmartTag")
        
        while IFS= read -r device; do
            for pattern in "${tracker_patterns[@]}"; do
                if [[ "$device" =~ $pattern ]]; then
                    print_status "$RED" "ALERT: Potential GPS tracker detected: $device"
                    echo "$(date),gps_tracker,bluetooth,$device" >> "$LOG_DIR/surveillance_alerts.csv"
                fi
            done
        done <<< "$bt_devices"
    fi
    
    # Check for cellular-based trackers (IMEI catchers)
    detect_imsi_catchers
}

# Detect IMSI catchers (Stingrays)
detect_imsi_catchers() {
    print_status "$BLUE" "Checking for IMSI catchers..."
    
    # Monitor cellular signal strength changes
    if command -v mmcli &> /dev/null; then
        local signal_strength=$(mmcli -m 0 --signal-get 2>/dev/null | grep "signal quality" | awk '{print $3}')
        
        # Store and compare signal strengths
        local prev_signal_file="$LOG_DIR/.prev_signal"
        if [ -f "$prev_signal_file" ]; then
            local prev_signal=$(cat "$prev_signal_file")
            local diff=$((signal_strength - prev_signal))
            
            if [ "$diff" -gt 20 ] || [ "$diff" -lt -20 ]; then
                print_status "$YELLOW" "Significant cellular signal change detected (${diff}%)"
                print_status "$YELLOW" "Possible IMSI catcher in area"
            fi
        fi
        echo "$signal_strength" > "$prev_signal_file"
    fi
}

# Detect hidden microphones
detect_microphones() {
    print_status "$BLUE" "Scanning for hidden microphones..."
    
    # Check for audio recording processes
    local audio_procs=$(ps aux | grep -E "(arecord|sox|rec|pulseaudio)" | grep -v grep)
    if [ -n "$audio_procs" ]; then
        print_status "$YELLOW" "Audio recording processes detected:"
        echo "$audio_procs"
    fi
    
    # Check for unauthorized audio devices
    if command -v pactl &> /dev/null; then
        local sources=$(pactl list sources short | grep -v "monitor")
        print_status "$BLUE" "Active audio input devices:"
        echo "$sources"
    fi
}

# Network anomaly detection
detect_network_anomalies() {
    print_status "$BLUE" "Checking for network anomalies..."
    
    # Check for promiscuous mode interfaces
    local promisc=$(ip link show | grep -B1 "PROMISC" | grep -E "^[0-9]+:" | cut -d: -f2)
    if [ -n "$promisc" ]; then
        print_status "$RED" "ALERT: Network interfaces in promiscuous mode:$promisc"
    fi
    
    # Check for suspicious connections
    local suspicious_ports="22,23,3389,5900,5901,4444,1337,31337"
    local connections=$(ss -tnp 2>/dev/null | grep -E "($suspicious_ports)" | grep ESTAB)
    
    if [ -n "$connections" ]; then
        print_status "$YELLOW" "Suspicious network connections detected:"
        echo "$connections"
    fi
    
    # Monitor for ARP spoofing
    detect_arp_spoofing
}

# ARP spoofing detection
detect_arp_spoofing() {
    print_status "$BLUE" "Checking for ARP spoofing..."
    
    # Get ARP table
    local arp_table=$(arp -n | tail -n +2)
    local arp_file="$LOG_DIR/.arp_baseline"
    
    if [ -f "$arp_file" ]; then
        # Compare with baseline
        local changes=$(diff <(echo "$arp_table" | sort) <(sort "$arp_file") 2>/dev/null)
        
        if [ -n "$changes" ]; then
            print_status "$YELLOW" "ARP table changes detected:"
            echo "$changes"
            
            # Check for duplicate IPs
            local dup_ips=$(echo "$arp_table" | awk '{print $1}' | sort | uniq -d)
            if [ -n "$dup_ips" ]; then
                print_status "$RED" "ALERT: Duplicate IP addresses in ARP table (possible spoofing):"
                echo "$dup_ips"
            fi
        fi
    fi
    
    # Save current ARP table as baseline
    echo "$arp_table" > "$arp_file"
}

# RF signal detection
detect_rf_signals() {
    print_status "$BLUE" "Scanning for suspicious RF signals..."
    
    # Check if RTL-SDR is available
    if command -v rtl_power &> /dev/null; then
        # Scan common surveillance frequencies
        # 433 MHz (common for bugs), 915 MHz (IoT), 2.4 GHz (WiFi/Bluetooth)
        print_status "$BLUE" "Scanning 433 MHz band..."
        timeout 10 rtl_power -f 433M:434M:1k -g 50 -i 1 -1 "$LOG_DIR/rf_433.csv" 2>/dev/null || true
        
        # Analyze for anomalies
        if [ -f "$LOG_DIR/rf_433.csv" ]; then
            local max_power=$(awk -F, '{for(i=7;i<=NF;i++) if($i>max) max=$i} END{print max}' "$LOG_DIR/rf_433.csv")
            if (( $(echo "$max_power > -30" | bc -l) )); then
                print_status "$YELLOW" "Strong RF signal detected at 433 MHz band (${max_power} dB)"
            fi
        fi
    else
        print_status "$YELLOW" "RTL-SDR not found. Install rtl-sdr for RF scanning."
    fi
}

# Physical inspection helper
physical_inspection_guide() {
    print_status "$BLUE" "Physical inspection checklist:"
    
    cat << EOF
${YELLOW}Hidden Camera Detection:${NC}
- Look for small holes or unusual objects
- Check smoke detectors, air purifiers, wall outlets
- Use phone camera to detect IR LEDs (appear as purple/white dots)
- Check mirrors with fingernail test (gap = real mirror)

${YELLOW}Hidden Microphone Detection:${NC}
- Check for tiny holes in walls, furniture
- Look for wires that don't belong
- Check behind pictures, under desks
- Use RF detector for wireless mics

${YELLOW}GPS Tracker Detection:${NC}
- Check wheel wells, bumpers, undercarriage
- Look for magnetic boxes
- Check OBD port for unknown devices
- Monitor car battery drain

${YELLOW}General Tips:${NC}
- Turn off lights and look for LED indicators
- Listen for unusual buzzing or clicking sounds
- Check for warm spots on walls (hidden electronics)
- Use smartphone magnetometer app near suspicious areas
EOF
}

# USB device monitoring
monitor_usb_devices() {
    print_status "$BLUE" "Monitoring USB devices..."
    
    local current_devices=$(lsusb | sort)
    local baseline_file="$LOG_DIR/.usb_baseline"
    
    if [ -f "$baseline_file" ]; then
        local changes=$(diff <(echo "$current_devices") "$baseline_file" 2>/dev/null)
        if [ -n "$changes" ]; then
            print_status "$YELLOW" "USB device changes detected:"
            echo "$changes"
            
            # Check for known malicious devices
            local bad_devices=("Rubber Ducky" "BadUSB" "Bash Bunny" "USB Killer")
            for device in "${bad_devices[@]}"; do
                if echo "$current_devices" | grep -qi "$device"; then
                    print_status "$RED" "ALERT: Potentially malicious USB device detected: $device"
                fi
            done
        fi
    fi
    
    echo "$current_devices" > "$baseline_file"
}

# Continuous monitoring mode
continuous_monitoring() {
    print_status "$GREEN" "Starting continuous counter-surveillance monitoring..."
    print_status "$GREEN" "Press Ctrl+C to stop"
    
    while true; do
        print_status "$BLUE" "=== Surveillance Scan $(date) ==="
        
        detect_cameras
        detect_gps_trackers
        detect_microphones
        detect_network_anomalies
        monitor_usb_devices
        
        # Alert if threats detected
        if [ -f "$LOG_DIR/surveillance_alerts.csv" ]; then
            local recent_alerts=$(tail -n 10 "$LOG_DIR/surveillance_alerts.csv" | wc -l)
            if [ "$recent_alerts" -gt 0 ]; then
                print_status "$RED" "⚠️  $recent_alerts surveillance threats detected! Check logs."
                
                # Play alert sound if available
                if [ -f "$ALERT_SOUND" ] && command -v paplay &> /dev/null; then
                    paplay "$ALERT_SOUND" 2>/dev/null &
                fi
            fi
        fi
        
        print_status "$GREEN" "Scan complete. Next scan in $SCAN_INTERVAL seconds..."
        sleep "$SCAN_INTERVAL"
    done
}

# Main menu
main_menu() {
    cat << EOF
${BLUE}Lackadaisical Counter-Surveillance Toolkit${NC}
=========================================

1) Quick Scan - Run all detection modules once
2) Continuous Monitoring - Real-time surveillance detection  
3) Camera Detection - Scan for hidden cameras
4) GPS Tracker Detection - Check for tracking devices
5) Microphone Detection - Find audio surveillance
6) Network Anomaly Detection - Check for network attacks
7) RF Signal Scan - Detect radio frequency devices
8) Physical Inspection Guide - Manual search tips
9) View Alerts Log - Show recent detections
0) Exit

EOF
    
    read -p "Select option: " choice
    
    case $choice in
        1)
            detect_cameras
            detect_gps_trackers
            detect_microphones
            detect_network_anomalies
            monitor_usb_devices
            ;;
        2)
            continuous_monitoring
            ;;
        3)
            detect_cameras
            ;;
        4)
            detect_gps_trackers
            ;;
        5)
            detect_microphones
            ;;
        6)
            detect_network_anomalies
            ;;
        7)
            detect_rf_signals
            ;;
        8)
            physical_inspection_guide
            ;;
        9)
            if [ -f "$LOG_DIR/surveillance_alerts.csv" ]; then
                print_status "$BLUE" "Recent surveillance alerts:"
                tail -n 20 "$LOG_DIR/surveillance_alerts.csv" | column -t -s,
            else
                print_status "$GREEN" "No alerts logged yet."
            fi
            ;;
        0)
            exit 0
            ;;
        *)
            print_status "$RED" "Invalid option"
            ;;
    esac
    
    echo
    read -p "Press Enter to continue..."
    main_menu
}

# Script entry point
main() {
    print_status "$BLUE" "Initializing Counter-Surveillance Toolkit..."
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        print_status "$YELLOW" "Warning: Some features require root privileges"
        print_status "$YELLOW" "Run with: sudo $0"
    fi
    
    check_requirements
    
    # Handle command line arguments
    case "${1:-}" in
        --quick)
            detect_cameras
            detect_gps_trackers
            detect_microphones
            detect_network_anomalies
            ;;
        --monitor)
            continuous_monitoring
            ;;
        --help)
            echo "Usage: $0 [--quick|--monitor|--help]"
            echo "  --quick   Run quick scan"
            echo "  --monitor Start continuous monitoring"
            echo "  --help    Show this help"
            exit 0
            ;;
        *)
            main_menu
            ;;
    esac
}

# Trap Ctrl+C
trap 'echo -e "\n${RED}Exiting...${NC}"; exit 0' INT

# Run main function
main "$@"
