#!/bin/bash

##############################################################################
# SDN-NIDPS Cleanup Script
# Removes all running services and cleans up system resources
##############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}SDN-NIDPS Cleanup Script${NC}"
echo -e "${GREEN}=========================================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[-] Please run as root (sudo)${NC}"
    exit 1
fi

# Confirm cleanup
echo -e "${YELLOW}[!] This will stop all SDN-NIDPS services and clean up resources${NC}"
read -p "Continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${YELLOW}[*] Cleanup cancelled${NC}"
    exit 0
fi

# Kill running processes
echo -e "${YELLOW}[*] Stopping running processes...${NC}"

echo "[*] Stopping Ryu controller..."
pkill -9 ryu-manager 2>/dev/null || true

echo "[*] Stopping Suricata..."
systemctl stop suricata 2>/dev/null || pkill -9 suricata || true

echo "[*] Stopping Mininet..."
mn -c 2>/dev/null || true
pkill -9 python3 2>/dev/null || true

echo "[*] Stopping Redis..."
systemctl stop redis-sdn-nidps 2>/dev/null || systemctl stop redis-server 2>/dev/null || pkill -9 redis-server || true

echo "[*] Stopping web dashboard..."
pkill -9 "python3 -m http.server" 2>/dev/null || true

echo -e "${GREEN}[+] Processes stopped${NC}"

# Clean up Mininet
echo -e "${YELLOW}[*] Cleaning up Mininet...${NC}"
mn -c 2>/dev/null || true

# Remove log files (but keep important ones)
echo -e "${YELLOW}[*] Cleaning up log files...${NC}"

if [ -d "logs" ]; then
    echo "[*] Removing old log files..."
    find logs -type f -mtime +7 -delete 2>/dev/null || true
    # Keep recent logs
    ls -la logs 2>/dev/null || true
fi

# Clean up temporary files
echo -e "${YELLOW}[*] Cleaning up temporary files...${NC}"

rm -f /tmp/sdn-nidps-* 2>/dev/null || true
rm -f .pids 2>/dev/null || true
rm -f *.pcap 2>/dev/null || true
rm -f *.log 2>/dev/null || true

# Clean up Redis cache (optional)
echo -e "${YELLOW}[*] Cleaning Redis cache (optional)${NC}"
read -p "Clear Redis cache? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    redis-cli FLUSHALL 2>/dev/null || true
    echo -e "${GREEN}[+] Redis cache cleared${NC}"
fi

# Clean up database (optional)
echo -e "${YELLOW}[*] Cleaning database files (optional)${NC}"
read -p "Delete threat database? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -f data/*.db 2>/dev/null || true
    echo -e "${GREEN}[+] Database files removed${NC}"
fi

# Reset network
echo -e "${YELLOW}[*] Resetting network settings...${NC}"
ifconfig 2>/dev/null | grep -q "virbr0" && (brctl show 2>/dev/null | grep -q "virbr0" && brctl delbr virbr0 2>/dev/null || true) || true

# Clear ARP cache
arp -a | awk '{print $1}' | xargs -I {} arp -d {} 2>/dev/null || true

echo -e "${GREEN}[+] Network settings reset${NC}"

# Remove PID files
echo -e "${YELLOW}[*] Removing PID files...${NC}"
rm -f *.pid 2>/dev/null || true

# Summary
echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}Cleanup Complete!${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo -e "${YELLOW}Summary of cleanup:${NC}"
echo "  ✓ Stopped all running services"
echo "  ✓ Cleaned up Mininet"
echo "  ✓ Removed temporary files"
echo "  ✓ Reset network settings"
echo ""
echo -e "${YELLOW}Directories:${NC}"
echo "  Logs: $(du -sh logs 2>/dev/null || echo 'N/A')"
echo "  Data: $(du -sh data 2>/dev/null || echo 'N/A')"
echo ""

# Show remaining services
echo -e "${YELLOW}Remaining SDN-NIDPS processes:${NC}"
ps aux | grep -E "sdn|ryu|suricata|mininet" | grep -v grep || echo "  None"

echo ""
