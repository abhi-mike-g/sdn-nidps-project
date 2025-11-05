#!/bin/bash

##############################################################################
# SDN-NIDPS Installation Verification Script
# Verifies all components are properly installed and configured
##############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}SDN-NIDPS Installation Verification${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""

# Check function
check_component() {
    local name=$1
    local command=$2
    local expected=$3
    
    ((TOTAL_CHECKS++))
    
    echo -n "Checking $name... "
    
    if eval "$command" &> /dev/null; then
        if [ -z "$expected" ] || eval "$command" 2>/dev/null | grep -q "$expected"; then
            echo -e "${GREEN}✓${NC}"
            ((PASSED_CHECKS++))
        else
            echo -e "${RED}✗${NC} (version mismatch)"
            ((FAILED_CHECKS++))
        fi
    else
        echo -e "${RED}✗${NC} (not found)"
        ((FAILED_CHECKS++))
    fi
}

# Python checks
echo -e "${BLUE}[Python Environment]${NC}"
check_component "Python 3" "python3 --version" "Python 3"
check_component "Python 3 development headers" "test -d /usr/include/python3*"
check_component "pip3" "pip3 --version"

echo ""
echo -e "${BLUE}[Python Packages]${NC}"
check_component "Ryu" "python3 -c 'import ryu'"
check_component "Flask" "python3 -c 'import flask'"
check_component "Scapy" "python3 -c 'import scapy'"
check_component "Redis" "python3 -c 'import redis'"

echo ""
echo -e "${BLUE}[System Tools]${NC}"
check_component "Mininet" "mn --version"
check_component "Open vSwitch" "ovs-vsctl --version"
check_component "Nmap" "nmap --version"
check_component "Hping3" "hping3 -v" "hping3"
check_component "tcpdump" "tcpdump -version"

echo ""
echo -e "${BLUE}[IDS/IPS Tools]${NC}"
check_component "Suricata" "suricata --version"
check_component "Redis Server" "redis-cli ping" "PONG"

echo ""
echo -e "${BLUE}[Project Structure]${NC}"
check_component "src/ directory" "test -d src"
check_component "tests/ directory" "test -d tests"
check_component "config/ directory" "test -d config"
check_component "dashboard/ directory" "test -d dashboard"
check_component "scripts/ directory" "test -d scripts"

echo ""
echo -e "${BLUE}[Project Files]${NC}"
check_component "SDN Controller" "test -f src/sdn_controller.py"
check_component "Threat Detector" "test -f src/threat_detector.py"
check_component "Suricata Manager" "test -f ids_integration/suricata_manager.py"
check_component "Network Topology" "test -f network/network_topology.py"
check_component "Dashboard" "test -f dashboard/advanced_dashboard.html"

echo ""
echo -e "${BLUE}[Configuration Files]${NC}"
check_component "System Config" "test -f config/system_config.yaml"
check_component ".env file" "test -f .env" || true
check_component "Requirements" "test -f requirements.txt"

echo ""
echo -e "${BLUE}[Network Connectivity]${NC}"
check_component "Localhost resolves" "ping -c 1 localhost" "bytes"
check_component "Port 6653 (OpenFlow)" "nc -zv localhost 6653" || true
check_component "Port 8080 (API)" "nc -zv localhost 8080" || true

echo ""
echo -e "${BLUE}[Permissions]${NC}"
check_component "Current user in sudoers" "sudo -n true" || true
check_component "Scripts are executable" "test -x scripts/start_all.sh"

echo ""
echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}Verification Summary${NC}"
echo -e "${GREEN}=========================================${NC}"
echo ""
echo "Total Checks: $TOTAL_CHECKS"
echo -e "Passed: ${GREEN}$PASSED_CHECKS${NC}"
echo -e "Failed: ${RED}$FAILED_CHECKS${NC}"
echo ""

# Determine overall status
PASS_RATE=$((PASSED_CHECKS * 100 / TOTAL_CHECKS))
echo "Pass Rate: ${GREEN}${PASS_RATE}%${NC}"
echo ""

if [ $FAILED_CHECKS -eq 0 ]; then
    echo -e "${GREEN}[✓] All checks passed!${NC}"
    echo -e "${GREEN}System is ready for deployment${NC}"
    exit 0
elif [ $PASS_RATE -ge 80 ]; then
    echo -e "${YELLOW}[!] Most checks passed, some optional components missing${NC}"
    echo -e "${YELLOW}System can proceed with limited functionality${NC}"
    exit 0
else
    echo -e "${RED}[✗] Multiple checks failed${NC}"
    echo -e "${RED}Please install missing components${NC}"
    echo ""
    echo -e "${YELLOW}Run the following to install missing dependencies:${NC}"
    echo "  sudo apt update && sudo apt upgrade -y"
    echo "  sudo bash scripts/setup_redis.sh"
    echo "  pip3 install -r requirements.txt"
    exit 1
fi
