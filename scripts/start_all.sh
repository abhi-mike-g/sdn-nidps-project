#!/bin/bash

echo "========================================="
echo "SDN-NIDPS Complete Startup Script"
echo "========================================="

# Load environment
if [ -f .env ]; then
    export $(cat .env | grep -v '#' | xargs)
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then
   echo "[-] Please run as root (sudo)"
   exit 1
fi

# Kill existing processes
echo "[*] Cleaning up existing processes..."
pkill -9 ryu-manager 2>/dev/null
pkill -9 suricata 2>/dev/null
mn -c 2>/dev/null

sleep 2

# Create log directories
echo "[*] Creating log directories..."
mkdir -p logs data

# Start Redis (if needed)
echo "[*] Checking Redis..."
if redis-cli ping > /dev/null 2>&1; then
    echo "    Redis is running"
else
    echo "    Starting Redis..."
    redis-server --daemonize yes
    sleep 2
fi

# Start Ryu SDN Controller
echo "[*] Starting Ryu SDN Controller..."
cd src
ryu-manager \
    --verbose \
    --wsapi-host 0.0.0.0 \
    --wsapi-port 8080 \
    sdn_controller.py \
    > ../logs/ryu_controller.log 2>&1 &
RYU_PID=$!
echo "    Ryu PID: $RYU_PID"
cd ..

sleep 5

# Start Mininet Network
echo "[*] Starting Mininet Network..."
python3 network/network_topology.py --no-cli \
    > logs/mininet.log 2>&1 &
MININET_PID=$!
echo "    Mininet PID: $MININET_PID"

sleep 5

# Start Suricata IDS
echo "[*] Starting Suricata IDS..."
if command -v suricata &> /dev/null; then
    suricata -c ids_integration/suricata.yaml \
        -i s1-eth1 \
        > logs/suricata.log 2>&1 &
    SURICATA_PID=$!
    echo "    Suricata PID: $SURICATA_PID"
else
    echo "    [!] Suricata not installed"
fi

sleep 5

# Start Web Dashboard Server
echo "[*] Starting Web Dashboard..."
cd dashboard
python3 -m http.server 8000 \
    > ../logs/dashboard.log 2>&1 &
DASHBOARD_PID=$!
echo "    Dashboard PID: $DASHBOARD_PID"
cd ..

# Save PIDs
echo "$RYU_PID $MININET_PID $SURICATA_PID $DASHBOARD_PID" > .pids

echo ""
echo "========================================="
echo "All Services Started!"
echo "========================================="
echo ""
echo "Accessing the System:"
echo "  SDN Controller API: http://localhost:8080/api"
echo "  Web Dashboard: http://localhost:8000/advanced_dashboard.html"
echo ""
echo "Log Files:"
echo "  Ryu: logs/ryu_controller.log"
echo "  Mininet: logs/mininet.log"
echo "  Suricata: logs/suricata.log"
echo "  Dashboard: logs/dashboard.log"
echo ""
echo "To stop all services: sudo bash scripts/stop_all.sh"
echo "========================================="
