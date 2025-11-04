#!/bin/bash

echo "========================================="
echo "SDN-NIDPS Deployment Script"
echo "========================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (sudo ./deploy.sh)"
    exit 1
fi

# 1. Start Ryu Controller
echo "Starting Ryu SDN Controller..."
ryu-manager --verbose \
    --wsapi-host 0.0.0.0 \
    --wsapi-port 8080 \
    sdn_controller.py > ryu.log 2>&1 &
RYU_PID=$!
echo "Ryu started with PID: $RYU_PID"
sleep 5

# 2. Start Mininet Topology
echo "Starting Mininet topology..."
python3 network_topology.py &
MININET_PID=$!
echo "Mininet started with PID: $MININET_PID"
sleep 10

# 3. Start Dashboard Server
echo "Starting Web Dashboard..."
python3 -m http.server 8000 --directory . > dashboard.log 2>&1 &
DASHBOARD_PID=$!
echo "Dashboard started with PID: $DASHBOARD_PID"

# 4. Display access information
echo ""
echo "========================================="
echo "Deployment Complete!"
echo "========================================="
echo "Dashboard: http://localhost:8000/dashboard.html"
echo "API Endpoint: http://localhost:8080/api"
echo ""
echo "To run attacks, use:"
echo "  sudo python3 attack_simulator.py 10.0.0.1"
echo ""
echo "To stop all services:"
echo "  sudo kill $RYU_PID $MININET_PID $DASHBOARD_PID"
echo "  sudo mn -c"
echo "========================================="

# Save PIDs for cleanup
echo "$RYU_PID $MININET_PID $DASHBOARD_PID" > .pids

# Wait for user input
read -p "Press Enter to view logs (Ctrl+C to exit)..."
tail -f ryu.log dashboard.log
