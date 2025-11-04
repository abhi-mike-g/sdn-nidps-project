#!/bin/bash

echo "========================================="
echo "SDN-NIDPS Shutdown Script"
echo "========================================="

if [ "$EUID" -ne 0 ]; then
   echo "[-] Please run as root (sudo)"
   exit 1
fi

# Read PIDs
if [ -f .pids ]; then
    PIDs=$(cat .pids)
    echo "[*] Killing processes: $PIDs"
    for pid in $PIDs; do
        if [ -n "$pid" ]; then
            kill -9 $pid 2>/dev/null
        fi
    done
    rm .pids
fi

# Stop Mininet
echo "[*] Stopping Mininet..."
mn -c 2>/dev/null

# Kill any remaining processes
echo "[*] Killing any remaining processes..."
pkill -9 ryu-manager 2>/dev/null
pkill -9 suricata 2>/dev/null
pkill -9 python3 2>/dev/null

echo "[+] All services stopped"
echo "========================================="
