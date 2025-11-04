#!/bin/bash

echo "========================================="
echo "SDN-NIDPS Attack Demonstration"
echo "========================================="

if [ "$EUID" -ne 0 ]; then
   echo "[-] Please run as root (sudo)"
   exit 1
fi

# Ask user which scenario to run
echo ""
echo "Select attack scenario:"
echo "1. External Attacks"
echo "2. Internal Attacks"
echo "3. Complete Attack Chain"
echo "4. Custom Target"
echo ""
read -p "Enter choice (1-4): " choice

TARGET="10.0.0.1"

case $choice in
    1)
        echo "[+] Running external attack simulation..."
        python3 attack_suite/external_attacks.py $TARGET
        ;;
    2)
        echo "[+] Running internal attack simulation..."
        python3 attack_suite/internal_attacks.py 10.0.0.100
        ;;
    3)
        echo "[+] Running complete attack chain..."
        echo "[+] Phase 1: External attacks"
        python3 attack_suite/external_attacks.py $TARGET
        sleep 5
        echo ""
        echo "[+] Phase 2: Internal attacks"
        python3 attack_suite/internal_attacks.py 10.0.0.100
        ;;
    4)
        read -p "Enter target IP: " TARGET
        python3 attack_suite/external_attacks.py $TARGET
        ;;
    *)
        echo "[-] Invalid choice"
        exit 1
        ;;
esac

echo ""
echo "========================================="
echo "Attack demonstration completed"
echo "Check the dashboard for results"
echo "http://localhost:8000/advanced_dashboard.html"
echo "========================================="
