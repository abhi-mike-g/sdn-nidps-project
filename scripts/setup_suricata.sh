#!/bin/bash

echo "Installing and Configuring Suricata IDS"
echo "========================================"

# Install Suricata
sudo add-apt-repository ppa:oisf/suricata-stable -y
sudo apt update
sudo apt install -y suricata jq

# Update Suricata rules
sudo suricata-update

# Install Python dependencies
pip3 install pyyaml requests

# Create log directories
sudo mkdir -p /var/log/suricata
sudo chmod 755 /var/log/suricata

# Run Python configuration
sudo python3 suricata_manager.py --configure

echo "Suricata installation complete!"
