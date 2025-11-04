# SDN-NIDPS Deployment Guide

## Quick Start (2-Day Implementation)

### Day 1: Setup & Configuration

#### Step 1: Environment Preparation
```bash
# Clone repository
git clone <your-repo>
cd sdn-nidps

# Install dependencies
sudo apt update
sudo apt install -y python3-pip mininet openvswitch-switch
pip3 install ryu flask flask-cors
```

#### Step 2: Deploy System
```bash
# Make deployment script executable
chmod +x deploy.sh

# Run deployment
sudo ./deploy.sh
```

#### Step 3: Verify Installation
```bash
# Check Ryu controller
curl http://localhost:8080/api/stats

# Check Mininet
sudo mn --test pingall

# Access dashboard
# Open browser: http://localhost:8000/dashboard.html
```

### Day 2: Testing & Demonstration

#### Attack Simulation
```bash
# Run demo scenarios
chmod +x demo_scenarios.sh
sudo ./demo_scenarios.sh
```

#### Monitor Results
1. Open dashboard: http://localhost:8000/dashboard.html
2. Run attacks from attacker host in Mininet
3. Observe real-time detection and blocking
4. Review threat logs

## Tool Integration Matrix

| Tool | Purpose | Integration Status |
|------|---------|-------------------|
| Ryu | SDN Controller | ✓ Core |
| Mininet | Network Simulation | ✓ Core |
| Suricata | IDS/IPS | ○ Optional |
| Nmap | Port Scanning | ✓ Integrated |
| Hping3 | DDoS Simulation | ✓ Integrated |
| Hydra | Brute Force | ○ Manual |
| SQLMap | SQL Injection | ○ Manual |
| Ettercap | MITM Attacks | ○ Manual |

## Architecture Overview
