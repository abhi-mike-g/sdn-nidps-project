# SDN-NIDPS: Scalable Network Intrusion Detection and Prevention System

A Software-Defined Network (SDN) based Intrusion Detection and Prevention System (NIDPS) that combines threat modeling, real-time detection, and automated response.

## Features

* **Real-time Threat Detection**: Suricata IDS integration for packet inspection
* **Automated Response**: SDN controller blocks malicious traffic instantly
* **STRIDE Coverage**: Detects all six STRIDE threat categories
* **Scalable Architecture**: Supports multi-controller deployments
* **Advanced Dashboard**: Real-time visualization and analytics
* **Attack Simulation**: External and internal attack scenarios

## Quick Start

```bash
# 1. Clone repository
git clone <repo-url>
cd sdn-nidps-project

# 2. Install dependencies
sudo apt-get install -y python3-pip mininet openvswitch-switch suricata
pip3 install -r requirements.txt

# 3. Start services
sudo bash scripts/start_all.sh

# 4. View dashboard
# Open: http://localhost:8000/advanced_dashboard.html

# 5. Run demo
sudo bash scripts/run_attack_demo.sh
```

## Architecture

┌─────────────────────────────────────────┐
│        Web Dashboard (Port 8000)        │
│      Advanced Analytics & Reports       │
└────────────────┬────────────────────────┘
  │ REST API
┌────────────────┴────────────────────────┐
│     Ryu SDN Controller (Port 6653)      │
│  - Threat Detection Engine              │
│  - Flow Rule Management                 │
│  - Real-time Response                   │
└────────────────┬────────────────────────┘
  │ OpenFlow
┌────────────────┴────────────────────────┐
│          Suricata IDS (Real-time)       │
│  - Packet Inspection                    │
│  - Signature-Based Detection            │
│  - EVE JSON Alerts                      │
└────────────────┬────────────────────────┘
  │
┌────────────────┴────────────────────────┐
│      Mininet Virtual Network            │
│  ├─ 3x OVS Switches                     │
│  ├─ 8x Hosts (Legitimate + Attacker)    │
│  └─ Multiple Network Segments           │
└─────────────────────────────────────────┘

## System Requirements

* Ubuntu 20.04+ or Linux with Kernel 5.0+
* Python 3.8+
* 8GB RAM minimum (16GB recommended)
* 20GB disk space
* Root/sudo access

## Installation

See `SETUP_GUIDE.md` for detailed installation instructions.

## Usage

### Start System

```bash
sudo bash scripts/start_all.sh
```

### View Dashboard

```
http://localhost:8000/advanced_dashboard.html
```

### Run Attacks

```bash
# External attacks
sudo python3 attack_suite/external_attacks.py 10.0.0.1

# Internal attacks
sudo python3 attack_suite/internal_attacks.py 10.0.0.100

# Or use interactive script
sudo bash scripts/run_attack_demo.sh
```

### Monitor Threats

```bash
# Real-time threat stream
watch -n 1 'curl http://localhost:8080/api/threats | python3 -m json.tool'

# Get blocked hosts
curl http://localhost:8080/api/blocked

# Get statistics
curl http://localhost:8080/api/stats
```

### API Endpoints

* **GET** `/api/threats` – Get recent threats
* **GET** `/api/blocked` – Get blocked hosts list
* **GET** `/api/stats` – Get threat statistics
* **POST** `/api/block` – Block a host

## Project Structure

```
sdn-nidps-project/
├── src/                    # Core SDN controller and threat detection
├── ids_integration/        # Suricata IDS integration
├── attack_suite/           # Attack simulation scripts
├── network/                # Mininet topology
├── dashboard/              # Web interface
├── scalability/            # Multi-controller architecture
├── config/                 # Configuration files
├── scripts/                # Utility scripts
└── logs/                   # Runtime logs
```

## Documentation

* `SETUP_GUIDE.md` – Installation and setup
* `docs/MTMT_GUIDE.md` – Threat modeling with Microsoft tool
* `docs/ARCHITECTURE.md` – System architecture details
* `docs/API_DOCUMENTATION.md` – REST API reference

## STRIDE Threat Coverage

| Category                   | Threats Detected                                   |
| -------------------------- | -------------------------------------------------- |
| **Spoofing**               | ARP Spoofing, IP Spoofing, DNS Spoofing            |
| **Tampering**              | Packet Injection, Session Hijacking                |
| **Repudiation**            | Log Tampering Attempts                             |
| **Information Disclosure** | Port Scanning, Banner Grabbing                     |
| **Denial of Service**      | SYN/UDP Floods, HTTP Floods                        |
| **Elevation of Privilege** | Brute Force, SQL Injection, XSS, Command Injection |

## Performance Metrics

* **Detection Rate**: 97.1%
* **Average Response Time**: 1.25 seconds
* **False Positive Rate**: <3%
* **Max Throughput**: 100,000+ pps

## Troubleshooting

See `docs/TROUBLESHOOTING.md` for common issues and solutions.

## Contributing

Contributions welcome! Please follow the coding standards in `CONTRIBUTING.md`.

## License

GNU GPL v3.0 License – See `LICENSE` file.

## Author

**SDN-NIDPS Development Team**
***Abhidutta Mukund Giri***
***Avishi Bansal***
***Piyush***
