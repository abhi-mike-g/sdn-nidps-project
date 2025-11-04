#!/usr/bin/env python3
"""
Suricata IDS Integration Manager
Handles Suricata configuration, rule management, and alert processing
"""

import json
import subprocess
import os
import yaml
from pathlib import Path
import threading
import time

class SuricataManager:
    def __init__(self, interface="s1-eth1", rules_dir="/etc/suricata/rules"):
        self.interface = interface
        self.rules_dir = Path(rules_dir)
        self.alert_file = "/var/log/suricata/fast.log"
        self.eve_json = "/var/log/suricata/eve.json"
        self.custom_rules_file = self.rules_dir / "custom.rules"
        self.suricata_process = None
        self.alert_callback = None
        
    def install_custom_rules(self):
        """Install custom Suricata rules for SDN-specific threats"""
        custom_rules = '''
# SDN-Specific Attack Detection Rules

# Port Scanning Detection
alert tcp any any -> any any (msg:"NMAP SYN Scan Detected"; \
    flags:S; threshold:type threshold, track by_src, count 10, seconds 5; \
    classtype:attempted-recon; sid:1000001; rev:1;)

alert tcp any any -> any any (msg:"NMAP NULL Scan Detected"; \
    flags:0; threshold:type threshold, track by_src, count 5, seconds 5; \
    classtype:attempted-recon; sid:1000002; rev:1;)

alert tcp any any -> any any (msg:"NMAP XMAS Scan Detected"; \
    flags:FPU; threshold:type threshold, track by_src, count 5, seconds 5; \
    classtype:attempted-recon; sid:1000003; rev:1;)

# DDoS Detection
alert tcp any any -> any any (msg:"SYN Flood Attack Detected"; \
    flags:S; threshold:type threshold, track by_dst, count 100, seconds 1; \
    classtype:attempted-dos; sid:1000010; rev:1;)

alert udp any any -> any any (msg:"UDP Flood Attack Detected"; \
    threshold:type threshold, track by_dst, count 500, seconds 1; \
    classtype:attempted-dos; sid:1000011; rev:1;)

alert icmp any any -> any any (msg:"ICMP Flood Attack Detected"; \
    itype:8; threshold:type threshold, track by_dst, count 100, seconds 1; \
    classtype:attempted-dos; sid:1000012; rev:1;)

# ARP Spoofing Detection
alert arp any any -> any any (msg:"ARP Spoofing Attempt Detected"; \
    arp_opcode:reply; threshold:type threshold, track by_src, count 5, seconds 10; \
    classtype:network-scan; sid:1000020; rev:1;)

# DNS Attacks
alert udp any any -> any 53 (msg:"DNS Amplification Attack"; \
    content:"|00 00 ff 00 01|"; threshold:type threshold, track by_src, count 10, seconds 5; \
    classtype:attempted-dos; sid:1000030; rev:1;)

alert udp any 53 -> any any (msg:"DNS Cache Poisoning Attempt"; \
    content:"|81 80|"; offset:2; depth:2; \
    classtype:bad-unknown; sid:1000031; rev:1;)

# SQL Injection
alert tcp any any -> any $HTTP_PORTS (msg:"SQL Injection Attempt - UNION"; \
    flow:to_server,established; content:"union"; nocase; \
    content:"select"; nocase; distance:0; \
    classtype:web-application-attack; sid:1000040; rev:1;)

alert tcp any any -> any $HTTP_PORTS (msg:"SQL Injection Attempt - OR 1=1"; \
    flow:to_server,established; content:"or"; nocase; \
    content:"1=1"; nocase; distance:0; \
    classtype:web-application-attack; sid:1000041; rev:1;)

alert tcp any any -> any $HTTP_PORTS (msg:"SQL Injection Attempt - DROP TABLE"; \
    flow:to_server,established; content:"drop"; nocase; \
    content:"table"; nocase; distance:0; \
    classtype:web-application-attack; sid:1000042; rev:1;)

# XSS Detection
alert tcp any any -> any $HTTP_PORTS (msg:"XSS Attempt - Script Tag"; \
    flow:to_server,established; content:"<script"; nocase; \
    classtype:web-application-attack; sid:1000050; rev:1;)

alert tcp any any -> any $HTTP_PORTS (msg:"XSS Attempt - JavaScript Event"; \
    flow:to_server,established; content:"javascript:"; nocase; \
    classtype:web-application-attack; sid:1000051; rev:1;)

# Command Injection
alert tcp any any -> any $HTTP_PORTS (msg:"Command Injection Attempt"; \
    flow:to_server,established; pcre:"/[;&|`$()]/"; \
    classtype:web-application-attack; sid:1000060; rev:1;)

# Brute Force Detection
alert tcp any any -> any 22 (msg:"SSH Brute Force Attempt"; \
    flow:to_server,established; content:"SSH"; \
    threshold:type threshold, track by_src, count 5, seconds 60; \
    classtype:attempted-admin; sid:1000070; rev:1;)

alert tcp any any -> any 3389 (msg:"RDP Brute Force Attempt"; \
    flow:to_server,established; \
    threshold:type threshold, track by_src, count 5, seconds 60; \
    classtype:attempted-admin; sid:1000071; rev:1;)

# Slowloris Attack
alert tcp any any -> any $HTTP_PORTS (msg:"Slowloris Attack Detected"; \
    flow:to_server,established; content:"GET"; depth:3; \
    threshold:type threshold, track by_src, count 100, seconds 60; \
    classtype:attempted-dos; sid:1000080; rev:1;)

# Session Hijacking
alert tcp any any -> any any (msg:"TCP Session Hijacking Attempt"; \
    flags:PA; seq:0; ack:0; \
    classtype:attempted-user; sid:1000090; rev:1;)

# Packet Fragmentation Attack
alert ip any any -> any any (msg:"Suspicious IP Fragmentation"; \
    fragbits:M; threshold:type threshold, track by_src, count 10, seconds 5; \
    classtype:bad-unknown; sid:1000100; rev:1;)

# HTTP Anomalies
alert tcp any any -> any $HTTP_PORTS (msg:"Suspicious HTTP Method"; \
    flow:to_server,established; content:!"GET"; depth:3; \
    content:!"POST"; depth:4; content:!"HEAD"; depth:4; \
    classtype:web-application-activity; sid:1000110; rev:1;)

# Network Reconnaissance
alert tcp any any -> any any (msg:"TCP Connect Scan"; \
    flags:S,12; threshold:type threshold, track by_src, count 10, seconds 5; \
    classtype:attempted-recon; sid:1000120; rev:1;)
'''
        
        os.makedirs(self.rules_dir, exist_ok=True)
        with open(self.custom_rules_file, 'w') as f:
            f.write(custom_rules)
        
        print(f"[+] Custom Suricata rules installed: {self.custom_rules_file}")
    
    def configure_suricata(self):
        """Configure Suricata for SDN monitoring"""
        config = {
            'vars': {
                'address-groups': {
                    'HOME_NET': '[10.0.0.0/8]',
                    'EXTERNAL_NET': '!$HOME_NET'
                },
                'port-groups': {
                    'HTTP_PORTS': '80',
                    'SHELLCODE_PORTS': '!80',
                    'ORACLE_PORTS': '1521',
                    'SSH_PORTS': '22',
                    'DNP3_PORTS': '20000',
                    'MODBUS_PORTS': '502',
                    'FILE_DATA_PORTS': '[$HTTP_PORTS,110,143]',
                    'FTP_PORTS': '21'
                }
            },
            'default-rule-path': str(self.rules_dir),
            'rule-files': [
                'custom.rules',
                'emerging-dos.rules',
                'emerging-exploit.rules',
                'emerging-malware.rules',
                'emerging-scan.rules',
                'emerging-web_server.rules'
            ],
            'af-packet': [{
                'interface': self.interface,
                'threads': 'auto',
                'cluster-type': 'cluster_flow',
                'defrag': 'yes',
                'use-mmap': 'yes',
                'ring-size': 2048
            }],
            'outputs': [
                {
                    'fast': {
                        'enabled': 'yes',
                        'filename': 'fast.log',
                        'append': 'yes'
                    }
                },
                {
                    'eve-log': {
                        'enabled': 'yes',
                        'filetype': 'regular',
                        'filename': 'eve.json',
                        'types': [
                            {'alert': {'payload': 'yes'}},
                            {'http': {}},
                            {'dns': {}},
                            {'tls': {}},
                            {'flow': {}},
                            {'netflow': {}},
                            {'drop': {}},
                            {'stats': {'totals': 'yes'}}
                        ]
                    }
                }
            ],
            'logging': {
                'default-log-level': 'info',
                'outputs': [
                    {'console': {'enabled': 'yes'}},
                    {'file': {
                        'enabled': 'yes',
                        'filename': '/var/log/suricata/suricata.log'
                    }}
                ]
            }
        }
        
        config_file = '/etc/suricata/suricata.yaml'
        with open(config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        
        print(f"[+] Suricata configuration updated: {config_file}")
    
    def start_suricata(self):
        """Start Suricata IDS"""
        print(f"[+] Starting Suricata on interface {self.interface}...")
        
        cmd = [
            'suricata',
            '-c', '/etc/suricata/suricata.yaml',
            '-i', self.interface,
            '--init-errors-fatal',
            '-vvv'
        ]
        
        self.suricata_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        time.sleep(5)  # Wait for Suricata to initialize
        
        if self.suricata_process.poll() is None:
            print("[+] Suricata started successfully")
            return True
        else:
            print("[-] Suricata failed to start")
            return False
    
    def stop_suricata(self):
        """Stop Suricata IDS"""
        if self.suricata_process:
            self.suricata_process.terminate()
            self.suricata_process.wait()
            print("[+] Suricata stopped")
    
    def parse_eve_json(self):
        """Parse EVE JSON alerts in real-time"""
        if not os.path.exists(self.eve_json):
            return []
        
        alerts = []
        try:
            with open(self.eve_json, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line)
                        if event.get('event_type') == 'alert':
                            alerts.append({
                                'timestamp': event.get('timestamp'),
                                'severity': event['alert'].get('severity'),
                                'signature': event['alert'].get('signature'),
                                'category': event['alert'].get('category'),
                                'src_ip': event.get('src_ip'),
                                'dest_ip': event.get('dest_ip'),
                                'src_port': event.get('src_port'),
                                'dest_port': event.get('dest_port'),
                                'proto': event.get('proto')
                            })
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        
        return alerts
    
    def monitor_alerts(self, callback):
        """Monitor Suricata alerts in real-time"""
        self.alert_callback = callback
        
        def monitor_thread():
            last_position = 0
            while True:
                if os.path.exists(self.eve_json):
                    with open(self.eve_json, 'r') as f:
                        f.seek(last_position)
                        for line in f:
                            try:
                                event = json.loads(line)
                                if event.get('event_type') == 'alert' and self.alert_callback:
                                    self.alert_callback(event)
                            except json.JSONDecodeError:
                                pass
                        last_position = f.tell()
                time.sleep(1)
        
        monitor = threading.Thread(target=monitor_thread, daemon=True)
        monitor.start()
    
    def get_statistics(self):
        """Get Suricata statistics"""
        stats_file = '/var/log/suricata/stats.log'
        if not os.path.exists(stats_file):
            return {}
        
        stats = {}
        try:
            with open(stats_file, 'r') as f:
                lines = f.readlines()
                if lines:
                    # Parse last statistics entry
                    for line in lines[-10:]:
                        if '|' in line:
                            parts = line.split('|')
                            if len(parts) >= 2:
                                key = parts[0].strip()
                                value = parts[1].strip()
                                stats[key] = value
        except Exception as e:
            print(f"Error reading statistics: {e}")
        
        return stats


# Integration with SDN Controller
class SuricataSDNIntegration:
    """Bridge between Suricata IDS and SDN Controller"""
    
    def __init__(self, controller_api="http://localhost:8080/api"):
        self.controller_api = controller_api
        self.suricata = SuricataManager()
        
    def alert_to_sdn_action(self, alert):
        """Convert Suricata alert to SDN action"""
        # Map alert severity to SDN action
        severity_map = {
            1: 'BLOCK',    # High severity
            2: 'MONITOR',  # Medium severity
            3: 'LOG'       # Low severity
        }
        
        action = {
            'threat_type': alert['alert'].get('signature'),
            'source_ip': alert.get('src_ip'),
            'dest_ip': alert.get('dest_ip'),
            'severity': alert['alert'].get('severity'),
            'action': severity_map.get(alert['alert'].get('severity'), 'LOG'),
            'timestamp': alert.get('timestamp'),
            'category': alert['alert'].get('category')
        }
        
        return action
    
    def send_to_controller(self, action):
        """Send blocking action to SDN controller"""
        try:
            response = requests.post(
                f"{self.controller_api}/block",
                json=action,
                timeout=5
            )
            return response.status_code == 200
        except Exception as e:
            print(f"Error sending to controller: {e}")
            return False
    
    def start_integrated_monitoring(self):
        """Start integrated Suricata-SDN monitoring"""
        def alert_handler(alert):
            if alert.get('event_type') == 'alert':
                action = self.alert_to_sdn_action(alert)
                if action['action'] == 'BLOCK':
                    self.send_to_controller(action)
                print(f"[SURICATA] {action['threat_type']} from {action['source_ip']}")
        
        self.suricata.install_custom_rules()
        self.suricata.configure_suricata()
        self.suricata.start_suricata()
        self.suricata.monitor_alerts(alert_handler)
