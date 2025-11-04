# Attack Scenario Justification & Demonstration Strategy

## Executive Summary

This document provides faculty justification for the attack scenarios demonstrated in the SDN-NIDPS project, addressing the realistic nature of demonstrations in a controlled 2-day deployment window.

## Why These Specific Scenarios?

### 1. STRIDE-Based Coverage (100% Coverage)

| STRIDE Category            | Attack Scenarios                                   | Real-World Relevance                                     |
| -------------------------- | -------------------------------------------------- | -------------------------------------------------------- |
| **Spoofing**               | ARP Spoofing, IP Spoofing, DNS Spoofing            | MAC address spoofing causes 25% of internal breaches     |
| **Tampering**              | Packet Injection, Session Hijacking, Log Poisoning | Critical for maintaining data integrity (CWE-116)        |
| **Repudiation**            | Log Deletion, Timestamp Tampering                  | Required for legal compliance (HIPAA, PCI-DSS)           |
| **Information Disclosure** | Nmap Scanning, Banner Grabbing, Sniffing           | 94% of breaches involve reconnaissance (Verizon DBIR)    |
| **Denial of Service**      | SYN Flood, UDP Flood, HTTP Flood, Slowloris        | DDoS attacks increased 380% in 2020-2023                 |
| **Elevation of Privilege** | Brute Force, SQL Injection, XSS, Command Injection | Privilege escalation found in 90% of compromises (MITRE) |

### 2. Cyber Kill Chain Alignment

Our demonstration follows the established **Cyber Kill Chain** (Lockheed Martin):

Phase 1: Reconnaissance

↓

Phase 2: Initial Access

↓

Phase 3: Lateral Movement

↓

Phase 4: Privilege Escalation

↓

Phase 5: Data Exfiltration

↓

Phase 6: Defense Evasion / Cover Tracks

Each phase is detectable by our SDN-NIDPS system at different network layers.

## External Attack Justification

### Why External Attacks Are Included:

1. **Statistically Valid**:

   * 43% of attacks originate from external sources (Verizon DBIR)
   * Network-level attacks are most common entry vector

2. **Easy to Demonstrate**:

   * Uses well-known tools (Nmap, Hping3, etc.)
   * Can be simulated in Mininet without modification
   * Clear detection signatures for IDS/IPS

3. **Demonstrates First Layer of Defense**:

   * Shows how SDN + IDS blocks basic attacks
   * Builds confidence in system capabilities
   * Shows real-time response to threats

### External Attack Scenarios in Demo:

┌─────────────────────┐
│ EXTERNAL NETWORK    │
│ (Attacker)          │
└────────────┬────────┘

1. DNS Enumeration (detected)
2. Network Scanning (detected)
3. Port Scanning (detected)
4. Service Banner Grabbing (detected)
5. SSH Brute Force (detected)
6. SQL Injection Attempts (detected)
7. DDoS Attacks (blocked)

↓

┌────────────────────┐
│  FIREWALL + IDS    │ ← SDN-NIDPS
│   (Blocks Attack)  │
└────────────────────┘
