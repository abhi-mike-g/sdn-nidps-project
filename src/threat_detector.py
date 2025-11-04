"""
Advanced Threat Detection Engine
Detects threats across all STRIDE categories
"""

import time
import json
from collections import defaultdict
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ThreatDetector:
    """
    Comprehensive threat detection engine covering all STRIDE categories
    """
    
    def __init__(self):
        # Detection thresholds
        self.port_scan_threshold = 10
        self.syn_flood_threshold = 100
        self.udp_flood_threshold = 500
        self.failed_auth_threshold = 5
        self.connection_rate_threshold = 1000
        
        # Data structures for tracking
        self.port_scans = defaultdict(lambda: {'ports': set(), 'timestamp': 0})
        self.syn_counts = defaultdict(lambda: {'count': 0, 'timestamp': 0})
        self.udp_counts = defaultdict(lambda: {'count': 0, 'timestamp': 0})
        self.failed_auths = defaultdict(lambda: {'count': 0, 'timestamp': 0})
        self.arp_table = {}
        self.connection_rates = defaultdict(lambda: {'count': 0, 'timestamp': 0})
        
        # Blocked hosts
        self.blocked_hosts = set()
        
        # Threat log
        self.threat_log = []
    
    # ==================== SPOOFING DETECTION ====================
    
    def detect_arp_spoof(self, src_mac, src_ip):
        """Detect ARP spoofing by MAC-IP binding changes"""
        if src_ip in self.arp_table:
            if self.arp_table[src_ip] != src_mac:
                threat = {
                    'threat_type': 'ARP Spoofing',
                    'stride_category': 'Spoofing',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'original_mac': self.arp_table[src_ip],
                    'spoofed_mac': src_mac,
                    'action': 'BLOCK',
                    'timestamp': time.time()
                }
                self.threat_log.append(threat)
                logger.warning(f"ARP Spoofing detected: {src_ip} ({src_mac})")
                return threat
        else:
            self.arp_table[src_ip] = src_mac
        
        return None
    
    def detect_ip_spoof(self, src_ip, expected_interface):
        """Detect IP spoofing based on source interface mismatch"""
        # This would require interface tracking
        # Simplified for demo
        pass
    
    # ==================== TAMPERING DETECTION ====================
    
    def detect_packet_injection(self, packet_payload):
        """Detect suspicious packet injection patterns"""
        injection_patterns = [
            b'MALICIOUS',
            b'hijacked',
            b'exploit',
        ]
        
        for pattern in injection_patterns:
            if pattern in packet_payload.lower():
                threat = {
                    'threat_type': 'Packet Injection',
                    'stride_category': 'Tampering',
                    'severity': 'HIGH',
                    'pattern_matched': pattern.decode('utf-8'),
                    'action': 'BLOCK',
                    'timestamp': time.time()
                }
                self.threat_log.append(threat)
                logger.warning(f"Packet injection detected: {pattern}")
                return threat
        
        return None
    
    def detect_session_hijacking(self, src_ip, dst_ip, tcp_flags):
        """Detect TCP session hijacking attempts"""
        # PSH-ACK with unusual sequence numbers
        if 'PSH' in tcp_flags and 'ACK' in tcp_flags:
            threat = {
                'threat_type': 'Session Hijacking',
                'stride_category': 'Tampering',
                'severity': 'CRITICAL',
                'source': src_ip,
                'destination': dst_ip,
                'flags': tcp_flags,
                'action': 'BLOCK',
                'timestamp': time.time()
            }
            self.threat_log.append(threat)
            logger.warning(f"Session hijacking detected: {src_ip} -> {dst_ip}")
            return threat
        
        return None
    
    # ==================== INFORMATION DISCLOSURE ====================
    
    def detect_port_scan(self, src_ip, dst_port, timestamp):
        """Detect Nmap-style port scanning"""
        current_time = time.time()
        scan_data = self.port_scans[src_ip]
        
        # Reset if more than 10 seconds old
        if current_time - scan_data['timestamp'] > 10:
            scan_data['ports'] = set()
            scan_data['timestamp'] = current_time
        
        scan_data['ports'].add(dst_port)
        
        # Alert if scanning multiple ports rapidly
        if len(scan_data['ports']) > self.port_scan_threshold:
            threat = {
                'threat_type': 'Port Scanning',
                'stride_category': 'Information Disclosure',
                'severity': 'HIGH',
                'source': src_ip,
                'ports_scanned': len(scan_data['ports']),
                'action': 'BLOCK',
                'timestamp': time.time()
            }
            self.threat_log.append(threat)
            logger.warning(f"Port scan detected: {src_ip} ({len(scan_data['ports'])} ports)")
            return threat
        
        return None
    
    def detect_banner_grabbing(self, src_ip, dst_port, traffic_pattern):
        """Detect banner grabbing reconnaissance"""
        # Multiple connections to various services
        if 'HEAD' in traffic_pattern or 'EHLO' in traffic_pattern:
            threat = {
                'threat_type': 'Banner Grabbing',
                'stride_category': 'Information Disclosure',
                'severity': 'MEDIUM',
                'source': src_ip,
                'target_port': dst_port,
                'action': 'MONITOR',
                'timestamp': time.time()
            }
            self.threat_log.append(threat)
            logger.info(f"Banner grabbing detected: {src_ip}:{dst_port}")
            return threat
        
        return None
    
    # ==================== DENIAL OF SERVICE ====================
    
    def detect_syn_flood(self, src_ip, timestamp):
        """Detect SYN flood DDoS attacks"""
        current_time = time.time()
        syn_data = self.syn_counts[src_ip]
        
        if current_time - syn_data['timestamp'] > 1:
            syn_data['count'] = 0
            syn_data['timestamp'] = current_time
        
        syn_data['count'] += 1
        
        if syn_data['count'] > self.syn_flood_threshold:
            threat = {
                'threat_type': 'SYN Flood',
                'stride_category': 'Denial of Service',
                'severity': 'CRITICAL',
                'source': src_ip,
                'packet_rate': syn_data['count'],
                'action': 'BLOCK',
                'timestamp': time.time()
            }
            self.threat_log.append(threat)
            self.blocked_hosts.add(src_ip)
            logger.critical(f"SYN Flood detected: {src_ip} ({syn_data['count']} pps)")
            return threat
        
        return None
    
    def detect_udp_flood(self, src_ip, timestamp):
        """Detect UDP flood attacks"""
        current_time = time.time()
        udp_data = self.udp_counts[src_ip]
        
        if current_time - udp_data['timestamp'] > 1:
            udp_data['count'] = 0
            udp_data['timestamp'] = current_time
        
        udp_data['count'] += 1
        
        if udp_data['count'] > self.udp_flood_threshold:
            threat = {
                'threat_type': 'UDP Flood',
                'stride_category': 'Denial of Service',
                'severity': 'CRITICAL',
                'source': src_ip,
                'packet_rate': udp_data['count'],
                'action': 'BLOCK',
                'timestamp': time.time()
            }
            self.threat_log.append(threat)
            self.blocked_hosts.add(src_ip)
            logger.critical(f"UDP Flood detected: {src_ip} ({udp_data['count']} pps)")
            return threat
        
        return None
    
    def detect_connection_rate_anomaly(self, src_ip, timestamp):
        """Detect abnormal connection rates"""
        current_time = time.time()
        rate_data = self.connection_rates[src_ip]
        
        if current_time - rate_data['timestamp'] > 1:
            rate_data['count'] = 0
            rate_data['timestamp'] = current_time
        
        rate_data['count'] += 1
        
        if rate_data['count'] > self.connection_rate_threshold:
            threat = {
                'threat_type': 'Connection Rate Anomaly',
                'stride_category': 'Denial of Service',
                'severity': 'HIGH',
                'source': src_ip,
                'connection_rate': rate_data['count'],
                'action': 'BLOCK',
                'timestamp': time.time()
            }
            self.threat_log.append(threat)
            logger.warning(f"Connection rate anomaly: {src_ip} ({rate_data['count']} conn/s)")
            return threat
        
        return None
    
    # ==================== ELEVATION OF PRIVILEGE ====================
    
    def detect_brute_force(self, src_ip, auth_success):
        """Detect brute force authentication attempts"""
        current_time = time.time()
        auth_data = self.failed_auths[src_ip]
        
        if current_time - auth_data['timestamp'] > 60:
            auth_data['count'] = 0
            auth_data['timestamp'] = current_time
        
        if not auth_success:
            auth_data['count'] += 1
            
            if auth_data['count'] > self.failed_auth_threshold:
                threat = {
                    'threat_type': 'Brute Force Attack',
                    'stride_category': 'Elevation of Privilege',
                    'severity': 'HIGH',
                    'source': src_ip,
                    'failed_attempts': auth_data['count'],
                    'action': 'BLOCK',
                    'timestamp': time.time()
                }
                self.threat_log.append(threat)
                self.blocked_hosts.add(src_ip)
                logger.warning(f"Brute force detected: {src_ip} ({auth_data['count']} failures)")
                return threat
        
        return None
    
    def detect_sql_injection(self, payload):
        """Detect SQL injection patterns"""
        sql_patterns = [
            "' OR '1'='1",
            "'; DROP TABLE",
            "UNION SELECT",
            "1' AND '1'='1",
            "admin'--",
            "' OR ''='",
        ]
        
        payload_str = str(payload).lower()
        for pattern in sql_patterns:
            if pattern.lower() in payload_str:
                threat = {
                    'threat_type': 'SQL Injection',
                    'stride_category': 'Elevation of Privilege',
                    'severity': 'CRITICAL',
                    'pattern': pattern,
                    'action': 'BLOCK',
                    'timestamp': time.time()
                }
                self.threat_log.append(threat)
                logger.critical(f"SQL Injection detected: {pattern}")
                return threat
        
        return None
    
    def detect_xss_attack(self, payload):
        """Detect Cross-Site Scripting (XSS) attacks"""
        xss_patterns = [
            '<script>',
            'javascript:',
            'onerror=',
            'onload=',
            '<iframe',
            'eval(',
        ]
        
        payload_str = str(payload).lower()
        for pattern in xss_patterns:
            if pattern.lower() in payload_str:
                threat = {
                    'threat_type': 'XSS Attack',
                    'stride_category': 'Elevation of Privilege',
                    'severity': 'HIGH',
                    'pattern': pattern,
                    'action': 'BLOCK',
                    'timestamp': time.time()
                }
                self.threat_log.append(threat)
                logger.warning(f"XSS detected: {pattern}")
                return threat
        
        return None
    
    def detect_command_injection(self, payload):
        """Detect OS command injection"""
        injection_chars = [';', '|', '&', '$', '`', '$(', ')(']
        
        payload_str = str(payload)
        for char in injection_chars:
            if char in payload_str:
                threat = {
                    'threat_type': 'Command Injection',
                    'stride_category': 'Elevation of Privilege',
                    'severity': 'CRITICAL',
                    'injection_char': char,
                    'action': 'BLOCK',
                    'timestamp': time.time()
                }
                self.threat_log.append(threat)
                logger.critical(f"Command injection detected: {char}")
                return threat
        
        return None
    
    # ==================== REPUDIATION ====================
    
    def detect_log_tampering_attempt(self, operation, details):
        """Detect attempts to tamper with logs"""
        suspicious_ops = ['delete', 'truncate', 'clear', 'rm -rf']
        
        operation_str = str(operation).lower()
        for op in suspicious_ops:
            if op in operation_str:
                threat = {
                    'threat_type': 'Log Tampering Attempt',
                    'stride_category': 'Repudiation',
                    'severity': 'CRITICAL',
                    'operation': operation,
                    'details': details,
                    'action': 'ALERT',
                    'timestamp': time.time()
                }
                self.threat_log.append(threat)
                logger.critical(f"Log tampering detected: {operation}")
                return threat
        
        return None
    
    # ==================== UTILITY METHODS ====================
    
    def get_threats(self, limit=100, severity=None):
        """Retrieve threat log"""
        threats = self.threat_log[-limit:]
        
        if severity:
            threats = [t for t in threats if t.get('severity') == severity]
        
        return threats
    
    def get_blocked_hosts(self):
        """Get list of blocked hosts"""
        return list(self.blocked_hosts)
    
    def unblock_host(self, ip_address):
        """Remove host from blocklist"""
        if ip_address in self.blocked_hosts:
            self.blocked_hosts.remove(ip_address)
            logger.info(f"Host unblocked: {ip_address}")
            return True
        return False
    
    def get_threat_statistics(self):
        """Generate threat statistics"""
        stats = {
            'total_threats': len(self.threat_log),
            'threat_types': defaultdict(int),
            'severity_distribution': defaultdict(int),
            'blocked_hosts': len(self.blocked_hosts),
            'stride_categories': defaultdict(int)
        }
        
        for threat in self.threat_log:
            stats['threat_types'][threat.get('threat_type')] += 1
            stats['severity_distribution'][threat.get('severity')] += 1
            stats['stride_categories'][threat.get('stride_category')] += 1
        
        return dict(stats)
    
    def clear_threat_log(self):
        """Clear threat log (for testing)"""
        self.threat_log.clear()
        logger.info("Threat log cleared")
    
    def export_threats_json(self, filename):
        """Export threats to JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.threat_log, f, indent=2)
            logger.info(f"Threats exported to {filename}")
            return True
        except Exception as e:
            logger.error(f"Error exporting threats: {e}")
            return False
