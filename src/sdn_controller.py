from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.lib import hub
import json
import time
from collections import defaultdict
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ThreatDetector:
    """Integrated threat detection engine"""
    
    def __init__(self):
        self.port_scan_threshold = 10  # ports per second
        self.syn_flood_threshold = 100  # packets per second
        self.failed_auth_threshold = 5  # attempts per minute
        
        # Track suspicious activities
        self.port_scans = defaultdict(lambda: {'ports': set(), 'timestamp': 0})
        self.syn_counts = defaultdict(lambda: {'count': 0, 'timestamp': 0})
        self.failed_auths = defaultdict(lambda: {'count': 0, 'timestamp': 0})
        self.arp_table = {}  # MAC-IP binding
        self.blocked_hosts = set()
        
        # Attack signatures
        self.attack_patterns = {
            'nmap_scan': self._detect_nmap_scan,
            'syn_flood': self._detect_syn_flood,
            'arp_spoof': self._detect_arp_spoof,
            'brute_force': self._detect_brute_force,
            'sql_injection': self._detect_sql_injection
        }
        
    def _detect_nmap_scan(self, src_ip, dst_port, timestamp):
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
            return {
                'threat': 'Port Scan (Nmap)',
                'severity': 'HIGH',
                'source': src_ip,
                'ports_scanned': len(scan_data['ports']),
                'action': 'BLOCK'
            }
        return None
    
    def _detect_syn_flood(self, src_ip, timestamp):
        """Detect SYN flood attacks (hping3 style)"""
        current_time = time.time()
        syn_data = self.syn_counts[src_ip]
        
        if current_time - syn_data['timestamp'] > 1:  # 1 second window
            syn_data['count'] = 0
            syn_data['timestamp'] = current_time
            
        syn_data['count'] += 1
        
        if syn_data['count'] > self.syn_flood_threshold:
            return {
                'threat': 'SYN Flood (DDoS)',
                'severity': 'CRITICAL',
                'source': src_ip,
                'packet_rate': syn_data['count'],
                'action': 'BLOCK'
            }
        return None
    
    def _detect_arp_spoof(self, src_mac, src_ip):
        """Detect ARP spoofing (Ettercap style)"""
        if src_ip in self.arp_table:
            if self.arp_table[src_ip] != src_mac:
                return {
                    'threat': 'ARP Spoofing',
                    'severity': 'CRITICAL',
                    'source_ip': src_ip,
                    'original_mac': self.arp_table[src_ip],
                    'spoofed_mac': src_mac,
                    'action': 'BLOCK'
                }
        else:
            self.arp_table[src_ip] = src_mac
        return None
    
    def _detect_brute_force(self, src_ip, auth_success):
        """Detect brute force attempts (Hydra style)"""
        current_time = time.time()
        auth_data = self.failed_auths[src_ip]
        
        if current_time - auth_data['timestamp'] > 60:  # 1 minute window
            auth_data['count'] = 0
            auth_data['timestamp'] = current_time
        
        if not auth_success:
            auth_data['count'] += 1
            
            if auth_data['count'] > self.failed_auth_threshold:
                return {
                    'threat': 'Brute Force Attack',
                    'severity': 'HIGH',
                    'source': src_ip,
                    'failed_attempts': auth_data['count'],
                    'action': 'BLOCK'
                }
        return None
    
    def _detect_sql_injection(self, payload):
        """Detect SQL injection attempts (SQLMap style)"""
        sql_patterns = [
            "' OR '1'='1",
            "'; DROP TABLE",
            "UNION SELECT",
            "1' AND '1'='1",
            "<script>",
            "javascript:",
            "../../../"
        ]
        
        payload_str = str(payload).lower()
        for pattern in sql_patterns:
            if pattern.lower() in payload_str:
                return {
                    'threat': 'SQL Injection Attempt',
                    'severity': 'CRITICAL',
                    'pattern': pattern,
                    'action': 'BLOCK'
                }
        return None


class SDNSecurityController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}
    
    def __init__(self, *args, **kwargs):
        super(SDNSecurityController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.threat_detector = ThreatDetector()
        self.threat_log = []
        
        # Start monitoring thread
        self.monitor_thread = hub.spawn(self._monitor)
        
        # Register REST API
        wsgi = kwargs['wsgi']
        wsgi.register(SecurityAPIController, {'controller': self})
        
        logger.info("SDN Security Controller initialized")
    
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change_handler(self, ev):
        """Handle switch connection events"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
                logger.info(f"Switch {datapath.id} connected")
        elif ev.state == 'DEAD':
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]
                logger.warning(f"Switch {datapath.id} disconnected")
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        logger.info(f"Switch {datapath.id} configured with table-miss entry")
    
    def add_flow(self, datapath, priority, match, actions, buffer_id=None,
                 idle_timeout=0, hard_timeout=0):
        """Install flow rule"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        datapath.send_msg(mod)
    
    def block_host(self, datapath, src_ip):
        """Block malicious host"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Drop all packets from this IP
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
        actions = []  # Empty actions = drop
        self.add_flow(datapath, 100, match, actions, hard_timeout=300)
        
        self.threat_detector.blocked_hosts.add(src_ip)
        logger.warning(f"BLOCKED malicious host: {src_ip}")
    
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Handle incoming packets"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        
        # Ignore LLDP packets
        if eth.ethertype == 0x88cc:
            return
        
        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        self.mac_to_port.setdefault(dpid, {})
        
        # Threat detection logic
        threat_detected = None
        
        # Check for ARP spoofing
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            threat_detected = self.threat_detector._detect_arp_spoof(
                arp_pkt.src_mac, arp_pkt.src_ip
            )
        
        # Check for TCP-based attacks
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            # Check if already blocked
            if src_ip in self.threat_detector.blocked_hosts:
                return  # Drop packet silently
            
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            if tcp_pkt:
                # Check for port scanning
                threat_detected = self.threat_detector._detect_nmap_scan(
                    src_ip, tcp_pkt.dst_port, time.time()
                )
                
                # Check for SYN flood
                if tcp_pkt.has_flags(tcp.TCP_SYN) and not tcp_pkt.has_flags(tcp.TCP_ACK):
                    syn_threat = self.threat_detector._detect_syn_flood(
                        src_ip, time.time()
                    )
                    if syn_threat:
                        threat_detected = syn_threat
                
                # Check for SQL injection in payload
                if tcp_pkt.dst_port in [80, 443, 8080]:  # HTTP ports
                    sql_threat = self.threat_detector._detect_sql_injection(
                        msg.data
                    )
                    if sql_threat:
                        sql_threat['source'] = src_ip
                        threat_detected = sql_threat
        
        # Handle threat
        if threat_detected:
            threat_detected['timestamp'] = time.time()
            threat_detected['switch_id'] = dpid
            threat_detected['in_port'] = in_port
            self.threat_log.append(threat_detected)
            
            logger.warning(f"THREAT DETECTED: {json.dumps(threat_detected, indent=2)}")
            
            if threat_detected['action'] == 'BLOCK':
                self.block_host(datapath, threat_detected['source'])
            return  # Stop processing this packet
        
        # Learn MAC address to avoid FLOOD next time
        self.mac_to_port[dpid][src] = in_port
        
        # Determine output port
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]
        
        # Install flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions, idle_timeout=30)
        
        # Send packet out
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                   in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
    
    def _monitor(self):
        """Background monitoring thread"""
        while True:
            hub.sleep(10)
            logger.info(f"Active threats logged: {len(self.threat_log)}")
            logger.info(f"Blocked hosts: {len(self.threat_detector.blocked_hosts)}")
    
    def get_threats(self, limit=100):
        """Get recent threats"""
        return self.threat_log[-limit:]
    
    def get_blocked_hosts(self):
        """Get list of blocked hosts"""
        return list(self.threat_detector.blocked_hosts)


class SecurityAPIController(ControllerBase):
    """REST API for security monitoring"""
    
    def __init__(self, req, link, data, **config):
        super(SecurityAPIController, self).__init__(req, link, data, **config)
        self.controller = data['controller']
    
    @route('security', '/api/threats', methods=['GET'])
    def get_threats(self, req, **kwargs):
        """Get recent threats"""
        limit = int(req.GET.get('limit', 100))
        threats = self.controller.get_threats(limit)
        return Response(content_type='application/json',
                       body=json.dumps(threats, indent=2))
    
    @route('security', '/api/blocked', methods=['GET'])
    def get_blocked(self, req, **kwargs):
        """Get blocked hosts"""
        blocked = self.controller.get_blocked_hosts()
        return Response(content_type='application/json',
                       body=json.dumps({'blocked_hosts': blocked}, indent=2))
    
    @route('security', '/api/stats', methods=['GET'])
    def get_stats(self, req, **kwargs):
        """Get security statistics"""
        threats = self.controller.get_threats()
        
        threat_types = defaultdict(int)
        severity_counts = defaultdict(int)
        
        for threat in threats:
            threat_types[threat['threat']] += 1
            severity_counts[threat['severity']] += 1
        
        stats = {
            'total_threats': len(threats),
            'threat_types': dict(threat_types),
            'severity_distribution': dict(severity_counts),
            'blocked_hosts': len(self.controller.get_blocked_hosts())
        }
        
        return Response(content_type='application/json',
                       body=json.dumps(stats, indent=2))


from werkzeug.wrappers import Response
