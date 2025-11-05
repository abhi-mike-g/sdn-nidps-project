"""
Distributed Threat Detection System
Coordinates threat detection across multiple nodes
"""

import json
import time
import redis
import threading
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DistributedThreatDetection:
    """Distributed threat detection coordination"""
    
    def __init__(self, redis_host='localhost', node_id='node1'):
        self.redis_client = redis.Redis(host=redis_host, decode_responses=True)
        self.node_id = node_id
        self.local_cache = {}
        self.threat_subscribers = []
    
    def report_threat(self, source_ip, threat_type, severity, details=None):
        """Report threat to distributed system"""
        threat_data = {
            'source_ip': source_ip,
            'threat_type': threat_type,
            'severity': severity,
            'details': details or {},
            'timestamp': time.time(),
            'detected_by': self.node_id
        }
        
        # Store in Redis
        threat_key = f"threat:{source_ip}:{int(time.time())}"
        self.redis_client.setex(threat_key, 3600, json.dumps(threat_data))
        
        # Publish to threat feed
        self.redis_client.publish('threat_feed', json.dumps(threat_data))
        
        # Update blocklist if critical
        if severity == 'CRITICAL':
            self.redis_client.sadd('blocklist', source_ip)
            self.redis_client.expire(f"blocklist:{source_ip}", 3600)
        
        logger.info(f"Reported threat: {threat_type} from {source_ip}")
    
    def check_threat_distributed(self, source_ip):
        """Check if IP is marked as threat"""
        # Check local cache first
        if source_ip in self.local_cache:
            return self.local_cache[source_ip]
        
        # Check distributed blocklist
        if self.redis_client.sismember('blocklist', source_ip):
            threat_data = {
                'source_ip': source_ip,
                'blocked': True,
                'cache_hit': True
            }
            self.local_cache[source_ip] = threat_data
            return threat_data
        
        return None
    
    def correlate_threats(self, time_window=300):
        """Correlate threats from multiple nodes"""
        correlations = defaultdict(list)
        
        for key in self.redis_client.scan_iter("threat:*"):
            threat_str = self.redis_client.get(key)
            if threat_str:
                threat = json.loads(threat_str)
                source_ip = threat['source_ip']
                correlations[source_ip].append(threat)
        
        # Analyze correlations
        critical_threats = []
        for source_ip, threats in correlations.items():
            if len(threats) > 5:  # Multiple threats from same source
                severity = 'CRITICAL'
                critical_threats.append({
                    'source_ip': source_ip,
                    'threat_count': len(threats),
                    'severity': severity,
                    'recommended_action': 'BLOCK'
                })
        
        logger.info(f"Correlated {len(correlations)} threat sources")
        return critical_threats
    
    def subscribe_threat_feed(self, callback):
        """Subscribe to distributed threat feed"""
        pubsub = self.redis_client.pubsub()
        pubsub.subscribe('threat_feed')
        
        def listener():
            for message in pubsub.listen():
                if message['type'] == 'message':
                    threat_data = json.loads(message['data'])
                    callback(threat_data)
        
        thread = threading.Thread(target=listener, daemon=True)
        thread.start()
    
    def sync_threat_data(self):
        """Synchronize threat data across nodes"""
        threats = []
        for key in self.redis_client.scan_iter("threat:*"):
            threat_str = self.redis_client.get(key)
            if threat_str:
                threats.append(json.loads(threat_str))
        
        return threats
