"""
Multi-Controller Synchronization
Ensures consistency across distributed SDN controllers
"""

import json
import time
import redis
import threading
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ControllerSync:
    """Synchronizes state across controllers"""
    
    def __init__(self, controller_id, redis_host='localhost'):
        self.controller_id = controller_id
        self.redis_client = redis.Redis(host=redis_host, decode_responses=True)
        self.flow_rules = {}
        self.blocked_hosts = set()
    
    def register_controller(self):
        """Register this controller in distributed system"""
        controller_info = {
            'id': self.controller_id,
            'timestamp': time.time(),
            'status': 'active'
        }
        
        key = f"controller:{self.controller_id}"
        self.redis_client.setex(key, 30, json.dumps(controller_info))
        
        logger.info(f"Controller {self.controller_id} registered")
    
    def share_flow_rule(self, flow_rule):
        """Share flow rule with other controllers"""
        rule_data = {
            'controller_id': self.controller_id,
            'rule': flow_rule,
            'timestamp': time.time()
        }
        
        rule_key = f"flow_rule:{flow_rule.get('id')}"
        self.redis_client.set(rule_key, json.dumps(rule_data))
        self.redis_client.expire(rule_key, 3600)
        
        # Publish update
        self.redis_client.publish('flow_updates', json.dumps(rule_data))
    
    def sync_blocked_hosts(self, blocked_hosts):
        """Synchronize blocked hosts list"""
        for host in blocked_hosts:
            self.redis_client.sadd('global_blocklist', host)
            self.redis_client.expire(f"blocked:{host}", 3600)
        
        self.redis_client.publish('blocklist_update', json.dumps({
            'hosts': list(blocked_hosts),
            'timestamp': time.time()
        }))
    
    def get_global_blocklist(self):
        """Get globally blocked hosts"""
        blocked = self.redis_client.smembers('global_blocklist')
        return blocked
    
    def handle_flow_updates(self, callback):
        """Listen for flow rule updates from other controllers"""
        pubsub = self.redis_client.pubsub()
        pubsub.subscribe('flow_updates')
        
        def listener():
            for message in pubsub.listen():
                if message['type'] == 'message':
                    update = json.loads(message['data'])
                    if update['controller_id'] != self.controller_id:
                        callback(update)
        
        thread = threading.Thread(target=listener, daemon=True)
        thread.start()
    
    def get_controller_status(self):
        """Get status of all controllers"""
        status = {}
        for key in self.redis_client.scan_iter("controller:*"):
            controller_str = self.redis_client.get(key)
            if controller_str:
                controller = json.loads(controller_str)
                status[controller['id']] = controller
        
        return status
