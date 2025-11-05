"""
Load Balancer for Distributed SDN Controllers
"""

import json
import time
import redis
from collections import defaultdict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class LoadBalancer:
    """Load balance across multiple SDN controllers"""
    
    def __init__(self, redis_host='localhost', redis_port=6379):
        self.redis_client = redis.Redis(host=redis_host, port=redis_port, decode_responses=True)
        self.controller_metrics = {}
        self.load_history = defaultdict(list)
    
    def register_controller(self, controller_id, ip, port):
        """Register a controller instance"""
        controller_info = {
            'id': controller_id,
            'ip': ip,
            'port': port,
            'timestamp': time.time(),
            'status': 'active'
        }
        
        key = f"controller:{controller_id}"
        self.redis_client.setex(key, 60, json.dumps(controller_info))
        logger.info(f"Registered controller: {controller_id}")
    
    def get_active_controllers(self):
        """Get list of active controllers"""
        controllers = []
        for key in self.redis_client.scan_iter("controller:*"):
            controller_data = self.redis_client.get(key)
            if controller_data:
                controllers.append(json.loads(controller_data))
        return controllers
    
    def get_controller_load(self, controller_id):
        """Get current load of a controller"""
        key = f"controller:{controller_id}:metrics"
        metrics = self.redis_client.get(key)
        
        if metrics:
            data = json.loads(metrics)
            return {
                'queue_size': data.get('queue_size', 0),
                'cpu_usage': data.get('cpu_usage', 0),
                'memory_usage': data.get('memory_usage', 0),
                'active_flows': data.get('active_flows', 0)
            }
        
        return {'queue_size': 0, 'cpu_usage': 0, 'memory_usage': 0, 'active_flows': 0}
    
    def select_best_controller(self, switch_id=None):
        """Select best controller for a switch"""
        controllers = self.get_active_controllers()
        
        if not controllers:
            logger.warning("No active controllers available")
            return None
        
        best_controller = None
        lowest_load = float('inf')
        
        for controller in controllers:
            metrics = self.get_controller_load(controller['id'])
            # Calculate composite load score
            load_score = (
                metrics['queue_size'] * 0.4 +
                metrics['cpu_usage'] * 0.3 +
                metrics['active_flows'] * 0.3
            )
            
            if load_score < lowest_load:
                lowest_load = load_score
                best_controller = controller
        
        logger.info(f"Selected controller {best_controller['id']} for switch {switch_id}")
        return best_controller
    
    def rebalance_switches(self):
        """Rebalance switches across controllers"""
        controllers = self.get_active_controllers()
        
        if len(controllers) < 2:
            return
        
        logger.info("Starting load rebalancing...")
        
        # Calculate average load
        loads = []
        for controller in controllers:
            metrics = self.get_controller_load(controller['id'])
            load_score = metrics['queue_size'] + metrics['cpu_usage']
            loads.append(load_score)
        
        avg_load = sum(loads) / len(loads) if loads else 0
        
        # Identify overloaded and underloaded controllers
        overloaded = [c for i, c in enumerate(controllers) if loads[i] > avg_load * 1.5]
        underloaded = [c for i, c in enumerate(controllers) if loads[i] < avg_load * 0.5]
        
        logger.info(f"Overloaded: {len(overloaded)}, Underloaded: {len(underloaded)}")
        
        # Migrate flows from overloaded to underloaded
        for over_ctrl in overloaded:
            if underloaded:
                under_ctrl = underloaded[0]
                self._migrate_flows(over_ctrl['id'], under_ctrl['id'])
    
    def _migrate_flows(self, from_controller, to_controller):
        """Migrate flows between controllers"""
        logger.info(f"Migrating flows from {from_controller} to {to_controller}")
        
        # Store migration record
        migration = {
            'from': from_controller,
            'to': to_controller,
            'timestamp': time.time()
        }
        
        self.redis_client.lpush('migrations', json.dumps(migration))
    
    def get_statistics(self):
        """Get load balancer statistics"""
        controllers = self.get_active_controllers()
        stats = {
            'total_controllers': len(controllers),
            'controllers': []
        }
        
        for controller in controllers:
            metrics = self.get_controller_load(controller['id'])
            stats['controllers'].append({
                'id': controller['id'],
                'ip': controller['ip'],
                'port': controller['port'],
                'metrics': metrics
            })
        
        return stats
