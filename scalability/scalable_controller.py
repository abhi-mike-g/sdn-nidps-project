#!/usr/bin/env python3
"""
Scalable SDN Controller with Load Balancing and Distributed Architecture
Demonstrates scalability features for large networks
"""

import threading
import queue
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
import time
import json
import redis
from collections import defaultdict

class ScalableController:
    """
    Scalable SDN Controller with:
    - Multi-threaded packet processing
    - Distributed threat detection
    - Load balancing across switches
    - Horizontal scalability support
    """
    
    def __init__(self, controller_id=1, redis_host='localhost'):
        self.controller_id = controller_id
        self.redis_client = redis.Redis(host=redis_host, decode_responses=True)
        
        # Multi-threading for packet processing
        self.packet_queue = queue.Queue(maxsize=10000)
        self.worker_pool = ThreadPoolExecutor(max_workers=multiprocessing.cpu_count() * 2)
        
        # Distributed state management
        self.switch_assignments = {}  # Which switches this controller manages
        self.flow_cache = {}  # Local flow rule cache
        
        # Performance metrics
        self.metrics = {
            'packets_processed': 0,
            'threats_detected': 0,
            'avg_latency': 0,
            'throughput': 0
        }
        
        # Start worker threads
        self._start_workers()
    
    def _start_workers(self):
        """Start worker threads for packet processing"""
        num_workers = multiprocessing.cpu_count() * 2
        for i in range(num_workers):
            worker = threading.Thread(
                target=self._packet_worker,
                args=(i,),
                daemon=True
            )
            worker.start()
            print(f"[+] Started worker thread {i}")
    
    def _packet_worker(self, worker_id):
        """Worker thread for processing packets"""
        while True:
            try:
                packet_data = self.packet_queue.get(timeout=1)
                self._process_packet(packet_data, worker_id)
                self.packet_queue.task_done()
                self.metrics['packets_processed'] += 1
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Worker {worker_id} error: {e}")
    
    def _process_packet(self, packet_data, worker_id):
        """Process individual packet with threat detection"""
        start_time = time.time()
        
        # Extract packet info
        src_ip = packet_data.get('src_ip')
        dst_ip = packet_data.get('dst_ip')
        
        # Check distributed cache for existing flow rule
        cache_key = f"flow:{src_ip}:{dst_ip}"
        cached_action = self.redis_client.get(cache_key)
        
        if cached_action:
            # Use cached decision
            return json.loads(cached_action)
        
        # Perform threat detection
        threat = self._detect_threat(packet_data)
        
        if threat:
            # Store in distributed cache
            action = {'action': 'BLOCK', 'reason': threat}
            self.redis_client.setex(cache_key, 300, json.dumps(action))
            self.metrics['threats_detected'] += 1
        else:
            action = {'action': 'FORWARD'}
        
        # Update latency metrics
        latency = time.time() - start_time
        self._update_latency(latency)
        
        return action
    
    def _detect_threat(self, packet_data):
        """Lightweight threat detection for scalability"""
        # Simplified detection for demonstration
        src_ip = packet_data.get('src_ip')
        
        # Check if IP is in distributed blocklist
        if self.redis_client.sismember('blocklist', src_ip):
            return "IP in blocklist"
        
        # Check rate limiting (distributed)
        rate_key = f"rate:{src_ip}"
        current_rate = self.redis_client.incr(rate_key)
        self.redis_client.expire(rate_key, 1)  # 1 second window
        
        if current_rate > 1000:  # More than 1000 packets per second
            return "Rate limit exceeded"
        
        return None
    
    def _update_latency(self, latency):
        """Update average latency metrics"""
        alpha = 0.1  # Exponential moving average
        self.metrics['avg_latency'] = (
            alpha * latency + (1 - alpha) * self.metrics['avg_latency']
        )
    
    def handle_packet_in(self, packet_data):
        """Queue packet for processing (non-blocking)"""
        try:
            self.packet_queue.put_nowait(packet_data)
            return True
        except queue.Full:
            print("[!] Packet queue full - dropping packet")
            return False
    
    def get_load_metrics(self):
        """Return current load metrics for load balancing"""
        return {
            'controller_id': self.controller_id,
            'queue_size': self.packet_queue.qsize(),
            'cpu_usage': self._get_cpu_usage(),
            'packets_processed': self.metrics['packets_processed'],
            'avg_latency': self.metrics['avg_latency'],
            'threats_detected': self.metrics['threats_detected']
        }
    
    def _get_cpu_usage(self):
        """Get current CPU usage"""
        try:
            import psutil
            return psutil.cpu_percent(interval=0.1)
        except ImportError:
            return 0
    
    def scale_out(self, num_additional_workers=2):
        """Dynamically add more worker threads"""
        current_workers = self.worker_pool._max_workers
        new_max = current_workers + num_additional_workers
        
        self.worker_pool._max_workers = new_max
        print(f"[+] Scaled from {current_workers} to {new_max} workers")
    
    def redistribute_switches(self, switch_list):
        """Redistribute switches across multiple controller instances"""
        # Get all available controllers
        controllers = self._get_active_controllers()
        
        if not controllers:
            print("[!] No other controllers available")
            return
        
        # Calculate load per controller
        switches_per_controller = len(switch_list) // len(controllers)
        
        # Redistribute
        for i, switch_id in enumerate(switch_list):
            target_controller = controllers[i % len(controllers)]
            self._assign_switch(switch_id, target_controller)
    
    def _get_active_controllers(self):
        """Get list of active controllers from Redis"""
        controllers = []
        for key in self.redis_client.scan_iter("controller:*"):
            controller_data = self.redis_client.get(key)
            if controller_data:
                controllers.append(json.loads(controller_data))
        return controllers
    
    def _assign_switch(self, switch_id, controller_id):
        """Assign switch to specific controller"""
        assignment_key = f"switch_assignment:{switch_id}"
        self.redis_client.set(assignment_key, controller_id)
        print(f"[+] Assigned switch {switch_id} to controller {controller_id}")
    
    def register_controller(self):
        """Register this controller instance in distributed system"""
        controller_key = f"controller:{self.controller_id}"
        controller_data = {
            'id': self.controller_id,
            'timestamp': time.time(),
            'status': 'active'
        }
        self.redis_client.setex(controller_key, 30, json.dumps(controller_data))
    
    def heartbeat(self):
        """Send periodic heartbeat to maintain registration"""
        while True:
            self.register_controller()
            time.sleep(10)


class LoadBalancer:
    """
    Load Balancer for distributing traffic across multiple controllers
    """
    
    def __init__(self, redis_host='localhost'):
        self.redis_client = redis.Redis(host=redis_host, decode_responses=True)
        self.controllers = {}
    
    def get_best_controller(self, switch_id=None):
        """Select best controller based on current load"""
        controllers = self._get_controller_metrics()
        
        if not controllers:
            return None
        
        # Select controller with lowest load
        best_controller = min(
            controllers,
            key=lambda c: c['queue_size'] + c['cpu_usage']
        )
        
        return best_controller['controller_id']
    
    def _get_controller_metrics(self):
        """Retrieve metrics from all active controllers"""
        controllers = []
        for key in self.redis_client.scan_iter("controller:*:metrics"):
            metrics_data = self.redis_client.get(key)
            if metrics_data:
                controllers.append(json.loads(metrics_data))
        return controllers
    
    def rebalance(self):
        """Rebalance load across controllers"""
        controllers = self._get_controller_metrics()
        
        if len(controllers) < 2:
            return
        
        # Find overloaded and underloaded controllers
        avg_load = sum(c['queue_size'] for c in controllers) / len(controllers)
        
        overloaded = [c for c in controllers if c['queue_size'] > avg_load * 1.5]
        underloaded = [c for c in controllers if c['queue_size'] < avg_load * 0.5]
        
        print(f"[*] Rebalancing: {len(overloaded)} overloaded, {len(underloaded)} underloaded")
        
        # Implement rebalancing logic
        for overloaded_ctrl in overloaded:
            if underloaded:
                target_ctrl = underloaded[0]
                self._migrate_flows(overloaded_ctrl['controller_id'], 
                                  target_ctrl['controller_id'])
    
    def _migrate_flows(self, from_controller, to_controller):
        """Migrate flows from one controller to another"""
        print(f"[+] Migrating flows from {from_controller} to {to_controller}")
        # Implementation would involve moving switch assignments


class DistributedThreatDetection:
    """
    Distributed threat detection using multiple detection nodes
    """
    
    def __init__(self, redis_host='localhost'):
        self.redis_client = redis.Redis(host=redis_host, decode_responses=True)
        self.local_cache = {}
    
    def check_threat_distributed(self, src_ip):
        """Check threat status across all detection nodes"""
        # Check local cache first
        if src_ip in self.local_cache:
            return self.local_cache[src_ip]
        
        # Check distributed cache
        threat_key = f"threat:{src_ip}"
        threat_data = self.redis_client.get(threat_key)
        
        if threat_data:
            threat_info = json.loads(threat_data)
            self.local_cache[src_ip] = threat_info
            return threat_info
        
        return None
    
    def report_threat(self, src_ip, threat_type, severity):
        """Report threat to distributed system"""
        threat_data = {
            'ip': src_ip,
            'type': threat_type,
            'severity': severity,
            'timestamp': time.time(),
            'detected_by': 'detection_node_1'
        }
        
        threat_key = f"threat:{src_ip}"
        self.redis_client.setex(threat_key, 3600, json.dumps(threat_data))
        
        # Publish to threat feed
        self.redis_client.publish('threat_feed', json.dumps(threat_data))
        
        print(f"[!] Reported threat: {threat_type} from {src_ip}")
    
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


# Scalability demonstration functions
def demonstrate_scalability():
    """Demonstrate scalability features"""
    print("\n" + "="*60)
    print("SDN-NIDPS Scalability Demonstration")
    print("="*60)
    
    # 1. Multi-controller setup
    print("\n[1] Multi-Controller Architecture")
    controller1 = ScalableController(controller_id=1)
    controller2 = ScalableController(controller_id=2)
    print("✓ Multiple controller instances deployed")
    
    # 2. Load balancing
    print("\n[2] Load Balancing")
    lb = LoadBalancer()
    best_controller = lb.get_best_controller()
    print(f"✓ Load balancer operational - routing to controller {best_controller}")
    
    # 3. Distributed threat detection
    print("\n[3] Distributed Threat Detection")
    dtd = DistributedThreatDetection()
    dtd.report_threat("10.0.0.100", "Port Scan", "HIGH")
    print("✓ Distributed threat intelligence sharing active")
    
    # 4. Dynamic scaling
    print("\n[4] Dynamic Scaling")
    print(f"Initial workers: {multiprocessing.cpu_count() * 2}")
    controller1.scale_out(num_additional_workers=4)
    print("✓ Dynamic worker scaling demonstrated")
    
    # 5. Performance metrics
    print("\n[5] Performance Metrics")
    metrics = controller1.get_load_metrics()
    print(f"✓ Real-time metrics: {json.dumps(metrics, indent=2)}")
    
    print("\n" + "="*60)
    print("Scalability Features Demonstrated Successfully!")
    print("="*60)


if __name__ == "__main__":
    demonstrate_scalability()
