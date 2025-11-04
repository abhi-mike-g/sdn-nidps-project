"""
Suricata Alert Processing
Processes EVE JSON alerts and integrates with SDN controller
"""

import json
import threading
import time
from collections import defaultdict
from datetime import datetime
import logging
import redis

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AlertProcessor:
    """Process Suricata EVE JSON alerts"""
    
    def __init__(self, eve_json_path="/var/log/suricata/eve.json"):
        self.eve_json_path = eve_json_path
        self.last_position = 0
        self.callbacks = []
        self.alert_stats = defaultdict(int)
        
    def add_callback(self, callback):
        """Register callback for new alerts"""
        self.callbacks.append(callback)
    
    def process_alert(self, alert_data):
        """Process individual alert"""
        try:
            event = json.loads(alert_data)
            
            if event.get('event_type') == 'alert':
                processed_alert = {
                    'timestamp': event.get('timestamp'),
                    'severity': event['alert'].get('severity'),
                    'signature': event['alert'].get('signature'),
                    'category': event['alert'].get('category'),
                    'source_ip': event.get('src_ip'),
                    'dest_ip': event.get('dest_ip'),
                    'source_port': event.get('src_port'),
                    'dest_port': event.get('dest_port'),
                    'protocol': event.get('proto'),
                    'action': self._determine_action(event)
                }
                
                # Update statistics
                self.alert_stats[processed_alert['signature']] += 1
                
                # Execute callbacks
                for callback in self.callbacks:
                    try:
                        callback(processed_alert)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")
                
                return processed_alert
        
        except json.JSONDecodeError:
            pass
        
        return None
    
    def _determine_action(self, event):
        """Determine response action based on alert"""
        severity = event['alert'].get('severity', 3)
        
        if severity == 1:  # High
            return 'BLOCK'
        elif severity == 2:  # Medium
            return 'MONITOR'
        else:  # Low
            return 'LOG'
    
    def monitor_alerts_stream(self):
        """Monitor alert file in real-time"""
        logger.info(f"Monitoring alerts from {self.eve_json_path}")
        
        while True:
            try:
                with open(self.eve_json_path, 'r') as f:
                    f.seek(self.last_position)
                    
                    for line in f:
                        self.process_alert(line)
                    
                    self.last_position = f.tell()
            
            except FileNotFoundError:
                logger.warning(f"Alert file not found: {self.eve_json_path}")
                time.sleep(5)
            
            except Exception as e:
                logger.error(f"Error monitoring alerts: {e}")
            
            time.sleep(1)
    
    def get_statistics(self):
        """Get alert statistics"""
        return dict(self.alert_stats)
    
    def get_top_alerts(self, limit=10):
        """Get top detected alerts"""
        sorted_alerts = sorted(
            self.alert_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_alerts[:limit]


class SuricataSDNBridge:
    """Bridge between Suricata alerts and SDN controller"""
    
    def __init__(self, controller_api_url="http://localhost:8080/api"):
        self.controller_api = controller_api_url
        self.processor = AlertProcessor()
        self.processor.add_callback(self.on_alert)
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(
            target=self.processor.monitor_alerts_stream,
            daemon=True
        )
    
    def start(self):
        """Start processing alerts"""
        self.monitor_thread.start()
        logger.info("Suricata-SDN bridge started")
    
    def on_alert(self, alert):
        """Handle alert from Suricata"""
        logger.info(f"Alert processed: {alert['signature']}")
        
        # Convert to SDN action
        sdn_action = self._convert_to_sdn_action(alert)
        
        # Send to controller if blocking
        if sdn_action['action'] == 'BLOCK':
            self._send_to_controller(sdn_action)
    
    def _convert_to_sdn_action(self, alert):
        """Convert Suricata alert to SDN action"""
        return {
            'threat_type': alert['signature'],
            'source_ip': alert['source_ip'],
            'action': alert['action'],
            'severity': alert['severity'],
            'timestamp': alert['timestamp'],
            'category': alert['category']
        }
    
    def _send_to_controller(self, action):
        """Send action to SDN controller"""
        try:
            import requests
            response = requests.post(
                f"{self.controller_api}/block",
                json=action,
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info(f"Action sent to controller: {action['threat_type']}")
            else:
                logger.error(f"Controller error: {response.status_code}")
        
        except Exception as e:
            logger.error(f"Error sending to controller: {e}")


class AlertAggregator:
    """Aggregate alerts and correlate events"""
    
    def __init__(self, window_size=60):
        self.window_size = window_size  # seconds
        self.events = defaultdict(list)
    
    def add_event(self, source_ip, event_type):
        """Add event for correlation"""
        timestamp = time.time()
        self.events[source_ip].append({
            'type': event_type,
            'timestamp': timestamp
        })
        
        # Clean old events
        cutoff = timestamp - self.window_size
        self.events[source_ip] = [
            e for e in self.events[source_ip]
            if e['timestamp'] > cutoff
        ]
    
    def get_event_count(self, source_ip, event_type):
        """Get event count for IP"""
        count = 0
        for event in self.events.get(source_ip, []):
            if event['type'] == event_type:
                count += 1
        return count
    
    def correlate_events(self, source_ip):
        """Detect event patterns"""
        if source_ip not in self.events:
            return None
        
        events = self.events[source_ip]
        
        # Pattern detection
        event_types = [e['type'] for e in events]
        
        # Check for attack chains
        if 'Port Scan' in event_types and 'Brute Force' in event_types:
            return {
                'pattern': 'Recon + Attack',
                'severity': 'CRITICAL',
                'recommendation': 'BLOCK'
            }
        
        if event_types.count('SYN Flood') > 10:
            return {
                'pattern': 'DDoS Attack',
                'severity': 'CRITICAL',
                'recommendation': 'RATE_LIMIT'
            }
        
        return None
