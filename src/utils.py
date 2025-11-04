"""
Utility functions for SDN-NIDPS
"""

import json
import logging
import os
from datetime import datetime
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ConfigManager:
    """Load and manage configuration files"""
    
    @staticmethod
    def load_yaml_config(filepath):
        """Load YAML configuration file"""
        try:
            import yaml
            with open(filepath, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Loaded config from {filepath}")
            return config
        except ImportError:
            logger.error("PyYAML not installed")
            return None
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return None
    
    @staticmethod
    def load_json_config(filepath):
        """Load JSON configuration file"""
        try:
            with open(filepath, 'r') as f:
                config = json.load(f)
            logger.info(f"Loaded config from {filepath}")
            return config
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return None
    
    @staticmethod
    def save_json_config(filepath, config):
        """Save JSON configuration file"""
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(config, f, indent=2)
            logger.info(f"Saved config to {filepath}")
            return True
        except Exception as e:
            logger.error(f"Error saving config: {e}")
            return False


class LogManager:
    """Centralized logging management"""
    
    @staticmethod
    def setup_logging(log_file, level=logging.INFO):
        """Setup logging configuration"""
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        
        logger = logging.getLogger()
        logger.addHandler(handler)
        logger.setLevel(level)
        
        return logger
    
    @staticmethod
    def log_security_event(event_type, details, severity):
        """Log security event with structured data"""
        event = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'details': details,
            'severity': severity
        }
        
        logger.warning(json.dumps(event))
        return event


class DataValidator:
    """Validate input data"""
    
    @staticmethod
    def is_valid_ip(ip_address):
        """Validate IP address format"""
        try:
            parts = ip_address.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except:
            return False
    
    @staticmethod
    def is_valid_mac(mac_address):
        """Validate MAC address format"""
        try:
            parts = mac_address.split(':')
            if len(parts) != 6:
                return False
            for part in parts:
                int(part, 16)
            return True
        except:
            return False
    
    @staticmethod
    def is_valid_port(port):
        """Validate port number"""
        try:
            port_num = int(port)
            return 0 < port_num < 65536
        except:
            return False


class SecurityUtils:
    """Security utility functions"""
    
    @staticmethod
    def hash_password(password):
        """Hash password using SHA256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def verify_password(password, hash_value):
        """Verify password against hash"""
        return SecurityUtils.hash_password(password) == hash_value
    
    @staticmethod
    def generate_token(length=32):
        """Generate random security token"""
        import secrets
        return secrets.token_hex(length // 2)
    
    @staticmethod
    def sanitize_input(user_input):
        """Sanitize user input for security"""
        # Remove dangerous characters
        dangerous_chars = ['<', '>', '"', "'", ';', '&', '|', '$', '`']
        result = user_input
        for char in dangerous_chars:
            result = result.replace(char, '')
        return result


class PerformanceMonitor:
    """Monitor system performance"""
    
    def __init__(self):
        self.metrics = {
            'packets_processed': 0,
            'threats_detected': 0,
            'avg_latency': 0,
            'throughput': 0
        }
        self.start_time = datetime.now()
    
    def record_packet(self):
        """Record packet processing"""
        self.metrics['packets_processed'] += 1
    
    def record_threat(self):
        """Record threat detection"""
        self.metrics['threats_detected'] += 1
    
    def update_latency(self, latency):
        """Update average latency"""
        alpha = 0.1
        self.metrics['avg_latency'] = (
            alpha * latency + (1 - alpha) * self.metrics['avg_latency']
        )
    
    def get_metrics(self):
        """Get current metrics"""
        elapsed_seconds = (datetime.now() - self.start_time).total_seconds()
        if elapsed_seconds > 0:
            self.metrics['throughput'] = self.metrics['packets_processed'] / elapsed_seconds
        
        return self.metrics
    
    def get_metrics_json(self):
        """Get metrics as JSON"""
        return json.dumps(self.get_metrics(), indent=2)


class NetworkUtils:
    """Network utility functions"""
    
    @staticmethod
    def ip_to_int(ip_address):
        """Convert IP address to integer"""
        try:
            parts = [int(p) for p in ip_address.split('.')]
            return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
        except:
            return None
    
    @staticmethod
    def int_to_ip(ip_int):
        """Convert integer to IP address"""
        return f"{(ip_int >> 24) & 0xff}.{(ip_int >> 16) & 0xff}." \
               f"{(ip_int >> 8) & 0xff}.{ip_int & 0xff}"
    
    @staticmethod
    def is_private_ip(ip_address):
        """Check if IP is private"""
        if not DataValidator.is_valid_ip(ip_address):
            return False
        
        private_ranges = [
            ('10.0.0.0', '10.255.255.255'),
            ('172.16.0.0', '172.31.255.255'),
            ('192.168.0.0', '192.168.255.255'),
        ]
        
        ip_int = NetworkUtils.ip_to_int(ip_address)
        for start, end in private_ranges:
            if NetworkUtils.ip_to_int(start) <= ip_int <= NetworkUtils.ip_to_int(end):
                return True
        
        return False


def initialize_project():
    """Initialize project directories and basic files"""
    directories = [
        'logs', 'data', 'attack_suite/attack_logs',
        'dashboard/assets', 'config'
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"Initialized directory: {directory}")
