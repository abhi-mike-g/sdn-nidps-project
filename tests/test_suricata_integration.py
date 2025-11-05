"""
Unit tests for Suricata IDS integration
"""

import pytest
import json
from unittest.mock import Mock, patch
from ids_integration.alert_processor import AlertProcessor, SuricataSDNBridge

@pytest.fixture
def processor():
    return AlertProcessor("/tmp/eve.json")

@pytest.fixture
def bridge():
    return SuricataSDNBridge()

class TestAlertProcessor:
    def test_alert_processing(self, processor):
        """Test alert processing"""
        alert_json = json.dumps({
            'event_type': 'alert',
            'timestamp': '2024-01-15T10:00:00.000000+0000',
            'alert': {
                'severity': 1,
                'signature': 'Test Alert',
                'category': 'test'
            },
            'src_ip': '192.168.1.100',
            'dest_ip': '10.0.0.1',
            'src_port': 12345,
            'dest_port': 80,
            'proto': 'TCP'
        })
        
        alert = processor.process_alert(alert_json)
        assert alert is not None
        assert alert['severity'] == 1

    def test_callback_execution(self, processor):
        """Test callback execution"""
        callback_called = False
        
        def test_callback(alert):
            nonlocal callback_called
            callback_called = True
        
        processor.add_callback(test_callback)
        
        alert_json = json.dumps({
            'event_type': 'alert',
            'timestamp': '2024-01-15T10:00:00.000000+0000',
            'alert': {'severity': 1, 'signature': 'Test'},
            'src_ip': '192.168.1.100'
        })
        
        processor.process_alert(alert_json)
        assert callback_called

class TestSuricataSDNBridge:
    def test_alert_conversion(self, bridge):
        """Test alert to SDN action conversion"""
        alert = {
            'event_type': 'alert',
            'severity': 1,
            'signature': 'Port Scan',
            'src_ip': '192.168.1.100',
            'category': 'Reconnaissance'
        }
        
        action = bridge._convert_to_sdn_action(alert)
        assert action['action'] == 'BLOCK'
        assert action['source_ip'] == '192.168.1.100'
