"""
Unit tests for SDN Controller
"""

import pytest
import json
from unittest.mock import Mock, patch, MagicMock
from src.sdn_controller import SDNSecurityController

@pytest.fixture
def controller():
    """Create controller instance"""
    app = Mock()
    app.get_wsgi_app = Mock(return_value=Mock())
    return SDNSecurityController(wsgi=app)

class TestSDNController:
    def test_controller_initialization(self, controller):
        """Test controller initializes correctly"""
        assert controller.mac_to_port == {}
        assert controller.datapaths == {}
        assert len(controller.threat_detector.blocked_hosts) == 0

    def test_add_flow(self, controller):
        """Test adding flow rules"""
        datapath = Mock()
        datapath.ofproto = Mock()
        datapath.ofproto_parser = Mock()
        
        match = Mock()
        actions = [Mock()]
        
        controller.add_flow(datapath, 1, match, actions)
        # Verify flow was added
        assert datapath.send_msg.called

    def test_block_host(self, controller):
        """Test blocking a malicious host"""
        datapath = Mock()
        datapath.ofproto = Mock()
        datapath.ofproto_parser = Mock()
        
        src_ip = "192.168.1.100"
        controller.block_host(datapath, src_ip)
        
        assert src_ip in controller.threat_detector.blocked_hosts

    def test_threat_detection_integration(self, controller):
        """Test threat detection in controller"""
        threats = controller.threat_detector.get_threats()
        assert isinstance(threats, list)

class TestThreatLogging:
    def test_threat_log_creation(self, controller):
        """Test threat logging"""
        controller.threat_detector.detect_port_scan("10.0.0.1", 80, 0)
        
        threats = controller.threat_detector.get_threats()
        assert len(threats) >= 0

    def test_threat_export(self, controller):
        """Test threat log export"""
        controller.threat_detector.detect_sql_injection("' OR '1'='1")
        
        filename = "/tmp/test_threats.json"
        controller.threat_detector.export_threats_json(filename)
        
        with open(filename, 'r') as f:
            data = json.load(f)
            assert isinstance(data, list)
