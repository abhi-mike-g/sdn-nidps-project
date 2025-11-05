"""
SDN-NIDPS Test Suite
Unit and integration tests for all components
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Test configuration
TEST_CONFIG = {
    'test_target': '10.0.0.1',
    'test_attacker': '10.0.0.100',
    'test_timeout': 30,
    'verbose': True
}

def pytest_configure(config):
    """Configure pytest"""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
