"""
Unit tests for attack simulation scenarios
"""

import pytest
import json
from attack_suite.external_attacks import ExternalAttackSimulator
from attack_suite.internal_attacks import InternalAttackSimulator

@pytest.fixture
def external_sim():
    return ExternalAttackSimulator("10.0.0.1")

@pytest.fixture
def internal_sim():
    return InternalAttackSimulator("10.0.0.100")

class TestExternalAttacks:
    def test_attack_logging(self, external_sim):
        """Test attack logging"""
        external_sim.log_attack("Test Attack", "Test details", True)
        
        assert len(external_sim.attacks) == 1
        assert external_sim.attacks[0]['type'] == 'Test Attack'

    def test_report_generation(self, external_sim):
        """Test report generation"""
        external_sim.log_attack("Attack 1", "Details 1", True)
        external_sim.log_attack("Attack 2", "Details 2", False)
        
        # Reports should be generated
        assert len(external_sim.attacks) == 2

class TestInternalAttacks:
    def test_internal_attack_logging(self, internal_sim):
        """Test internal attack logging"""
        internal_sim.log_attack("Internal Attack", "Details", True)
        
        assert len(internal_sim.attacks) == 1
        assert internal_sim.attacks[0]['attacker'] == "10.0.0.100"

    def test_attack_chain(self, internal_sim):
        """Test attack chain scenarios"""
        internal_sim.log_attack("Phase 1", "Recon", True)
        internal_sim.log_attack("Phase 2", "Access", True)
        internal_sim.log_attack("Phase 3", "Escalation", True)
        
        assert len(internal_sim.attacks) == 3
