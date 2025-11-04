"""
SDN-NIDPS Package Initialization
Scalable Network Intrusion Detection and Prevention System
"""

__version__ = "1.0.0"
__author__ = "SDN-NIDPS Development Team"
__description__ = "Software-Defined Network Intrusion Detection and Prevention System"

# Import main components
from .sdn_controller import SDNSecurityController
from .threat_detector import ThreatDetector
from .scalable_controller import ScalableController
from .utils import *

__all__ = [
    'SDNSecurityController',
    'ThreatDetector',
    'ScalableController',
]
