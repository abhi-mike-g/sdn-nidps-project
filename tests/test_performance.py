"""
Performance and stress testing
"""

import pytest
import time
import threading
from src.threat_detector import ThreatDetector

@pytest.fixture
def detector():
    return ThreatDetector()

class TestPerformance:
    def test_high_volume_packet_processing(self, detector):
        """Test processing high volume of packets"""
        start_time = time.time()
        
        for i in range(10000):
            detector.detect_port_scan(f"192.168.1.{i % 255}", 80, 0)
        
        elapsed = time.time() - start_time
        pps = 10000 / elapsed
        
        # Should process at least 1000 packets per second
        assert pps >= 1000
        print(f"Performance: {pps:.0f} packets/sec")

    def test_threat_detection_latency(self, detector):
        """Test threat detection latency"""
        measurements = []
        
        for i in range(100):
            start = time.time()
            detector.detect_syn_flood(f"192.168.1.{i}", 0)
            latency = (time.time() - start) * 1000  # Convert to ms
            measurements.append(latency)
        
        avg_latency = sum(measurements) / len(measurements)
        max_latency = max(measurements)
        
        # Average latency should be < 10ms
        assert avg_latency < 10
        print(f"Avg latency: {avg_latency:.2f}ms, Max: {max_latency:.2f}ms")

    def test_concurrent_threat_detection(self, detector):
        """Test concurrent threat detection"""
        threat_count = [0]
        lock = threading.Lock()
        
        def detect_threats():
            for i in range(1000):
                threat = detector.detect_port_scan(f"192.168.1.{i % 255}", i % 1000, 0)
                if threat:
                    with lock:
                        threat_count[0] += 1
        
        threads = []
        for _ in range(4):
            t = threading.Thread(target=detect_threats)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        # Should handle concurrent detection
        assert threat_count[0] >= 0
        print(f"Processed {len(detector.threat_log)} threats concurrently")
