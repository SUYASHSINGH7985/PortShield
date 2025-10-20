"""
Unit Tests for PortShield Threat Detection System
Tests the core functionality of threat detection and firewall management
"""

import unittest
import time
from datetime import datetime, timedelta
from src.monitor.threat_detector import ThreatDetector
from src.monitor.connection_monitor import ConnectionMonitor
from src.monitor.port_scanner import PortScanner
from src.firewall.firewall_manager import FirewallManager


class TestThreatDetector(unittest.TestCase):
    """Test ThreatDetector module"""
    
    def setUp(self):
        """Initialize test fixtures"""
        self.detector = ThreatDetector()
    
    def test_port_scan_detection(self):
        """Test detection of port scanning"""
        attack_ip = "203.0.113.100"
        
        # Simulate port scan: access 15 different ports
        for port in range(1000, 1015):
            threat = self.detector.analyze_connection(attack_ip, port, 'TCP')
        
        # Should detect HIGH threat
        threats = self.detector.get_threats_from_ip(attack_ip)
        self.assertGreater(len(threats), 0)
        self.assertIn('PORT_SCAN', [t['type'] for t in threats])
    
    def test_brute_force_detection(self):
        """Test detection of brute-force attacks"""
        attack_ip = "198.51.100.50"
        
        # Simulate brute-force: rapid SSH connection attempts
        for _ in range(8):
            self.detector.analyze_connection(attack_ip, 22, 'TCP')
        
        threats = self.detector.get_threats_from_ip(attack_ip)
        self.assertGreater(len(threats), 0)
        self.assertIn('BRUTE_FORCE', [t['type'] for t in threats])
    
    def test_threat_level_classification(self):
        """Test threat level classification"""
        threat = {
            'ip': '192.0.2.1',
            'type': 'PORT_SCAN',
            'details': 'Test threat',
            'timestamp': datetime.now(),
            'action_taken': 'NONE'
        }
        
        self.detector.threat_log.append(threat)
        threats = self.detector.get_threats_from_ip('192.0.2.1')
        
        self.assertEqual(len(threats), 1)
        self.assertEqual(threats[0]['type'], 'PORT_SCAN')
    
    def test_threat_ip_blocking(self):
        """Test marking IP as threat"""
        test_ip = "203.0.113.50"
        
        self.assertFalse(self.detector.is_ip_threat(test_ip))
        self.detector.mark_ip_as_threat(test_ip)
        self.assertTrue(self.detector.is_ip_threat(test_ip))
    
    def test_get_recent_threats(self):
        """Test retrieving recent threats"""
        # Add a threat
        self.detector._log_threat('192.0.2.1', 'TEST', 'Test threat')
        
        # Get recent threats
        recent = self.detector.get_recent_threats(minutes=60)
        self.assertGreater(len(recent), 0)
    
    def test_threat_summary(self):
        """Test threat summary generation"""
        # Add multiple threats
        self.detector._log_threat('192.0.2.1', 'PORT_SCAN', 'Test')
        self.detector._log_threat('192.0.2.2', 'BRUTE_FORCE', 'Test')
        
        summary = self.detector.get_threat_summary()
        
        self.assertIn('total_threats', summary)
        self.assertIn('threatened_ips', summary)
        self.assertIn('threats_by_type', summary)


class TestFirewallManager(unittest.TestCase):
    """Test FirewallManager module"""
    
    def setUp(self):
        """Initialize firewall manager"""
        self.fw = FirewallManager()
    
    def test_block_ip(self):
        """Test blocking an IP"""
        test_ip = "203.0.113.100"
        
        self.fw.block_ip(test_ip, "Test block")
        self.assertTrue(self.fw.is_ip_blocked(test_ip))
    
    def test_unblock_ip(self):
        """Test unblocking an IP"""
        test_ip = "203.0.113.101"
        
        self.fw.block_ip(test_ip)
        self.assertTrue(self.fw.is_ip_blocked(test_ip))
        
        self.fw.unblock_ip(test_ip)
        self.assertFalse(self.fw.is_ip_blocked(test_ip))
    
    def test_get_blocked_ips(self):
        """Test retrieving blocked IPs list"""
        test_ips = ["203.0.113.1", "203.0.113.2", "203.0.113.3"]
        
        for ip in test_ips:
            self.fw.block_ip(ip)
        
        blocked = self.fw.get_blocked_ips()
        for ip in test_ips:
            self.assertIn(ip, blocked)
    
    def test_blocked_ip_count(self):
        """Test counting blocked IPs"""
        initial_count = self.fw.get_blocked_ips_count()
        
        test_ip = "203.0.113.200"
        self.fw.block_ip(test_ip)
        
        new_count = self.fw.get_blocked_ips_count()
        self.assertEqual(new_count, initial_count + 1)
    
    def test_firewall_statistics(self):
        """Test firewall statistics generation"""
        self.fw.block_ip("203.0.113.50")
        
        stats = self.fw.get_statistics()
        
        self.assertIn('blocked_ips_count', stats)
        self.assertIn('blocked_ips', stats)
        self.assertIn('timestamp', stats)
    
    def test_persistence(self):
        """Test blocklist persistence to file"""
        test_ip = "203.0.113.150"
        
        self.fw.block_ip(test_ip, persist=True)
        
        # Create new instance - should load from file
        fw_new = FirewallManager()
        self.assertTrue(fw_new.is_ip_blocked(test_ip))


class TestPortScanner(unittest.TestCase):
    """Test PortScanner module"""
    
    def setUp(self):
        """Initialize port scanner"""
        self.scanner = PortScanner()
    
    def test_get_service_name(self):
        """Test service name lookup"""
        self.assertEqual(self.scanner.get_service_name(22), 'SSH')
        self.assertEqual(self.scanner.get_service_name(80), 'HTTP')
        self.assertEqual(self.scanner.get_service_name(443), 'HTTPS')
    
    def test_common_ports_dict(self):
        """Test common ports mapping"""
        self.assertIn(22, self.scanner.COMMON_PORTS)
        self.assertIn(80, self.scanner.COMMON_PORTS)
        self.assertIn(443, self.scanner.COMMON_PORTS)
    
    def test_scan_summary(self):
        """Test scan summary generation"""
        summary = self.scanner.get_scan_summary()
        
        self.assertIn('scan_results', summary)
        self.assertIn('last_scan_time', summary)
        self.assertIn('total_hosts_scanned', summary)
        self.assertIn('total_open_ports', summary)
    
    def test_listening_ports_advanced(self):
        """Test getting listening ports"""
        ports = self.scanner.get_listening_ports_advanced()
        
        # Should be a list
        self.assertIsInstance(ports, list)
        
        # Each port should have required fields
        for port in ports:
            self.assertIn('port', port)
            self.assertIn('service', port)
            self.assertIn('state', port)


class TestIntegration(unittest.TestCase):
    """Integration tests for complete workflow"""
    
    def setUp(self):
        """Initialize all components"""
        self.detector = ThreatDetector()
        self.fw = FirewallManager()
    
    def test_detect_and_block_workflow(self):
        """Test complete workflow: detect threat -> block IP"""
        attack_ip = "203.0.113.99"
        
        # Step 1: Simulate port scan
        for port in range(1000, 1015):
            self.detector.analyze_connection(attack_ip, port, 'TCP')
        
        # Step 2: Check threat detected
        threats = self.detector.get_threats_from_ip(attack_ip)
        self.assertGreater(len(threats), 0)
        
        # Step 3: Block the IP
        self.fw.block_ip(attack_ip, "Detected: " + threats[0]['type'])
        
        # Step 4: Verify blocked
        self.assertTrue(self.fw.is_ip_blocked(attack_ip))
    
    def test_multiple_threat_detection(self):
        """Test detecting multiple threats simultaneously"""
        ips_and_threats = [
            ("203.0.113.1", list(range(1000, 1020))),  # Port scan
            ("198.51.100.2", [22] * 8),                # Brute force
            ("192.0.2.3", [80, 81, 82, 83, 84])       # Anomaly
        ]
        
        for ip, ports in ips_and_threats:
            for port in ports:
                self.detector.analyze_connection(ip, port, 'TCP')
        
        summary = self.detector.get_threat_summary()
        self.assertGreater(summary['total_threats'], 0)


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and error handling"""
    
    def setUp(self):
        """Initialize components"""
        self.detector = ThreatDetector()
        self.fw = FirewallManager()
    
    def test_empty_connection_list(self):
        """Test handling empty connection data"""
        summary = self.detector.get_threat_summary()
        self.assertEqual(summary['total_threats'], 0)
    
    def test_duplicate_block(self):
        """Test blocking same IP twice"""
        test_ip = "203.0.113.50"
        
        self.fw.block_ip(test_ip)
        self.fw.block_ip(test_ip)  # Should not error
        
        blocked = self.fw.get_blocked_ips()
        count = sum(1 for ip in blocked if ip == test_ip)
        self.assertEqual(count, 1)  # Should not duplicate
    
    def test_invalid_threat_handling(self):
        """Test handling of invalid threat data"""
        # Should not raise exception
        threats = self.detector.get_threats_from_ip("invalid-ip-format")
        self.assertEqual(threats, [])
    
    def test_concurrent_threat_detection(self):
        """Test detecting threats from multiple IPs"""
        attack_ips = [f"203.0.113.{i}" for i in range(10, 20)]
        
        for ip in attack_ips:
            for port in range(1000, 1005):
                self.detector.analyze_connection(ip, port, 'TCP')
        
        summary = self.detector.get_threat_summary()
        self.assertGreater(summary['threatened_ips'], 0)


def run_tests():
    """Run all tests"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestThreatDetector))
    suite.addTests(loader.loadTestsFromTestCase(TestFirewallManager))
    suite.addTests(loader.loadTestsFromTestCase(TestPortScanner))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestEdgeCases))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("="*70)
    
    return result.wasSuccessful()


if __name__ == '__main__':
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
