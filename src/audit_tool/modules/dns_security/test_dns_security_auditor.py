import unittest
from unittest.mock import patch, MagicMock, call
from .dns_security_auditor import DNSSecurityAuditor
import dns.resolver
import dns.flags
import dns.message
import dns.query
import socket
from typing import List, Dict, Any

class TestDNSSecurityAuditor(unittest.TestCase):
    def setUp(self):
        self.target = "example.com"
        self.config = {"timeout": 5}
        self.auditor = DNSSecurityAuditor(self.target, self.config)
        self.test_nameservers = ["ns1.example.com", "ns2.example.com"]
        self.auditor.nameservers = self.test_nameservers

    def test_initialization(self):
        """Test proper initialization of the auditor."""
        self.assertEqual(self.auditor.target, self.target)
        self.assertEqual(self.auditor.resolver.timeout, 5)
        self.assertEqual(self.auditor.nameservers, self.test_nameservers)

    @patch('dns.resolver.Resolver')
    def test_discover_nameservers(self, mock_resolver):
        """Test nameserver discovery functionality."""
        # Test successful discovery
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        mock_records = [MagicMock(to_text=lambda: ns) for ns in self.test_nameservers]
        mock_instance.resolve.return_value = mock_records

        self.auditor.discover_nameservers()
        self.assertEqual(len(self.auditor.findings), 1)
        self.assertEqual(self.auditor.findings[0]['severity'], 'Info')

        # Test discovery failure
        mock_instance.resolve.side_effect = dns.resolver.NXDOMAIN()
        self.auditor.discover_nameservers()
        self.assertTrue(any(f['severity'] == 'High' for f in self.auditor.findings))

    @patch('socket.gethostbyname')
    def test_check_dns_redundancy(self, mock_gethostbyname):
        """Test DNS redundancy checks."""
        # Test with nameservers in different networks
        mock_gethostbyname.side_effect = ['192.168.1.1', '10.0.0.1']
        self.auditor.check_dns_redundancy()
        self.assertFalse(any(f['severity'] == 'High' for f in self.auditor.findings))

        # Test with nameservers in same network
        mock_gethostbyname.side_effect = ['192.168.1.1', '192.168.1.2']
        self.auditor.check_dns_redundancy()
        self.assertTrue(any(f['severity'] == 'Medium' for f in self.auditor.findings))

        # Test with single nameserver
        self.auditor.nameservers = ['ns1.example.com']
        self.auditor.check_dns_redundancy()
        self.assertTrue(any(f['severity'] == 'High' for f in self.auditor.findings))

    @patch('dns.query.xfr')
    def test_check_zone_transfer(self, mock_xfr):
        """Test zone transfer security checks."""
        # Test when zone transfer is allowed
        mock_xfr.return_value = iter([MagicMock()])
        self.auditor.check_zone_transfer()
        self.assertTrue(any(
            f['severity'] == 'Critical' and 'zone transfer' in f['description'].lower() 
            for f in self.auditor.findings
        ))

        # Test when zone transfer is blocked
        mock_xfr.side_effect = dns.exception.FormError()
        self.auditor.check_zone_transfer()
        self.assertFalse(any(
            f['severity'] == 'Critical' and 'zone transfer' in f['description'].lower() 
            for f in self.auditor.findings[-1:]
        ))

    @patch('dns.resolver.Resolver')
    def test_check_recursion(self, mock_resolver):
        """Test recursion security checks."""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance

        # Test when recursion is enabled
        mock_instance.resolve.return_value = MagicMock()
        self.auditor.check_recursion()
        self.assertTrue(any(
            f['severity'] == 'High' and 'recursive' in f['description'].lower() 
            for f in self.auditor.findings
        ))

        # Test when recursion is disabled
        mock_instance.resolve.side_effect = dns.resolver.NoAnswer()
        self.auditor.check_recursion()
        self.assertFalse(any(
            f['severity'] == 'High' and 'recursive' in f['description'].lower() 
            for f in self.auditor.findings[-1:]
        ))

    @patch('dns.resolver.Resolver')
    def test_check_dnssec(self, mock_resolver):
        """Test DNSSEC implementation checks."""
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance

        # Test properly configured DNSSEC
        mock_instance.resolve.return_value = MagicMock()
        self.auditor.check_dnssec()
        self.assertTrue(any(
            f['severity'] == 'Info' and 'dnssec' in f['description'].lower() 
            for f in self.auditor.findings
        ))

        # Test missing DS record
        mock_instance.resolve.side_effect = [MagicMock(), dns.resolver.NoAnswer()]
        self.auditor.check_dnssec()
        self.assertTrue(any(
            f['severity'] == 'High' and 'dnssec' in f['description'].lower() 
            for f in self.auditor.findings
        ))

    @patch('socket.socket')
    def test_check_cache_poisoning_protection(self, mock_socket):
        """Test cache poisoning protection checks."""
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        
        # Test with insufficient port randomization
        mock_sock.getsockname.return_value = ('', 1234)
        self.auditor.check_cache_poisoning_protection()
        self.assertTrue(any(
            f['severity'] == 'High' and 'port randomization' in f['description'].lower() 
            for f in self.auditor.findings
        ))

    def test_generate_report(self):
        """Test report generation."""
        # Add some test findings
        test_finding = {
            'severity': 'High',
            'description': 'Test finding',
            'details': 'Test details',
            'recommendation': 'Test recommendation',
            'reference': 'Test reference',
            'category': 'Test category'
        }
        self.auditor.findings.append(test_finding)

        report = self.auditor.generate_report()
        self.assertEqual(report['target'], self.target)
        self.assertEqual(report['nameservers'], self.test_nameservers)
        self.assertEqual(report['findings'], [test_finding])

    def test_run_all_checks(self):
        """Test that all checks are executed."""
        with patch.multiple(self.auditor,
                          discover_nameservers=MagicMock(),
                          check_dns_redundancy=MagicMock(),
                          check_zone_transfer=MagicMock(),
                          check_recursion=MagicMock(),
                          check_dnssec=MagicMock(),
                          check_response_rate_limiting=MagicMock(),
                          check_version_disclosure=MagicMock(),
                          check_edns_support=MagicMock(),
                          check_tcp_support=MagicMock(),
                          check_cache_poisoning_protection=MagicMock()):
            
            self.auditor.run_all_checks()
            
            self.auditor.discover_nameservers.assert_called_once()
            self.auditor.check_dns_redundancy.assert_called_once()
            self.auditor.check_zone_transfer.assert_called_once()
            self.auditor.check_recursion.assert_called_once()
            self.auditor.check_dnssec.assert_called_once()
            self.auditor.check_response_rate_limiting.assert_called_once()
            self.auditor.check_version_disclosure.assert_called_once()
            self.auditor.check_edns_support.assert_called_once()
            self.auditor.check_tcp_support.assert_called_once()
            self.auditor.check_cache_poisoning_protection.assert_called_once()

if __name__ == '__main__':
    unittest.main() 