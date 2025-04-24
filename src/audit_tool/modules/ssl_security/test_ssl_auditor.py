import unittest
from unittest.mock import patch, MagicMock
from .ssl_auditor import SSLAuditor

class TestSSLAuditor(unittest.TestCase):
    def setUp(self):
        self.auditor = SSLAuditor()
        self.test_hostname = "example.com"

    @patch('ssl.create_default_context')
    @patch('socket.create_connection')
    def test_check_ssl_version(self, mock_socket, mock_ssl_context):
        # Mock SSL context and socket
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_socket.return_value = MagicMock()
        
        # Test with TLS 1.2
        mock_context.get_protocol_version_name.return_value = "TLSv1.2"
        findings = self.auditor._check_ssl_version(self.test_hostname)
        self.assertTrue(any(finding.severity == "INFO" for finding in findings))

        # Test with SSL 3.0 (should raise warning)
        mock_context.get_protocol_version_name.return_value = "SSLv3"
        findings = self.auditor._check_ssl_version(self.test_hostname)
        self.assertTrue(any(finding.severity == "HIGH" for finding in findings))

    @patch('ssl.create_default_context')
    @patch('socket.create_connection')
    def test_check_certificate(self, mock_socket, mock_ssl_context):
        # Mock SSL context and socket
        mock_context = MagicMock()
        mock_ssl_context.return_value = mock_context
        mock_socket.return_value = MagicMock()
        
        # Mock certificate
        mock_cert = MagicMock()
        mock_cert.has_expired.return_value = False
        mock_cert.get_subject().get_components.return_value = [(b'CN', b'example.com')]
        mock_context.get_peer_certificate.return_value = mock_cert

        findings = self.auditor._check_certificate(self.test_hostname)
        self.assertTrue(any(finding.severity == "INFO" for finding in findings))

    def test_audit(self):
        with patch.object(SSLAuditor, '_check_ssl_version') as mock_version_check, \
             patch.object(SSLAuditor, '_check_certificate') as mock_cert_check:
            
            mock_version_check.return_value = []
            mock_cert_check.return_value = []
            
            findings = self.auditor.audit(self.test_hostname)
            self.assertIsInstance(findings, list)
            mock_version_check.assert_called_once_with(self.test_hostname)
            mock_cert_check.assert_called_once_with(self.test_hostname)

if __name__ == '__main__':
    unittest.main() 