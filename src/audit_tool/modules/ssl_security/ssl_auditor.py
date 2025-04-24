import socket
import ssl
from typing import Dict, List, Any
from ...core.base_auditor import BaseAuditor

class SSLAuditor(BaseAuditor):
    """Auditor for SSL/TLS security checks."""

    def __init__(self):
        super().__init__()
        self.category = "SSL/TLS Security"
        self.findings = []
        
    def _check_ssl_version(self, hostname: str, port: int = 443) -> List[Dict[str, Any]]:
        """Check supported SSL/TLS versions."""
        findings = []
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Check TLS version
                    if version < "TLSv1.2":
                        findings.append({
                            "severity": "High",
                            "category": self.category,
                            "description": f"Outdated TLS version detected: {version}",
                            "details": f"The server supports {version} which is considered insecure. Current cipher: {cipher[0]}",
                            "recommendation": "Upgrade to TLS 1.2 or higher and disable older protocols.",
                            "reference": "https://www.nist.gov/publications/guidelines-tlsssl-protocol-version-recommendations"
                        })
                    
                    # Check cipher strength
                    weak_ciphers = ["RC4", "DES", "3DES", "MD5"]
                    if any(weak in cipher[0] for weak in weak_ciphers):
                        findings.append({
                            "severity": "High",
                            "category": self.category,
                            "description": "Weak cipher suite detected",
                            "details": f"The server supports weak cipher suite: {cipher[0]}",
                            "recommendation": "Configure the server to use strong cipher suites only.",
                            "reference": "https://www.owasp.org/index.php/Transport_Layer_Protection_Cheat_Sheet"
                        })
                        
        except ssl.SSLError as e:
            findings.append({
                "severity": "High",
                "category": self.category,
                "description": "SSL/TLS connection error",
                "details": f"Failed to establish SSL/TLS connection: {str(e)}",
                "recommendation": "Verify SSL/TLS configuration and certificate installation.",
                "reference": "https://www.ssllabs.com/ssltest/"
            })
        except socket.error as e:
            findings.append({
                "severity": "Info",
                "category": self.category,
                "description": "Connection error",
                "details": f"Could not connect to host: {str(e)}",
                "recommendation": "Verify that the host is accessible and the port is open.",
                "reference": None
            })
            
        return findings
        
    def _check_certificate(self, hostname: str, port: int = 443) -> List[Dict[str, Any]]:
        """Check SSL certificate validity and properties."""
        findings = []
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    if not cert.get('notAfter'):
                        findings.append({
                            "severity": "High",
                            "category": self.category,
                            "description": "Certificate expiration date not found",
                            "details": "Unable to determine certificate expiration date",
                            "recommendation": "Verify certificate validity and installation",
                            "reference": None
                        })
                    
                    # Check subject alternative names
                    if not cert.get('subjectAltName'):
                        findings.append({
                            "severity": "Medium",
                            "category": self.category,
                            "description": "Missing Subject Alternative Names",
                            "details": "The certificate does not have Subject Alternative Names (SANs)",
                            "recommendation": "Use certificates with proper SANs for improved security",
                            "reference": "https://tools.ietf.org/html/rfc5280#section-4.2.1.6"
                        })
                        
                    # Check key usage
                    if not cert.get('keyUsage'):
                        findings.append({
                            "severity": "Low",
                            "category": self.category,
                            "description": "Missing Key Usage extension",
                            "details": "The certificate does not specify key usage constraints",
                            "recommendation": "Use certificates with proper key usage extensions",
                            "reference": "https://tools.ietf.org/html/rfc5280#section-4.2.1.3"
                        })
                        
        except Exception as e:
            findings.append({
                "severity": "Info",
                "category": self.category,
                "description": "Certificate check error",
                "details": f"Failed to check certificate: {str(e)}",
                "recommendation": "Verify certificate installation and configuration",
                "reference": None
            })
            
        return findings
        
    def audit(self, target: str) -> List[Dict[str, Any]]:
        """
        Perform SSL/TLS security audit.
        
        Args:
            target (str): The target hostname to audit
            
        Returns:
            List[Dict[str, Any]]: List of findings
        """
        self.findings = []
        
        # Remove protocol prefix if present
        if "://" in target:
            target = target.split("://")[1]
            
        # Remove path and query components
        if "/" in target:
            target = target.split("/")[0]
            
        # Check SSL/TLS version and ciphers
        self.findings.extend(self._check_ssl_version(target))
        
        # Check certificate properties
        self.findings.extend(self._check_certificate(target))
        
        return self.findings 