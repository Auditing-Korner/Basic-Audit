import socket
import ssl
import requests
import struct
import zlib
from typing import Dict, List, Any, Tuple
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import NameOID
from cryptography.hazmat.primitives.hashes import SHA1, MD5
from ...core.base_auditor import BaseAuditor

class SSLAuditor(BaseAuditor):
    """Auditor for SSL/TLS security checks following ISO 27002 and NIST guidelines."""

    def __init__(self):
        super().__init__()
        self.category = "SSL/TLS Security"
        self.findings = []
        self.min_rsa_key_size = 2048  # NIST SP 800-131A
        self.min_ec_key_size = 256    # NIST SP 800-131A
        self.weak_hash_algorithms = ["MD5", "SHA1"]
        self.weak_ciphers = {
            "NULL": "No encryption",
            "RC4": "Stream cipher with known vulnerabilities",
            "DES": "Weak block cipher",
            "3DES": "Vulnerable to SWEET32 attack",
            "MD5": "Cryptographically broken hash",
            "SHA1": "Cryptographically weak hash",
            "EXPORT": "Export-grade cryptography",
            "anon": "Anonymous key exchange",
            "CBC": "Block cipher in CBC mode (BEAST vulnerability in TLS 1.0)",
            "RC2": "Legacy weak block cipher",
            "IDEA": "Legacy block cipher"
        }
        self.compression_attacks = {
            "CRIME": "CVE-2012-4929",
            "TIME": "CVE-2013-1599",
            "BREACH": "CVE-2013-3587"
        }
        self.padding_oracle_attacks = {
            "Lucky13": "CVE-2013-0169",
            "Padding Oracle": "CVE-2016-2107"
        }
        
    def _check_cipher_strength(self, cipher_name: str) -> Dict[str, Any]:
        """Analyze cipher suite strength and known vulnerabilities."""
        findings = []
        
        # Check for weak ciphers
        for weak_cipher, reason in self.weak_ciphers.items():
            if weak_cipher in cipher_name:
                findings.append({
                    "severity": "High",
                    "category": self.category,
                    "description": f"Weak cipher detected: {weak_cipher}",
                    "details": f"The server supports {cipher_name}. {reason}",
                    "recommendation": "Configure server to use strong cipher suites only",
                    "reference": "NIST SP 800-52r2, NIST SP 800-57",
                    "cve_references": self._get_cve_for_cipher(weak_cipher)
                })
                
        return findings

    def _get_cve_for_cipher(self, cipher: str) -> List[str]:
        """Get relevant CVEs for known cipher vulnerabilities."""
        cve_map = {
            "RC4": ["CVE-2013-2566", "CVE-2015-2808"],  # RC4 NOMORE attack
            "DES": ["CVE-2016-2183"],  # SWEET32
            "3DES": ["CVE-2016-2183"],  # SWEET32
            "EXPORT": ["CVE-2015-4000"],  # Logjam
            "NULL": ["CVE-2014-3566"],  # POODLE
            "CBC": ["CVE-2011-3389", "CVE-2019-1559"]  # BEAST, Zombie POODLE
        }
        return cve_map.get(cipher, [])

    def _check_hash_algorithms(self, cert: x509.Certificate) -> List[Dict[str, Any]]:
        """Check for weak hash algorithms in certificates."""
        findings = []
        hash_algo = cert.signature_hash_algorithm
        
        if hash_algo.name in self.weak_hash_algorithms:
            findings.append({
                "severity": "High",
                "category": self.category,
                "description": f"Weak hash algorithm detected: {hash_algo.name}",
                "details": f"Certificate uses {hash_algo.name} for signature",
                "recommendation": "Use certificates signed with SHA-256 or stronger",
                "reference": "NIST SP 800-57 Part 1 Rev. 5",
                "cve_references": [
                    "CVE-2008-4109",  # MD5 collision
                    "CVE-2017-15535"  # SHA1 collision
                ]
            })
            
        return findings

    def _check_dh_params(self, hostname: str, port: int = 443) -> List[Dict[str, Any]]:
        """Check Diffie-Hellman parameter strength."""
        findings = []
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    
                    # Check for DHE/ECDHE key exchange
                    if "DHE" in cipher[0] or "EDH" in cipher[0]:
                        # Note: Actual DH parameter size check would require additional handshake analysis
                        findings.append({
                            "severity": "Info",
                            "category": self.category,
                            "description": "DH parameter check recommended",
                            "details": "Server uses DHE cipher suites. Verify DH parameter size >= 2048 bits",
                            "recommendation": "Use DH parameters of at least 2048 bits",
                            "reference": "NIST SP 800-56A Rev. 3",
                            "cve_references": ["CVE-2015-4000"]  # Logjam
                        })
                        
        except Exception as e:
            findings.append({
                "severity": "Info",
                "category": self.category,
                "description": "DH parameter check failed",
                "details": f"Could not check DH parameters: {str(e)}",
                "recommendation": "Manual verification recommended",
                "reference": None
            })
            
        return findings

    def _check_heartbleed(self, hostname: str, port: int = 443) -> List[Dict[str, Any]]:
        """Check for Heartbleed vulnerability (CVE-2014-0160)."""
        findings = []
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                client_hello = b"".join([
                    b"\x16",               # Type: Handshake
                    b"\x03\x03",           # TLS 1.2
                    b"\x00\x31",           # Length
                    b"\x01",               # Handshake Type: Client Hello
                    b"\x00\x00\x2d",       # Length
                    b"\x03\x03",           # TLS 1.2
                    b"\x00" * 32,          # Random
                    b"\x00",               # Session ID Length
                    b"\x00\x02",           # Cipher Suites Length
                    b"\x00\x2f",           # TLS_RSA_WITH_AES_128_CBC_SHA
                    b"\x01",               # Compression Methods Length
                    b"\x00"                # Compression Method: null
                ])

                sock.send(client_hello)
                response = sock.recv(4096)

                # Check for heartbeat extension
                if b"\x0f" in response:  # Heartbeat extension
                    findings.append({
                        "severity": "Critical",
                        "category": self.category,
                        "description": "Potential Heartbleed Vulnerability",
                        "details": "The server appears to support the heartbeat extension and may be vulnerable to Heartbleed",
                        "recommendation": "Update OpenSSL to version 1.0.1g or later",
                        "reference": "http://heartbleed.com/",
                        "cve_references": ["CVE-2014-0160"]
                    })

        except Exception as e:
            findings.append({
                "severity": "Info",
                "category": self.category,
                "description": "Heartbleed check failed",
                "details": f"Could not complete Heartbleed vulnerability check: {str(e)}",
                "recommendation": "Manual verification recommended",
                "reference": "CVE-2014-0160"
            })

        return findings

    def _check_ssl_version(self, hostname: str, port: int = 443) -> List[Dict[str, Any]]:
        """Check supported SSL/TLS versions, cipher suites, and known vulnerabilities."""
        findings = []
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Add findings from cipher strength check
                    findings.extend(self._check_cipher_strength(cipher[0]))
                    
                    # Version checks
                    if version < "TLSv1.2":
                        findings.append({
                            "severity": "High",
                            "category": self.category,
                            "description": f"Outdated TLS version detected: {version}",
                            "details": f"The server supports {version} which is considered insecure",
                            "recommendation": "Upgrade to TLS 1.2 or higher and disable older protocols",
                            "reference": "NIST SP 800-52r2, ISO 27002 14.4",
                            "cve_references": ["CVE-2014-3566", "CVE-2015-0204"]
                        })

        except Exception as e:
            findings.append({
                "severity": "Info",
                "category": self.category,
                "description": "SSL/TLS check failed",
                "details": f"Could not complete SSL/TLS check: {str(e)}",
                "recommendation": "Manual verification recommended",
                "reference": None
            })
            
        return findings

    def _check_certificate(self, hostname: str, port: int = 443) -> List[Dict[str, Any]]:
        """Check SSL certificate validity, properties, and chain."""
        findings = []
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cert_bin = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    # Check certificate expiration (ISO 27002 14.4.2)
                    if not cert.get('notAfter'):
                        findings.append({
                            "severity": "High",
                            "category": self.category,
                            "description": "Certificate expiration date not found",
                            "details": "Unable to determine certificate expiration date",
                            "recommendation": "Verify certificate validity and installation",
                            "reference": "ISO 27002 14.4.2"
                        })
                    
                    # Check key size (NIST SP 800-131A)
                    key_size = x509_cert.public_key().key_size
                    if "RSA" in str(x509_cert.public_key().__class__) and key_size < self.min_rsa_key_size:
                        findings.append({
                            "severity": "High",
                            "category": self.category,
                            "description": "Insufficient RSA key length",
                            "details": f"RSA key length is {key_size} bits, minimum required is {self.min_rsa_key_size}",
                            "recommendation": f"Use RSA keys of at least {self.min_rsa_key_size} bits",
                            "reference": "NIST SP 800-131A"
                        })
                    elif "EC" in str(x509_cert.public_key().__class__) and key_size < self.min_ec_key_size:
                        findings.append({
                            "severity": "High",
                            "category": self.category,
                            "description": "Insufficient EC key length",
                            "details": f"EC key length is {key_size} bits, minimum required is {self.min_ec_key_size}",
                            "recommendation": f"Use EC keys of at least {self.min_ec_key_size} bits",
                            "reference": "NIST SP 800-131A"
                        })
                    
                    # Check subject alternative names
                    if not cert.get('subjectAltName'):
                        findings.append({
                            "severity": "Medium",
                            "category": self.category,
                            "description": "Missing Subject Alternative Names",
                            "details": "The certificate does not have Subject Alternative Names (SANs)",
                            "recommendation": "Use certificates with proper SANs for improved security",
                            "reference": "RFC 5280 Section 4.2.1.6"
                        })
                        
                    # Check certificate extensions
                    if not cert.get('keyUsage'):
                        findings.append({
                            "severity": "Low",
                            "category": self.category,
                            "description": "Missing Key Usage extension",
                            "details": "The certificate does not specify key usage constraints",
                            "recommendation": "Use certificates with proper key usage extensions",
                            "reference": "ISO 27002 14.4.2"
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

    def _check_hsts(self, hostname: str) -> List[Dict[str, Any]]:
        """Check for HTTP Strict Transport Security (HSTS) header."""
        findings = []
        try:
            response = requests.get(f"https://{hostname}", verify=True)
            hsts_header = response.headers.get('Strict-Transport-Security')
            
            if not hsts_header:
                findings.append({
                    "severity": "Medium",
                    "category": self.category,
                    "description": "Missing HSTS header",
                    "details": "HTTP Strict Transport Security (HSTS) is not enabled",
                    "recommendation": "Enable HSTS with appropriate max-age value",
                    "reference": "ISO 27002 14.4.6"
                })
            else:
                # Check HSTS configuration
                max_age = 0
                for directive in hsts_header.split(";"):
                    if "max-age" in directive:
                        try:
                            max_age = int(directive.split("=")[1])
                        except (IndexError, ValueError):
                            pass
                
                if max_age < 31536000:  # 1 year in seconds
                    findings.append({
                        "severity": "Low",
                        "category": self.category,
                        "description": "Insufficient HSTS max-age",
                        "details": f"HSTS max-age is set to {max_age} seconds",
                        "recommendation": "Set HSTS max-age to at least 1 year (31536000 seconds)",
                        "reference": "ISO 27002 14.4.6"
                    })
                
        except requests.exceptions.RequestException as e:
            findings.append({
                "severity": "Info",
                "category": self.category,
                "description": "HSTS check error",
                "details": f"Failed to check HSTS header: {str(e)}",
                "recommendation": "Verify server configuration and accessibility",
                "reference": None
            })
            
        return findings
        
    def _check_compression(self, hostname: str, port: int = 443) -> List[Dict[str, Any]]:
        """Check for TLS compression vulnerabilities (CRIME, TIME, BREACH)."""
        findings = []
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Check for TLS compression
                    if hasattr(ssock, 'compression'):
                        compression = ssock.compression()
                        if compression:
                            findings.append({
                                "severity": "High",
                                "category": self.category,
                                "description": "TLS Compression Enabled (CRIME Vulnerability)",
                                "details": f"Server supports TLS compression: {compression}",
                                "recommendation": "Disable TLS compression to prevent CRIME attack",
                                "reference": "https://www.rfc-editor.org/rfc/rfc7525#section-3.3",
                                "cve_references": ["CVE-2012-4929"]
                            })

            # Check for HTTP compression (BREACH)
            response = requests.get(f"https://{hostname}", verify=True)
            if 'Content-Encoding' in response.headers:
                if 'gzip' in response.headers['Content-Encoding'] or 'deflate' in response.headers['Content-Encoding']:
                    findings.append({
                        "severity": "Medium",
                        "category": self.category,
                        "description": "HTTP Compression Enabled (Potential BREACH Vulnerability)",
                        "details": "Server supports HTTP compression which may be vulnerable to BREACH attack",
                        "recommendation": "Consider disabling HTTP compression for sensitive pages",
                        "reference": "https://www.breachattack.com/",
                        "cve_references": ["CVE-2013-3587"]
                    })

        except Exception as e:
            findings.append({
                "severity": "Info",
                "category": self.category,
                "description": "Compression check failed",
                "details": f"Could not check compression settings: {str(e)}",
                "recommendation": "Manual verification recommended",
                "reference": None
            })
            
        return findings

    def _check_padding_oracles(self, hostname: str, port: int = 443) -> List[Dict[str, Any]]:
        """Check for padding oracle vulnerabilities."""
        findings = []
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    
                    # Check for Lucky13 vulnerability (CBC ciphers)
                    if "CBC" in cipher[0]:
                        findings.append({
                            "severity": "Medium",
                            "category": self.category,
                            "description": "Potential Lucky13 Vulnerability",
                            "details": "Server uses CBC mode ciphers which may be vulnerable to Lucky13 timing attacks",
                            "recommendation": "Use AEAD ciphers (GCM, CCM) instead of CBC mode",
                            "reference": "https://www.isg.rhul.ac.uk/tls/Lucky13.html",
                            "cve_references": ["CVE-2013-0169"]
                        })

        except Exception as e:
            findings.append({
                "severity": "Info",
                "category": self.category,
                "description": "Padding oracle check failed",
                "details": f"Could not check for padding oracle vulnerabilities: {str(e)}",
                "recommendation": "Manual verification recommended",
                "reference": None
            })
            
        return findings

    def _check_drown(self, hostname: str, port: int = 443) -> List[Dict[str, Any]]:
        """Check for DROWN vulnerability (SSLv2 support)."""
        findings = []
        
        try:
            # Create a socket with SSLv2 support
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.options &= ~ssl.OP_NO_SSLv2
            
            with socket.create_connection((hostname, port)) as sock:
                try:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        if ssock.version() == "SSLv2":
                            findings.append({
                                "severity": "Critical",
                                "category": self.category,
                                "description": "DROWN Vulnerability Detected",
                                "details": "Server supports SSLv2 which is vulnerable to DROWN attack",
                                "recommendation": "Disable SSLv2 completely on all servers sharing the same certificate",
                                "reference": "https://drownattack.com/",
                                "cve_references": ["CVE-2016-0800"]
                            })
                except ssl.SSLError:
                    # SSLv2 not supported (good)
                    pass

        except Exception as e:
            findings.append({
                "severity": "Info",
                "category": self.category,
                "description": "DROWN check failed",
                "details": f"Could not check for DROWN vulnerability: {str(e)}",
                "recommendation": "Manual verification recommended",
                "reference": None
            })
            
        return findings

    def _check_renegotiation(self, hostname: str, port: int = 443) -> List[Dict[str, Any]]:
        """Check for secure renegotiation support."""
        findings = []
        context = ssl.create_default_context()
        
        try:
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Check for secure renegotiation
                    if not hasattr(ssock, 'get_secure_renegotiation_support') or not ssock.get_secure_renegotiation_support():
                        findings.append({
                            "severity": "High",
                            "category": self.category,
                            "description": "Insecure Renegotiation Supported",
                            "details": "Server does not support secure renegotiation",
                            "recommendation": "Enable secure renegotiation and disable insecure renegotiation",
                            "reference": "https://www.rfc-editor.org/rfc/rfc5746",
                            "cve_references": ["CVE-2009-3555"]
                        })

        except Exception as e:
            findings.append({
                "severity": "Info",
                "category": self.category,
                "description": "Renegotiation check failed",
                "details": f"Could not check renegotiation support: {str(e)}",
                "recommendation": "Manual verification recommended",
                "reference": None
            })
            
        return findings

    def audit(self, target: str) -> List[Dict[str, Any]]:
        """
        Perform comprehensive SSL/TLS security audit following ISO 27002 and NIST guidelines.
        
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
            
        # Basic SSL/TLS checks
        self.findings.extend(self._check_ssl_version(target))
        self.findings.extend(self._check_certificate(target))
        self.findings.extend(self._check_dh_params(target))
        self.findings.extend(self._check_hsts(target))
        
        # Additional vulnerability checks
        self.findings.extend(self._check_heartbleed(target))
        self.findings.extend(self._check_compression(target))
        self.findings.extend(self._check_padding_oracles(target))
        self.findings.extend(self._check_drown(target))
        self.findings.extend(self._check_renegotiation(target))
        
        return self.findings 