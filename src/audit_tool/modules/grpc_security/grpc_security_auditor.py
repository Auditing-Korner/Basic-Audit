import grpc
import ssl
import socket
import requests
import json
from typing import Dict, Any, List, Optional
from ...core.base_auditor import BaseAuditor
from concurrent import futures
import re
from cryptography import x509
from cryptography.hazmat.backends import default_backend

class GRPCSecurityAuditor(BaseAuditor):
    """
    gRPC Security Auditor implementing checks based on:
    - gRPC Security Best Practices
    - OWASP API Security Top 10
    - CWE Common Weakness Enumeration
    - NIST Guidelines
    """
    
    def __init__(self, target: str, config: Dict[str, Any] = None):
        """Initialize the gRPC security auditor."""
        super().__init__(target, config)
        self.grpc_port = config.get('grpc_port', 50051)
        self.services = {}
        self.reflection_enabled = False
        self.tls_config = {}
        
    def run_all_checks(self) -> None:
        """Run all gRPC security checks."""
        # Discovery and configuration checks
        self.discover_grpc_services()
        self.check_reflection_security()
        
        # TLS and encryption checks
        self.check_tls_configuration()
        self.check_certificate_security()
        self.check_cipher_suites()
        
        # Authentication and authorization checks
        self.check_authentication_mechanisms()
        self.check_authorization_controls()
        self.check_token_security()
        
        # Protocol and configuration checks
        self.check_keepalive_config()
        self.check_max_message_size()
        self.check_compression_security()
        
        # Additional security checks
        self.check_metadata_security()
        self.check_error_handling()
        self.check_rate_limiting()
        self.check_ddos_protection()
        self.check_interceptor_security()
        self.check_deadline_security()
        self.check_streaming_security()
        self.check_channel_security()
        self.check_load_balancing_security()
        self.check_retry_policy()
        self.check_health_check_security()
        self.check_proto_security()
        self.check_service_mesh_security()
        self.check_mtls_configuration()
        self.check_keepalive_attacks()
        self.check_context_security()
        self.check_header_validation()
        self.check_service_config_security()
        self.check_proxy_security()
        self.check_version_security()

    def _create_ssl_credentials(self, cert_chain: bytes = None, private_key: bytes = None, root_certs: bytes = None) -> grpc.ChannelCredentials:
        """Create SSL credentials for secure connection."""
        try:
            return grpc.ssl_channel_credentials(
                certificate_chain=cert_chain,
                private_key=private_key,
                root_certificates=root_certs
            )
        except Exception as e:
            self.add_finding(
                severity='Error',
                description='SSL Credentials Creation Failed',
                details=f'Failed to create SSL credentials: {str(e)}',
                recommendation='Verify SSL certificate and key configuration',
                category='SSL/TLS'
            )
            return None

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create a secure SSL context with proper configuration."""
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        return context

    def discover_grpc_services(self) -> None:
        """Discover available gRPC services and check for security issues."""
        try:
            # Try to establish connection
            with grpc.insecure_channel(f"{self.target}:{self.grpc_port}") as channel:
                try:
                    # Check if reflection service is enabled
                    from grpc_reflection.v1alpha import reflection_pb2_grpc
                    reflection_pb2_grpc.ServerReflectionStub(channel)
                    self.reflection_enabled = True
                    self.add_finding(
                        severity="Medium",
                        description="gRPC reflection service enabled",
                        details="Server reflection allows service discovery which could be used for reconnaissance",
                        recommendation="Disable reflection service in production unless absolutely necessary",
                        reference="gRPC Server Reflection Tutorial",
                        category="gRPC Security"
                    )
                    
                    # List available services
                    if self.reflection_enabled:
                        self.services = self._get_services_via_reflection(channel)
                        
                except Exception:
                    self.reflection_enabled = False
                    
        except Exception as e:
            self.logger.error(f"Error discovering gRPC services: {str(e)}")
            
    def check_tls_configuration(self) -> None:
        """Check TLS configuration and security settings."""
        try:
            # Check if TLS is enabled
            creds = self._create_ssl_credentials()
            if not creds:
                return

            try:
                with grpc.secure_channel(f"{self.target}:{self.grpc_port}", creds) as channel:
                    state = channel.get_state(try_to_connect=True)
                    if state == grpc.ChannelConnectivity.READY:
                        self.tls_config['enabled'] = True
                    else:
                        self.add_finding(
                            severity="Critical",
                            description="TLS not enabled",
                            details="gRPC server is not using TLS encryption",
                            recommendation="Enable TLS encryption for all gRPC communications",
                            reference="gRPC Authentication Guide",
                            category="gRPC Security"
                        )
            except Exception:
                self.tls_config['enabled'] = False
                
            # Check TLS version if enabled
            if self.tls_config.get('enabled'):
                context = self._create_ssl_context()
                with socket.create_connection((self.target, self.grpc_port)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        version = ssock.version()
                        if version not in ['TLSv1.2', 'TLSv1.3']:
                            self.add_finding(
                                severity="High",
                                description="Weak TLS version",
                                details=f"Server using {version} which is considered insecure",
                                recommendation="Configure server to use TLS 1.2 or TLS 1.3",
                                reference="NIST SP 800-52r2",
                                category="gRPC Security"
                            )
                            
        except Exception as e:
            self.logger.error(f"Error checking TLS configuration: {str(e)}")
            
    def check_certificate_security(self) -> None:
        """Check certificate configuration and security."""
        try:
            if not self.tls_config.get('enabled'):
                return
                
            context = self._create_ssl_context()
            with socket.create_connection((self.target, self.grpc_port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert_binary = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(cert_binary, default_backend())
                    
                    # Check certificate expiration
                    from datetime import datetime
                    if cert.not_valid_after < datetime.now():
                        self.add_finding(
                            severity="Critical",
                            description="Expired TLS certificate",
                            details="Server's TLS certificate has expired",
                            recommendation="Renew the TLS certificate",
                            reference="OWASP Transport Layer Protection Cheat Sheet",
                            category="gRPC Security"
                        )
                        
                    # Check key size
                    public_key = cert.public_key()
                    key_size = public_key.key_size
                    if key_size < 2048:
                        self.add_finding(
                            severity="High",
                            description="Weak certificate key size",
                            details=f"Certificate using {key_size}-bit key which is considered weak",
                            recommendation="Use certificates with at least 2048-bit RSA keys or equivalent",
                            reference="NIST SP 800-57 Part 1 Rev. 5",
                            category="gRPC Security"
                        )
                        
                    # Check signature algorithm
                    sig_alg = cert.signature_algorithm_oid._name
                    weak_algorithms = ['md5', 'sha1']
                    if any(alg in sig_alg.lower() for alg in weak_algorithms):
                        self.add_finding(
                            severity="High",
                            description="Weak certificate signature algorithm",
                            details=f"Certificate using weak signature algorithm: {sig_alg}",
                            recommendation="Use certificates signed with SHA-256 or stronger",
                            reference="NIST SP 800-57 Part 1 Rev. 5",
                            category="gRPC Security"
                        )
                        
        except Exception as e:
            self.logger.error(f"Error checking certificate security: {str(e)}")

    def check_cipher_suites(self) -> None:
        """Check supported cipher suites for security."""
        try:
            context = self._create_ssl_context()
            with socket.create_connection((self.target, self.grpc_port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL']
                        if any(weak in cipher_name for weak in weak_ciphers):
                            self.add_finding(
                                severity="High",
                                description="Weak cipher suite in use",
                                details=f"Server using weak cipher suite: {cipher_name}",
                                recommendation="Configure server to use strong cipher suites only",
                                reference="NIST SP 800-52r2",
                                category="gRPC Security"
                            )
        except Exception as e:
            self.logger.error(f"Error checking cipher suites: {str(e)}")

    # ... [Additional security check methods would go here] ... 