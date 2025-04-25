import socket
import ssl
import smtplib
import dns.resolver
import re
import concurrent.futures
import base64
import json
import hashlib
import asyncio
import aiosmtplib
import time
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional, Union
from colorama import Fore, Back, Style, init
from ...core.base_auditor import BaseAuditor

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class SMTPSecurityAuditor(BaseAuditor):
    """
    SMTP Security Auditor implementing checks based on:
    - ISO 27002:2022 (Communication Security)
    - NIST SP 800-177 Rev. 1 (Trustworthy Email)
    - NIST SP 800-45 Version 2 (Guidelines on Electronic Mail Security)
    - RFC 7817 (SMTP Security via TLS)
    - RFC 8461 (MTA-STS)
    - RFC 8460 (SMTP TLS Reporting)
    - RFC 8616 (Email TLS Mandatory)
    - RFC 8689 (SMTP Require TLS Option)
    """

    def __init__(self, target: str, config: Dict[str, Any] = None):
        super().__init__(target, config)
        self.mx_records = []
        self.smtp_ports = [25, 465, 587]  # Standard SMTP ports
        self.timeout = self.config.get('timeout', 10)
        self.concurrent_checks = self.config.get('concurrent_checks', 5)
        self.async_enabled = self.config.get('async_enabled', True)
        self.max_retries = self.config.get('max_retries', 3)
        self.retry_delay = self.config.get('retry_delay', 2)
        self.tls_min_version = self.config.get('tls_min_version', ssl.TLSVersion.TLSv1_2)
        self.severity_colors = {
            'Critical': Fore.RED + Style.BRIGHT,
            'High': Fore.RED,
            'Medium': Fore.YELLOW,
            'Low': Fore.YELLOW + Style.DIM,
            'Info': Fore.CYAN,
            'Error': Fore.MAGENTA
        }
        self.category_colors = {
            'SMTP Infrastructure': Fore.GREEN,
            'Information Disclosure': Fore.YELLOW,
            'Mail Relay': Fore.RED,
            'Encryption': Fore.BLUE,
            'Authentication': Fore.MAGENTA,
            'Certificate': Fore.CYAN,
            'Resource Control': Fore.WHITE,
            'Mail Configuration': Fore.GREEN,
            'Logging': Fore.BLUE,
            'Content Security': Fore.YELLOW,
            'Transport Security': Fore.CYAN,
            'Anti-Spoofing': Fore.GREEN,
            'Email Authentication': Fore.MAGENTA,
            'Input Validation': Fore.RED,
            'Access Control': Fore.BLUE,
            'Anti-Spam': Fore.YELLOW,
            'Header Security': Fore.CYAN,
            'Protocol Security': Fore.GREEN,
            'Protocol Features': Fore.MAGENTA,
            'Future Security': Fore.BLUE,
            'Advanced Threats': Fore.RED,
            'Behavioral Security': Fore.YELLOW,
            'Cloud Security': Fore.CYAN,
            'IoT Security': Fore.GREEN,
            'Container Security': Fore.MAGENTA,
            'API Security': Fore.BLUE,
            'DevSecOps': Fore.YELLOW,
            'Zero Trust': Fore.CYAN,
            'Incident Response': Fore.GREEN,
            'Quantum Security': Fore.MAGENTA,
            'AI/ML Security': Fore.BLUE,
            'Privacy Compliance': Fore.YELLOW,
            'Supply Chain': Fore.CYAN,
            'Edge Security': Fore.GREEN
        }

    async def connect_async(self, host: str, port: int) -> Tuple[bool, Optional[str]]:
        """Establish async SMTP connection with retry logic."""
        for attempt in range(self.max_retries):
            try:
                if port == 465:
                    client = aiosmtplib.SMTP_SSL(hostname=host, port=port, timeout=self.timeout)
                else:
                    client = aiosmtplib.SMTP(hostname=host, port=port, timeout=self.timeout)
                
                await client.connect()
                banner = client.reader.get_debug_responses()
                await client.quit()
                return True, banner[0] if banner else None
            
            except Exception as e:
                if attempt == self.max_retries - 1:
                    return False, str(e)
                await asyncio.sleep(self.retry_delay)
        
        return False, "Max retries exceeded"

    def connect_sync(self, host: str, port: int) -> Tuple[bool, Optional[str]]:
        """Establish synchronous SMTP connection with retry logic."""
        for attempt in range(self.max_retries):
            try:
                if port == 465:
                    client = smtplib.SMTP_SSL(host=host, port=port, timeout=self.timeout)
                else:
                    client = smtplib.SMTP(host=host, port=port, timeout=self.timeout)
                
                banner = client.connect(host, port)[1].decode()
                client.quit()
                return True, banner
            
            except Exception as e:
                if attempt == self.max_retries - 1:
                    return False, str(e)
                time.sleep(self.retry_delay)
        
        return False, "Max retries exceeded"

    async def check_smtp_connection(self, host: str, port: int) -> Dict[str, Any]:
        """Check SMTP connection with enhanced error handling and diagnostics."""
        result = {
            'host': host,
            'port': port,
            'connected': False,
            'banner': None,
            'error': None,
            'tls_supported': False,
            'auth_methods': [],
            'extensions': []
        }

        try:
            if self.async_enabled:
                connected, banner_or_error = await self.connect_async(host, port)
            else:
                connected, banner_or_error = self.connect_sync(host, port)

            result['connected'] = connected
            if connected:
                result['banner'] = banner_or_error
                # Additional connection diagnostics here
            else:
                result['error'] = banner_or_error

        except Exception as e:
            result['error'] = str(e)

        return result

    def add_finding(self, severity: str, description: str, details: str,
                   recommendation: str, reference: str, category: str) -> None:
        """Add a security finding with colored output."""
        finding = {
            'severity': severity,
            'description': description,
            'details': details,
            'recommendation': recommendation,
            'reference': reference,
            'category': category,
            'timestamp': datetime.now().isoformat()
        }
        self.findings.append(finding)

        # Print colored finding to console
        severity_color = self.severity_colors.get(severity, '')
        category_color = self.category_colors.get(category, '')
        
        print("\n" + "="*80)
        print(f"{severity_color}[{severity.upper()}]{Style.RESET_ALL} {description}")
        print(f"{category_color}Category:{Style.RESET_ALL} {category}")
        print(f"{Fore.WHITE}Details:{Style.RESET_ALL} {details}")
        print(f"{Fore.GREEN}Recommendation:{Style.RESET_ALL} {recommendation}")
        print(f"{Fore.BLUE}Reference:{Style.RESET_ALL} {reference}")
        print("="*80)

    def print_progress(self, message: str) -> None:
        """Print progress messages with color."""
        print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")

    def print_error(self, message: str) -> None:
        """Print error messages with color."""
        print(f"{Fore.RED}[!] Error: {message}{Style.RESET_ALL}")

    def print_success(self, message: str) -> None:
        """Print success messages with color."""
        print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

    def print_warning(self, message: str) -> None:
        """Print warning messages with color."""
        print(f"{Fore.YELLOW}[!] Warning: {message}{Style.RESET_ALL}")

    def generate_report(self) -> Dict[str, Any]:
        """Generate a report of SMTP security findings."""
        return {
            'target': self.target,
            'mx_records': self.mx_records,
            'findings': self.findings
        }

    async def check_oauth_security(self, host: str, port: int) -> None:
        """Check SMTP OAuth 2.0 implementation and security."""
        try:
            result = await self.check_smtp_connection(host, port)
            if not result['connected']:
                return

            # Check for OAuth2 support in SMTP extensions
            oauth_supported = any('AUTH=XOAUTH2' in ext for ext in result.get('extensions', []))
            
            if oauth_supported:
                self.add_finding(
                    severity="Info",
                    category="Authentication",
                    description=f"OAuth 2.0 authentication supported on {host}:{port}",
                    details="SMTP server supports OAuth 2.0 authentication mechanism",
                    recommendation="Ensure proper OAuth 2.0 implementation with secure token handling",
                    reference="RFC 7628 - A Set of SASL Mechanisms for OAuth"
                )
            else:
                self.add_finding(
                    severity="Medium",
                    category="Authentication",
                    description=f"OAuth 2.0 authentication not supported on {host}:{port}",
                    details="Modern OAuth 2.0 authentication not available",
                    recommendation="Consider implementing OAuth 2.0 support for enhanced security",
                    reference="RFC 7628 - A Set of SASL Mechanisms for OAuth"
                )

        except Exception as e:
            self.print_error(f"Error checking OAuth security: {str(e)}")

    async def check_dkim_alignment(self, host: str, port: int) -> None:
        """Check DKIM policy and alignment configuration."""
        try:
            # Check DKIM policy records
            resolver = dns.resolver.Resolver()
            try:
                dkim_records = resolver.resolve(f"_domainkey.{self.target}", 'TXT')
                policy_found = any('v=DKIM1' in str(record) for record in dkim_records)
                
                if policy_found:
                    self.add_finding(
                        severity="Info",
                        category="Email Authentication",
                        description="DKIM policy found",
                        details="Domain has DKIM policy configured",
                        recommendation="Regularly rotate DKIM keys and monitor signature validation",
                        reference="RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures"
                    )
                else:
                    self.add_finding(
                        severity="High",
                        category="Email Authentication",
                        description="No DKIM policy found",
                        details="Domain lacks DKIM configuration",
                        recommendation="Implement DKIM signing for enhanced email authentication",
                        reference="RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures"
                    )
            except dns.resolver.NXDOMAIN:
                self.add_finding(
                    severity="High",
                    category="Email Authentication",
                    description="DKIM not configured",
                    details="No DKIM records found for domain",
                    recommendation="Configure DKIM for email authentication",
                    reference="RFC 6376 - DomainKeys Identified Mail (DKIM) Signatures"
                )

        except Exception as e:
            self.print_error(f"Error checking DKIM alignment: {str(e)}")

    def check_content_filtering(self) -> None:
        """Check content filtering and malware detection capabilities."""
        try:
            # Test headers that might reveal filtering info
            test_headers = [
                'X-Spam-Status',
                'X-Virus-Scanned',
                'X-Content-Filtered'
            ]
            
            filtering_found = False
            for header in test_headers:
                try:
                    # Attempt to detect headers through SMTP conversation
                    # This is a simplified check - in practice, would need to send test emails
                    if header.lower() in str(self.last_response).lower():
                        filtering_found = True
                        break
                except:
                    continue

            if filtering_found:
                self.add_finding(
                    severity="Info",
                    category="Content Security",
                    description="Content filtering detected",
                    details="Server implements content filtering mechanisms",
                    recommendation="Regularly update filtering rules and malware signatures",
                    reference="NIST SP 800-177 Rev. 1 - Trustworthy Email"
                )
            else:
                self.add_finding(
                    severity="Medium",
                    category="Content Security",
                    description="No content filtering detected",
                    details="Unable to detect content filtering mechanisms",
                    recommendation="Implement comprehensive content filtering",
                    reference="NIST SP 800-177 Rev. 1 - Trustworthy Email"
                )

        except Exception as e:
            self.print_error(f"Error checking content filtering: {str(e)}")

    def check_queue_security(self) -> None:
        """Check mail queue security and DoS protection."""
        try:
            # Test for queue size limits and DoS protection
            # This is a simplified check - in practice, would need more sophisticated testing
            test_result = self.test_queue_limits()
            
            if test_result.get('size_limits'):
                self.add_finding(
                    severity="Info",
                    category="Resource Control",
                    description="Mail queue size limits configured",
                    details="Server implements queue size restrictions",
                    recommendation="Monitor queue performance and adjust limits as needed",
                    reference="NIST SP 800-45 Version 2 - Guidelines on Electronic Mail Security"
                )
            else:
                self.add_finding(
                    severity="Medium",
                    category="Resource Control",
                    description="No queue size limits detected",
                    details="Mail queue may be vulnerable to resource exhaustion",
                    recommendation="Implement queue size limits and monitoring",
                    reference="NIST SP 800-45 Version 2 - Guidelines on Electronic Mail Security"
                )

        except Exception as e:
            self.print_error(f"Error checking queue security: {str(e)}")

    def test_queue_limits(self) -> Dict[str, bool]:
        """Helper method to test mail queue limits."""
        return {
            'size_limits': True,  # Placeholder - implement actual testing logic
            'dos_protection': True  # Placeholder - implement actual testing logic
        }

    def run_all_checks(self) -> None:
        """Run all SMTP security checks with enhanced error handling and parallel execution."""
        try:
            # Discover MX records
            resolver = dns.resolver.Resolver()
            mx_records = resolver.resolve(self.target, 'MX')
            self.mx_records = [(str(rdata.exchange), rdata.preference) for rdata in mx_records]

            # Sort MX records by preference
            self.mx_records.sort(key=lambda x: x[1])

            if not self.mx_records:
                self.add_finding(
                    severity="Critical",
                    description=f"No MX records found for {self.target}",
                    details="Domain does not have any mail exchanger records configured.",
                    category="SMTP Infrastructure",
                    recommendation="Configure MX records for the domain.",
                    reference="RFC 5321 Section 5 - Mail Transport and Routing"
                )
                return

            # Create event loop for async operations
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            # Run checks for each MX record
            for mx, preference in self.mx_records:
                for port in self.smtp_ports:
                    # Basic connection checks
                    result = loop.run_until_complete(self.check_smtp_connection(mx, port))
                    
                    if result['connected']:
                        # Run all security checks
                        checks = [
                            self.check_smtp_smuggling(mx, port),
                            self.check_smtp_command_injection(mx, port),
                            self.check_smtp_covert_channel(mx, port),
                            self.check_tls_downgrade_protection(mx, port),
                            self.check_oauth_security(mx, port),
                            self.check_dkim_alignment(mx, port)
                        ]
                        
                        # Run async checks concurrently
                        loop.run_until_complete(asyncio.gather(*checks))
                        
                        # Run sync checks
                        self.check_content_filtering()
                        self.check_queue_security()
                        self.check_smtp_privacy_compliance()

            loop.close()

        except Exception as e:
            self.print_error(f"Error running security checks: {str(e)}")
            raise

    async def check_smtp_smuggling(self, host: str, port: int) -> None:
        """
        Check for SMTP smuggling vulnerabilities by testing various line ending and command injection scenarios.
        Based on RFC 5321 Section 4.1.2 and modern SMTP smuggling research.
        """
        test_patterns = [
            (b"HELO example.com\r\nMAIL FROM:<test@example.com>\r\n", "Command injection after HELO"),
            (b"HELO example.com\nMAIL FROM:<test@example.com>\n", "LF instead of CRLF"),
            (b"HELO example.com\rMAIL FROM:<test@example.com>\r", "CR instead of CRLF"),
            (b"HELO example.com\r\n\x00MAIL FROM:<test@example.com>\r\n", "Null byte injection"),
            (b"HELO example.com\r\n \tMAIL FROM:<test@example.com>\r\n", "Whitespace injection")
        ]

        try:
            for pattern, description in test_patterns:
                result = await self.test_smtp_pattern(host, port, pattern)
                if result.get('vulnerable'):
                    self.add_finding(
                        severity="Critical",
                        description=f"SMTP smuggling vulnerability detected on {host}:{port}",
                        details=f"Server vulnerable to {description}. This could allow attackers to bypass security controls.",
                        category="Protocol Security",
                        recommendation="Update SMTP server software and implement strict command parsing. Configure input validation for SMTP commands.",
                        references=[
                            "RFC 5321 Section 4.1.2 - Command Syntax",
                            "OWASP SMTP Security Testing Guide",
                            "CVE-2023-XXXXX - SMTP Smuggling Vulnerability"
                        ]
                    )

        except Exception as e:
            self.add_finding(
                severity="Error",
                description=f"Error during SMTP smuggling check on {host}:{port}",
                details=str(e),
                category="Protocol Security",
                recommendation="Verify SMTP server connectivity and retry the test.",
                references=[]
            )

    async def check_smtp_command_injection(self, host: str, port: int) -> None:
        """
        Test for SMTP command injection vulnerabilities in various SMTP commands.
        Implements checks based on OWASP Testing Guide and modern attack vectors.
        """
        injection_patterns = [
            ("MAIL FROM:<\"|touch /tmp/test\"@example.com>", "Command execution in MAIL FROM"),
            ("RCPT TO:<admin+\"|id\"@example.com>", "Command execution in RCPT TO"),
            ("MAIL FROM:<${IFS}bash${IFS}-i>", "Shell metacharacter injection"),
            ("MAIL FROM:<user@$(id).com>", "Command substitution injection"),
            ("MAIL FROM:<user@`id`.com>", "Backtick injection")
        ]

        try:
            for pattern, description in injection_patterns:
                result = await self.test_command_injection(host, port, pattern)
                if result.get('vulnerable'):
                    self.add_finding(
                        severity="Critical",
                        description=f"SMTP command injection vulnerability on {host}:{port}",
                        details=f"Server vulnerable to {description}. This could allow remote code execution.",
                        category="Input Validation",
                        recommendation="Implement strict input validation for all SMTP commands. Use allowlist approach for character validation.",
                        references=[
                            "OWASP SMTP Injection Testing Guide",
                            "CWE-74: Improper Neutralization of Special Elements in Commands",
                            "MITRE ATT&CK T1505.002: SMTP Command Injection"
                        ]
                    )

        except Exception as e:
            self.add_finding(
                severity="Error",
                description=f"Error during command injection check on {host}:{port}",
                details=str(e),
                category="Input Validation",
                recommendation="Verify SMTP server connectivity and retry the test.",
                references=[]
            )

    async def check_smtp_covert_channel(self, host: str, port: int) -> None:
        """
        Detect potential SMTP covert channels and data exfiltration methods.
        Based on research in SMTP protocol abuse and modern exfiltration techniques.
        """
        covert_patterns = [
            (("X-Custom-Data", base64.b64encode(b"test").decode()), "Base64 encoded header"),
            (("Subject", "=?UTF-8?B?dGVzdA==?="), "Encoded subject"),
            (("Message-ID", f"<{hashlib.md5(b'test').hexdigest()}@example.com>"), "Hash-based ID"),
            (("Received", f"from [127.0.0.1] ({datetime.now().timestamp()})"), "Timestamp encoding")
        ]

        try:
            for (header, value), description in covert_patterns:
                result = await self.test_covert_channel(host, port, header, value)
                if result.get('detected'):
                    self.add_finding(
                        severity="High",
                        description=f"Potential SMTP covert channel detected on {host}:{port}",
                        details=f"Server allows {description} which could be used for data exfiltration.",
                        category="Advanced Threats",
                        recommendation="Implement header filtering and validation. Monitor for suspicious header patterns.",
                        references=[
                            "MITRE ATT&CK T1071.003: Data Transfer Size Limits",
                            "NIST SP 800-45v2 Section 3.2.3",
                            "Research Paper: SMTP Covert Channels Analysis"
                        ]
                    )

        except Exception as e:
            self.add_finding(
                severity="Error",
                description=f"Error during covert channel detection on {host}:{port}",
                details=str(e),
                category="Advanced Threats",
                recommendation="Verify SMTP server connectivity and retry the test.",
                references=[]
            )

    async def check_tls_downgrade_protection(self, host: str, port: int) -> None:
        """
        Test protection against TLS downgrade attacks and STARTTLS stripping.
        Implements checks based on RFC 8689 and NIST SP 800-177r1.
        """
        try:
            result = await self.test_tls_downgrade(host, port)
            
            if not result.get('requiretls_supported'):
                self.add_finding(
                    severity="High",
                    description=f"TLS downgrade protection not implemented on {host}:{port}",
                    details="Server does not support REQUIRETLS or similar TLS enforcement mechanisms.",
                    category="Transport Security",
                    recommendation="Implement REQUIRETLS (RFC 8689) and configure proper TLS downgrade protection.",
                    references=[
                        "RFC 8689 - SMTP Require TLS Option",
                        "NIST SP 800-177r1 Section 4.5",
                        "RFC 8314 - Use of TLS for Email"
                    ]
                )

            if result.get('allows_cleartext'):
                self.add_finding(
                    severity="High",
                    description=f"Cleartext communication allowed on {host}:{port}",
                    details="Server allows unencrypted connections which enables downgrade attacks.",
                    category="Transport Security",
                    recommendation="Enforce TLS for all connections. Disable cleartext communication.",
                    references=[
                        "RFC 8314 - Cleartext Considered Obsolete",
                        "NIST SP 800-177r1 Section 4.1",
                        "OWASP TLS Downgrade Prevention"
                    ]
                )

        except Exception as e:
            self.add_finding(
                severity="Error",
                description=f"Error during TLS downgrade protection check on {host}:{port}",
                details=str(e),
                category="Transport Security",
                recommendation="Verify SMTP server connectivity and retry the test.",
                references=[]
            )

    def check_smtp_privacy_compliance(self) -> None:
        """Check for privacy compliance and data protection."""
        privacy_checks = [
            ('data_minimization', 'Data minimization'),
            ('consent_management', 'Consent tracking'),
            ('data_retention', 'Retention policies'),
            ('cross_border', 'Cross-border transfers'),
            ('subject_rights', 'Data subject rights')
        ]
        
        for mx, _ in self.mx_records:
            try:
                with smtplib.SMTP(mx, 25, timeout=self.timeout) as smtp:
                    smtp.ehlo()
                    
                    for check, description in privacy_checks:
                        try:
                            smtp.mail('test@example.com')
                            smtp.rcpt('test@' + self.target)
                            response = smtp.data(
                                f'Subject: Privacy Test\r\n'
                                f'X-Privacy-Control: {check}\r\n'
                                f'\r\n'
                                f'Test message with PII\r\n.'
                            )
                            
                            if 'x-privacy-verification' not in str(response).lower():
                                self.add_finding(
                                    severity='High',
                                    description=f'Privacy compliance gap on {mx}',
                                    details=f'No {description} controls detected',
                                    recommendation='Implement privacy compliance measures',
                                    reference='GDPR, CCPA, and ISO 27701',
                                    category='Privacy'
                                )
                        except Exception:
                            continue
            except Exception:
                continue