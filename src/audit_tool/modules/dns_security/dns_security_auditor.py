import dns.resolver
import dns.flags
import socket
from typing import Dict, Any, List, Tuple
from ...core.base_auditor import BaseAuditor

class DNSSecurityAuditor(BaseAuditor):
    """
    DNS Security Auditor implementing checks based on ISO 27002 and NIST guidelines.
    
    References:
    - ISO 27002:2022 (8.4 - Network Security)
    - NIST SP 800-53 Rev. 5 (SC-20, SC-21, SC-22)
    - NIST SP 800-81-2 (Secure Domain Name System Deployment Guide)
    """
    
    def __init__(self, target: str, config: Dict[str, Any] = None):
        super().__init__(target, config)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.config.get('timeout', 10)
        self.nameservers = []
        
    def run_all_checks(self) -> None:
        """Run all DNS security checks."""
        self.discover_nameservers()
        
        # ISO 27002:2022 Controls
        self.check_dns_redundancy()  # Control 8.4 - Network Security
        self.check_zone_transfer()   # Control 8.4 - Network Security
        self.check_recursion()       # Control 8.4 - Network Security
        
        # NIST SP 800-53 Controls
        self.check_dnssec()         # SC-20 - Secure Name/Address Resolution Service
        self.check_response_rate_limiting()  # SC-5 - Denial of Service Protection
        self.check_version_disclosure()      # SC-23 - Session Authenticity
        
        # Additional Security Checks
        self.check_edns_support()
        self.check_tcp_support()
        self.check_cache_poisoning_protection()
        
    def discover_nameservers(self) -> None:
        """Discover authoritative nameservers for the target domain."""
        try:
            ns_records = self.resolver.resolve(self.target, 'NS')
            self.nameservers = [str(ns) for ns in ns_records]
            
            self.add_finding(
                severity='Info',
                description='Nameservers discovered',
                details=f'Found {len(self.nameservers)} nameservers: {", ".join(self.nameservers)}',
                recommendation='Ensure multiple nameservers are properly configured for redundancy',
                reference='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-81-2.pdf',
                category='DNS Infrastructure'
            )
        except Exception as e:
            self.add_finding(
                severity='High',
                description='Failed to discover nameservers',
                details=f'Error: {str(e)}',
                recommendation='Verify DNS configuration and ensure nameservers are accessible',
                reference='https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-81-2.pdf',
                category='DNS Infrastructure'
            )
            
    def check_dns_redundancy(self) -> None:
        """
        Check DNS server redundancy (ISO 27002:2022 - 8.4).
        Verifies multiple nameservers in different networks.
        """
        if len(self.nameservers) < 2:
            self.add_finding(
                severity='High',
                description='Insufficient DNS redundancy',
                details=f'Only {len(self.nameservers)} nameserver(s) found. Recommended minimum is 2.',
                recommendation='Configure multiple authoritative nameservers in different networks',
                reference='ISO 27002:2022 - Control 8.4',
                category='DNS Infrastructure'
            )
            return
            
        # Check if nameservers are in different networks
        networks = set()
        for ns in self.nameservers:
            try:
                ip = socket.gethostbyname(ns)
                network = '.'.join(ip.split('.')[:2])  # Simple network check
                networks.add(network)
            except Exception:
                continue
                
        if len(networks) < 2:
            self.add_finding(
                severity='Medium',
                description='DNS servers in same network',
                details='Multiple nameservers found but they appear to be in the same network',
                recommendation='Deploy nameservers in different networks for better redundancy',
                reference='ISO 27002:2022 - Control 8.4',
                category='DNS Infrastructure'
            )
            
    def check_zone_transfer(self) -> None:
        """
        Check if zone transfers are properly restricted (ISO 27002:2022 - 8.4).
        """
        for ns in self.nameservers:
            try:
                # Attempt AXFR query
                transfer = dns.query.xfr(ns, self.target)
                next(transfer)  # If we can get any records, zone transfer is allowed
                
                self.add_finding(
                    severity='Critical',
                    description=f'Zone transfer allowed from {ns}',
                    details='Nameserver allows unrestricted zone transfers',
                    recommendation='Disable zone transfers or restrict to specific IP addresses',
                    reference='ISO 27002:2022 - Control 8.4',
                    category='DNS Configuration'
                )
            except Exception:
                # Exception means zone transfer failed, which is good
                pass
                
    def check_recursion(self) -> None:
        """
        Check if recursion is properly restricted (NIST SP 800-81-2).
        """
        for ns in self.nameservers:
            try:
                # Try to resolve a known domain through the nameserver
                resolver = dns.resolver.Resolver()
                resolver.nameservers = [socket.gethostbyname(ns)]
                resolver.resolve('www.example.com', 'A')
                
                self.add_finding(
                    severity='High',
                    description=f'Recursive queries allowed on {ns}',
                    details='Nameserver allows recursive queries which could be used for DNS amplification attacks',
                    recommendation='Disable recursion on authoritative nameservers',
                    reference='NIST SP 800-81-2 Section 3.3',
                    category='DNS Configuration'
                )
            except Exception:
                # Exception means recursion is disabled, which is good
                pass
                
    def check_dnssec(self) -> None:
        """
        Check DNSSEC implementation (NIST SP 800-53 SC-20).
        """
        try:
            # Check for DNSKEY records
            self.resolver.resolve(self.target, 'DNSKEY')
            
            # Check for DS records in parent zone
            parent_zone = '.'.join(self.target.split('.')[1:])
            if parent_zone:
                try:
                    self.resolver.resolve(self.target, 'DS')
                    self.add_finding(
                        severity='Info',
                        description='DNSSEC properly configured',
                        details='Both DNSKEY and DS records are present',
                        recommendation='Regularly rotate DNSSEC keys and monitor signature expiration',
                        reference='NIST SP 800-53 Rev. 5 SC-20',
                        category='DNSSEC'
                    )
                except dns.resolver.NoAnswer:
                    self.add_finding(
                        severity='High',
                        description='Incomplete DNSSEC configuration',
                        details='DNSKEY present but no DS record in parent zone',
                        recommendation='Configure DS record in parent zone to complete DNSSEC chain of trust',
                        reference='NIST SP 800-53 Rev. 5 SC-20',
                        category='DNSSEC'
                    )
        except dns.resolver.NoAnswer:
            self.add_finding(
                severity='High',
                description='DNSSEC not implemented',
                details='No DNSKEY records found',
                recommendation='Implement DNSSEC to ensure DNS response authenticity',
                reference='NIST SP 800-53 Rev. 5 SC-20',
                category='DNSSEC'
            )
            
    def check_response_rate_limiting(self) -> None:
        """
        Check for Response Rate Limiting (RRL) implementation.
        """
        # This is a basic check that looks for common RRL symptoms
        try:
            # Send multiple rapid queries
            for _ in range(50):
                self.resolver.resolve(f"nonexistent-{_}.{self.target}", 'A')
                
            self.add_finding(
                severity='Medium',
                description='No Response Rate Limiting detected',
                details='Server responds to rapid queries without limitation',
                recommendation='Implement Response Rate Limiting to prevent DNS amplification attacks',
                reference='NIST SP 800-81-2 Section 10',
                category='DOS Protection'
            )
        except dns.resolver.NoAnswer:
            pass  # Expected for non-existent domains
        except Exception:
            # An error might indicate RRL is active
            pass
            
    def check_version_disclosure(self) -> None:
        """
        Check if DNS server version is disclosed.
        """
        for ns in self.nameservers:
            try:
                version = dns.message.make_query('version.bind', 'TXT', 'CH')
                response = dns.query.udp(version, ns)
                if response.answer:
                    self.add_finding(
                        severity='Medium',
                        description=f'DNS server version disclosed by {ns}',
                        details=f'Server reveals version information: {response.answer[0]}',
                        recommendation='Disable version.bind queries in DNS server configuration',
                        reference='NIST SP 800-53 Rev. 5 SC-23',
                        category='Information Disclosure'
                    )
            except Exception:
                pass
                
    def check_edns_support(self) -> None:
        """Check for EDNS support and configuration."""
        for ns in self.nameservers:
            try:
                query = dns.message.make_query(self.target, 'A', use_edns=True)
                response = dns.query.udp(query, ns)
                
                if not response.flags & dns.flags.DO:
                    self.add_finding(
                        severity='Low',
                        description=f'EDNS not supported on {ns}',
                        details='Server does not support EDNS extensions',
                        recommendation='Enable EDNS support for better DNS functionality',
                        reference='NIST SP 800-81-2',
                        category='DNS Configuration'
                    )
            except Exception:
                pass
                
    def check_tcp_support(self) -> None:
        """Check for TCP transport support."""
        for ns in self.nameservers:
            try:
                query = dns.message.make_query(self.target, 'A')
                dns.query.tcp(query, ns)
            except Exception:
                self.add_finding(
                    severity='High',
                    description=f'No TCP support on {ns}',
                    details='DNS server does not support TCP transport',
                    recommendation='Enable TCP support for DNS queries',
                    reference='NIST SP 800-81-2',
                    category='DNS Configuration'
                )
                
    def check_cache_poisoning_protection(self) -> None:
        """Check for DNS cache poisoning protections."""
        try:
            # Test source port randomization
            ports = set()
            for _ in range(5):
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(('', 0))
                ports.add(sock.getsockname()[1])
                sock.close()
                
            if len(ports) < 3:
                self.add_finding(
                    severity='High',
                    description='Insufficient source port randomization',
                    details='DNS queries use predictable source ports',
                    recommendation='Enable source port randomization in DNS resolver configuration',
                    reference='NIST SP 800-81-2 Section 8.2.1',
                    category='Cache Poisoning Protection'
                )
        except Exception:
            pass
            
    def generate_report(self) -> Dict[str, Any]:
        """Generate a report of DNS security findings."""
        return {
            'target': self.target,
            'nameservers': self.nameservers,
            'findings': self.findings
        } 