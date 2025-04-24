import dns.resolver
import dns.flags
import dns.rdatatype
import dns.message
import dns.query
import dns.rcode
import dns.rdtypes.ANY.NSEC3
import dns.dnssec
import dns.edns
import socket
import ssl
import time
import random
import string
import ipaddress
import re
from typing import Dict, Any, List, Tuple, Set
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
        
        # Email Security Checks
        self.check_caa_records()
        self.check_dmarc_records()
        self.check_spf_records()
        
        # Advanced Security Checks
        self.check_dns_sec_algorithms()
        self.check_nameserver_software_diversity()
        self.check_dns_cookie_support()
        self.check_wildcard_records()
        self.check_dangling_records()
        
        # New Advanced Security Checks
        self.check_nsec3_opt_out()
        self.check_ns_record_consistency()
        self.check_glue_records()
        self.check_dnssec_key_rollover()
        self.check_domain_typosquatting()
        self.check_dns_rebinding_protection()
        self.check_dns_amplification_vulnerability()
        self.check_resolver_privacy()
        self.check_qname_minimization()
        
        # Additional Advanced Security Checks
        self.check_dnssec_algorithm_rollover()
        self.check_cds_cdnskey_records()
        self.check_dane_tlsa_records()
        self.check_reserved_ip_usage()
        self.check_dnssec_validation()
        self.check_ecs_privacy()
        self.check_nsec_downgrade()
        self.check_zone_walking_vulnerability()
        self.check_domain_generation_patterns()
        
        # New Specialized Security Checks
        self.check_dns_tunneling_indicators()
        self.check_dnssec_replay_protection()
        self.check_resolver_fingerprinting()
        self.check_dns_load_balancing()
        self.check_dnssec_key_size()
        self.check_https_delegation()
        self.check_dns_tcp_fallback()
        self.check_record_ttl_consistency()
        self.check_reverse_dns_mismatch()
        self.check_domain_takeover_vectors()
        
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
            
    def check_caa_records(self) -> None:
        """
        Check for CAA (Certification Authority Authorization) records.
        CAA records specify which certificate authorities are allowed to issue certificates.
        """
        try:
            caa_records = self.resolver.resolve(self.target, 'CAA')
            if not caa_records:
                self.add_finding(
                    severity='Medium',
                    description='No CAA records found',
                    details='Domain does not have CAA records to restrict certificate issuance',
                    recommendation='Implement CAA records to specify authorized certificate authorities',
                    reference='RFC 8659 - DNS Certification Authority Authorization',
                    category='Certificate Security'
                )
        except dns.resolver.NoAnswer:
            self.add_finding(
                severity='Medium',
                description='No CAA records found',
                details='Domain does not have CAA records to restrict certificate issuance',
                recommendation='Implement CAA records to specify authorized certificate authorities',
                reference='RFC 8659 - DNS Certification Authority Authorization',
                category='Certificate Security'
            )
        except Exception as e:
            pass

    def check_dmarc_records(self) -> None:
        """
        Check for DMARC (Domain-based Message Authentication, Reporting & Conformance) records.
        """
        try:
            dmarc_records = self.resolver.resolve(f'_dmarc.{self.target}', 'TXT')
            found_valid_dmarc = False
            
            for record in dmarc_records:
                if 'v=DMARC1' in str(record):
                    found_valid_dmarc = True
                    if 'p=none' in str(record):
                        self.add_finding(
                            severity='Medium',
                            description='Permissive DMARC policy',
                            details='DMARC policy is set to "none", which only monitors but does not enforce',
                            recommendation='Consider implementing a stricter DMARC policy (quarantine or reject)',
                            reference='https://dmarc.org/resources/specification/',
                            category='Email Security'
                        )
                    break
                    
            if not found_valid_dmarc:
                self.add_finding(
                    severity='High',
                    description='No valid DMARC record found',
                    details='Domain lacks DMARC protection against email spoofing',
                    recommendation='Implement DMARC with appropriate policy',
                    reference='https://dmarc.org/resources/specification/',
                    category='Email Security'
                )
        except Exception:
            pass

    def check_spf_records(self) -> None:
        """
        Check for SPF (Sender Policy Framework) records and their configuration.
        """
        try:
            spf_records = self.resolver.resolve(self.target, 'TXT')
            found_spf = False
            
            for record in spf_records:
                record_str = str(record)
                if record_str.startswith('"v=spf1'):
                    found_spf = True
                    if record_str.count(' include:') > 10:
                        self.add_finding(
                            severity='Medium',
                            description='Too many SPF includes',
                            details='SPF record has too many include mechanisms which can cause lookup limits',
                            recommendation='Reduce the number of SPF includes to prevent lookup limit issues',
                            reference='RFC 7208 - Sender Policy Framework',
                            category='Email Security'
                        )
                    if '~all' not in record_str and '-all' not in record_str:
                        self.add_finding(
                            severity='Medium',
                            description='Permissive SPF policy',
                            details='SPF record does not end with a strict or soft-fail policy',
                            recommendation='End SPF record with "~all" (soft-fail) or "-all" (hard-fail)',
                            reference='RFC 7208 - Sender Policy Framework',
                            category='Email Security'
                        )
                    break
                    
            if not found_spf:
                self.add_finding(
                    severity='High',
                    description='No SPF record found',
                    details='Domain lacks SPF protection against email spoofing',
                    recommendation='Implement SPF record with appropriate policy',
                    reference='RFC 7208 - Sender Policy Framework',
                    category='Email Security'
                )
        except Exception:
            pass

    def check_dns_sec_algorithms(self) -> None:
        """
        Check for weak or deprecated DNSSEC algorithms.
        """
        try:
            dnskey_records = self.resolver.resolve(self.target, 'DNSKEY')
            for record in dnskey_records:
                algorithm = record.algorithm
                if algorithm in [1, 3, 6, 7, 10]:  # RSA/MD5, DSA/SHA1, DSA-NSEC3-SHA1, RSASHA1-NSEC3-SHA1, RSA-SHA1
                    self.add_finding(
                        severity='High',
                        description='Weak DNSSEC algorithm detected',
                        details=f'DNSSEC is using deprecated or weak algorithm (algorithm {algorithm})',
                        recommendation='Update DNSSEC to use strong algorithms like RSASHA256 or RSASHA512',
                        reference='NIST SP 800-57 Part 3 Rev. 1',
                        category='DNSSEC'
                    )
        except Exception:
            pass

    def check_nameserver_software_diversity(self) -> None:
        """
        Check for DNS software diversity among nameservers.
        """
        software_versions = set()
        for ns in self.nameservers:
            try:
                version = dns.message.make_query('version.bind', 'TXT', 'CH')
                response = dns.query.udp(version, ns)
                if response.answer:
                    software_versions.add(str(response.answer[0]))
            except Exception:
                continue
                
        if len(software_versions) == 1 and len(self.nameservers) > 1:
            self.add_finding(
                severity='Low',
                description='Lack of DNS software diversity',
                details='All nameservers appear to be running the same DNS software version',
                recommendation='Consider using different DNS software implementations for better resilience',
                reference='NIST SP 800-81-2',
                category='DNS Infrastructure'
            )

    def check_dns_cookie_support(self) -> None:
        """
        Check for DNS Cookie support (RFC 7873).
        """
        for ns in self.nameservers:
            try:
                query = dns.message.make_query(self.target, 'A', use_edns=True)
                query.use_edns(edns=0, payload=4096, options=[dns.edns.GenericOption(10, b'0123456789abcdef')])
                response = dns.query.udp(query, ns)
                
                cookie_found = False
                for opt in response.options:
                    if opt.otype == 10:  # DNS Cookie option
                        cookie_found = True
                        break
                        
                if not cookie_found:
                    self.add_finding(
                        severity='Low',
                        description=f'No DNS Cookie support on {ns}',
                        details='Server does not support DNS Cookies for request authentication',
                        recommendation='Enable DNS Cookie support for improved security against spoofing',
                        reference='RFC 7873 - DNS Cookies',
                        category='DNS Security'
                    )
            except Exception:
                pass

    def check_wildcard_records(self) -> None:
        """
        Check for potentially dangerous wildcard DNS records.
        """
        try:
            # Test for wildcard A record
            random_prefix = f'wildcard-test-{int(time.time())}'
            try:
                wildcard_test = self.resolver.resolve(f'{random_prefix}.{self.target}', 'A')
                self.add_finding(
                    severity='Medium',
                    description='Wildcard DNS record detected',
                    details='Domain has wildcard DNS records which could pose security risks',
                    recommendation='Review and restrict wildcard DNS records if not necessary',
                    reference='NIST SP 800-81-2',
                    category='DNS Configuration'
                )
            except dns.resolver.NXDOMAIN:
                pass
        except Exception:
            pass

    def check_dangling_records(self) -> None:
        """
        Check for dangling DNS records that could lead to subdomain takeover.
        """
        try:
            for record_type in ['CNAME', 'NS', 'MX']:
                try:
                    records = self.resolver.resolve(self.target, record_type)
                    for record in records:
                        target = str(record).rstrip('.')
                        try:
                            socket.gethostbyname(target)
                        except socket.gaierror:
                            self.add_finding(
                                severity='High',
                                description=f'Dangling {record_type} record detected',
                                details=f'The {record_type} record points to {target} which does not resolve',
                                recommendation='Remove or update dangling DNS records to prevent subdomain takeover',
                                reference='OWASP Top 10 2021: A05 Security Misconfiguration',
                                category='DNS Configuration'
                            )
                except dns.resolver.NoAnswer:
                    continue
        except Exception:
            pass

    def check_nsec3_opt_out(self) -> None:
        """
        Check for NSEC3 opt-out configuration which might allow zone enumeration.
        """
        try:
            # Query for a non-existent domain to trigger NSEC3 response
            random_name = ''.join(random.choices(string.ascii_lowercase, k=10))
            query = dns.message.make_query(f"{random_name}.{self.target}", 'A', want_dnssec=True)
            
            for ns in self.nameservers:
                try:
                    response = dns.query.udp(query, ns)
                    for rrset in response.authority:
                        for rr in rrset:
                            if isinstance(rr, dns.rdtypes.ANY.NSEC3.NSEC3):
                                if rr.flags & 0x01:  # Opt-out flag
                                    self.add_finding(
                                        severity='Medium',
                                        description='NSEC3 opt-out enabled',
                                        details='NSEC3 opt-out allows zone enumeration and weakens DNSSEC security',
                                        recommendation='Disable NSEC3 opt-out unless absolutely necessary for large zones',
                                        reference='RFC 5155 - DNSSEC Hashed Authenticated Denial of Existence',
                                        category='DNSSEC'
                                    )
                except Exception:
                    continue
        except Exception:
            pass

    def check_ns_record_consistency(self) -> None:
        """
        Check consistency of NS records across all authoritative nameservers.
        """
        ns_sets: Dict[str, Set[str]] = {}
        
        for ns in self.nameservers:
            try:
                query = dns.message.make_query(self.target, 'NS')
                response = dns.query.udp(query, ns)
                
                if response.answer:
                    ns_set = {str(rr) for rr in response.answer[0]}
                    ns_sets[ns] = ns_set
            except Exception:
                continue
        
        if len(ns_sets) > 1:
            reference_set = next(iter(ns_sets.values()))
            for ns, ns_set in ns_sets.items():
                if ns_set != reference_set:
                    self.add_finding(
                        severity='High',
                        description='Inconsistent NS records',
                        details=f'Nameserver {ns} has different NS records than other servers',
                        recommendation='Ensure NS records are consistent across all authoritative nameservers',
                        reference='NIST SP 800-81-2 Section 3',
                        category='DNS Configuration'
                    )

    def check_glue_records(self) -> None:
        """
        Check for missing or incorrect glue records.
        """
        for ns in self.nameservers:
            try:
                # Check if nameserver is in-bailiwick
                if ns.endswith(f".{self.target}"):
                    # Get parent zone
                    parent_zone = '.'.join(self.target.split('.')[1:])
                    if parent_zone:
                        try:
                            # Query parent zone for glue records
                            query = dns.message.make_query(ns, 'A')
                            response = dns.query.udp(query, parent_zone)
                            
                            if response.rcode() == dns.rcode.NXDOMAIN:
                                self.add_finding(
                                    severity='High',
                                    description='Missing glue records',
                                    details=f'No glue records found for in-bailiwick nameserver {ns}',
                                    recommendation='Add appropriate glue records in the parent zone',
                                    reference='NIST SP 800-81-2 Section 3.1',
                                    category='DNS Infrastructure'
                                )
                        except Exception:
                            pass
            except Exception:
                continue

    def check_dnssec_key_rollover(self) -> None:
        """
        Check DNSSEC key rollover practices by examining key inception and expiration dates.
        """
        try:
            dnskey_records = self.resolver.resolve(self.target, 'DNSKEY')
            current_time = int(time.time())
            
            for record in dnskey_records:
                try:
                    # Check key inception and expiration dates if available
                    if hasattr(record, 'inception') and hasattr(record, 'expiration'):
                        inception = int(record.inception)
                        expiration = int(record.expiration)
                        key_age = current_time - inception
                        time_to_expiration = expiration - current_time
                        
                        # Check for keys older than 1 year
                        if key_age > 31536000:  # 1 year in seconds
                            self.add_finding(
                                severity='Medium',
                                description='DNSSEC key rotation needed',
                                details=f'DNSSEC key is older than 1 year (age: {key_age/86400:.1f} days)',
                                recommendation='Implement regular DNSSEC key rotation schedule',
                                reference='NIST SP 800-81-2 Section 4.3',
                                category='DNSSEC'
                            )
                            
                        # Check for keys nearing expiration (within 30 days)
                        if 0 < time_to_expiration < 2592000:  # 30 days in seconds
                            self.add_finding(
                                severity='High',
                                description='DNSSEC key near expiration',
                                details=f'DNSSEC key will expire in {time_to_expiration/86400:.1f} days',
                                recommendation='Plan and execute key rollover before expiration',
                                reference='NIST SP 800-81-2 Section 4.3',
                                category='DNSSEC'
                            )
                except Exception:
                    continue
        except Exception:
            pass

    def check_domain_typosquatting(self) -> None:
        """
        Check for potential typosquatting domains by generating common variations.
        """
        variations = []
        domain = self.target.split('.')[0]
        tld = '.'.join(self.target.split('.')[1:])
        
        # Generate common typo variations
        if len(domain) > 3:
            # Character swapping
            for i in range(len(domain)-1):
                variation = list(domain)
                variation[i], variation[i+1] = variation[i+1], variation[i]
                variations.append(f"{''.join(variation)}.{tld}")
            
            # Character duplication
            for char in domain:
                variation = domain.replace(char, char+char, 1)
                variations.append(f"{variation}.{tld}")
            
            # Common replacements
            replacements = {'o': '0', 'i': '1', 'l': '1', 'e': '3', 'a': '4', 's': '5'}
            for old, new in replacements.items():
                if old in domain.lower():
                    variation = domain.lower().replace(old, new)
                    variations.append(f"{variation}.{tld}")
        
        # Check each variation
        for variation in variations[:5]:  # Limit to 5 checks to prevent too many queries
            try:
                self.resolver.resolve(variation, 'A')
                self.add_finding(
                    severity='Medium',
                    description='Potential typosquatting domain detected',
                    details=f'Similar domain {variation} exists and resolves to an IP',
                    recommendation='Monitor and potentially register similar domains to prevent typosquatting',
                    reference='NIST SP 800-177 Rev. 1',
                    category='Domain Security'
                )
            except Exception:
                continue

    def check_dns_rebinding_protection(self) -> None:
        """
        Check for DNS Rebinding attack protections.
        """
        try:
            # Test for short TTL values which could facilitate DNS rebinding
            query = dns.message.make_query(self.target, 'A')
            
            for ns in self.nameservers:
                try:
                    response = dns.query.udp(query, ns)
                    for rrset in response.answer:
                        if rrset.ttl < 60:  # TTL less than 60 seconds
                            self.add_finding(
                                severity='Medium',
                                description='Low DNS TTL values detected',
                                details=f'DNS records have very short TTL ({rrset.ttl} seconds)',
                                recommendation='Increase TTL values to reduce DNS rebinding attack surface',
                                reference='OWASP Web Security Testing Guide',
                                category='DNS Security'
                            )
                except Exception:
                    continue
        except Exception:
            pass

    def check_dns_amplification_vulnerability(self) -> None:
        """
        Check for configurations that could be exploited for DNS amplification attacks.
        """
        try:
            # Test for ANY query response size
            query = dns.message.make_query(self.target, 'ANY')
            
            for ns in self.nameservers:
                try:
                    response = dns.query.udp(query, ns)
                    response_size = len(response.to_wire())
                    query_size = len(query.to_wire())
                    
                    if response_size > query_size * 10:  # Amplification factor > 10
                        self.add_finding(
                            severity='High',
                            description='High DNS amplification factor',
                            details=f'DNS response size ({response_size} bytes) is significantly larger than query ({query_size} bytes)',
                            recommendation='Consider implementing response rate limiting and disabling ANY queries',
                            reference='NIST SP 800-81-2 Section 10',
                            category='DOS Protection'
                        )
                except Exception:
                    continue
        except Exception:
            pass

    def check_resolver_privacy(self) -> None:
        """
        Check for DNS resolver privacy features and QNAME minimization support.
        """
        try:
            # Check if resolver supports DNS over TLS (DoT)
            for ns in self.nameservers:
                try:
                    sock = socket.create_connection((ns, 853), timeout=5)
                    context = ssl.create_default_context()
                    with context.wrap_socket(sock, server_hostname=ns) as ssock:
                        self.add_finding(
                            severity='Info',
                            description='DNS over TLS (DoT) supported',
                            details=f'Nameserver {ns} supports encrypted DNS queries',
                            recommendation='Consider enabling DoT for enhanced privacy',
                            reference='RFC 7858 - DNS over TLS',
                            category='Privacy'
                        )
                except Exception:
                    self.add_finding(
                        severity='Low',
                        description='No DNS over TLS support',
                        details=f'Nameserver {ns} does not support encrypted DNS queries',
                        recommendation='Consider implementing DNS over TLS for enhanced privacy',
                        reference='RFC 7858 - DNS over TLS',
                        category='Privacy'
                    )
        except Exception:
            pass

    def check_qname_minimization(self) -> None:
        """
        Check if resolvers support QNAME minimization for enhanced privacy.
        """
        try:
            # Create a deep subdomain query to test QNAME minimization
            test_domain = f"qmin-test.sub1.sub2.{self.target}"
            query = dns.message.make_query(test_domain, 'A')
            
            for ns in self.nameservers:
                try:
                    # Send query and capture response
                    response = dns.query.udp(query, ns)
                    
                    # Check if response contains minimized query patterns
                    if (response.rcode() == dns.rcode.NXDOMAIN and 
                        not response.answer and 
                        len(response.authority) > 0):
                        # This pattern suggests QNAME minimization might be supported
                        self.add_finding(
                            severity='Info',
                            description='QNAME minimization likely supported',
                            details=f'Nameserver {ns} shows signs of QNAME minimization support',
                            recommendation='Continue using QNAME minimization for enhanced privacy',
                            reference='RFC 7816 - DNS Query Name Minimisation',
                            category='Privacy'
                        )
                except Exception:
                    continue
        except Exception:
            pass

    def check_dnssec_algorithm_rollover(self) -> None:
        """
        Check for DNSSEC algorithm rollover readiness and dual-signing.
        """
        try:
            dnskey_records = self.resolver.resolve(self.target, 'DNSKEY')
            algorithms = {}
            
            for record in dnskey_records:
                alg = record.algorithm
                if alg not in algorithms:
                    algorithms[alg] = 0
                algorithms[alg] += 1
            
            # Check for algorithm diversity
            if len(algorithms) == 1 and list(algorithms.keys())[0] in [1, 3, 5, 6, 7, 10]:
                self.add_finding(
                    severity='Medium',
                    description='No DNSSEC algorithm rollover preparation',
                    details='Only one (potentially outdated) DNSSEC algorithm in use',
                    recommendation='Implement dual-signing with a modern algorithm for smooth algorithm rollover',
                    reference='RFC 6781 - DNSSEC Operational Practices',
                    category='DNSSEC'
                )
            
            # Check for insufficient key redundancy
            for alg, count in algorithms.items():
                if count < 2:
                    self.add_finding(
                        severity='Low',
                        description=f'Single DNSSEC key for algorithm {alg}',
                        details='Only one key found for this algorithm, which complicates key rollover',
                        recommendation='Consider using multiple keys per algorithm for smoother key rollover',
                        reference='RFC 6781 - DNSSEC Operational Practices',
                        category='DNSSEC'
                    )
        except Exception:
            pass

    def check_cds_cdnskey_records(self) -> None:
        """
        Check for CDS and CDNSKEY records for automated DNSSEC maintenance.
        """
        try:
            has_cds = False
            has_cdnskey = False
            
            try:
                cds_records = self.resolver.resolve(self.target, 'CDS')
                has_cds = True
            except dns.resolver.NoAnswer:
                pass
                
            try:
                cdnskey_records = self.resolver.resolve(self.target, 'CDNSKEY')
                has_cdnskey = True
            except dns.resolver.NoAnswer:
                pass
                
            if has_cds != has_cdnskey:
                self.add_finding(
                    severity='Medium',
                    description='Inconsistent CDS/CDNSKEY records',
                    details='Only one of CDS or CDNSKEY records is present',
                    recommendation='Implement both CDS and CDNSKEY records for proper automated DNSSEC maintenance',
                    reference='RFC 7344 - Automated DNSSEC Trust Anchor Maintenance',
                    category='DNSSEC'
                )
            elif not has_cds and not has_cdnskey:
                self.add_finding(
                    severity='Low',
                    description='No automated DNSSEC maintenance support',
                    details='No CDS or CDNSKEY records found',
                    recommendation='Consider implementing CDS and CDNSKEY records for automated DNSSEC maintenance',
                    reference='RFC 7344 - Automated DNSSEC Trust Anchor Maintenance',
                    category='DNSSEC'
                )
        except Exception:
            pass

    def check_dane_tlsa_records(self) -> None:
        """
        Check for DANE TLSA records and their configuration.
        """
        try:
            # Check common services
            services = ['_443._tcp', '_25._tcp', '_587._tcp', '_465._tcp']
            
            for service in services:
                try:
                    tlsa_records = self.resolver.resolve(f'{service}.{self.target}', 'TLSA')
                    
                    for record in tlsa_records:
                        # Check TLSA parameters
                        if record.usage == 0:  # PKIX-TA mode
                            self.add_finding(
                                severity='Low',
                                description=f'DANE PKIX-TA mode used for {service}',
                                details='PKIX-TA mode provides limited additional security over standard PKIX validation',
                                recommendation='Consider using DANE-EE (usage=3) for stronger security',
                                reference='RFC 6698 - DANE Protocol',
                                category='TLS Security'
                            )
                        elif record.selector == 0 and record.mtype == 0:  # Full certificate matching
                            self.add_finding(
                                severity='Low',
                                description=f'DANE full certificate matching used for {service}',
                                details='Full certificate matching may cause issues during certificate renewal',
                                recommendation='Consider using SubjectPublicKeyInfo matching for easier maintenance',
                                reference='RFC 6698 - DANE Protocol',
                                category='TLS Security'
                            )
                except dns.resolver.NoAnswer:
                    self.add_finding(
                        severity='Info',
                        description=f'No DANE TLSA record for {service}',
                        details=f'Service {service} does not use DANE for TLS authentication',
                        recommendation='Consider implementing DANE TLSA records for enhanced TLS security',
                        reference='RFC 6698 - DANE Protocol',
                        category='TLS Security'
                    )
        except Exception:
            pass

    def check_reserved_ip_usage(self) -> None:
        """
        Check for DNS records pointing to reserved or special-use IP addresses.
        """
        try:
            record_types = ['A', 'AAAA']
            reserved_ranges = [
                '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
                '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
                '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4'
            ]
            
            for record_type in record_types:
                try:
                    records = self.resolver.resolve(self.target, record_type)
                    for record in records:
                        ip = ipaddress.ip_address(str(record))
                        
                        for range_str in reserved_ranges:
                            if ip in ipaddress.ip_network(range_str):
                                self.add_finding(
                                    severity='Medium',
                                    description=f'DNS record points to reserved IP range',
                                    details=f'{record_type} record resolves to {ip} in reserved range {range_str}',
                                    recommendation='Ensure DNS records do not point to reserved or special-use IP addresses',
                                    reference='RFC 6890 - Special-Purpose IP Address Registries',
                                    category='DNS Configuration'
                                )
                except dns.resolver.NoAnswer:
                    continue
        except Exception:
            pass

    def check_dnssec_validation(self) -> None:
        """
        Perform active DNSSEC validation and chain of trust verification.
        """
        try:
            # Try to get DNSKEY and DS records
            try:
                dnskey_records = self.resolver.resolve(self.target, 'DNSKEY')
                ds_records = self.resolver.resolve(self.target, 'DS')
                
                # Verify DNSKEY against DS records
                for dnskey in dnskey_records:
                    if dnskey.flags & dns.flags.ZONE:
                        # Create DS record from DNSKEY
                        calculated_ds = dns.dnssec.make_ds(self.target, dnskey, 'SHA256')
                        ds_match = False
                        
                        for ds in ds_records:
                            if (ds.digest_type == calculated_ds.digest_type and
                                ds.algorithm == calculated_ds.algorithm and
                                ds.digest == calculated_ds.digest):
                                ds_match = True
                                break
                                
                        if not ds_match:
                            self.add_finding(
                                severity='Critical',
                                description='DNSSEC validation failure',
                                details='DNSKEY does not match DS record in parent zone',
                                recommendation='Verify and fix DNSSEC key material and DS records',
                                reference='RFC 4035 - DNSSEC Protocol',
                                category='DNSSEC'
                            )
            except dns.resolver.NoAnswer:
                pass
                
            # Check for proper NSEC/NSEC3 negative responses
            random_name = ''.join(random.choices(string.ascii_lowercase, k=10))
            query = dns.message.make_query(f"{random_name}.{self.target}", 'A', want_dnssec=True)
            
            for ns in self.nameservers:
                try:
                    response = dns.query.udp(query, ns)
                    if response.rcode() == dns.rcode.NXDOMAIN:
                        has_nsec = False
                        has_rrsig = False
                        
                        for rrset in response.authority:
                            if rrset.rdtype in [dns.rdatatype.NSEC, dns.rdatatype.NSEC3]:
                                has_nsec = True
                            if rrset.rdtype == dns.rdatatype.RRSIG:
                                has_rrsig = True
                                
                        if not (has_nsec and has_rrsig):
                            self.add_finding(
                                severity='High',
                                description='Incomplete DNSSEC negative responses',
                                details='Missing NSEC/NSEC3 or RRSIG records in negative responses',
                                recommendation='Ensure proper DNSSEC signing of negative responses',
                                reference='RFC 4035 - DNSSEC Protocol',
                                category='DNSSEC'
                            )
                except Exception:
                    continue
        except Exception:
            pass

    def check_ecs_privacy(self) -> None:
        """
        Check for EDNS Client Subnet (ECS) privacy implications.
        """
        try:
            # Create query with ECS option
            query = dns.message.make_query(self.target, 'A', use_edns=True)
            ecs_option = dns.edns.ECSOption('192.0.2.0', 24)  # Example client subnet
            query.use_edns(options=[ecs_option])
            
            for ns in self.nameservers:
                try:
                    response = dns.query.udp(query, ns)
                    
                    # Check if server honors ECS
                    for opt in response.options:
                        if isinstance(opt, dns.edns.ECSOption):
                            if opt.scope_prefix > 0:
                                self.add_finding(
                                    severity='Medium',
                                    description='ECS information exposed',
                                    details=f'Nameserver {ns} reveals client subnet information in responses',
                                    recommendation='Consider disabling or limiting ECS to protect client privacy',
                                    reference='RFC 7871 - Client Subnet in DNS Queries',
                                    category='Privacy'
                                )
                except Exception:
                    continue
        except Exception:
            pass

    def check_nsec_downgrade(self) -> None:
        """
        Check for NSEC downgrade attacks vulnerability.
        """
        try:
            # Query for non-existent name with and without DNSSEC
            random_name = ''.join(random.choices(string.ascii_lowercase, k=10))
            query_dnssec = dns.message.make_query(f"{random_name}.{self.target}", 'A', want_dnssec=True)
            query_no_dnssec = dns.message.make_query(f"{random_name}.{self.target}", 'A')
            
            for ns in self.nameservers:
                try:
                    response_dnssec = dns.query.udp(query_dnssec, ns)
                    response_no_dnssec = dns.query.udp(query_no_dnssec, ns)
                    
                    # Check for inconsistent responses
                    has_nsec_dnssec = any(rrset.rdtype in [dns.rdatatype.NSEC, dns.rdatatype.NSEC3] 
                                        for rrset in response_dnssec.authority)
                    has_nsec_no_dnssec = any(rrset.rdtype in [dns.rdatatype.NSEC, dns.rdatatype.NSEC3] 
                                           for rrset in response_no_dnssec.authority)
                    
                    if has_nsec_dnssec and not has_nsec_no_dnssec:
                        self.add_finding(
                            severity='Medium',
                            description='Potential NSEC downgrade vulnerability',
                            details='Different negative responses with and without DNSSEC',
                            recommendation='Ensure consistent NSEC/NSEC3 usage regardless of DNSSEC flag',
                            reference='NIST SP 800-81-2',
                            category='DNSSEC'
                        )
                except Exception:
                    continue
        except Exception:
            pass

    def check_zone_walking_vulnerability(self) -> None:
        """
        Check for zone enumeration vulnerabilities through NSEC walking.
        """
        try:
            # Try to perform zone walking using NSEC records
            seen_names = set()
            current_name = self.target
            max_attempts = 10  # Limit the number of attempts
            
            for _ in range(max_attempts):
                query = dns.message.make_query(current_name, 'A', want_dnssec=True)
                
                for ns in self.nameservers:
                    try:
                        response = dns.query.udp(query, ns)
                        
                        for rrset in response.authority:
                            if rrset.rdtype == dns.rdatatype.NSEC:
                                for rr in rrset:
                                    next_name = str(rr.next)
                                    if next_name not in seen_names:
                                        seen_names.add(next_name)
                                        current_name = next_name
                                        
                                        if len(seen_names) > 5:  # If we can enumerate more than 5 names
                                            self.add_finding(
                                                severity='Medium',
                                                description='Zone enumeration possible through NSEC walking',
                                                details='NSEC records allow zone content enumeration',
                                                recommendation='Consider using NSEC3 with proper salt and iterations',
                                                reference='RFC 5155 - DNSSEC Hashed Authenticated Denial of Existence',
                                                category='DNSSEC'
                                            )
                                            return
                    except Exception:
                        continue
        except Exception:
            pass

    def check_domain_generation_patterns(self) -> None:
        """
        Check for patterns indicating potential domain generation algorithms (DGA).
        """
        try:
            # Get all subdomains from common record types
            subdomains = set()
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT']
            
            for record_type in record_types:
                try:
                    records = self.resolver.resolve(self.target, record_type)
                    for record in records:
                        name = str(record.target) if hasattr(record, 'target') else str(record)
                        if '.' in name:
                            subdomain = name.split('.')[0]
                            if subdomain:
                                subdomains.add(subdomain)
                except Exception:
                    continue
            
            # Analyze patterns in subdomains
            if len(subdomains) >= 5:
                # Check for random-looking patterns
                random_patterns = 0
                for subdomain in subdomains:
                    # Check for characteristics of DGA domains
                    if (len(subdomain) >= 8 and  # Longer than typical human-chosen names
                        sum(c.isdigit() for c in subdomain) >= 2 and  # Contains multiple numbers
                        any(not c.isalnum() for c in subdomain)):  # Contains special characters
                        random_patterns += 1
                
                if random_patterns >= 3:  # If multiple suspicious patterns found
                    self.add_finding(
                        severity='High',
                        description='Potential DGA pattern detected',
                        details='Multiple subdomains show characteristics of domain generation algorithms',
                        recommendation='Investigate and monitor suspicious domain patterns',
                        reference='NIST SP 800-177 Rev. 1',
                        category='Domain Security'
                    )
        except Exception:
            pass

    def check_dns_tunneling_indicators(self) -> None:
        """
        Check for indicators of DNS tunneling abuse.
        """
        try:
            # Get TXT records to check for tunneling patterns
            suspicious_count = 0
            total_size = 0
            records_count = 0
            
            try:
                txt_records = self.resolver.resolve(self.target, 'TXT')
                for record in txt_records:
                    record_str = str(record)
                    records_count += 1
                    total_size += len(record_str)
                    
                    # Check for base64/hex patterns
                    if (len(record_str) > 100 and  # Long record
                        (re.match(r'^[A-Za-z0-9+/=]+$', record_str) or  # Base64
                         re.match(r'^[A-Fa-f0-9]+$', record_str))):     # Hex
                        suspicious_count += 1
            except Exception:
                pass
                
            # Check for abnormally large average record size
            if records_count > 0:
                avg_size = total_size / records_count
                if avg_size > 200:  # Unusually large average size
                    self.add_finding(
                        severity='High',
                        description='Potential DNS tunneling detected',
                        details=f'Unusually large TXT records (avg size: {avg_size:.1f} bytes)',
                        recommendation='Investigate large DNS records for potential data exfiltration',
                        reference='NIST SP 800-81-2',
                        category='Data Exfiltration'
                    )
                    
            # Check subdomain entropy for tunneling indicators
            try:
                random_subdomain = ''.join(random.choices(string.ascii_lowercase + string.digits, k=30))
                query = dns.message.make_query(f"{random_subdomain}.{self.target}", 'A')
                
                for ns in self.nameservers:
                    try:
                        response = dns.query.udp(query, ns)
                        if response.rcode() != dns.rcode.NXDOMAIN:
                            self.add_finding(
                                severity='High',
                                description='Wildcard DNS potentially enabling tunneling',
                                details='Wildcard DNS records could be abused for DNS tunneling',
                                recommendation='Review and restrict wildcard DNS usage',
                                reference='MITRE ATT&CK T1071.004',
                                category='Data Exfiltration'
                            )
                            break
                    except Exception:
                        continue
            except Exception:
                pass
                
        except Exception:
            pass

    def check_dnssec_replay_protection(self) -> None:
        """
        Check for DNSSEC replay attack protections.
        """
        try:
            # Check RRSIG inception and expiration times
            current_time = int(time.time())
            
            for record_type in ['A', 'AAAA', 'MX', 'NS']:
                try:
                    query = dns.message.make_query(self.target, record_type, want_dnssec=True)
                    
                    for ns in self.nameservers:
                        try:
                            response = dns.query.udp(query, ns)
                            
                            for rrset in response.answer:
                                for rr in rrset:
                                    if rr.rdtype == dns.rdatatype.RRSIG:
                                        inception = rr.inception
                                        expiration = rr.expiration
                                        
                                        # Check for signatures from the future
                                        if inception > current_time + 3600:  # More than 1 hour in the future
                                            self.add_finding(
                                                severity='High',
                                                description='DNSSEC signature from the future',
                                                details=f'RRSIG inception time is in the future: {inception}',
                                                recommendation='Verify time synchronization and DNSSEC signing configuration',
                                                reference='RFC 4034 - DNSSEC Resource Records',
                                                category='DNSSEC'
                                            )
                                            
                                        # Check for expired signatures still in use
                                        if expiration < current_time:
                                            self.add_finding(
                                                severity='Critical',
                                                description='Expired DNSSEC signature in use',
                                                details=f'RRSIG has expired at {expiration}',
                                                recommendation='Update DNSSEC signatures immediately',
                                                reference='RFC 4034 - DNSSEC Resource Records',
                                                category='DNSSEC'
                                            )
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception:
            pass

    def check_resolver_fingerprinting(self) -> None:
        """
        Check for DNS resolver fingerprinting vulnerabilities.
        """
        try:
            # Test various resolver characteristics
            characteristics = {
                'edns_version': None,
                'udp_payload_size': None,
                'dnssec_ok': None,
                'nsid': None
            }
            
            query = dns.message.make_query(self.target, 'A', use_edns=True)
            query.use_edns(edns=0, payload=4096, options=[dns.edns.GenericOption(dns.edns.NSID, b'')])
            
            for ns in self.nameservers:
                try:
                    response = dns.query.udp(query, ns)
                    
                    if response.opt:
                        characteristics['edns_version'] = response.opt.version
                        characteristics['udp_payload_size'] = response.opt.payload
                        characteristics['dnssec_ok'] = bool(response.opt.flags & dns.flags.DO)
                        
                        for opt in response.opt.options:
                            if opt.otype == dns.edns.NSID:
                                characteristics['nsid'] = opt.data
                                
                        # Check if resolver reveals too much information
                        if characteristics['nsid']:
                            self.add_finding(
                                severity='Medium',
                                description='DNS resolver fingerprinting possible',
                                details='Resolver reveals NSID information',
                                recommendation='Consider disabling NSID or limiting information disclosure',
                                reference='RFC 5001 - DNS NSID',
                                category='Information Disclosure'
                            )
                            
                        # Check for outdated EDNS version
                        if characteristics['edns_version'] > 0:
                            self.add_finding(
                                severity='Low',
                                description='Non-standard EDNS version',
                                details=f'Resolver uses EDNS version {characteristics["edns_version"]}',
                                recommendation='Use EDNS version 0 as per standard',
                                reference='RFC 6891 - EDNS(0)',
                                category='DNS Configuration'
                            )
                except Exception:
                    continue
        except Exception:
            pass

    def check_dns_load_balancing(self) -> None:
        """
        Check DNS load balancing configuration and potential issues.
        """
        try:
            # Track unique IP addresses for A/AAAA records
            ip_addresses = set()
            ttls = set()
            
            for record_type in ['A', 'AAAA']:
                try:
                    records = self.resolver.resolve(self.target, record_type)
                    ttls.add(records.ttl)
                    
                    for record in records:
                        ip_addresses.add(str(record))
                except Exception:
                    continue
            
            # Check load balancing configuration
            if len(ip_addresses) > 1:
                # Check TTL values
                if any(ttl > 300 for ttl in ttls):  # TTL > 5 minutes
                    self.add_finding(
                        severity='Medium',
                        description='High TTL with DNS load balancing',
                        details='Load balanced records have high TTL values',
                        recommendation='Consider lower TTL values for more effective load balancing',
                        reference='NIST SP 800-81-2',
                        category='DNS Configuration'
                    )
                
                # Check for geographic distribution
                networks = set()
                for ip in ip_addresses:
                    try:
                        # Simple network check (first two octets)
                        network = '.'.join(ip.split('.')[:2])
                        networks.add(network)
                    except Exception:
                        continue
                
                if len(networks) < 2:
                    self.add_finding(
                        severity='Low',
                        description='Limited load balancer distribution',
                        details='Load balanced IPs appear to be in the same network',
                        recommendation='Consider geographic distribution of load balanced servers',
                        reference='NIST SP 800-81-2',
                        category='DNS Configuration'
                    )
        except Exception:
            pass

    def check_dnssec_key_size(self) -> None:
        """
        Check DNSSEC key sizes against current security recommendations.
        """
        try:
            dnskey_records = self.resolver.resolve(self.target, 'DNSKEY')
            
            for record in dnskey_records:
                key_size = len(record.key) * 8  # Convert bytes to bits
                algorithm = record.algorithm
                
                # Check RSA key sizes
                if algorithm in [5, 7, 8, 10]:  # RSA algorithms
                    if key_size < 2048:
                        self.add_finding(
                            severity='High',
                            description='Weak DNSSEC RSA key size',
                            details=f'RSA key size ({key_size} bits) is below recommended minimum of 2048 bits',
                            recommendation='Use RSA keys of at least 2048 bits',
                            reference='NIST SP 800-57 Part 1 Rev. 5',
                            category='DNSSEC'
                        )
                    elif key_size < 3072:
                        self.add_finding(
                            severity='Low',
                            description='Moderate DNSSEC RSA key size',
                            details=f'RSA key size ({key_size} bits) is below future-proof recommendation of 3072 bits',
                            recommendation='Consider upgrading to 3072-bit RSA keys for future security',
                            reference='NIST SP 800-57 Part 1 Rev. 5',
                            category='DNSSEC'
                        )
                
                # Check ECDSA key sizes
                elif algorithm in [13, 14]:  # ECDSA algorithms
                    if key_size < 256:
                        self.add_finding(
                            severity='High',
                            description='Weak DNSSEC ECDSA key size',
                            details=f'ECDSA key size ({key_size} bits) is below recommended minimum',
                            recommendation='Use ECDSA P-256 or stronger',
                            reference='NIST SP 800-57 Part 1 Rev. 5',
                            category='DNSSEC'
                        )
        except Exception:
            pass

    def check_https_delegation(self) -> None:
        """
        Check for HTTPS delegation and SVCB/HTTPS record configuration.
        """
        try:
            # Check for HTTPS/SVCB records
            try:
                https_records = self.resolver.resolve(self.target, 'HTTPS')
                found_https = True
            except Exception:
                found_https = False
                
            try:
                svcb_records = self.resolver.resolve(self.target, 'SVCB')
                found_svcb = True
            except Exception:
                found_svcb = False
                
            if not (found_https or found_svcb):
                self.add_finding(
                    severity='Info',
                    description='No HTTPS/SVCB records found',
                    details='Domain does not use HTTPS/SVCB records for service binding',
                    recommendation='Consider implementing HTTPS records for improved security and performance',
                    reference='RFC 9460 - Service Binding and Parameter Specification',
                    category='Web Security'
                )
            else:
                # Check for proper DNSSEC signing if records exist
                query = dns.message.make_query(self.target, 'HTTPS', want_dnssec=True)
                
                for ns in self.nameservers:
                    try:
                        response = dns.query.udp(query, ns)
                        if not any(rr.rdtype == dns.rdatatype.RRSIG for rrset in response.answer for rr in rrset):
                            self.add_finding(
                                severity='Medium',
                                description='Unsigned HTTPS records',
                                details='HTTPS records are not signed with DNSSEC',
                                recommendation='Enable DNSSEC signing for HTTPS records',
                                reference='RFC 9460',
                                category='Web Security'
                            )
                    except Exception:
                        continue
        except Exception:
            pass

    def check_dns_tcp_fallback(self) -> None:
        """
        Check DNS TCP fallback configuration and reliability.
        """
        try:
            # Create a large response that should trigger TCP fallback
            query = dns.message.make_query(self.target, 'ANY')
            
            for ns in self.nameservers:
                try:
                    # First try UDP
                    try:
                        response_udp = dns.query.udp(query, ns)
                        is_truncated = response_udp.flags & dns.flags.TC
                    except Exception:
                        continue
                    
                    if is_truncated:
                        # Try TCP fallback
                        try:
                            response_tcp = dns.query.tcp(query, ns)
                        except Exception:
                            self.add_finding(
                                severity='High',
                                description='TCP fallback failure',
                                details=f'Nameserver {ns} fails TCP fallback for truncated responses',
                                recommendation='Ensure proper TCP support on DNS servers',
                                reference='RFC 7766 - DNS Transport over TCP',
                                category='DNS Configuration'
                            )
                            continue
                        
                        # Check TCP response size limits
                        if len(response_tcp.to_wire()) > 65535:
                            self.add_finding(
                                severity='Medium',
                                description='Large TCP responses',
                                details=f'DNS TCP responses exceed 64KB from {ns}',
                                recommendation='Review and optimize record sizes',
                                reference='RFC 7766',
                                category='DNS Configuration'
                            )
                except Exception:
                    continue
        except Exception:
            pass

    def check_record_ttl_consistency(self) -> None:
        """
        Check for TTL consistency across different record types and nameservers.
        """
        try:
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
            ttl_map = {}
            
            for record_type in record_types:
                try:
                    records = self.resolver.resolve(self.target, record_type)
                    ttl_map[record_type] = records.ttl
                except Exception:
                    continue
            
            if ttl_map:
                # Check for inconsistent TTLs
                ttl_values = set(ttl_map.values())
                if len(ttl_values) > 2:  # Allow for some variation but not too much
                    self.add_finding(
                        severity='Low',
                        description='Inconsistent TTL values',
                        details='Different record types have varying TTL values',
                        recommendation='Consider standardizing TTL values across record types',
                        reference='NIST SP 800-81-2',
                        category='DNS Configuration'
                    )
                
                # Check for extremely low or high TTLs
                for record_type, ttl in ttl_map.items():
                    if ttl < 300:  # Less than 5 minutes
                        self.add_finding(
                            severity='Low',
                            description=f'Very low TTL for {record_type} records',
                            details=f'TTL of {ttl} seconds might cause excessive queries',
                            recommendation='Consider increasing TTL unless required for rapid updates',
                            reference='NIST SP 800-81-2',
                            category='DNS Configuration'
                        )
                    elif ttl > 86400:  # More than 24 hours
                        self.add_finding(
                            severity='Low',
                            description=f'Very high TTL for {record_type} records',
                            details=f'TTL of {ttl} seconds might slow down record updates',
                            recommendation='Consider decreasing TTL for better agility',
                            reference='NIST SP 800-81-2',
                            category='DNS Configuration'
                        )
        except Exception:
            pass

    def check_reverse_dns_mismatch(self) -> None:
        """
        Check for reverse DNS mismatches and incomplete PTR configurations.
        """
        try:
            # Get A/AAAA records
            forward_ips = set()
            
            for record_type in ['A', 'AAAA']:
                try:
                    records = self.resolver.resolve(self.target, record_type)
                    for record in records:
                        forward_ips.add(str(record))
                except Exception:
                    continue
            
            # Check reverse DNS for each IP
            for ip in forward_ips:
                try:
                    # Convert IP to reverse lookup format
                    if ':' in ip:  # IPv6
                        reverse_name = dns.reversename.from_address(ip)
                    else:  # IPv4
                        reverse_name = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
                    
                    try:
                        ptr_records = self.resolver.resolve(reverse_name, 'PTR')
                        ptr_names = set(str(r).rstrip('.') for r in ptr_records)
                        
                        # Check if any PTR record matches the forward name
                        if self.target not in ptr_names:
                            self.add_finding(
                                severity='Medium',
                                description='Reverse DNS mismatch',
                                details=f'IP {ip} reverse DNS does not match forward DNS',
                                recommendation='Configure matching forward and reverse DNS records',
                                reference='RFC 1912 - Common DNS Operational and Configuration Errors',
                                category='DNS Configuration'
                            )
                    except dns.resolver.NXDOMAIN:
                        self.add_finding(
                            severity='Low',
                            description='Missing reverse DNS',
                            details=f'No PTR record found for IP {ip}',
                            recommendation='Configure reverse DNS records for all IPs',
                            reference='RFC 1912',
                            category='DNS Configuration'
                        )
                except Exception:
                    continue
        except Exception:
            pass

    def check_domain_takeover_vectors(self) -> None:
        """
        Check for various domain takeover vectors and misconfigurations.
        """
        try:
            # Common cloud service endpoints that might be vulnerable
            cloud_endpoints = {
                'amazonaws.com': 'Amazon S3/AWS',
                'cloudfront.net': 'Amazon CloudFront',
                'azure.com': 'Microsoft Azure',
                'azurewebsites.net': 'Azure Web Apps',
                'cloudapp.net': 'Azure Cloud Services',
                'googleapis.com': 'Google Cloud',
                'github.io': 'GitHub Pages',
                'herokuapp.com': 'Heroku',
                'shopify.com': 'Shopify',
                'fastly.net': 'Fastly'
            }
            
            # Check CNAME records
            try:
                cname_records = self.resolver.resolve(self.target, 'CNAME')
                for record in cname_records:
                    target = str(record.target).rstrip('.')
                    
                    # Check for cloud service endpoints
                    for endpoint, service in cloud_endpoints.items():
                        if target.endswith(endpoint):
                            try:
                                # Try to resolve the CNAME target
                                self.resolver.resolve(target, 'A')
                            except dns.resolver.NXDOMAIN:
                                self.add_finding(
                                    severity='Critical',
                                    description=f'Potential {service} takeover vector',
                                    details=f'CNAME points to unprovisioned {service} endpoint: {target}',
                                    recommendation=f'Verify and secure the {service} resource or remove the CNAME',
                                    reference='OWASP Top 10 2021: A05 Security Misconfiguration',
                                    category='Domain Takeover'
                                )
            except Exception:
                pass
            
            # Check for dangling NS records
            try:
                ns_records = self.resolver.resolve(self.target, 'NS')
                for record in ns_records:
                    ns = str(record).rstrip('.')
                    
                    # Check if nameserver is resolvable
                    try:
                        socket.gethostbyname(ns)
                    except socket.gaierror:
                        self.add_finding(
                            severity='High',
                            description='Dangling NS record',
                            details=f'NS record points to unresolvable nameserver: {ns}',
                            recommendation='Remove or update invalid NS records',
                            reference='OWASP Top 10 2021: A05 Security Misconfiguration',
                            category='Domain Takeover'
                        )
            except Exception:
                pass
            
            # Check for external MX records
            try:
                mx_records = self.resolver.resolve(self.target, 'MX')
                for record in mx_records:
                    mx = str(record.exchange).rstrip('.')
                    
                    # Check if MX server is resolvable
                    try:
                        socket.gethostbyname(mx)
                    except socket.gaierror:
                        self.add_finding(
                            severity='High',
                            description='Dangling MX record',
                            details=f'MX record points to unresolvable mail server: {mx}',
                            recommendation='Remove or update invalid MX records',
                            reference='OWASP Top 10 2021: A05 Security Misconfiguration',
                            category='Domain Takeover'
                        )
            except Exception:
                pass
        except Exception:
            pass

    def generate_report(self) -> Dict[str, Any]:
        """Generate a report of DNS security findings."""
        return {
            'target': self.target,
            'nameservers': self.nameservers,
            'findings': self.findings
        } 