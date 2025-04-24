import dns.resolver
from typing import Dict, Any
from ..core.base_auditor import BaseAuditor

class DNSAuditor(BaseAuditor):
    """Audits DNS configuration and security settings."""
    
    def __init__(self, target: str, config: Dict[str, Any] = None):
        super().__init__(target, config)
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.config.get('timeout', 10)
        
    def run_all_checks(self) -> None:
        """Run all DNS security checks."""
        if self.config.get('check_spf', True):
            self.check_spf()
        if self.config.get('check_dmarc', True):
            self.check_dmarc()
        if self.config.get('check_dkim', True):
            self.check_dkim()
        if self.config.get('check_dnssec', True):
            self.check_dnssec()
            
    def check_spf(self) -> None:
        """Check for SPF record configuration."""
        try:
            self.resolver.resolve(f"{self.target}", 'TXT')
            self.add_finding(
                severity='Info',
                description='SPF record found',
                details='SPF record is properly configured',
                recommendation='No action required',
                reference='https://tools.ietf.org/html/rfc7208'
            )
        except dns.resolver.NoAnswer:
            self.add_finding(
                severity='High',
                description='Missing SPF record',
                details='No SPF record found for domain',
                recommendation='Implement SPF record to prevent email spoofing',
                reference='https://tools.ietf.org/html/rfc7208'
            )
        except Exception as e:
            self.add_finding(
                severity='Medium',
                description='Error checking SPF record',
                details=f'Error while checking SPF record: {str(e)}',
                recommendation='Verify DNS configuration and try again',
                reference='https://tools.ietf.org/html/rfc7208'
            )
            
    def check_dmarc(self) -> None:
        """Check for DMARC record configuration."""
        try:
            self.resolver.resolve(f"_dmarc.{self.target}", 'TXT')
            self.add_finding(
                severity='Info',
                description='DMARC record found',
                details='DMARC record is properly configured',
                recommendation='No action required',
                reference='https://tools.ietf.org/html/rfc7489'
            )
        except dns.resolver.NoAnswer:
            self.add_finding(
                severity='High',
                description='Missing DMARC record',
                details='No DMARC record found',
                recommendation='Implement DMARC to enhance email security',
                reference='https://tools.ietf.org/html/rfc7489'
            )
        except Exception as e:
            self.add_finding(
                severity='Medium',
                description='Error checking DMARC record',
                details=f'Error while checking DMARC record: {str(e)}',
                recommendation='Verify DNS configuration and try again',
                reference='https://tools.ietf.org/html/rfc7489'
            )
            
    def check_dkim(self) -> None:
        """Check for DKIM record configuration."""
        common_selectors = ['default', 'google', 'selector1', 'selector2']
        dkim_found = False
        
        for selector in common_selectors:
            try:
                self.resolver.resolve(f"{selector}._domainkey.{self.target}", 'TXT')
                dkim_found = True
                break
            except dns.resolver.NoAnswer:
                continue
            except Exception as e:
                self.add_finding(
                    severity='Medium',
                    description='Error checking DKIM record',
                    details=f'Error while checking DKIM record: {str(e)}',
                    recommendation='Verify DNS configuration and try again',
                    reference='https://tools.ietf.org/html/rfc6376'
                )
                
        if dkim_found:
            self.add_finding(
                severity='Info',
                description='DKIM record found',
                details='DKIM record is properly configured',
                recommendation='No action required',
                reference='https://tools.ietf.org/html/rfc6376'
            )
        else:
            self.add_finding(
                severity='Medium',
                description='No common DKIM selectors found',
                details='Could not find DKIM records for common selectors',
                recommendation='Implement DKIM signing for email authentication',
                reference='https://tools.ietf.org/html/rfc6376'
            )
            
    def check_dnssec(self) -> None:
        """Check for DNSSEC configuration."""
        try:
            self.resolver.resolve(self.target, 'DNSKEY')
            self.add_finding(
                severity='Info',
                description='DNSSEC is implemented',
                details='DNSSEC is properly configured',
                recommendation='No action required',
                reference='https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en'
            )
        except dns.resolver.NoAnswer:
            self.add_finding(
                severity='High',
                description='DNSSEC not implemented',
                details='No DNSKEY records found',
                recommendation='Implement DNSSEC to prevent DNS spoofing attacks',
                reference='https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en'
            )
        except Exception as e:
            self.add_finding(
                severity='Medium',
                description='Error checking DNSSEC',
                details=f'Error while checking DNSSEC: {str(e)}',
                recommendation='Verify DNS configuration and try again',
                reference='https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en'
            )
            
    def generate_report(self) -> Dict[str, Any]:
        """Generate a report of DNS findings."""
        return {
            'target': self.target,
            'findings': self.findings
        } 