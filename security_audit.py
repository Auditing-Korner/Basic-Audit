#!/usr/bin/env python3

import argparse
import logging
from typing import Dict, Any
from modules.dns.dns_auditor import DNSAuditor
from modules.web.web_auditor import WebAuditor
from modules.web.oauth_auditor import OAuthAuditor
from modules.utils.output import (
    print_summary,
    print_detailed_findings,
    save_report,
    save_html_report
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_audit.log'),
        logging.StreamHandler()
    ]
)

def combine_reports(*reports: Dict[str, Any]) -> Dict[str, Any]:
    """Combine multiple security reports into a single report"""
    if not reports:
        return {}

    # Initialize combined report with first report's domain and timestamp
    combined_report = {
        'domain': reports[0]['domain'],
        'timestamp': reports[0].get('timestamp', ''),
        'summary': {
            'total_vulnerabilities': 0,
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        },
        'vulnerabilities_by_type': {}
    }

    # Combine all reports
    for report in reports:
        # Add vulnerability counts
        for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
            combined_report['summary'][severity] += report['summary'].get(severity, 0)
        
        combined_report['summary']['total_vulnerabilities'] += report['summary']['total_vulnerabilities']

        # Combine vulnerabilities by type
        for vuln_type, vulns in report.get('vulnerabilities_by_type', {}).items():
            if vuln_type not in combined_report['vulnerabilities_by_type']:
                combined_report['vulnerabilities_by_type'][vuln_type] = []
            combined_report['vulnerabilities_by_type'][vuln_type].extend(vulns)

    return combined_report

def main():
    parser = argparse.ArgumentParser(description='Security Audit Tool')
    parser.add_argument('domain', help='Domain to audit')
    parser.add_argument('--output', '-o', help='Output file for the report', default='security_report.json')
    parser.add_argument('--html', help='Generate HTML report', action='store_true')
    parser.add_argument('--subdomain', help='Specific subdomain to test (e.g., omni-cms)', default='')
    args = parser.parse_args()

    target_domain = f"{args.subdomain}.{args.domain}" if args.subdomain else args.domain
    logging.info(f"Starting security audit for {target_domain}")
    
    # Run DNS audit
    logging.info("Running DNS security checks...")
    dns_auditor = DNSAuditor(target_domain)
    dns_auditor.run_all_checks()
    dns_report = dns_auditor.generate_report()
    
    # Run web audit
    logging.info("Running web security checks...")
    web_auditor = WebAuditor(target_domain)
    web_auditor.run_all_checks()
    web_report = web_auditor.generate_report()
    
    # Run OAuth audit
    logging.info("Running OAuth security checks...")
    oauth_auditor = OAuthAuditor(target_domain)
    oauth_auditor.run_all_checks()
    oauth_report = oauth_auditor.generate_report()
    
    # Combine reports
    combined_report = combine_reports(dns_report, web_report, oauth_report)
    
    # Save JSON report
    save_report(combined_report, args.output)
    
    # Generate HTML report if requested
    if args.html:
        html_filename = args.output.replace('.json', '.html')
        save_html_report(combined_report, html_filename)
    
    # Print results
    print_summary(combined_report)
    print_detailed_findings(combined_report)

if __name__ == "__main__":
    main() 