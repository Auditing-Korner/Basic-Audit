from abc import ABC, abstractmethod
from typing import Dict, Any
import json
from datetime import datetime

class ReportGenerator(ABC):
    """Base class for report generators."""
    
    def __init__(self, findings: Dict[str, Any]):
        """
        Initialize the report generator.
        
        Args:
            findings (Dict[str, Any]): The findings to generate a report from
        """
        self.findings = findings
        self.timestamp = datetime.now().isoformat()
        
    @abstractmethod
    def generate(self) -> str:
        """Generate the report in the specific format."""
        pass
    
    def _get_summary(self) -> Dict[str, int]:
        """Generate a summary of findings by severity."""
        summary = {
            'total_vulnerabilities': 0,
            'Critical': 0,
            'High': 0,
            'Medium': 0,
            'Low': 0,
            'Info': 0
        }
        
        for finding in self.findings.get('findings', []):
            severity = finding.get('severity', 'Info')
            if severity in summary:
                summary[severity] += 1
                summary['total_vulnerabilities'] += 1
                
        return summary

class JSONReportGenerator(ReportGenerator):
    """Generate reports in JSON format."""
    
    def generate(self) -> str:
        """Generate a JSON report."""
        report = {
            'target': self.findings.get('target', ''),
            'timestamp': self.timestamp,
            'summary': self._get_summary(),
            'findings': self.findings.get('findings', [])
        }
        return json.dumps(report, indent=2)

class HTMLReportGenerator(ReportGenerator):
    """Generate reports in HTML format."""
    
    def generate(self) -> str:
        """Generate an HTML report."""
        summary = self._get_summary()
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Audit Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .summary {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; }}
                .finding {{ margin: 10px 0; padding: 10px; border-left: 4px solid #ccc; }}
                .Critical {{ border-left-color: #ff0000; }}
                .High {{ border-left-color: #ff6600; }}
                .Medium {{ border-left-color: #ffcc00; }}
                .Low {{ border-left-color: #00cc00; }}
                .Info {{ border-left-color: #0066cc; }}
            </style>
        </head>
        <body>
            <h1>Security Audit Report</h1>
            <p>Target: {self.findings.get('target', '')}</p>
            <p>Generated: {self.timestamp}</p>
            
            <div class="summary">
                <h2>Summary</h2>
                <p>Total Vulnerabilities: {summary['total_vulnerabilities']}</p>
                <p>Critical: {summary['Critical']}</p>
                <p>High: {summary['High']}</p>
                <p>Medium: {summary['Medium']}</p>
                <p>Low: {summary['Low']}</p>
                <p>Info: {summary['Info']}</p>
            </div>
            
            <h2>Findings</h2>
        """
        
        for finding in self.findings.get('findings', []):
            html += f"""
            <div class="finding {finding.get('severity', '')}">
                <h3>{finding.get('description', '')}</h3>
                <p><strong>Severity:</strong> {finding.get('severity', '')}</p>
                <p><strong>Details:</strong> {finding.get('details', '')}</p>
                <p><strong>Recommendation:</strong> {finding.get('recommendation', '')}</p>
                {f'<p><strong>Reference:</strong> <a href="{finding.get("reference", "")}">{finding.get("reference", "")}</a></p>' if finding.get('reference') else ''}
            </div>
            """
            
        html += """
        </body>
        </html>
        """
        
        return html 