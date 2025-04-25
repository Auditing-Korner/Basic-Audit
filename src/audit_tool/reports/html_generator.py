import os
import json
import yaml
from typing import Dict, List, Any
from datetime import datetime
from pathlib import Path
from jinja2 import Environment, FileSystemLoader
import plotly.graph_objects as go
import plotly.utils
import plotly.express as px

class HTMLReportGenerator:
    """Generate beautiful HTML reports for security audit findings."""

    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(__file__), 'templates')
        self.env = Environment(loader=FileSystemLoader(self.template_dir))
        self.template = self.env.get_template('report_template.html')
        self.reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), 'reports')
        self.config = self._load_config()
        
        # Create reports directory if it doesn't exist
        os.makedirs(self.reports_dir, exist_ok=True)
        
        # Create .gitkeep to preserve directory
        Path(os.path.join(self.reports_dir, '.gitkeep')).touch()

    def _load_config(self) -> Dict[str, Any]:
        """Load report configuration from YAML file."""
        config_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'config',
            'report_config.yaml'
        )
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Could not load config file: {e}")
            return {}

    def _generate_severity_chart(self, findings: List[Dict[str, Any]]) -> str:
        """Generate an interactive pie chart for severity distribution."""
        severity_counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Info": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "Info")
            severity_counts[severity] += 1
            
        colors = {sev: info['color'] for sev, info in self.config.get('severity_levels', {}).items()}
        if not colors:  # Fallback colors if config not loaded
            colors = {
                "Critical": "#DC2626",
                "High": "#D97706",
                "Medium": "#F59E0B",
                "Low": "#059669",
                "Info": "#3B82F6"
            }
        
        fig = go.Figure(data=[go.Pie(
            labels=list(severity_counts.keys()),
            values=list(severity_counts.values()),
            marker=dict(colors=[colors[sev] for sev in severity_counts.keys()]),
            textinfo='label+percent',
            hole=.3
        )])
        
        fig.update_layout(
            title="Findings by Severity",
            showlegend=True,
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )
        
        return plotly.utils.get_plotlyjs() + fig.to_html(full_html=False)

    def _generate_timeline_chart(self, findings: List[Dict[str, Any]]) -> str:
        """Generate a timeline of findings by severity."""
        df = []
        for finding in findings:
            df.append({
                'Severity': finding.get('severity', 'Info'),
                'Description': finding.get('description', ''),
                'Date': datetime.now()  # In a real scenario, use finding's discovery date
            })
        
        colors = {sev: info['color'] for sev, info in self.config.get('severity_levels', {}).items()}
        
        fig = px.timeline(
            df,
            x_start='Date',
            y='Severity',
            color='Severity',
            hover_data=['Description'],
            color_discrete_map=colors
        )
        
        fig.update_layout(
            title="Findings Timeline",
            showlegend=True,
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )
        
        return fig.to_html(full_html=False)

    def _generate_vulnerability_summary(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate a summary of vulnerabilities found."""
        summary = {
            "total_findings": len(findings),
            "severity_counts": {
                "Critical": 0,
                "High": 0,
                "Medium": 0,
                "Low": 0,
                "Info": 0
            },
            "cve_count": 0,
            "categories": set(),
            "severity_descriptions": self.config.get('severity_levels', {}),
            "risk_score": 0
        }
        
        # Calculate risk score and count findings
        severity_weights = {
            "Critical": 5,
            "High": 4,
            "Medium": 3,
            "Low": 2,
            "Info": 1
        }
        
        for finding in findings:
            severity = finding.get("severity", "Info")
            summary["severity_counts"][severity] += 1
            summary["categories"].add(finding.get("category", "Unknown"))
            if "cve_references" in finding:
                summary["cve_count"] += len(finding["cve_references"])
            
            # Calculate weighted risk score
            summary["risk_score"] += severity_weights.get(severity, 1)
        
        # Normalize risk score to 0-100
        max_possible_score = len(findings) * 5  # if all findings were Critical
        if max_possible_score > 0:
            summary["risk_score"] = round((summary["risk_score"] / max_possible_score) * 100)
                
        summary["categories"] = list(summary["categories"])
        return summary

    def _group_findings_by_category(self, findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by their category."""
        grouped = {}
        for finding in findings:
            category = finding.get("category", "Unknown")
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(finding)
        return grouped

    def _generate_executive_summary(self, findings: List[Dict[str, Any]], summary: Dict[str, Any]) -> str:
        """Generate an executive summary of the findings."""
        critical_high = summary["severity_counts"]["Critical"] + summary["severity_counts"]["High"]
        total = summary["total_findings"]
        
        return f"""
        The security audit identified {total} findings, including {critical_high} critical/high severity issues 
        that require immediate attention. The overall risk score is {summary["risk_score"]}/100, indicating 
        {'a high' if summary["risk_score"] > 75 else 'a moderate' if summary["risk_score"] > 50 else 'a low'} 
        level of risk in the SSL/TLS implementation.
        
        Key findings include:
        - {summary["severity_counts"]["Critical"]} Critical severity issues
        - {summary["severity_counts"]["High"]} High severity issues
        - {summary["cve_count"]} Known CVEs identified
        """

    def generate_report(self, findings: List[Dict[str, Any]], target: str) -> str:
        """
        Generate a comprehensive HTML report for the audit findings.
        
        Args:
            findings: List of finding dictionaries
            target: The target that was audited
            
        Returns:
            str: Path to the generated report file
        """
        summary = self._generate_vulnerability_summary(findings)
        
        # Prepare report data
        report_data = {
            "target": target,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "findings": findings,
            "summary": summary,
            "grouped_findings": self._group_findings_by_category(findings),
            "severity_chart": self._generate_severity_chart(findings),
            "timeline_chart": self._generate_timeline_chart(findings),
            "executive_summary": self._generate_executive_summary(findings, summary),
            "config": self.config
        }
        
        # Generate HTML
        html_content = self.template.render(**report_data)
        
        # Create report filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_filename = f"ssl_audit_report_{target}_{timestamp}.html"
        report_path = os.path.join(self.reports_dir, report_filename)
        
        # Save report
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        # Also save findings as JSON for future reference
        json_filename = f"ssl_audit_findings_{target}_{timestamp}.json"
        json_path = os.path.join(self.reports_dir, json_filename)
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2)
            
        return report_path 