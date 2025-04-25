from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import json
from datetime import datetime
import yaml
import os
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

# Try to import plotly, but don't fail if it's not available
try:
    import plotly.graph_objects as go
    import plotly.express as px
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False

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
        self.config = self._load_config()
        
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
        
    @abstractmethod
    def generate(self) -> str:
        """Generate the report in the specific format."""
        pass
    
    def _get_summary(self) -> Dict[str, Any]:
        """Generate a comprehensive summary of findings."""
        summary = {
            'total_vulnerabilities': 0,
            'severity_counts': {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Info': 0
            },
            'categories': {},
            'risk_score': 0,
            'resolved_count': 0,
            'unresolved_count': 0
        }
        
        # Severity weights for risk score calculation
        severity_weights = {
            'Critical': 10,
            'High': 8,
            'Medium': 5,
            'Low': 2,
            'Info': 0
        }
        
        max_score = 0
        current_score = 0
        
        for finding in self.findings.get('findings', []):
            severity = finding.get('severity', 'Info')
            category = finding.get('category', 'Uncategorized')
            
            # Update severity counts
            if severity in summary['severity_counts']:
                summary['severity_counts'][severity] += 1
                summary['total_vulnerabilities'] += 1
            
            # Update category counts
            if category not in summary['categories']:
                summary['categories'][category] = {
                    'count': 0,
                    'severities': {sev: 0 for sev in severity_weights.keys()}
                }
            summary['categories'][category]['count'] += 1
            summary['categories'][category]['severities'][severity] += 1
            
            # Update resolution counts
            if finding.get('resolved', False):
                summary['resolved_count'] += 1
            else:
                summary['unresolved_count'] += 1
            
            # Calculate risk score
            weight = severity_weights.get(severity, 0)
            current_score += weight
            max_score += 10  # Maximum possible weight
        
        # Normalize risk score to 0-100
        summary['risk_score'] = round((current_score / max_score * 100) if max_score > 0 else 0)
        
        return summary

class JSONReportGenerator(ReportGenerator):
    """Generate reports in JSON format."""
    
    def generate(self) -> str:
        """Generate a JSON report."""
        report = {
            'target': self.findings.get('target', ''),
            'timestamp': self.timestamp,
            'summary': self._get_summary(),
            'findings': self.findings.get('findings', []),
            'metadata': {
                'tool_version': '1.0.0',
                'config': self.config
            }
        }
        return json.dumps(report, indent=2)

class HTMLReportGenerator(ReportGenerator):
    """Generate reports in HTML format."""
    
    def __init__(self, findings: Dict[str, Any]):
        super().__init__(findings)
        template_dir = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            'reports',
            'templates'
        )
        self.env = Environment(loader=FileSystemLoader(template_dir))
        
    def _generate_severity_chart(self, summary: Dict[str, Any]) -> Optional[str]:
        """Generate an interactive pie chart for severity distribution."""
        if not PLOTLY_AVAILABLE:
            return self._generate_severity_table(summary)
            
        labels = []
        values = []
        colors = []
        
        for severity, count in summary['severity_counts'].items():
            if count > 0:  # Only include severities with findings
                labels.append(severity)
                values.append(count)
                colors.append(self.config['severity_levels'][severity]['color'])
        
        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            hole=.3,
            marker=dict(colors=colors),
            textinfo='label+percent',
            hovertemplate="<b>%{label}</b><br>" +
                         "Count: %{value}<br>" +
                         "<extra></extra>"
        )])
        
        fig.update_layout(
            title="Findings by Severity",
            showlegend=True,
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )
        
        return fig.to_html(full_html=False, include_plotlyjs=True)
    
    def _generate_severity_table(self, summary: Dict[str, Any]) -> str:
        """Generate a table representation of severity distribution when plotly is not available."""
        template = self.env.get_template('severity_table.html')
        return template.render(summary=summary, config=self.config)
    
    def _generate_category_chart(self, summary: Dict[str, Any]) -> Optional[str]:
        """Generate a bar chart for findings by category."""
        if not PLOTLY_AVAILABLE:
            return self._generate_category_table(summary)
            
        categories = []
        counts = []
        
        for category, data in summary['categories'].items():
            categories.append(category)
            counts.append(data['count'])
        
        fig = go.Figure(data=[go.Bar(
            x=categories,
            y=counts,
            marker_color=self.config['branding']['primary_color'],
            hovertemplate="<b>%{x}</b><br>" +
                         "Findings: %{y}<br>" +
                         "<extra></extra>"
        )])
        
        fig.update_layout(
            title="Findings by Category",
            xaxis_title="Category",
            yaxis_title="Number of Findings",
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )
        
        return fig.to_html(full_html=False, include_plotlyjs=False)
    
    def _generate_category_table(self, summary: Dict[str, Any]) -> str:
        """Generate a table representation of category distribution when plotly is not available."""
        template = self.env.get_template('category_table.html')
        return template.render(summary=summary, config=self.config)
    
    def _generate_risk_gauge(self, risk_score: int) -> Optional[str]:
        """Generate a gauge chart for the overall risk score."""
        if not PLOTLY_AVAILABLE:
            return self._generate_risk_indicator(risk_score)
            
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=risk_score,
            domain={'x': [0, 1], 'y': [0, 1]},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': self.config['branding']['primary_color']},
                'steps': [
                    {'range': [0, 20], 'color': self.config['severity_levels']['Info']['color']},
                    {'range': [20, 40], 'color': self.config['severity_levels']['Low']['color']},
                    {'range': [40, 60], 'color': self.config['severity_levels']['Medium']['color']},
                    {'range': [60, 80], 'color': self.config['severity_levels']['High']['color']},
                    {'range': [80, 100], 'color': self.config['severity_levels']['Critical']['color']}
                ]
            }
        ))
        
        fig.update_layout(
            title="Overall Risk Score",
            height=300,
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)'
        )
        
        return fig.to_html(full_html=False, include_plotlyjs=False)
    
    def _generate_risk_indicator(self, risk_score: int) -> str:
        """Generate a simple risk indicator when plotly is not available."""
        template = self.env.get_template('risk_indicator.html')
        return template.render(risk_score=risk_score, config=self.config)
    
    def _group_findings_by_category(self) -> Dict[str, List[Dict[str, Any]]]:
        """Group findings by their category."""
        grouped = {}
        for finding in self.findings.get('findings', []):
            category = finding.get('category', 'Uncategorized')
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(finding)
        return grouped
    
    def _generate_executive_summary(self, summary: Dict[str, Any]) -> str:
        """Generate an executive summary of the findings."""
        template = self.env.get_template('executive_summary.html')
        return template.render(summary=summary, config=self.config)
    
    def generate(self) -> str:
        """Generate an HTML report."""
        summary = self._get_summary()
        grouped_findings = self._group_findings_by_category()
        
        # Load main template
        template = self.env.get_template('report_template.html')
        
        # Generate visualizations
        severity_chart = self._generate_severity_chart(summary)
        category_chart = self._generate_category_chart(summary)
        risk_gauge = self._generate_risk_gauge(summary['risk_score'])
        executive_summary = self._generate_executive_summary(summary)
        
        # Prepare template variables
        template_vars = {
            'target': self.findings.get('target', ''),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'summary': summary,
            'findings': self.findings.get('findings', []),
            'grouped_findings': grouped_findings,
            'config': self.config,
            'severity_chart': severity_chart,
            'category_chart': category_chart,
            'risk_gauge': risk_gauge,
            'executive_summary': executive_summary,
            'plotly_available': PLOTLY_AVAILABLE
        }
        
        # Render template
        return template.render(**template_vars) 