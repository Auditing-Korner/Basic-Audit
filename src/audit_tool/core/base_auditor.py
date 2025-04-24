from abc import ABC, abstractmethod
from typing import Dict, Any, List
import logging

class BaseAuditor(ABC):
    """Base class for all security auditors."""
    
    def __init__(self, target: str, config: Dict[str, Any] = None):
        """
        Initialize the auditor.
        
        Args:
            target (str): The target to audit (domain, URL, etc.)
            config (Dict[str, Any], optional): Configuration for the auditor
        """
        self.target = target
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)
        self.findings: List[Dict[str, Any]] = []
        
    @abstractmethod
    def run_all_checks(self) -> None:
        """Run all security checks for this auditor."""
        pass
    
    @abstractmethod
    def generate_report(self) -> Dict[str, Any]:
        """Generate a report of findings."""
        pass
    
    def add_finding(self, 
                   severity: str, 
                   description: str, 
                   details: str, 
                   recommendation: str, 
                   reference: str = None,
                   category: str = None) -> None:
        """
        Add a security finding to the auditor's findings list.
        
        Args:
            severity (str): Severity level (Critical, High, Medium, Low, Info)
            description (str): Brief description of the finding
            details (str): Detailed explanation of the finding
            recommendation (str): Recommended fix or mitigation
            reference (str, optional): Reference URL or documentation
            category (str, optional): Category of the finding
        """
        finding = {
            'severity': severity,
            'description': description,
            'details': details,
            'recommendation': recommendation,
            'reference': reference,
            'category': category or self.__class__.__name__
        }
        self.findings.append(finding)
        self.logger.info(f"Added {severity} finding: {description}") 