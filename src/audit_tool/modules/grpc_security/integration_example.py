"""Example of integrating HTTP/2 and metadata security checks into the main auditor."""

from typing import Dict, Any
from ...core.base_auditor import BaseAuditor
from .http2_security_checks import check_http2_settings_security
from .metadata_security_checks import check_metadata_security

class GRPCSecurityAuditorExample(BaseAuditor):
    """Example class showing integration of new security checks."""
    
    def __init__(self, target: str, config: Dict[str, Any] = None):
        """Initialize the gRPC security auditor."""
        super().__init__(target, config)
        self.grpc_port = config.get('grpc_port', 50051)

    def check_http2_settings(self) -> None:
        """Check HTTP/2 settings security."""
        try:
            findings = check_http2_settings_security(self.target, self.grpc_port)
            for severity, description, details, recommendation, reference in findings:
                self.add_finding(
                    severity=severity,
                    description=description,
                    details=details,
                    recommendation=recommendation,
                    reference=reference,
                    category="gRPC Security"
                )
        except Exception as e:
            self.logger.error(f"Error checking HTTP/2 settings: {str(e)}")

    def check_metadata_validation(self) -> None:
        """Check metadata validation and security."""
        try:
            findings = check_metadata_security(self.target, self.grpc_port)
            for severity, description, details, recommendation, reference in findings:
                self.add_finding(
                    severity=severity,
                    description=description,
                    details=details,
                    recommendation=recommendation,
                    reference=reference,
                    category="gRPC Security"
                )
        except Exception as e:
            self.logger.error(f"Error checking metadata validation: {str(e)}")

    def run_all_checks(self) -> None:
        """Example of running all security checks including the new ones."""
        # Existing checks
        self.discover_grpc_services()
        self.check_tls_configuration()
        self.check_certificate_security()
        # ... other existing checks ...

        # New checks
        self.check_http2_settings()
        self.check_metadata_validation() 