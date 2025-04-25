import requests
import json
import re
import ssl
import socket
import urllib.parse
import base64
from typing import Dict, Any, List, Tuple, Optional
from ...core.base_auditor import BaseAuditor
import jwt  # Add this import at the top with other imports
from jwt.algorithms import get_default_algorithms
from datetime import datetime, timedelta

class OAuthSecurityAuditor(BaseAuditor):
    """
    OAuth Security Auditor implementing checks based on:
    - OAuth 2.0 Security Best Current Practice (RFC 6819)
    - OAuth 2.1 Security Best Practices
    - IETF OAuth 2.0 for Browser-Based Apps
    - NIST SP 800-63C Digital Identity Guidelines
    """
    
    def __init__(self, target: str, config: Dict[str, Any] = None):
        """Initialize the OAuth security auditor."""
        super().__init__(target, config)
        self.oauth_endpoints = {}
        self.supported_flows = set()
        self.client_types = set()
        
    def run_all_checks(self) -> None:
        """Run all OAuth security checks."""
        # Discovery and configuration checks
        self.discover_oauth_endpoints()
        self.identify_supported_flows()
        
        # Authorization endpoint checks
        self.check_authorization_endpoint_security()
        self.check_pkce_implementation()
        self.check_state_parameter()
        self.check_redirect_uri_validation()
        
        # Token endpoint checks
        self.check_token_endpoint_security()
        self.check_token_format()
        self.check_token_lifetime()
        
        # Client authentication checks
        self.check_client_authentication()
        self.check_client_secrets_security()
        
        # Grant type specific checks
        self.check_implicit_grant_usage()
        self.check_authorization_code_security()
        self.check_refresh_token_security()
        
        # Advanced security checks
        self.check_csrf_protection()
        self.check_cors_configuration()
        self.check_token_binding()
        self.check_proof_of_possession()
        self.check_dpop_proof_security()
        
        # Additional security features
        self.check_jarm_support()
        self.check_par_support()
        self.check_rar_support()
        
        # JWT security checks
        self.check_jwt_security()
        
    def discover_oauth_endpoints(self) -> None:
        """Discover and validate OAuth endpoints."""
        try:
            # Try standard discovery endpoints
            discovery_endpoints = [
                "/.well-known/oauth-authorization-server",
                "/.well-known/openid-configuration",
                "/oauth2/authorization-server/.well-known/oauth-authorization-server"
            ]
            
            for endpoint in discovery_endpoints:
                try:
                    response = requests.get(f"https://{self.target}{endpoint}", timeout=10)
                    if response.status_code == 200:
                        self.oauth_endpoints = response.json()
                        self.add_finding(
                            severity="Info",
                            description="OAuth discovery endpoint found",
                            details=f"OAuth configuration available at {endpoint}",
                            recommendation="Ensure sensitive configuration details are not exposed",
                            reference="OAuth 2.0 Authorization Server Metadata (RFC 8414)",
                            category="OAuth Configuration"
                        )
                        break
                except Exception:
                    continue
                    
            if not self.oauth_endpoints:
                self.add_finding(
                    severity="Low",
                    description="OAuth discovery endpoint not found",
                    details="Could not automatically discover OAuth endpoints",
                    recommendation="Consider implementing OAuth discovery endpoints for better interoperability",
                    reference="OAuth 2.0 Authorization Server Metadata (RFC 8414)",
                    category="OAuth Configuration"
                )
                
        except Exception as e:
            self.logger.error(f"Error discovering OAuth endpoints: {str(e)}")
            
    def check_authorization_endpoint_security(self) -> None:
        """Check authorization endpoint security configuration."""
        try:
            auth_endpoint = self.oauth_endpoints.get("authorization_endpoint")
            if not auth_endpoint:
                return
                
            # Check TLS configuration
            parsed = urllib.parse.urlparse(auth_endpoint)
            if parsed.scheme != "https":
                self.add_finding(
                    severity="Critical",
                    description="Authorization endpoint not using HTTPS",
                    details="OAuth authorization endpoint must use HTTPS",
                    recommendation="Configure authorization endpoint to require HTTPS",
                    reference="OAuth 2.0 Security Best Current Practice Section 2.1",
                    category="OAuth Security"
                )
                
            # Check for secure TLS configuration
            if parsed.hostname:
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((parsed.hostname, 443)) as sock:
                        with context.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                            cipher = ssock.cipher()
                            if "TLSv1.2" not in str(ssock.version()) and "TLSv1.3" not in str(ssock.version()):
                                self.add_finding(
                                    severity="High",
                                    description="Weak TLS version on authorization endpoint",
                                    details=f"Authorization endpoint using {ssock.version()}",
                                    recommendation="Configure authorization endpoint to require TLS 1.2 or higher",
                                    reference="OAuth 2.0 Security Best Current Practice Section 2.1",
                                    category="OAuth Security"
                                )
                except Exception as e:
                    self.logger.error(f"Error checking TLS configuration: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Error checking authorization endpoint security: {str(e)}")
            
    def check_pkce_implementation(self) -> None:
        """Check PKCE (Proof Key for Code Exchange) implementation."""
        try:
            auth_endpoint = self.oauth_endpoints.get("authorization_endpoint")
            if not auth_endpoint:
                return
                
            # Test PKCE support
            test_params = {
                "response_type": "code",
                "client_id": "test_client",
                "redirect_uri": "https://example.com/callback",
                "code_challenge": "test_challenge",
                "code_challenge_method": "S256"
            }
            
            try:
                response = requests.get(auth_endpoint, params=test_params, allow_redirects=False)
                if response.status_code in [302, 400]:  # 302 redirect or 400 bad request (due to invalid client) is expected
                    pkce_supported = True
                else:
                    pkce_supported = False
                    
                if not pkce_supported:
                    self.add_finding(
                        severity="High",
                        description="PKCE not supported",
                        details="Authorization server does not appear to support PKCE",
                        recommendation="Implement PKCE support for enhanced security of authorization code flow",
                        reference="OAuth 2.0 Security Best Current Practice Section 2.1.1",
                        category="OAuth Security"
                    )
                    
            except Exception as e:
                self.logger.error(f"Error testing PKCE support: {str(e)}")
                
        except Exception as e:
            self.logger.error(f"Error checking PKCE implementation: {str(e)}")
            
    def check_implicit_grant_usage(self) -> None:
        """Check for deprecated implicit grant usage."""
        try:
            # Check if implicit grant is supported
            if "implicit" in str(self.oauth_endpoints).lower() or "token" in str(self.supported_flows).lower():
                self.add_finding(
                    severity="High",
                    description="Implicit grant type supported",
                    details="The authorization server supports the implicit grant type, which is deprecated",
                    recommendation="Migrate to authorization code flow with PKCE for browser-based applications",
                    reference="OAuth 2.0 Security Best Current Practice Section 2.1.2",
                    category="OAuth Security"
                )
                
        except Exception as e:
            self.logger.error(f"Error checking implicit grant usage: {str(e)}")
            
    def check_state_parameter(self) -> None:
        """Check state parameter implementation and CSRF protection."""
        try:
            auth_endpoint = self.oauth_endpoints.get("authorization_endpoint")
            if not auth_endpoint:
                return
                
            # Test state parameter requirement
            test_params = {
                "response_type": "code",
                "client_id": "test_client",
                "redirect_uri": "https://example.com/callback"
            }
            
            try:
                response = requests.get(auth_endpoint, params=test_params, allow_redirects=False)
                if response.status_code == 302:  # Redirect without state parameter
                    self.add_finding(
                        severity="High",
                        description="State parameter not enforced",
                        details="Authorization endpoint allows requests without state parameter",
                        recommendation="Enforce state parameter usage for CSRF protection",
                        reference="OAuth 2.0 Security Best Current Practice Section 2.1.3",
                        category="OAuth Security"
                    )
            except Exception as e:
                self.logger.error(f"Error testing state parameter: {str(e)}")
                
        except Exception as e:
            self.logger.error(f"Error checking state parameter: {str(e)}")
            
    def check_redirect_uri_validation(self) -> None:
        """Check redirect URI validation and open redirect vulnerabilities."""
        try:
            auth_endpoint = self.oauth_endpoints.get("authorization_endpoint")
            if not auth_endpoint:
                return
                
            # Test various redirect URI patterns
            test_cases = [
                ("http://attacker.com", "Non-HTTPS redirect URI"),
                ("https://attacker.com", "Unregistered domain"),
                ("https://example.com/callback/../../../attack", "Path traversal"),
                ("https://example.com@attacker.com", "URL confusion"),
                ("https://example.com%2F@attacker.com", "Encoded URL confusion")
            ]
            
            for test_uri, description in test_cases:
                test_params = {
                    "response_type": "code",
                    "client_id": "test_client",
                    "redirect_uri": test_uri,
                    "state": "test_state"
                }
                
                try:
                    response = requests.get(auth_endpoint, params=test_params, allow_redirects=False)
                    if response.status_code == 302:
                        self.add_finding(
                            severity="Critical",
                            description=f"Redirect URI validation bypass: {description}",
                            details=f"Authorization endpoint accepted dangerous redirect URI: {test_uri}",
                            recommendation="Implement strict redirect URI validation with exact matching",
                            reference="OAuth 2.0 Security Best Current Practice Section 2.1.4",
                            category="OAuth Security"
                        )
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error checking redirect URI validation: {str(e)}")
            
    def check_token_endpoint_security(self) -> None:
        """Check token endpoint security configuration."""
        try:
            token_endpoint = self.oauth_endpoints.get("token_endpoint")
            if not token_endpoint:
                return
                
            # Check TLS configuration
            parsed = urllib.parse.urlparse(token_endpoint)
            if parsed.scheme != "https":
                self.add_finding(
                    severity="Critical",
                    description="Token endpoint not using HTTPS",
                    details="OAuth token endpoint must use HTTPS",
                    recommendation="Configure token endpoint to require HTTPS",
                    reference="OAuth 2.0 Security Best Current Practice Section 2.1",
                    category="OAuth Security"
                )
                
            # Test token endpoint security headers
            try:
                response = requests.options(token_endpoint)
                headers = response.headers
                
                # Check CORS configuration
                if "Access-Control-Allow-Origin" in headers:
                    if headers["Access-Control-Allow-Origin"] == "*":
                        self.add_finding(
                            severity="High",
                            description="Insecure CORS configuration on token endpoint",
                            details="Token endpoint allows requests from any origin",
                            recommendation="Configure specific allowed origins for CORS",
                            reference="OAuth 2.0 Security Best Current Practice Section 2.1.5",
                            category="OAuth Security"
                        )
                        
                # Check security headers
                security_headers = {
                    "Strict-Transport-Security": "Missing HSTS header",
                    "X-Content-Type-Options": "Missing content type options header",
                    "X-Frame-Options": "Missing frame options header"
                }
                
                for header, description in security_headers.items():
                    if header not in headers:
                        self.add_finding(
                            severity="Medium",
                            description=description,
                            details=f"Token endpoint missing security header: {header}",
                            recommendation=f"Add {header} security header",
                            reference="OWASP Secure Headers Project",
                            category="OAuth Security"
                        )
                        
            except Exception as e:
                self.logger.error(f"Error checking token endpoint headers: {str(e)}")
                
        except Exception as e:
            self.logger.error(f"Error checking token endpoint security: {str(e)}")
            
    def check_token_format(self) -> None:
        """Check token format and content security."""
        try:
            token_endpoint = self.oauth_endpoints.get("token_endpoint")
            if not token_endpoint:
                return
                
            # Test token request
            test_data = {
                "grant_type": "authorization_code",
                "code": "test_code",
                "redirect_uri": "https://example.com/callback",
                "client_id": "test_client"
            }
            
            try:
                response = requests.post(token_endpoint, data=test_data)
                if response.status_code == 400:  # Expected error for invalid code
                    content_type = response.headers.get("Content-Type", "")
                    if not content_type.startswith("application/json"):
                        self.add_finding(
                            severity="Low",
                            description="Non-standard token response format",
                            details="Token endpoint responses should use application/json content type",
                            recommendation="Configure token endpoint to return JSON responses",
                            reference="OAuth 2.0 RFC 6749 Section 5.1",
                            category="OAuth Security"
                        )
                        
            except Exception as e:
                self.logger.error(f"Error testing token format: {str(e)}")
                
        except Exception as e:
            self.logger.error(f"Error checking token format: {str(e)}")
            
    def check_client_authentication(self) -> None:
        """Check client authentication methods and security."""
        try:
            supported_auth_methods = self.oauth_endpoints.get("token_endpoint_auth_methods_supported", [])
            
            # Check for insecure authentication methods
            insecure_methods = {
                "none": "No client authentication",
                "client_secret_post": "Client secret in POST body",
                "client_secret_basic": "Basic authentication with static secret"
            }
            
            for method in supported_auth_methods:
                if method in insecure_methods:
                    self.add_finding(
                        severity="Medium",
                        description=f"Insecure client authentication method: {method}",
                        details=f"Server supports {insecure_methods[method]}",
                        recommendation="Use more secure client authentication methods like private_key_jwt",
                        reference="OAuth 2.0 Security Best Current Practice Section 2.1.7",
                        category="OAuth Security"
                    )
                    
            # Check if secure methods are supported
            secure_methods = ["private_key_jwt", "tls_client_auth", "self_signed_tls_client_auth"]
            if not any(method in supported_auth_methods for method in secure_methods):
                self.add_finding(
                    severity="Medium",
                    description="No secure client authentication methods",
                    details="Server does not support any recommended client authentication methods",
                    recommendation="Implement support for private_key_jwt or mutual TLS authentication",
                    reference="OAuth 2.0 Security Best Current Practice Section 2.1.7",
                    category="OAuth Security"
                )
                
        except Exception as e:
            self.logger.error(f"Error checking client authentication: {str(e)}")
            
    def check_refresh_token_security(self) -> None:
        """Check refresh token security and rotation."""
        try:
            # Check refresh token configuration
            if "refresh_token" in str(self.oauth_endpoints).lower():
                rotation_supported = False
                
                # Check for refresh token rotation
                test_data = {
                    "grant_type": "refresh_token",
                    "refresh_token": "test_token",
                    "client_id": "test_client"
                }
                
                try:
                    token_endpoint = self.oauth_endpoints.get("token_endpoint")
                    if token_endpoint:
                        response = requests.post(token_endpoint, data=test_data)
                        if response.status_code == 400:  # Expected error for invalid token
                            rotation_supported = "refresh_token" in response.text.lower()
                            
                except Exception:
                    pass
                    
                if not rotation_supported:
                    self.add_finding(
                        severity="Medium",
                        description="Refresh token rotation not detected",
                        details="Server may not implement refresh token rotation",
                        recommendation="Implement refresh token rotation for enhanced security",
                        reference="OAuth 2.0 Security Best Current Practice Section 2.2.2",
                        category="OAuth Security"
                    )
                    
        except Exception as e:
            self.logger.error(f"Error checking refresh token security: {str(e)}")
            
    def check_cors_configuration(self) -> None:
        """Check CORS configuration for OAuth endpoints."""
        try:
            endpoints = [
                ("authorization_endpoint", "Authorization"),
                ("token_endpoint", "Token"),
                ("userinfo_endpoint", "UserInfo"),
                ("revocation_endpoint", "Revocation")
            ]
            
            for endpoint_key, endpoint_name in endpoints:
                endpoint = self.oauth_endpoints.get(endpoint_key)
                if not endpoint:
                    continue
                    
                try:
                    response = requests.options(endpoint)
                    headers = response.headers
                    
                    # Check CORS headers
                    cors_headers = {
                        "Access-Control-Allow-Origin": "Wildcard origin (*)",
                        "Access-Control-Allow-Credentials": "Credentials allowed with wildcard",
                        "Access-Control-Allow-Methods": "Unsafe methods",
                        "Access-Control-Allow-Headers": "Overly permissive headers"
                    }
                    
                    for header, issue in cors_headers.items():
                        if header in headers:
                            value = headers[header]
                            if header == "Access-Control-Allow-Origin" and value == "*":
                                self.add_finding(
                                    severity="High",
                                    description=f"Insecure CORS configuration on {endpoint_name} endpoint",
                                    details=f"{issue}: {value}",
                                    recommendation="Configure specific allowed origins",
                                    reference="OAuth 2.0 Security Best Current Practice Section 2.1.5",
                                    category="OAuth Security"
                                )
                            elif header == "Access-Control-Allow-Credentials" and value.lower() == "true":
                                if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
                                    self.add_finding(
                                        severity="Critical",
                                        description=f"Dangerous CORS configuration on {endpoint_name} endpoint",
                                        details="Credentials allowed with wildcard origin",
                                        recommendation="Configure specific allowed origins when allowing credentials",
                                        reference="OAuth 2.0 Security Best Current Practice Section 2.1.5",
                                        category="OAuth Security"
                                    )
                                    
                except Exception as e:
                    self.logger.error(f"Error checking CORS for {endpoint_name} endpoint: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Error checking CORS configuration: {str(e)}")

    def check_token_binding(self) -> None:
        """Check token binding support and configuration."""
        try:
            # Check token binding metadata
            supported_bindings = self.oauth_endpoints.get("token_binding_supported", [])
            
            if not supported_bindings:
                self.add_finding(
                    severity="Low",
                    description="Token binding not supported",
                    details="Server does not support token binding",
                    recommendation="Consider implementing token binding for enhanced security",
                    reference="OAuth 2.0 Token Binding (RFC 8473)",
                    category="OAuth Security"
                )
            else:
                # Check for secure binding methods
                secure_bindings = ["provided_token_binding", "referred_token_binding"]
                if not any(binding in supported_bindings for binding in secure_bindings):
                    self.add_finding(
                        severity="Low",
                        description="Limited token binding support",
                        details="Server does not support recommended token binding methods",
                        recommendation="Implement support for provided and referred token binding",
                        reference="OAuth 2.0 Token Binding (RFC 8473)",
                        category="OAuth Security"
                    )
                    
        except Exception as e:
            self.logger.error(f"Error checking token binding: {str(e)}")
            
    def check_proof_of_possession(self) -> None:
        """Check proof of possession token support."""
        try:
            # Check for DPoP support
            token_endpoint = self.oauth_endpoints.get("token_endpoint")
            if not token_endpoint:
                return
                
            try:
                response = requests.options(token_endpoint)
                headers = response.headers
                
                if "DPoP-Bound-Access-Tokens" not in str(headers):
                    self.add_finding(
                        severity="Low",
                        description="DPoP not supported",
                        details="Server does not support Demonstrating Proof of Possession (DPoP)",
                        recommendation="Implement DPoP support for enhanced token security",
                        reference="OAuth 2.0 DPoP (draft-ietf-oauth-dpop)",
                        category="OAuth Security"
                    )
                    
            except Exception as e:
                self.logger.error(f"Error checking DPoP support: {str(e)}")
                
        except Exception as e:
            self.logger.error(f"Error checking proof of possession: {str(e)}")
            
    def check_authorization_code_security(self) -> None:
        """Check authorization code security measures."""
        try:
            auth_endpoint = self.oauth_endpoints.get("authorization_endpoint")
            if not auth_endpoint:
                return
                
            # Test code security features
            test_params = {
                "response_type": "code",
                "client_id": "test_client",
                "redirect_uri": "https://example.com/callback",
                "state": "test_state"
            }
            
            try:
                response = requests.get(auth_endpoint, params=test_params, allow_redirects=False)
                if response.status_code == 302:
                    location = response.headers.get("Location", "")
                    
                    # Check code length (should be sufficiently long)
                    if "code=" in location:
                        code = re.search(r"code=([^&]+)", location)
                        if code and len(code.group(1)) < 32:
                            self.add_finding(
                                severity="Medium",
                                description="Short authorization code",
                                details="Authorization code length is less than recommended minimum",
                                recommendation="Use authorization codes of at least 32 bytes",
                                reference="OAuth 2.0 Security Best Current Practice Section 4.1",
                                category="OAuth Security"
                            )
                            
            except Exception as e:
                self.logger.error(f"Error testing authorization code: {str(e)}")
                
        except Exception as e:
            self.logger.error(f"Error checking authorization code security: {str(e)}")
            
    def identify_supported_flows(self) -> None:
        """Identify supported OAuth flows and grant types."""
        try:
            # Check supported response types
            response_types = self.oauth_endpoints.get("response_types_supported", [])
            grant_types = self.oauth_endpoints.get("grant_types_supported", [])
            
            # Map response types to flows
            flow_mapping = {
                "code": "authorization_code",
                "token": "implicit",
                "id_token": "implicit",
                "code token": "hybrid",
                "code id_token": "hybrid",
                "token id_token": "hybrid",
                "code token id_token": "hybrid"
            }
            
            for response_type in response_types:
                if response_type in flow_mapping:
                    self.supported_flows.add(flow_mapping[response_type])
                    
            # Add grant types
            for grant_type in grant_types:
                self.supported_flows.add(grant_type)
                
            # Check for deprecated or insecure flows
            deprecated_flows = {
                "implicit": "The implicit flow is deprecated and has known security issues",
                "password": "The password grant type exposes user credentials",
                "client_credentials": "Ensure proper client authentication for this flow"
            }
            
            for flow, warning in deprecated_flows.items():
                if flow in self.supported_flows:
                    severity = "High" if flow == "implicit" else "Medium"
                    self.add_finding(
                        severity=severity,
                        description=f"Potentially insecure flow supported: {flow}",
                        details=warning,
                        recommendation=f"Consider removing support for the {flow} flow",
                        reference="OAuth 2.0 Security Best Current Practice",
                        category="OAuth Security"
                    )
                    
        except Exception as e:
            self.logger.error(f"Error identifying supported flows: {str(e)}")
            
    def check_token_lifetime(self) -> None:
        """Check token lifetime and expiration configuration."""
        try:
            # Check token lifetime configuration
            if "access_token" in str(self.oauth_endpoints).lower():
                # Try to get token lifetime information
                token_endpoint = self.oauth_endpoints.get("token_endpoint")
                if not token_endpoint:
                    return
                    
                test_data = {
                    "grant_type": "client_credentials",
                    "client_id": "test_client"
                }
                
                try:
                    response = requests.post(token_endpoint, data=test_data)
                    if response.status_code == 400:  # Expected error for invalid client
                        if "expires_in" not in response.text.lower():
                            self.add_finding(
                                severity="Low",
                                description="Token lifetime not specified",
                                details="Server does not return token expiration information",
                                recommendation="Include expires_in parameter in token responses",
                                reference="OAuth 2.0 RFC 6749 Section 5.1",
                                category="OAuth Security"
                            )
                            
                except Exception as e:
                    self.logger.error(f"Error testing token lifetime: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Error checking token lifetime: {str(e)}")
            
    def check_client_secrets_security(self) -> None:
        """Check client secrets handling and security."""
        try:
            # Check client authentication methods
            auth_methods = self.oauth_endpoints.get("token_endpoint_auth_methods_supported", [])
            
            if "client_secret_basic" in auth_methods or "client_secret_post" in auth_methods:
                # Test client secret requirements
                token_endpoint = self.oauth_endpoints.get("token_endpoint")
                if not token_endpoint:
                    return
                    
                test_cases = [
                    ("short_secret", "test"),
                    ("weak_secret", "password123"),
                    ("simple_secret", "clientsecret")
                ]
                
                for test_id, secret in test_cases:
                    auth_str = f"{test_id}:{secret}"
                    headers = {
                        "Authorization": f"Basic {base64.b64encode(auth_str.encode()).decode()}"
                    }
                    
                    try:
                        response = requests.post(token_endpoint, headers=headers)
                        if response.status_code == 401:  # Expected unauthorized
                            if "invalid_client" not in response.text.lower():
                                self.add_finding(
                                    severity="Low",
                                    description="Non-standard client authentication error",
                                    details="Server does not return standard OAuth error for invalid clients",
                                    recommendation="Use standard OAuth error responses",
                                    reference="OAuth 2.0 RFC 6749 Section 5.2",
                                    category="OAuth Security"
                                )
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            self.logger.error(f"Error checking client secrets security: {str(e)}")
            
    def check_csrf_protection(self) -> None:
        """Check CSRF protection mechanisms."""
        try:
            auth_endpoint = self.oauth_endpoints.get("authorization_endpoint")
            if not auth_endpoint:
                return
                
            # Test CSRF protection
            test_cases = [
                ({"response_type": "code", "client_id": "test_client"}, "Missing state parameter"),
                ({"response_type": "code", "client_id": "test_client", "state": ""}, "Empty state parameter"),
                ({"response_type": "code", "client_id": "test_client", "state": "a"}, "Short state parameter")
            ]
            
            for params, description in test_cases:
                try:
                    response = requests.get(auth_endpoint, params=params, allow_redirects=False)
                    if response.status_code == 302:
                        self.add_finding(
                            severity="High",
                            description=f"Insufficient CSRF protection: {description}",
                            details="Authorization endpoint accepts requests with inadequate CSRF protection",
                            recommendation="Enforce proper state parameter usage",
                            reference="OAuth 2.0 Security Best Current Practice Section 4.7",
                            category="OAuth Security"
                        )
                        
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error checking CSRF protection: {str(e)}")

    def check_jarm_support(self) -> None:
        """Check JWT Secured Authorization Response Mode (JARM) support."""
        try:
            # Check for JARM support in metadata
            response_modes = self.oauth_endpoints.get("response_modes_supported", [])
            jarm_modes = ["jwt", "query.jwt", "fragment.jwt", "form_post.jwt"]
            
            if not any(mode in response_modes for mode in jarm_modes):
                self.add_finding(
                    severity="Low",
                    description="JARM not supported",
                    details="Server does not support JWT Secured Authorization Response Mode",
                    recommendation="Consider implementing JARM for enhanced security of authorization responses",
                    reference="OAuth 2.0 JARM (JWT Secured Authorization Response Mode)",
                    category="OAuth Security"
                )
                
        except Exception as e:
            self.logger.error(f"Error checking JARM support: {str(e)}")
            
    def check_par_support(self) -> None:
        """Check Pushed Authorization Request (PAR) support."""
        try:
            # Check for PAR endpoint
            par_endpoint = self.oauth_endpoints.get("pushed_authorization_request_endpoint")
            if not par_endpoint:
                self.add_finding(
                    severity="Low",
                    description="PAR not supported",
                    details="Server does not support Pushed Authorization Requests",
                    recommendation="Implement PAR support for enhanced security and privacy",
                    reference="OAuth 2.0 Pushed Authorization Requests (RFC 9126)",
                    category="OAuth Security"
                )
            else:
                # Test PAR endpoint security
                try:
                    response = requests.options(par_endpoint)
                    headers = response.headers
                    
                    if "Access-Control-Allow-Origin" in headers and headers["Access-Control-Allow-Origin"] == "*":
                        self.add_finding(
                            severity="High",
                            description="Insecure CORS configuration on PAR endpoint",
                            details="PAR endpoint allows requests from any origin",
                            recommendation="Configure specific allowed origins for PAR endpoint",
                            reference="OAuth 2.0 Pushed Authorization Requests (RFC 9126)",
                            category="OAuth Security"
                        )
                        
                except Exception as e:
                    self.logger.error(f"Error checking PAR endpoint security: {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Error checking PAR support: {str(e)}")
            
    def check_rar_support(self) -> None:
        """Check Rich Authorization Request (RAR) support."""
        try:
            # Check for RAR support in metadata
            auth_methods = self.oauth_endpoints.get("authorization_details_types_supported", [])
            if not auth_methods:
                self.add_finding(
                    severity="Info",
                    description="RAR not supported",
                    details="Server does not support Rich Authorization Requests",
                    recommendation="Consider implementing RAR for fine-grained authorization",
                    reference="OAuth 2.0 Rich Authorization Requests (draft-ietf-oauth-rar)",
                    category="OAuth Security"
                )
                
        except Exception as e:
            self.logger.error(f"Error checking RAR support: {str(e)}")
            
    def check_dpop_proof_security(self) -> None:
        """Check DPoP proof security requirements."""
        try:
            token_endpoint = self.oauth_endpoints.get("token_endpoint")
            if not token_endpoint:
                return
                
            # Test DPoP requirements
            test_headers = {
                "DPoP": "invalid_proof"
            }
            
            try:
                response = requests.post(token_endpoint, headers=test_headers)
                if response.status_code == 400:
                    if "invalid_dpop_proof" not in response.text.lower():
                        self.add_finding(
                            severity="Low",
                            description="Non-standard DPoP error handling",
                            details="Server does not return standard DPoP error responses",
                            recommendation="Implement standard DPoP error responses",
                            reference="OAuth 2.0 DPoP (draft-ietf-oauth-dpop)",
                            category="OAuth Security"
                        )
                        
            except Exception as e:
                self.logger.error(f"Error testing DPoP requirements: {str(e)}")
                
        except Exception as e:
            self.logger.error(f"Error checking DPoP proof security: {str(e)}")

    def check_jwt_security(self) -> None:
        """Check JWT token security and algorithm vulnerabilities."""
        try:
            token_endpoint = self.oauth_endpoints.get("token_endpoint")
            if not token_endpoint:
                return

            # Get supported signing algorithms
            supported_algs = self.oauth_endpoints.get("id_token_signing_alg_values_supported", [])
            if not supported_algs:
                # Try to get a token to analyze its algorithm
                test_data = {
                    "grant_type": "client_credentials",
                    "client_id": "test_client"
                }
                try:
                    response = requests.post(token_endpoint, data=test_data)
                    if response.status_code == 400:  # Expected error
                        # Try to extract JWT from error response
                        jwt_pattern = r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"
                        match = re.search(jwt_pattern, response.text)
                        if match:
                            token = match.group(0)
                            # Get algorithm from header
                            header = jwt.get_unverified_header(token)
                            if header and 'alg' in header:
                                supported_algs = [header['alg']]
                except Exception as e:
                    self.logger.error(f"Error testing token endpoint: {str(e)}")

            # Check for vulnerable algorithms
            vulnerable_algs = {
                "none": {
                    "severity": "Critical",
                    "description": "Algorithm 'none' supported",
                    "details": "The 'none' algorithm allows tokens without signature verification",
                    "cve": "CVE-2015-9235"
                },
                "HS256": {
                    "severity": "Medium",
                    "description": "HMAC-SHA256 algorithm used",
                    "details": "HMAC-SHA256 is vulnerable to key confusion attacks if used with RSA public keys",
                    "cve": "CVE-2016-5431"
                },
                "RS1": {
                    "severity": "Critical",
                    "description": "RSA-SHA1 algorithm used",
                    "details": "SHA-1 is cryptographically broken",
                    "cve": "CVE-2020-28042"
                }
            }

            # Additional checks for known algorithm vulnerabilities
            algorithm_checks = {
                r"^RS\d+$": {
                    "check": lambda alg: int(alg[2:]) < 256,
                    "severity": "High",
                    "description": "Weak RSA signature algorithm",
                    "details": "RSA signature algorithm using weak hash function",
                    "recommendation": "Use RS256 or stronger"
                },
                r"^HS\d+$": {
                    "check": lambda alg: int(alg[2:]) < 256,
                    "severity": "High",
                    "description": "Weak HMAC algorithm",
                    "details": "HMAC algorithm using weak hash function",
                    "recommendation": "Use HS256 or stronger"
                },
                r"^ES\d+$": {
                    "check": lambda alg: int(alg[2:]) < 256,
                    "severity": "High",
                    "description": "Weak ECDSA algorithm",
                    "details": "ECDSA algorithm using weak hash function",
                    "recommendation": "Use ES256 or stronger"
                }
            }

            for alg in supported_algs:
                # Check for known vulnerable algorithms
                if alg.lower() in vulnerable_algs:
                    vuln = vulnerable_algs[alg.lower()]
                    self.add_finding(
                        severity=vuln["severity"],
                        description=vuln["description"],
                        details=vuln["details"],
                        recommendation="Disable this algorithm and use secure alternatives",
                        reference=f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln['cve']}",
                        category="JWT Security"
                    )

                # Check for weak algorithm variants
                for pattern, check in algorithm_checks.items():
                    if re.match(pattern, alg):
                        if check["check"](alg):
                            self.add_finding(
                                severity=check["severity"],
                                description=check["description"],
                                details=check["details"],
                                recommendation=check["recommendation"],
                                reference="NIST SP 800-57 Part 1 Rev. 5",
                                category="JWT Security"
                            )

            # Check for missing secure algorithms
            recommended_algs = {"RS256", "ES256", "PS256"}
            if not any(alg in supported_algs for alg in recommended_algs):
                self.add_finding(
                    severity="Medium",
                    description="No recommended signing algorithms",
                    details="Server does not support any of the recommended signing algorithms",
                    recommendation="Implement support for RS256, ES256, or PS256",
                    reference="JWT Best Current Practices (RFC 8725)",
                    category="JWT Security"
                )

        except Exception as e:
            self.logger.error(f"Error checking JWT security: {str(e)}")

    def check_jwt_key_confusion(self, token: str) -> None:
        """Check for JWT key confusion vulnerabilities."""
        try:
            header = jwt.get_unverified_header(token)
            if header.get('alg', '').startswith('HS'):
                # Test for RSA public key confusion
                try:
                    # Try to verify with a public key as HMAC secret
                    test_pubkey = b"-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv\nvkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc\naT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy\ntvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0\ne+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb\nV6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9\nMwIDAQAB\n-----END PUBLIC KEY-----"
                    jwt.decode(token, test_pubkey, algorithms=['HS256'])
                    self.add_finding(
                        severity="Critical",
                        description="JWT key confusion vulnerability",
                        details="Token is vulnerable to key confusion attacks using RSA public key as HMAC secret",
                        recommendation="Use separate keys for different algorithms and implement proper key management",
                        reference="CVE-2016-5431",
                        category="JWT Security"
                    )
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"Error checking JWT key confusion: {str(e)}")

    def check_jwt_kid_attacks(self, token: str) -> None:
        """Check for JWT 'kid' (Key ID) header attacks."""
        try:
            header = jwt.get_unverified_header(token)
            if 'kid' in header:
                kid = header['kid']
                
                # Check for directory traversal
                if '../' in kid or './' in kid:
                    self.add_finding(
                        severity="Critical",
                        description="JWT kid header path traversal",
                        details="Key ID contains directory traversal sequences",
                        recommendation="Validate and sanitize kid header values",
                        reference="OWASP JWT Security Cheat Sheet",
                        category="JWT Security"
                    )
                
                # Check for SQL injection
                sql_patterns = ["'", "\"", "OR", "AND", "UNION", "--"]
                if any(pattern.lower() in kid.lower() for pattern in sql_patterns):
                    self.add_finding(
                        severity="Critical",
                        description="JWT kid header potential SQL injection",
                        details="Key ID contains SQL injection patterns",
                        recommendation="Use parameterized queries and validate kid values",
                        reference="OWASP SQL Injection Prevention Cheat Sheet",
                        category="JWT Security"
                    )
                
                # Check for command injection
                if any(c in kid for c in '|&;`$()"\''):
                    self.add_finding(
                        severity="Critical",
                        description="JWT kid header command injection",
                        details="Key ID contains command injection characters",
                        recommendation="Validate and sanitize kid values, use whitelist approach",
                        reference="OWASP Command Injection Prevention Cheat Sheet",
                        category="JWT Security"
                    )
                
                # Check for large kid values (DoS)
                if len(kid) > 128:
                    self.add_finding(
                        severity="Medium",
                        description="JWT kid header length",
                        details="Key ID is unusually long which could lead to DoS",
                        recommendation="Limit kid header length",
                        reference="OWASP Denial of Service Cheat Sheet",
                        category="JWT Security"
                    )
        except Exception as e:
            self.logger.error(f"Error checking JWT kid attacks: {str(e)}")

    def check_jwt_signature_stripping(self, token: str) -> None:
        """Check for JWT signature stripping vulnerabilities."""
        try:
            parts = token.split('.')
            if len(parts) == 3:
                # Try signature stripping attack
                stripped_token = '.'.join(parts[:2] + [''])
                try:
                    # Attempt to use the token without signature
                    requests.get(
                        self.oauth_endpoints.get('userinfo_endpoint', ''),
                        headers={'Authorization': f'Bearer {stripped_token}'},
                        allow_redirects=False
                    )
                    self.add_finding(
                        severity="Critical",
                        description="JWT signature stripping vulnerability",
                        details="Server accepts tokens with stripped signatures",
                        recommendation="Always verify JWT signatures and reject tokens with invalid signatures",
                        reference="JWT Best Current Practices (RFC 8725)",
                        category="JWT Security"
                    )
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"Error checking JWT signature stripping: {str(e)}")

    def check_jwt_claim_injection(self, token: str) -> None:
        """Check for JWT claim injection vulnerabilities."""
        try:
            # Decode payload without verification
            payload_segment = token.split('.')[1]
            payload_bytes = base64.urlsafe_b64decode(payload_segment + '=' * (-len(payload_segment) % 4))
            payload = json.loads(payload_bytes)
            
            # Check for dangerous claims
            dangerous_claims = {
                'role': ['admin', 'administrator', 'root'],
                'groups': ['admin', 'administrators', 'root'],
                'permissions': ['all', '*', 'admin'],
                'scope': ['admin', 'all', '*']
            }
            
            for claim, values in dangerous_claims.items():
                if claim in payload:
                    if isinstance(payload[claim], (str, list)):
                        claim_values = [payload[claim]] if isinstance(payload[claim], str) else payload[claim]
                        if any(val.lower() in [dv.lower() for dv in values] for val in claim_values):
                            self.add_finding(
                                severity="High",
                                description="JWT contains privileged claims",
                                details=f"Token contains potentially dangerous {claim} values",
                                recommendation="Validate and sanitize JWT claims, implement proper role checks",
                                reference="OWASP JWT Security Cheat Sheet",
                                category="JWT Security"
                            )
            
            # Check for claim duplication
            if isinstance(payload, dict):
                seen_claims = set()
                for claim in payload:
                    if claim.lower() in seen_claims:
                        self.add_finding(
                            severity="High",
                            description="JWT duplicate claims",
                            details="Token contains duplicate claims which could lead to claim shadowing attacks",
                            recommendation="Reject tokens with duplicate claims",
                            reference="JWT Best Current Practices (RFC 8725)",
                            category="JWT Security"
                        )
                    seen_claims.add(claim.lower())
                    
        except Exception as e:
            self.logger.error(f"Error checking JWT claim injection: {str(e)}")

    def check_jwt_algorithm_confusion(self, token: str) -> None:
        """Check for JWT algorithm confusion vulnerabilities."""
        try:
            header = jwt.get_unverified_header(token)
            alg = header.get('alg', '')
            
            # Check for algorithm substitution risks
            if alg.startswith('RS'):
                # Try to verify RS* token as HS*
                try:
                    modified_header = header.copy()
                    modified_header['alg'] = 'HS' + alg[2:]
                    # Create new token with modified algorithm
                    parts = token.split('.')
                    modified_token = base64.urlsafe_b64encode(
                        json.dumps(modified_header).encode()
                    ).rstrip(b'=').decode() + '.' + parts[1] + '.' + parts[2]
                    
                    # Try to use modified token
                    response = requests.get(
                        self.oauth_endpoints.get('userinfo_endpoint', ''),
                        headers={'Authorization': f'Bearer {modified_token}'},
                        allow_redirects=False
                    )
                    
                    if response.status_code != 401:
                        self.add_finding(
                            severity="Critical",
                            description="JWT algorithm confusion vulnerability",
                            details="Server accepts tokens with modified algorithms",
                            recommendation="Enforce expected algorithms and reject algorithm changes",
                            reference="CVE-2015-9235",
                            category="JWT Security"
                        )
                except Exception:
                    pass
                    
        except Exception as e:
            self.logger.error(f"Error checking JWT algorithm confusion: {str(e)}")

    def analyze_jwt_token(self, token: str) -> None:
        """Analyze a JWT token for security issues."""
        try:
            # Decode header without verification
            header = jwt.get_unverified_header(token)
            
            # Try to decode payload without verification
            try:
                payload_segment = token.split('.')[1]
                payload_bytes = base64.urlsafe_b64decode(payload_segment + '=' * (-len(payload_segment) % 4))
                payload = json.loads(payload_bytes)
            except Exception:
                payload = {}

            # Check header parameters
            if 'alg' in header:
                # Check for algorithm security
                if header['alg'].lower() == 'none':
                    self.add_finding(
                        severity="Critical",
                        description="JWT uses 'none' algorithm",
                        details="Token uses the 'none' algorithm which bypasses signature verification",
                        recommendation="Reject tokens with 'none' algorithm",
                        reference="CVE-2015-9235",
                        category="JWT Security"
                    )

                # Check for weak algorithms
                if header['alg'] in ['HS1', 'RS1', 'ES1']:
                    self.add_finding(
                        severity="High",
                        description="JWT uses weak signing algorithm",
                        details=f"Token uses {header['alg']} which is cryptographically weak",
                        recommendation="Use strong algorithms like RS256, ES256, or PS256",
                        reference="JWT Best Current Practices (RFC 8725)",
                        category="JWT Security"
                    )

            # Check for missing type
            if 'typ' not in header:
                self.add_finding(
                    severity="Low",
                    description="JWT missing type header",
                    details="Token header does not specify 'typ' parameter",
                    recommendation="Include 'typ': 'JWT' in token header",
                    reference="JWT Best Current Practices (RFC 8725)",
                    category="JWT Security"
                )

            # Check payload claims
            if payload:
                # Check for missing expiration
                if 'exp' not in payload:
                    self.add_finding(
                        severity="Medium",
                        description="JWT missing expiration",
                        details="Token does not include an expiration claim",
                        recommendation="Include 'exp' claim in all tokens",
                        reference="JWT Best Current Practices (RFC 8725)",
                        category="JWT Security"
                    )
                else:
                    # Check for long expiration
                    try:
                        exp_date = datetime.fromtimestamp(payload['exp'])
                        if exp_date > datetime.now() + timedelta(days=30):
                            self.add_finding(
                                severity="Medium",
                                description="JWT long expiration time",
                                details="Token has expiration time more than 30 days in the future",
                                recommendation="Use shorter expiration times for tokens",
                                reference="OWASP JWT Security Cheat Sheet",
                                category="JWT Security"
                            )
                    except Exception:
                        pass

                # Check for missing issued at
                if 'iat' not in payload:
                    self.add_finding(
                        severity="Low",
                        description="JWT missing issued at",
                        details="Token does not include an issued at claim",
                        recommendation="Include 'iat' claim in all tokens",
                        reference="JWT Best Current Practices (RFC 8725)",
                        category="JWT Security"
                    )

            # Additional security checks
            self.check_jwt_key_confusion(token)
            self.check_jwt_kid_attacks(token)
            self.check_jwt_signature_stripping(token)
            self.check_jwt_claim_injection(token)
            self.check_jwt_algorithm_confusion(token)
            
            # Check for nested JWT attacks
            try:
                payload_segment = token.split('.')[1]
                payload_bytes = base64.urlsafe_b64decode(payload_segment + '=' * (-len(payload_segment) % 4))
                payload = json.loads(payload_bytes)
                
                # Look for nested JWTs in claims
                for value in payload.values():
                    if isinstance(value, str) and value.count('.') == 2:
                        try:
                            nested_header = jwt.get_unverified_header(value)
                            if nested_header:  # It's a valid JWT
                                self.add_finding(
                                    severity="Medium",
                                    description="Nested JWT detected",
                                    details="Token contains nested JWT which could lead to parsing vulnerabilities",
                                    recommendation="Avoid using nested JWTs, validate token structure",
                                    reference="OWASP JWT Security Cheat Sheet",
                                    category="JWT Security"
                                )
                                # Recursively analyze nested token
                                self.analyze_jwt_token(value)
                        except Exception:
                            pass
                            
            except Exception:
                pass
                
        except Exception as e:
            self.logger.error(f"Error analyzing JWT token: {str(e)}")

    def generate_report(self) -> Dict[str, Any]:
        """Generate a report of OAuth security findings."""
        return {
            "target": self.target,
            "findings": self.findings,
            "oauth_endpoints": self.oauth_endpoints,
            "supported_flows": list(self.supported_flows),
            "client_types": list(self.client_types)
        } 