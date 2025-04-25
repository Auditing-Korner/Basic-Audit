"""MongoDB Security Auditor Module."""

import ssl
import socket
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from pymongo import MongoClient, errors
from pymongo.server_api import ServerApi
from ...core.base_auditor import BaseAuditor

class MongoDBSecurityAuditor(BaseAuditor):
    """
    MongoDB Security Auditor implementing checks based on security best practices.
    
    This auditor performs comprehensive security checks including:
    - Authentication and Authorization
    - Network Security
    - Encryption
    - Audit Logging
    - Configuration Security
    - User Access Controls
    - Database Operations Security
    - Backup and Recovery
    - Monitoring and Alerting
    """
    
    # Common configuration parameters
    SECURE_PORTS = {27017, 27018, 27019}
    WEAK_AUTHENTICATION_MECHANISMS = {'MONGODB-CR', 'SCRAM-SHA-1'}
    REQUIRED_ROLES = {'backup', 'restore', 'userAdmin', 'dbAdmin'}
    SENSITIVE_COMMANDS = {'dropDatabase', 'dropUser', 'shutdown', 'replSetReconfig'}
    
    def __init__(self, target: str, config: Dict[str, Any] = None):
        """Initialize MongoDB Security Auditor with all modules enabled by default."""
        super().__init__(target, config)
        self.client = None
        self.port = 27017
        self.use_ssl = True
        self.username = config.get('username') if config else None
        self.password = config.get('password') if config else None
        self.databases = []
        self.findings = []
        
        # Default module configuration
        self.enabled_modules = {
            'authentication': True,
            'authorization': True,
            'network_security': True,
            'encryption': True,
            'audit_logging': True,
            'configuration': True,
            'access_control': True,
            'high_availability': True,
            'backup': True,
            'monitoring': True
        }
        
        # Update enabled modules from config if provided
        if config and 'enabled_modules' in config:
            self.enabled_modules.update(config['enabled_modules'])

    def connect(self) -> None:
        """Establish connection to MongoDB server."""
        try:
            # Parse target
            if ':' in self.target:
                host, port = self.target.split(':')
                self.port = int(port)
            else:
                host = self.target
            
            # Connection options
            options = {
                'serverSelectionTimeoutMS': 5000,
                'connectTimeoutMS': 5000,
                'server_api': ServerApi('1'),
                'ssl': self.use_ssl,
                'ssl_cert_reqs': ssl.CERT_REQUIRED
            }
            
            if self.username and self.password:
                options['username'] = self.username
                options['password'] = self.password
            
            self.client = MongoClient(f"mongodb://{host}:{self.port}/", **options)
            self.client.admin.command('ping')  # Test connection
            
        except errors.ConnectionFailure as e:
            self.add_finding(
                severity='Critical',
                description='MongoDB Connection Failed',
                details=f'Could not connect to MongoDB server: {str(e)}',
                recommendation='Verify server availability and network connectivity',
                category='Connectivity'
            )
            raise
            
    def run_all_checks(self) -> None:
        """Run all MongoDB security checks based on enabled modules."""
        try:
            self.connect()
            
            # Authentication and Authorization checks
            if self.enabled_modules['authentication']:
                self.check_authentication_enabled()
                self.check_default_credentials()
                self.check_password_policy()
            
            if self.enabled_modules['authorization']:
                self.check_authorization_enabled()
                self.check_role_based_access()
                self.check_superuser_accounts()
                self.check_user_permissions()
                self.check_database_permissions()
            
            # Network Security checks
            if self.enabled_modules['network_security']:
                self.check_network_binding()
                self.check_ssl_tls_config()
                self.check_firewall_rules()
                self.check_http_interface()
            
            # Encryption and Data Security checks
            if self.enabled_modules['encryption']:
                self.check_encryption_at_rest()
                self.check_encryption_in_transit()
                self.check_key_management()
                self.check_sensitive_data()
            
            # Audit Logging and Monitoring checks
            if self.enabled_modules['audit_logging']:
                self.check_audit_logging()
                self.check_log_rotation()
            
            if self.enabled_modules['monitoring']:
                self.check_monitoring_configuration()
            
            # Configuration Security checks
            if self.enabled_modules['configuration']:
                self.check_version()
                self.check_security_options()
                self.check_javascript_enabled()
                self.check_index_security()
            
            # High Availability Security checks
            if self.enabled_modules['high_availability']:
                self.check_replication_security()
                self.check_sharding_security()
            
            # Backup and Recovery checks
            if self.enabled_modules['backup']:
                self.check_backup_configuration()
            
        except Exception as e:
            self.add_finding(
                severity='Critical',
                description='Error Running Security Checks',
                details=f'An error occurred while running security checks: {str(e)}',
                recommendation='Review MongoDB configuration and permissions',
                category='Audit Process'
            )
        finally:
            if self.client:
                self.client.close()

    def get_enabled_modules(self) -> Dict[str, bool]:
        """Get the status of all security check modules."""
        return self.enabled_modules

    def enable_module(self, module_name: str) -> None:
        """Enable a specific security check module."""
        if module_name in self.enabled_modules:
            self.enabled_modules[module_name] = True

    def disable_module(self, module_name: str) -> None:
        """Disable a specific security check module."""
        if module_name in self.enabled_modules:
            self.enabled_modules[module_name] = False

    def enable_all_modules(self) -> None:
        """Enable all security check modules."""
        for module in self.enabled_modules:
            self.enabled_modules[module] = True

    def disable_all_modules(self) -> None:
        """Disable all security check modules."""
        for module in self.enabled_modules:
            self.enabled_modules[module] = False

    def add_finding(self, severity: str, description: str, details: str, recommendation: str, category: str, reference: str = None) -> None:
        """Add a security finding to the report."""
        finding = {
            'severity': severity,
            'description': description,
            'details': details,
            'recommendation': recommendation,
            'category': category
        }
        if reference:
            finding['reference'] = reference
        self.findings.append(finding)

    def handle_operation_failure(self, operation: str, error: Any) -> None:
        """Handle operation failures."""
        self.add_finding(
            severity='Error',
            description=f'Operation Failed: {operation}',
            details=f'Error during {operation}: {str(error)}',
            recommendation='Check permissions and MongoDB configuration',
            category='Operation'
        )

    def generate_report(self) -> Dict[str, Any]:
        """Generate a security audit report."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.target,
            'findings': self.findings,
            'summary': {
                'total': len(self.findings),
                'by_severity': {},
                'by_category': {}
            }
        }
        
        # Calculate statistics
        for finding in self.findings:
            severity = finding['severity']
            category = finding['category']
            report['summary']['by_severity'][severity] = report['summary']['by_severity'].get(severity, 0) + 1
            report['summary']['by_category'][category] = report['summary']['by_category'].get(category, 0) + 1
        
        return report

    def check_certificate_expiration(self, cert_path: str) -> None:
        """Check certificate expiration."""
        try:
            # TODO: Implement certificate expiration check logic
            # This is a placeholder for future implementation
            pass
        except Exception as e:
            self.handle_operation_failure('check_certificate_expiration', str(e))

    def check_authentication_enabled(self) -> None:
        """Check if authentication is enabled."""
        try:
            config = self.client.admin.command('getCmdLineOpts')
            if not config.get('security', {}).get('authorization'):
                self.add_finding(
                    severity='Critical',
                    description='Authentication Not Enabled',
                    details='MongoDB is running without authentication enabled',
                    recommendation='Enable authentication in configuration',
                    category='Authentication',
                    reference='https://docs.mongodb.com/manual/core/authentication/'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_authentication', e)

    def check_authorization_enabled(self) -> None:
        """Check if authorization is enabled."""
        try:
            config = self.client.admin.command('getCmdLineOpts')
            if not config.get('security', {}).get('authorization') == 'enabled':
                self.add_finding(
                    severity='Critical',
                    description='Authorization Not Enabled',
                    details='MongoDB authorization is not enabled',
                    recommendation='Enable authorization in configuration file',
                    category='Authorization',
                    reference='https://docs.mongodb.com/manual/core/authorization/'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_authorization', e)

    def check_default_credentials(self) -> None:
        """Check for default admin credentials."""
        try:
            users = self.client.admin.command('usersInfo')
            for user in users.get('users', []):
                if user['user'] == 'admin':
                    self.add_finding(
                        severity='High',
                        description='Default Admin User Present',
                        details='The default admin user account is still present',
                        recommendation='Change default admin password and create custom admin users',
                        category='Authentication',
                        reference='https://docs.mongodb.com/manual/tutorial/create-users/'
                    )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_default_credentials', e)

    def check_ssl_tls_config(self) -> None:
        """Check SSL/TLS configuration."""
        try:
            config = self.client.admin.command('getCmdLineOpts')
            net_config = config.get('net', {}).get('ssl', {})
            if not net_config or not net_config.get('mode') == 'requireSSL':
                self.add_finding(
                    severity='High',
                    description='SSL/TLS Not Required',
                    details='SSL/TLS is not required for all connections',
                    recommendation='Enable SSL/TLS and require it for all connections',
                    category='Encryption',
                    reference='https://docs.mongodb.com/manual/tutorial/configure-ssl/'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_ssl_tls_config', e)

    def check_encryption_at_rest(self) -> None:
        """Check encryption at rest configuration."""
        try:
            config = self.client.admin.command('getCmdLineOpts')
            security = config.get('parsed', {}).get('security', {})
            
            if not security.get('enableEncryption'):
                self.add_finding(
                    severity='High',
                    description='Encryption at Rest Not Enabled',
                    details='Database is not configured with encryption at rest',
                    recommendation='Enable encryption at rest using WiredTiger storage engine',
                    reference='https://docs.mongodb.com/manual/core/security-encryption-at-rest/',
                    category='Encryption'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_encryption_at_rest', e)
                
    def check_audit_logging(self) -> None:
        """Check audit logging configuration."""
        try:
            config = self.client.admin.command('getCmdLineOpts')
            audit_config = config.get('auditLog', {})
            if not audit_config or not audit_config.get('destination'):
                self.add_finding(
                    severity='Medium',
                    description='Audit Logging Not Configured',
                    details='Audit logging is not enabled',
                    recommendation='Enable audit logging for security-relevant operations',
                    category='Audit',
                    reference='https://docs.mongodb.com/manual/tutorial/configure-audit-filters/'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_audit_logging', e)
                
    def check_version(self) -> None:
        """Check MongoDB version."""
        try:
            server_info = self.client.server_info()
            version = server_info.get('version', '')
            if version:
                version_parts = [int(x) for x in version.split('.')]
                if version_parts[0] < 4:
                    self.add_finding(
                        severity='High',
                        description='Outdated MongoDB Version',
                        details=f'Running MongoDB version {version}',
                        recommendation='Upgrade to the latest stable version of MongoDB',
                        category='Version',
                        reference='https://docs.mongodb.com/manual/release-notes/'
                    )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_version', e)
                
    def check_network_binding(self) -> None:
        """Check network interface binding configuration."""
        try:
            config = self.client.admin.command('getCmdLineOpts')
            net_config = config.get('net', {})
            if not net_config.get('bindIp') or net_config.get('bindIp') == '0.0.0.0':
                self.add_finding(
                    severity='Critical',
                    description='Insecure Network Binding',
                    details='MongoDB is bound to all network interfaces',
                    recommendation='Bind MongoDB to specific IP addresses',
                    category='Network Security',
                    reference='https://docs.mongodb.com/manual/core/security-mongodb-configuration/'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_network_binding', e)
                
    def check_role_based_access(self) -> None:
        """Check role-based access control implementation."""
        try:
            roles = self.client.admin.command('rolesInfo')
            custom_roles = roles.get('roles', [])
            if not custom_roles:
                self.add_finding(
                    severity='Medium',
                    description='No Custom Roles Defined',
                    details='No custom roles found in the database',
                    recommendation='Implement role-based access control with custom roles',
                    category='Authorization',
                    reference='https://docs.mongodb.com/manual/core/security-built-in-roles/'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_role_based_access', e)

    def check_password_policy(self) -> None:
        """Check password policy configuration."""
        try:
            config = self.client.admin.command('getParameter', '*')
            if not config.get('passwordPolicy'):
                self.add_finding(
                    severity='Medium',
                    description='No Password Policy',
                    details='Password policy is not configured',
                    recommendation='Configure password policy with minimum length and complexity requirements',
                    category='Authentication',
                    reference='https://docs.mongodb.com/manual/reference/parameters/#mongodb-parameter-param.passwordPolicy'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_password_policy', e)

    def check_sensitive_data(self) -> None:
        """Check sensitive data handling."""
        try:
            for db in self.client.list_database_names():
                if db not in ['admin', 'local', 'config']:
                    collections = self.client[db].list_collection_names()
                    for collection in collections:
                        # Check for common sensitive data patterns
                        sample = self.client[db][collection].find_one()
                        if sample:
                            for key in sample.keys():
                                if any(pattern in key.lower() for pattern in ['password', 'secret', 'key', 'token', 'credit']):
                                    self.add_finding(
                                        severity='High',
                                        description=f'Potential Sensitive Data in {db}.{collection}',
                                        details=f'Collection contains fields that may store sensitive data: {key}',
                                        recommendation='Encrypt sensitive data or use field level encryption',
                                        category='Data Security',
                                        reference='https://docs.mongodb.com/manual/core/security-client-side-encryption/'
                                    )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_sensitive_data', e)

    def check_backup_configuration(self) -> None:
        """Check backup configuration and security."""
        try:
            roles = self.client.admin.command('rolesInfo')
            backup_role_exists = any(role.get('role') == 'backup' for role in roles.get('roles', []))
            if not backup_role_exists:
                self.add_finding(
                    severity='Medium',
                    description='No Backup Role Configured',
                    details='No dedicated backup role found',
                    recommendation='Create a dedicated backup role with minimum required privileges',
                    category='Backup',
                    reference='https://docs.mongodb.com/manual/core/backup-and-recovery/'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_backup_configuration', e)

    def check_replication_security(self) -> None:
        """Check replication security configuration."""
        try:
            is_replica = self.client.admin.command('isMaster').get('ismaster', False)
            if is_replica:
                config = self.client.admin.command('replSetGetConfig')
                if not config.get('settings', {}).get('chainingAllowed', True):
                    self.add_finding(
                        severity='Medium',
                        description='Replication Chaining Allowed',
                        details='Replication chaining is enabled which may impact security',
                        recommendation='Disable replication chaining unless required',
                        category='Replication',
                        reference='https://docs.mongodb.com/manual/tutorial/enforce-keyfile-access-control-in-existing-replica-set/'
                    )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_replication_security', e)

    def check_sharding_security(self) -> None:
        """Check sharding security configuration."""
        try:
            is_sharded = False
            try:
                self.client.admin.command('listShards')
                is_sharded = True
            except errors.OperationFailure:
                pass
            
            if is_sharded:
                # Check chunk size
                config = self.client.config.settings.find_one({'_id': 'chunksize'})
                if config and config.get('value', 64) > 128:
                    self.add_finding(
                        severity='Medium',
                        description='Large Chunk Size',
                        details='Chunk size may cause migration issues',
                        recommendation='Consider reducing chunk size to improve stability',
                        category='Sharding'
                    )
                
                # Check balancer configuration
                balancer_config = self.client.config.settings.find_one({'_id': 'balancer'})
                if not balancer_config or not balancer_config.get('stopped', False):
                    self.add_finding(
                        severity='Low',
                        description='Balancer Always Active',
                        details='Balancer runs during all hours',
                        recommendation='Configure balancer window for off-peak hours',
                        category='Sharding'
                    )
                
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_sharding_security', e)

    def check_monitoring_configuration(self) -> None:
        """Check monitoring and alerting configuration."""
        try:
            profiling_enabled = False
            for db_name in self.client.list_database_names():
                db = self.client[db_name]
                profile_level = db.command('profile', -1)
                if profile_level.get('was', 0) > 0:
                    profiling_enabled = True
                    break
            
            if not profiling_enabled:
                self.add_finding(
                    severity='Low',
                    description='Profiling Disabled',
                    details='Database profiling is not enabled on any database',
                    recommendation='Enable profiling for security monitoring',
                    category='Monitoring'
                )
                
            # Check slow query logging
            config = self.client.admin.command('getCmdLineOpts')
            if not config.get('parsed', {}).get('operationProfiling', {}).get('slowOpThresholdMs'):
                self.add_finding(
                    severity='Low',
                    description='Slow Query Logging Disabled',
                    details='Slow query logging is not configured',
                    recommendation='Enable slow query logging for performance monitoring',
                    category='Monitoring'
                )
                
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_monitoring_configuration', e)

    def check_javascript_enabled(self) -> None:
        """Check if server-side JavaScript is enabled."""
        try:
            config = self.client.admin.command('getCmdLineOpts')
            if not config.get('security', {}).get('javascriptEnabled') is False:
                self.add_finding(
                    severity='Medium',
                    description='Server-Side JavaScript Enabled',
                    details='Server-side JavaScript execution is enabled',
                    recommendation='Disable server-side JavaScript unless required',
                    category='Configuration',
                    reference='https://docs.mongodb.com/manual/core/server-side-javascript/'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_javascript_enabled', e)

    def check_index_security(self) -> None:
        """Check index configuration security."""
        try:
            for db_name in self.client.list_database_names():
                if db_name not in ['admin', 'config', 'local']:
                    db = self.client[db_name]
                    for collection in db.list_collection_names():
                        indexes = list(db[collection].list_indexes())
                        if not any(idx.get('background', False) for idx in indexes):
                            self.add_finding(
                                severity='Low',
                                description=f'Non-Background Indexes in {db_name}.{collection}',
                                details='Indexes not created with background option',
                                recommendation='Create indexes in background to avoid blocking operations',
                                category='Performance'
                            )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_index_security', e)

    def check_http_interface(self) -> None:
        """Check if the HTTP interface is enabled."""
        try:
            config = self.client.admin.command('getCmdLineOpts')
            if not config.get('parsed', {}).get('net', {}).get('http', {}).get('enabled', False):
                self.add_finding(
                    severity='Info',
                    description='HTTP Interface Disabled',
                    details='MongoDB HTTP interface is not enabled',
                    recommendation='Enable HTTP interface for administrative access',
                    category='Configuration'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_http_interface', e)

    def check_key_management(self) -> None:
        """Check encryption key management."""
        try:
            config = self.client.admin.command('getCmdLineOpts')
            security = config.get('security', {}).get('keyFile')
            if not security:
                self.add_finding(
                    severity='High',
                    description='No Keyfile Configuration',
                    details='No keyfile configured for internal authentication',
                    recommendation='Configure a keyfile for internal authentication in replica sets',
                    category='Encryption',
                    reference='https://docs.mongodb.com/manual/tutorial/enforce-keyfile-access-control-in-existing-replica-set/'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_key_management', e)

    def check_security_options(self) -> None:
        """Check security options configuration."""
        try:
            config = self.client.admin.command('getCmdLineOpts')
            security = config.get('parsed', {}).get('security', {})
            
            if not security.get('enableEncryption'):
                self.add_finding(
                    severity='High',
                    description='Encryption Not Enabled',
                    details='Encryption is not enabled',
                    recommendation='Enable encryption for security',
                    reference='https://docs.mongodb.com/manual/core/security-encryption/',
                    category='Encryption'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_security_options', e)

    def check_superuser_accounts(self) -> None:
        """Check for superuser accounts."""
        try:
            users = self.client.admin.command('usersInfo')
            for user in users.get('users', []):
                roles = user.get('roles', [])
                if any(role.get('role') == 'root' for role in roles):
                    self.add_finding(
                        severity='High',
                        description=f'Superuser Account: {user["user"]}',
                        details='User has root role privileges',
                        recommendation='Limit use of root role and implement principle of least privilege',
                        category='Authorization',
                        reference='https://docs.mongodb.com/manual/core/security-built-in-roles/#superuser-roles'
                    )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_superuser_accounts', e)

    def check_user_permissions(self) -> None:
        """Check user permissions."""
        try:
            users = list(self.client.admin.system.users.find())
            for user in users:
                if user['user'] not in ['admin', 'root', 'mongodb']:
                    self.check_user_privileges(user)
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_user_permissions', e)

    def check_database_permissions(self) -> None:
        """Check database permissions."""
        try:
            databases = self.client.list_database_names()
            for db_name in databases:
                if db_name not in ['admin', 'config', 'local']:
                    self.check_database_privileges(db_name)
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_database_permissions', e)

    def check_user_privileges(self, user: Dict[str, Any]) -> None:
        """Check if user privileges follow the principle of least privilege."""
        privileges = user.get('roles', [])
        for privilege in privileges:
            resource = privilege.get('resource', {})
            actions = privilege.get('actions', [])
            
            # Check for overly permissive privileges
            if resource.get('db') == '*' and resource.get('collection') == '*':
                if 'anyAction' in actions or len(actions) > 10:
                    self.add_finding(
                        severity='High',
                        description=f"Overly Permissive User: {user['user']}",
                        details='User has excessive privileges across all databases',
                        recommendation='Implement more granular access control',
                        category='Authorization'
                    )

    def check_database_privileges(self, db_name: str) -> None:
        """Check database privileges."""
        try:
            db = self.client[db_name]
            collections = db.list_collection_names()
            for collection in collections:
                self.check_collection_privileges(db_name, collection)
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_database_privileges', e)

    def check_collection_privileges(self, db_name: str, collection: str) -> None:
        """Check collection privileges."""
        try:
            db = self.client[db_name]
            privileges = db[collection].find_one()
            if privileges:
                self.check_privileges(db_name, collection, privileges)
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_collection_privileges', e)

    def check_privileges(self, db_name: str, collection: str, privileges: Dict[str, Any]) -> None:
        """Check if privileges follow the principle of least privilege."""
        for privilege in privileges:
            resource = privilege.get('resource', {})
            actions = privilege.get('actions', [])
            
            # Check for overly permissive privileges
            if resource.get('db') == '*' and resource.get('collection') == '*':
                if 'anyAction' in actions or len(actions) > 10:
                    self.add_finding(
                        severity='High',
                        description=f"Overly Permissive Privilege: {db_name}.{collection}",
                        details='Privilege has excessive privileges across all collections',
                        recommendation='Implement more granular access control',
                        category='Authorization'
                    )

    def check_firewall_rules(self) -> None:
        """Check firewall configuration."""
        try:
            # This is a basic check - in practice, you'd need to integrate with the system's firewall
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            for port in range(27017, 27020):
                if s.connect_ex((self.target, port)) == 0:
                    self.add_finding(
                        severity='Medium',
                        description=f'Open MongoDB Port: {port}',
                        details=f'MongoDB port {port} is accessible',
                        recommendation='Restrict access to MongoDB ports using firewall rules',
                        category='Network Security',
                        reference='https://docs.mongodb.com/manual/security/#network-security'
                    )
        except Exception as e:
            self.handle_operation_failure('check_firewall_rules', e)
        finally:
            s.close()

    def check_log_rotation(self) -> None:
        """Check log rotation configuration."""
        try:
            config = self.client.admin.command('getCmdLineOpts')
            audit = config.get('parsed', {}).get('auditLog', {})
            
            if not audit.get('destination'):
                self.add_finding(
                    severity='Medium',
                    description='Audit Logging Not Configured',
                    details='Audit logging is not enabled',
                    recommendation='Enable audit logging for security events',
                    reference='https://docs.mongodb.com/manual/tutorial/configure-audit-filters/',
                    category='Auditing'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_log_rotation', e)

    def check_encryption_in_transit(self) -> None:
        """Check encryption in transit configuration."""
        try:
            config = self.client.admin.command('getCmdLineOpts')
            net_config = config.get('net', {}).get('ssl', {})
            if not net_config or not net_config.get('mode') == 'requireSSL':
                self.add_finding(
                    severity='High',
                    description='Encryption in Transit Not Required',
                    details='SSL/TLS encryption is not required for data in transit',
                    recommendation='Enable and require SSL/TLS for all connections',
                    category='Encryption',
                    reference='https://docs.mongodb.com/manual/core/security-encryption-at-rest/'
                )
        except errors.OperationFailure as e:
            self.handle_operation_failure('check_encryption_in_transit', e)
