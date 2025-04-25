"""Tests for MongoDB Security Auditor."""

import pytest
from unittest.mock import Mock, patch
from pymongo import errors
from audit_tool.modules.mongodb_security import MongoDBSecurityAuditor

@pytest.fixture
def mock_client():
    """Create a mock MongoDB client."""
    client = Mock()
    client.admin.command.return_value = {
        'parsed': {
            'security': {'authorization': 'enabled'},
            'net': {'ssl': {'mode': 'requireSSL'}},
            'auditLog': {'destination': 'file'}
        }
    }
    client.server_info.return_value = {'version': '6.0.0'}
    return client

@pytest.fixture
def auditor():
    """Create a MongoDB security auditor instance."""
    return MongoDBSecurityAuditor('localhost', {'username': 'test', 'password': 'test'})

def test_initialization(auditor):
    """Test auditor initialization."""
    assert auditor.target == 'localhost'
    assert auditor.port == 27017
    assert auditor.use_ssl is True
    assert auditor.username == 'test'
    assert auditor.password == 'test'

@patch('audit_tool.modules.mongodb_security.mongodb_security_auditor.MongoClient')
def test_connection_success(mock_mongo_client, auditor, mock_client):
    """Test successful MongoDB connection."""
    mock_mongo_client.return_value = mock_client
    auditor.connect()
    assert auditor.client is not None

@patch('audit_tool.modules.mongodb_security.mongodb_security_auditor.MongoClient')
def test_connection_failure(mock_mongo_client, auditor):
    """Test MongoDB connection failure."""
    mock_mongo_client.side_effect = errors.ConnectionFailure('Connection failed')
    with pytest.raises(errors.ConnectionFailure):
        auditor.connect()
    assert len(auditor.findings) == 1
    assert auditor.findings[0]['severity'] == 'Critical'

def test_check_authentication_enabled(auditor, mock_client):
    """Test authentication check."""
    auditor.client = mock_client
    auditor.check_authentication_enabled()
    assert len(auditor.findings) == 0

    # Test disabled authentication
    mock_client.admin.command.return_value = {
        'parsed': {'security': {'authorization': 'disabled'}}
    }
    auditor.check_authentication_enabled()
    assert len(auditor.findings) == 1
    assert auditor.findings[0]['severity'] == 'Critical'

def test_check_ssl_tls_config(auditor, mock_client):
    """Test SSL/TLS configuration check."""
    auditor.client = mock_client
    auditor.check_ssl_tls_config()
    assert len(auditor.findings) == 0

    # Test disabled SSL
    mock_client.admin.command.return_value = {
        'parsed': {'net': {'ssl': {'mode': 'disabled'}}}
    }
    auditor.check_ssl_tls_config()
    assert len(auditor.findings) == 1
    assert auditor.findings[0]['severity'] == 'High'

def test_check_version(auditor, mock_client):
    """Test version check."""
    auditor.client = mock_client
    auditor.check_version()
    assert len(auditor.findings) == 0

    # Test outdated version
    mock_client.server_info.return_value = {'version': '4.0.0'}
    auditor.check_version()
    assert len(auditor.findings) == 1
    assert auditor.findings[0]['severity'] == 'High'

def test_check_network_binding(auditor, mock_client):
    """Test network binding check."""
    auditor.client = mock_client
    
    # Test secure binding
    mock_client.admin.command.return_value = {
        'parsed': {'net': {'bindIp': '127.0.0.1'}}
    }
    auditor.check_network_binding()
    assert len(auditor.findings) == 0

    # Test insecure binding
    mock_client.admin.command.return_value = {
        'parsed': {'net': {'bindIp': '0.0.0.0'}}
    }
    auditor.check_network_binding()
    assert len(auditor.findings) == 1
    assert auditor.findings[0]['severity'] == 'Critical'

def test_check_audit_logging(auditor, mock_client):
    """Test audit logging check."""
    auditor.client = mock_client
    auditor.check_audit_logging()
    assert len(auditor.findings) == 0

    # Test disabled audit logging
    mock_client.admin.command.return_value = {
        'parsed': {'auditLog': {}}
    }
    auditor.check_audit_logging()
    assert len(auditor.findings) == 1
    assert auditor.findings[0]['severity'] == 'Medium'

def test_generate_report(auditor):
    """Test report generation."""
    # Add some test findings
    auditor.add_finding(severity='Critical', description='Test Critical')
    auditor.add_finding(severity='High', description='Test High')
    auditor.add_finding(severity='Medium', description='Test Medium')
    
    report = auditor.generate_report()
    assert report['target'] == 'localhost'
    assert report['summary']['critical'] == 1
    assert report['summary']['high'] == 1
    assert report['summary']['medium'] == 1 