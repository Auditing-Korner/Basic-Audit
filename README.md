# Basic-Audit

[![Documentation Status](https://github.com/yourusername/Basic-Audit/workflows/Documentation/badge.svg)](https://yourusername.github.io/Basic-Audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![Code Style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A comprehensive security auditing tool implementing ISO 27002:2022 and NIST guidelines for DNS and SSL/TLS security assessments.

## 🚀 Features

- **Standards Compliance**
  - ISO 27002:2022 Network Security Controls
  - NIST SP 800-53 Rev. 5 Security Controls
  - NIST SP 800-81-2 DNS Guidelines
  - NIST SP 800-52 Rev. 2 TLS Guidelines

- **DNS Security Module**
  - DNSSEC implementation verification
  - Zone transfer security assessment
  - Cache poisoning protection checks
  - DNS redundancy analysis
  - Response rate limiting tests

- **SSL/TLS Security Module**
  - Protocol version verification
  - Cipher suite security analysis
  - Certificate validation
  - Perfect Forward Secrecy checks
  - HSTS implementation testing

## 📋 Requirements

- Python 3.11 or higher
- dnspython
- cryptography
- requests
- colorama

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/Basic-Audit.git
cd Basic-Audit

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## 🚦 Quick Start

```python
from audit_tool.modules.dns_security import DNSSecurityAuditor
from audit_tool.modules.ssl_security import SSLAuditor

# DNS Security Assessment
dns_auditor = DNSSecurityAuditor("example.com")
dns_findings = dns_auditor.run_all_checks()

# SSL/TLS Security Assessment
ssl_auditor = SSLAuditor("example.com")
ssl_findings = ssl_auditor.audit()
```

## 📖 Documentation

Comprehensive documentation is available at [https://yourusername.github.io/Basic-Audit/](https://yourusername.github.io/Basic-Audit/)

- [Installation Guide](https://yourusername.github.io/Basic-Audit/getting-started/installation/)
- [Quick Start Tutorial](https://yourusername.github.io/Basic-Audit/getting-started/quickstart/)
- [API Reference](https://yourusername.github.io/Basic-Audit/development/api-reference/)
- [Contributing Guidelines](https://yourusername.github.io/Basic-Audit/development/contributing/)

## 🔍 Example Output

```json
{
  "target": "example.com",
  "timestamp": "2024-02-20T10:00:00Z",
  "findings": [
    {
      "severity": "High",
      "category": "DNS Security",
      "description": "DNSSEC not implemented",
      "details": "No DNSKEY records found",
      "recommendation": "Implement DNSSEC to ensure DNS response authenticity",
      "reference": "NIST SP 800-53 Rev. 5 SC-20"
    }
  ]
}
```

## 🧪 Testing

```bash
# Run all tests
python -m pytest

# Run specific module tests
python -m pytest tests/test_dns_security.py
python -m pytest tests/test_ssl_security.py
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔐 Security

For security issues, please see our [Security Policy](SECURITY.md) and report any vulnerabilities responsibly.

## 📊 Standards Implementation Matrix

| Standard | Section | Implementation | Module |
|----------|---------|----------------|--------|
| ISO 27002:2022 | 8.4 | Network Security | DNS Security |
| NIST SP 800-53 | SC-20 | DNSSEC | DNS Security |
| NIST SP 800-52 | 3.1 | TLS Protocol | SSL Security |
| NIST SP 800-81-2 | 6 | DNS Security | DNS Security |

## ✨ Acknowledgments

- NIST Special Publications
- ISO 27002:2022 Guidelines
- Open Source Security Community

## 🔄 Committing to Main

For maintainers with direct access to the main branch:

```bash
# Ensure you're on the main branch
git checkout main

# Pull latest changes
git pull origin main

# Make your changes
# ... make your changes ...

# Add your changes
git add .

# Commit your changes
git commit -m "Description of your changes"

# Push to main
git push origin main
```

Note: Direct commits to main should be limited to minor fixes and updates. For significant changes, please follow the contributing guidelines and use feature branches.