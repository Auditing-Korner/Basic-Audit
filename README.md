# Basic-Audit

[![CI](https://github.com/yourusername/Basic-Audit/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/Basic-Audit/actions/workflows/ci.yml)
[![Documentation Status](https://github.com/yourusername/Basic-Audit/workflows/Documentation/badge.svg)](https://yourusername.github.io/Basic-Audit/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![Code Style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Security: bandit](https://img.shields.io/badge/security-bandit-yellow.svg)](https://github.com/PyCQA/bandit)
[![codecov](https://codecov.io/gh/yourusername/Basic-Audit/branch/main/graph/badge.svg)](https://codecov.io/gh/yourusername/Basic-Audit)

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
  - Advanced DNS security checks:
    - NSEC3 implementation
    - DNS rebinding protection
    - DNS amplification vulnerability
    - DANE/TLSA records
    - DNS tunneling detection

- **SSL/TLS Security Module**
  - Protocol version verification
  - Cipher suite security analysis
  - Certificate validation
  - Perfect Forward Secrecy checks
  - HSTS implementation testing

- **Advanced Reporting**
  - Interactive HTML reports with charts
  - Risk score calculation
  - Timeline visualization
  - Executive summary generation
  - JSON export for data analysis

## 📋 Requirements

- Python 3.11 or higher
- Dependencies listed in `requirements.txt`

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
from audit_tool.reports.html_generator import HTMLReportGenerator

# DNS Security Assessment
dns_auditor = DNSSecurityAuditor("example.com")
dns_findings = dns_auditor.run_all_checks()

# SSL/TLS Security Assessment
ssl_auditor = SSLAuditor("example.com")
ssl_findings = ssl_auditor.audit()

# Generate HTML Report
generator = HTMLReportGenerator()
report_path = generator.generate_report(ssl_findings, "example.com")
print(f"Report generated at: {report_path}")
```

## 📖 Documentation

Visit our [comprehensive documentation](https://yourusername.github.io/Basic-Audit/) for detailed information about:

- [Installation Guide](https://yourusername.github.io/Basic-Audit/getting-started/installation/)
- [Quick Start Tutorial](https://yourusername.github.io/Basic-Audit/getting-started/quickstart/)
- [API Reference](https://yourusername.github.io/Basic-Audit/development/api-reference/)
- [Contributing Guidelines](https://yourusername.github.io/Basic-Audit/development/contributing/)

## 🧪 Testing

```bash
# Install test dependencies
pip install -r requirements-dev.txt

# Run tests with coverage
pytest --cov=src/ tests/

# Run linting
black .
isort .
ruff check .
mypy src/
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📊 Standards Implementation Matrix

| Standard | Section | Implementation | Module |
|----------|---------|----------------|--------|
| ISO 27002:2022 | 8.4 | Network Security | DNS Security |
| NIST SP 800-53 | SC-20 | DNSSEC | DNS Security |
| NIST SP 800-52 | 3.1 | TLS Protocol | SSL Security |
| NIST SP 800-81-2 | 6 | DNS Security | DNS Security |

## 🔐 Security

For security issues, please see our [Security Policy](SECURITY.md) and report any vulnerabilities responsibly.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ✨ Acknowledgments

- NIST Special Publications
- ISO 27002:2022 Guidelines
- Open Source Security Community