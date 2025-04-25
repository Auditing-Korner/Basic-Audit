# Contributing to Basic-Audit

First off, thank you for considering contributing to Basic-Audit! It's people like you that make Basic-Audit such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report for Basic-Audit. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

**Before Submitting A Bug Report**

* Check the documentation for a list of common questions and problems.
* Ensure the bug was not already reported by searching on GitHub under [Issues](https://github.com/yourusername/Basic-Audit/issues).
* If you're unable to find an open issue addressing the problem, open a new one.

**How Do I Submit A (Good) Bug Report?**

Bugs are tracked as GitHub issues. Create an issue and provide the following information:

* Use a clear and descriptive title
* Describe the exact steps which reproduce the problem
* Provide specific examples to demonstrate the steps
* Describe the behavior you observed after following the steps
* Explain which behavior you expected to see instead and why
* Include screenshots and animated GIFs if possible

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion for Basic-Audit, including completely new features and minor improvements to existing functionality.

**Before Submitting An Enhancement Suggestion**

* Check if there's already a package which provides that enhancement.
* Determine which repository the enhancement should be suggested in.
* Perform a cursory search to see if the enhancement has already been suggested.

### Pull Requests

* Fill in the required template
* Do not include issue numbers in the PR title
* Include screenshots and animated GIFs in your pull request whenever possible
* Follow the Python styleguides
* Document new code based on the Documentation Styleguide
* End all files with a newline

## Styleguides

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

### Python Styleguide

* Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
* Use [Black](https://github.com/psf/black) for code formatting
* Use [isort](https://pycqa.github.io/isort/) for import sorting
* Use [mypy](http://mypy-lang.org/) for static type checking
* Use [ruff](https://github.com/charliermarsh/ruff) for linting

### Documentation Styleguide

* Use [Google style](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) for docstrings
* Use [Markdown](https://guides.github.com/features/mastering-markdown/) for documentation

## Development Process

Here's how we generally manage the development process:

1. Fork the repo
2. Create a new branch from `main`
3. Make your changes
4. Run the test suite
5. Push your changes to your fork
6. Submit a Pull Request

### Setting Up Development Environment

```bash
# Clone your fork
git clone git@github.com:your-username/Basic-Audit.git

# Add upstream remote
git remote add upstream https://github.com/original-username/Basic-Audit.git

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Setup pre-commit hooks
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_dns_security.py

# Run with coverage
pytest --cov=src/ tests/
```

## Additional Notes

### Issue and Pull Request Labels

This section lists the labels we use to help us track and manage issues and pull requests.

* `bug` - Issues that are bugs
* `enhancement` - Issues that are feature requests
* `documentation` - Issues or PRs that affect documentation
* `good first issue` - Good for newcomers
* `help wanted` - Extra attention is needed

## Recognition

Contributors who have made significant contributions will be recognized in our README.md file. 