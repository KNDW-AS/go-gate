# Contributing to GO-GATE

Thank you for your interest in contributing to GO-GATE! This document provides guidelines for contributing.

## Code of Conduct

This project adheres to a code of conduct. By participating, you are expected to uphold this code.

## Contributor License Agreement (CLA)

Before we can accept your contributions, you must sign our [Contributor License Agreement](CLA.md). This ensures:

- You retain copyright to your contributions
- We can use and distribute your contributions
- The project remains open source under Apache 2.0

## How to Contribute

### Reporting Bugs

1. Check if the issue already exists
2. Create a new issue with:
   - Clear description
   - Steps to reproduce
   - Expected vs actual behavior
   - System information

### Suggesting Features

1. Open an issue with the "feature request" label
2. Describe the use case
3. Explain why it benefits GO-GATE

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`pytest`)
5. Run linting (`black . && flake8`)
6. Commit with clear messages
7. Push to your fork
8. Open a Pull Request

## Development Setup

```bash
git clone https://github.com/billyxp74/go-gate.git
cd go-gate
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

## Code Style

- **Black** for formatting
- **Flake8** for linting
- **Type hints** for all functions
- **Docstrings** for all public APIs

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=go_gate --cov-report=html

# Run specific test file
pytest tests/test_go_gate.py
```

## Security

If you discover a security vulnerability, please email security@go-gate.io instead of opening a public issue.

## Questions?

Join our discussions or open an issue!
