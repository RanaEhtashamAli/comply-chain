# Contributing to ComplyChain

Thank you for your interest in contributing to ComplyChain! This document provides guidelines and information for contributors.

## Getting Started

1. **Fork the repository**: [https://github.com/RanaEhtashamAli/comply-chain](https://github.com/RanaEhtashamAli/comply-chain)
2. **Clone your fork**: `git clone https://github.com/YOUR_USERNAME/comply-chain.git`
3. **Create a feature branch**: `git checkout -b feature/your-feature-name`
4. **Make your changes** and commit them
5. **Push to your fork** and create a Pull Request

## Development Setup

```bash
# Install dependencies
pip install -r requirements.txt
pip install -e .

# Run tests
python -m pytest complychain/tests/ -v

# Run linting
black complychain/
ruff check complychain/
```

## Code Style

- **Python**: Follow PEP 8 guidelines
- **Type hints**: Use type hints for all functions and methods
- **Docstrings**: Use Google-style docstrings
- **Tests**: Write tests for new functionality
- **Security**: Follow security best practices for cryptographic code

## Testing

- Run the full test suite: `python -m pytest complychain/tests/ -v`
- Run specific test files: `python -m pytest complychain/tests/test_crypto.py -v`
- Run with coverage: `python -m pytest complychain/tests/ --cov=complychain`

## Pull Request Guidelines

1. **Title**: Use a clear, descriptive title
2. **Description**: Explain what the PR does and why
3. **Tests**: Ensure all tests pass
4. **Documentation**: Update documentation if needed
5. **Security**: For cryptographic changes, include security analysis

## Security Considerations

- **Cryptographic code**: Must be reviewed by security experts
- **Key management**: Follow NIST guidelines
- **Algorithm selection**: Use NIST-approved algorithms
- **Fallback mechanisms**: Ensure graceful degradation

## Contact

- **Issues**: [GitHub Issues](https://github.com/RanaEhtashamAli/comply-chain/issues)
- **Discussions**: [GitHub Discussions](https://github.com/RanaEhtashamAli/comply-chain/discussions)
- **Email**: ranaehtashamali1@gmail.com
- **Phone**: +923224712517

## License

By contributing to ComplyChain, you agree that your contributions will be licensed under the Apache License 2.0. 