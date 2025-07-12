from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="complychain",
    version="1.0.0",
    author="Rana Ehtasham Ali",
    author_email="ranaehtashamali1@gmail.com",
    description="Enterprise-grade GLBA compliance toolkit with quantum-safe cryptography",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/RanaEhtashamAli/comply-chain",
    project_urls={
        "Bug Tracker": "https://github.com/RanaEhtashamAli/comply-chain/issues",
        "Documentation": "https://github.com/RanaEhtashamAli/comply-chain/wiki",
        "Source Code": "https://github.com/RanaEhtashamAli/comply-chain",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Financial and Insurance Industry",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security :: Cryptography",
        "Topic :: Office/Business :: Financial",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Environment :: Console",
        "Framework :: Pytest",
        "Typing :: Typed",
    ],
    python_requires=">=3.9",
    install_requires=[
        "scikit-learn>=1.3.0",
        "reportlab>=4.0.0",
        "click>=8.0.0",
        "cryptography>=41.0.0",
        "joblib>=1.3.0",
        "numpy>=1.24.0",
        "requests>=2.31.0",
        "pyyaml>=6.0.0",
        "typer>=0.9.0",
        "rich>=13.0.0",
        "pqcrypto (>=0.3.4,<0.4.0)",
        "PyPDF2>=3.0.0",
    ],
    extras_require={
        "quantum": [
            # liboqs-python is not on PyPI, install manually or use Docker
            # "liboqs-python>=0.7.2",
        ],
        "pqcrypto": [
            "pqcrypto>=0.3.0",
        ],
        "legacy": [
            "pqcrypto>=0.3.0",
        ],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
            "black>=23.0.0",
            "ruff>=0.1.0",
            "mypy>=1.0.0",
            "coverage-badge>=1.1.0",
        ],
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
        ],
        "docs": [
            "sphinx>=6.0.0",
            "sphinx-rtd-theme>=1.2.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "complychain=complychain.cli_enhanced:app",
        ],
    },
    include_package_data=True,
    package_data={
        "complychain": ["py.typed"],
    },
    keywords=[
        "glba",
        "compliance",
        "cryptography",
        "quantum-safe",
        "audit",
        "fintech",
        "regtech",
        "dilithium3",
        "nist",
        "fips",
        "financial",
        "security",
    ],
) 