# Aegis-Lite: Ethical Attack Surface Scanner for SMEs

## Overview

Aegis-Lite is a free, automated cybersecurity tool designed for small-medium enterprises. It discovers hidden digital assets, scans for vulnerabilities, and generates actionable security reports through both command-line and web interfaces.

## Features

- **Asset Discovery**: Find subdomains and network services
- **Vulnerability Scanning**: Detect security issues using Nuclei templates
- **Risk Scoring**: 0-100 risk assessment algorithm
- **Dual Interface**: CLI for automation and Streamlit web dashboard
- **Ethical Scanning**: Built-in rate limiting and resource monitoring
- **Professional Reporting**: JSON, CSV, and PDF export capabilities
- **Docker Support**: Containerized deployment with all dependencies

## Installation

### Prerequisites
- Python 3.10+
- Git
- Docker (optional)

### Local Installation
```bash
git clone <repository-url>
cd Aegis-Project
python -m venv venv
source venv/bin/activate
pip install -e .
```

### Docker Installation
```bash
docker build -t aegis-lite .
docker run -p 8501:8501 aegis-lite
```

## Usage

### Command Line Interface
```bash
# Scan a domain
python -m aegis.cli scan example.com --ethical

# View results
python -m aegis.cli view --format table

# Generate report
python -m aegis.cli report

# Export data
python -m aegis.cli export --format json
```

### Web Interface
```bash
streamlit run aegis/ui.py
```
Then open http://localhost:8501 in your browser.

## Testing

The project includes comprehensive tests with 66% coverage on core business logic:

```bash
# Run all tests
python tests/runtests.py

# Run specific test categories
python -m pytest tests/test_core_functionality.py
python -m pytest tests/test_integration.py
python -m pytest tests/test_external_tools.py

# Generate coverage report
python -m pytest --cov=aegis --cov-report=html tests/
```

### Test Structure
- `test_core_functionality.py` - Unit tests for utilities, database, scanners
- `test_integration.py` - End-to-end workflow testing
- `test_external_tools.py` - External tool integration (Nuclei, threading)

## Project Structure

```
Aegis-Project/
├── aegis/                 # Core Python package
│   ├── cli.py            # Command-line interface
│   ├── database.py       # SQLite data layer
│   ├── scanners.py       # Security scanning engine
│   ├── ui.py             # Streamlit web interface
│   └── utils.py          # Shared utilities
├── tests/                # Comprehensive test suite
│   ├── test_core_functionality.py
│   ├── test_integration.py
│   └── test_external_tools.py
├── docs/                 # Documentation
├── Dockerfile           # Container configuration
└── requirements.txt     # Python dependencies
```

## Dependencies

Core dependencies include:
- Python 3.10+
- Click (CLI framework)
- Streamlit (web UI)
- SQLite (database)
- Requests (HTTP client)
- Pytest (testing framework)

External security tools:
- Subfinder (subdomain enumeration)
- Nmap (port scanning)
- Nuclei (vulnerability scanning)

## Documentation

- Full documentation: `/docs/`
- API reference: `/docs/API_REFERENCE.md`
- Project blueprint: `/docs/Aegis_Lite_Phase1_Blueprint.markdown`

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions, please check the documentation or create an issue in the project repository.