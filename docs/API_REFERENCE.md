# Aegis-Lite API Reference

## Core Modules

### CLI Module (`aegis/cli.py`)
- `scan(domain, ethical, monitor)` - Main scanning command
- `view()` - Display scan results  
- `report()` - Generate security reports
- `benchmark()` - Performance testing

### Database Module (`aegis/database.py`)
- `init_db()` - Initialize database
- `save_asset()` - Store scan results
- `get_all_assets()` - Retrieve all scans
- `get_db_stats()` - Analytics and metrics

### Scanners Module (`aegis/scanners.py`)
- `run_subfinder()` - Subdomain discovery
- `run_nmap()` - Port scanning
- `check_web_vulnerabilities()` - Security scanning
- `calculate_score()` - Risk assessment