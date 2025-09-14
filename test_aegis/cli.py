"""
CLI Module for Aegis-Lite
======================================================

Main cli interface of project functionalities.
"""

import click
import time
import json
import csv
import subprocess
from typing import Dict, Any, List
import uuid

# Import the simplified modules
from aegis import database
from aegis.scanners import (
    run_subfinder, run_nmap, resolve_ip, calculate_score,
    check_https, check_web_vulnerabilities, show_system_resources,
    simple_rate_limit
)

def validate_scan_inputs(domain: str) -> tuple[bool, str]:
    """Simple input validation"""
    if not domain:
        return False, "Domain cannot be empty"

    if len(domain) > 253:
        return False, "Domain too long"

    # Basic format check
    if not domain.replace('.', '').replace('-', '').isalnum():
        return False, "Domain contains invalid characters"

    return True, "Valid"

def run_scan_logic(domain: str, ethical: bool, monitor: bool, max_subdomains: int = None) -> Dict[str, Any]:
    """
    Main scan logic - simplified version
    Processes one domain at a time
    """
    scan_id = str(uuid.uuid4())[:8]
    print(f"\n{'='*50}")
    print(f"Starting scan {scan_id} for {domain}")
    print(f"{'='*50}")

    # Validate input
    is_valid, error_msg = validate_scan_inputs(domain)
    if not is_valid:
        print(f"Error: {error_msg}")
        return {"success": False, "error": error_msg}

    # Initialize scan statistics
    scan_stats = {
        "domain": domain,
        "scan_id": scan_id,
        "start_time": time.time(),
        "subdomains_found": 0,
        "successful_scans": 0,
        "failed_scans": 0
    }

    try:
        # Show system resources if monitoring is enabled
        if monitor:
            print("\nSystem Resources:")
            show_system_resources()

        # Phase 1: Find subdomains
        print(f"\nPhase 1: Finding subdomains for {domain}...")
        if ethical:
            print("(Using ethical mode - slower but respectful)")

        subdomains = run_subfinder(domain, timeout=120)

        if max_subdomains and len(subdomains) > max_subdomains:
            subdomains = subdomains[:max_subdomains]

        scan_stats["subdomains_found"] = len(subdomains)

        # Always include the input domain itself
        domains_to_scan = [domain]
        domains_to_scan.extend(subdomains)

        if not domains_to_scan:
            print("No domains to scan.")
            return finalize_scan(scan_stats, True)

        print(f"Found {len(subdomains)} subdomains. Total {len(domains_to_scan)} domains to scan")

        # Phase 2: Process each domain
        print(f"\nPhase 2: Scanning each domain...")

        for i, current_domain in enumerate(domains_to_scan, 1):
            print(f"\nScanning {i}/{len(domains_to_scan)}: {current_domain}")

            try:
                # Ethical rate limiting
                if ethical and i > 1:
                    print("  Waiting 2 seconds (ethical mode)...")
                    simple_rate_limit()

                # Step 1: Resolve IP
                print("  Resolving IP address...")
                ip = resolve_ip(current_domain, timeout=10)
                if ip == "Unknown":
                    print("  Could not resolve IP address")
                    scan_stats["failed_scans"] += 1
                    continue

                print(f"  IP: {ip}")

                # Step 2: Scan ports
                print("  Scanning ports...")
                ports = run_nmap(ip, current_domain, ethical)

                # Step 3: Check HTTPS
                print("  Checking HTTPS...")
                https_result = check_https(current_domain)

                # Step 4: Basic web vulnerability check
                web_result = {"vulnerabilities": [], "has_admin_panel": False}
                if ports and ('80' in ports or '443' in ports):
                    print("  Checking for basic vulnerabilities...")
                    protocol = "https" if '443' in ports else "http"
                    web_result = check_web_vulnerabilities(f"{protocol}://{current_domain}")

                # Step 5: Calculate trust score
                score = calculate_score(ports)

                # Step 6: Save to database
                success = database.insert_asset(
                    current_domain,
                    ip=ip,
                    ports=ports,
                    score=score,
                    ssl_vulnerabilities=json.dumps(https_result),
                    web_vulnerabilities=json.dumps(web_result)
                )

                if success:
                    scan_stats["successful_scans"] += 1
                    print(f"  ✓ Completed: Score {score}, Ports: {ports or 'none'}")
                else:
                    scan_stats["failed_scans"] += 1
                    print(f"  ✗ Failed to save results")

            except Exception as e:
                scan_stats["failed_scans"] += 1
                print(f"  ✗ Error scanning {current_domain}: {e}")
                continue

        return finalize_scan(scan_stats, True)

    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        return finalize_scan(scan_stats, False)
    except Exception as e:
        print(f"Unexpected error during scan: {e}")
        return finalize_scan(scan_stats, False)

def finalize_scan(scan_stats: Dict[str, Any], success: bool) -> Dict[str, Any]:
    """Display scan summary and return results"""
    scan_stats["end_time"] = time.time()
    scan_stats["duration"] = scan_stats["end_time"] - scan_stats["start_time"]
    scan_stats["success"] = success

    # Display summary
    print(f"\n{'='*50}")
    print(f"Scan {scan_stats['scan_id']} Summary")
    print(f"{'='*50}")
    print(f"Domain: {scan_stats['domain']}")
    print(f"Duration: {scan_stats['duration']:.1f} seconds")
    print(f"Subdomains found: {scan_stats['subdomains_found']}")
    print(f"Successful scans: {scan_stats['successful_scans']}")
    print(f"Failed scans: {scan_stats['failed_scans']}")

    if success and scan_stats["successful_scans"] > 0:
        print("✓ Scan completed successfully!")
    elif success:
        print("✓ Scan completed (no reachable assets found)")
    else:
        print("✗ Scan completed with errors")

    print(f"{'='*50}")
    return scan_stats

# Initialize database when CLI starts
try:
    database.init_db()
    print("Database initialized successfully")
except Exception as e:
    print(f"Database initialization failed: {e}")
    exit(1)

@click.group()
def cli():
    """Aegis-Lite: Ethical Security Scanner for Small-Medium Enterprises"""
    pass

@cli.command()
@click.argument("domain")
@click.option("--ethical", is_flag=True, default=True, help="Use ethical scanning mode")
@click.option("--monitor", is_flag=True, help="Show system resource usage")
@click.option("--max-subdomains", type=int, default=None, help="Limit number of subdomains to scan")
def scan(domain, ethical, monitor, max_subdomains):
    """Scan a domain for subdomains and security issues"""
    result = run_scan_logic(domain, ethical, monitor, max_subdomains)

    if not result.get("success", False):
        exit(1)

@cli.command()
@click.option("--format", "output_format",
              type=click.Choice(["table", "json", "csv"]),
              default="table",
              help="Output format")
@click.option("--limit", type=int, help="Limit number of results")
def view(output_format, limit):
    """View all scanned assets in the database"""
    try:
        assets = database.get_all_assets()
    except Exception as e:
        print(f"Database error: {e}")
        return

    if not assets:
        print("No assets found. Run a scan first!")
        return

    # Apply limit if specified
    if limit and limit > 0:
        assets = assets[:limit]
        print(f"Showing first {len(assets)} assets")

    if output_format == "json":
        print(json.dumps([dict(asset) for asset in assets], indent=2))
        return
    elif output_format == "csv":
        if assets:
            fieldnames = assets[0].keys()
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows([dict(asset) for asset in assets])
            print(output.getvalue())
        return

    # Default table format
    print("-" * 100)
    print(f"| {'ID':<4} | {'Domain':<30} | {'IP':<15} | {'Ports':<15} | {'Score':<6} | {'HTTPS':<8} |")
    print("-" * 100)

    for asset in assets:
        try:
            # Parse HTTPS status
            https_data = json.loads(asset.get('ssl_vulnerabilities', '{}'))
            https_status = "Yes" if https_data.get('has_https') else "No"

            # Truncate long values
            domain = asset['domain'][:30]
            ports = (asset.get('ports') or '')[:15]

            print(f"| {asset['id']:<4} | {domain:<30} | {asset.get('ip', 'Unknown'):<15} | "
                  f"{ports:<15} | {asset.get('score', 0):<6} | {https_status:<8} |")

        except Exception as e:
            print(f"Error displaying asset {asset.get('id')}: {e}")

    print("-" * 100)
    print(f"Total assets: {len(assets)}")

@cli.command()
def report():
    """Generate a simple security report"""
    try:
        assets = database.get_all_assets()
        stats = database.get_db_stats()
    except Exception as e:
        print(f"Database error: {e}")
        return

    if not assets:
        print("No assets found. Run a scan first!")
        return

    print("=" * 50)
    print("AEGIS-LITE SECURITY REPORT")
    print("=" * 50)
    print(f"Report generated: {time.ctime()}")
    print(f"Total assets: {stats['total_assets']}")
    print(f"Average risk score: {stats['avg_score']:.1f}/100")
    print()

    # Risk breakdown
    print("RISK DISTRIBUTION:")
    print(f"  High risk (>50):    {stats['high_risk_assets']} assets")
    print(f"  Medium risk (20-50): {stats['medium_risk_assets']} assets")
    print(f"  Low risk (≤20):      {stats['low_risk_assets']} assets")
    print()

    # Key findings
    print("KEY FINDINGS:")
    https_count = 0
    vuln_count = 0

    for asset in assets:
        try:
            https_data = json.loads(asset.get('ssl_vulnerabilities', '{}'))
            web_data = json.loads(asset.get('web_vulnerabilities', '{}'))

            if https_data.get('has_https'):
                https_count += 1

            vulns = web_data.get('vulnerabilities', [])
            vuln_count += len(vulns)

        except json.JSONDecodeError:
            continue

    print(f"  Assets with HTTPS: {https_count}/{len(assets)}")
    print(f"  Total vulnerabilities found: {vuln_count}")

    if stats['high_risk_assets'] > 0:
        print(f"  WARNING: {stats['high_risk_assets']} high-risk assets need attention")
    else:
        print("  ✓ No high-risk assets found")

    print("=" * 50)

@cli.command()
@click.argument("format", type=click.Choice(["json", "csv"]), default="json")
@click.option("--output", "-o", help="Output filename")
def export(format, output):
    """Export scan results to JSON or CSV"""
    try:
        assets = database.get_all_assets()
    except Exception as e:
        print(f"Database error: {e}")
        return

    if not assets:
        print("No assets found to export")
        return

    # Generate filename if not provided
    if output:
        filename = output
        if not filename.endswith(f".{format}"):
            filename += f".{format}"
    else:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"aegis_export_{timestamp}.{format}"

    try:
        if format == "json":
            with open(filename, "w") as f:
                json.dump([dict(asset) for asset in assets], f, indent=2)
        elif format == "csv":
            with open(filename, "w", newline='') as f:
                if assets:
                    fieldnames = assets[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows([dict(asset) for asset in assets])

        print(f"Successfully exported {len(assets)} assets to {filename}")

    except Exception as e:
        print(f"Export failed: {e}")

@cli.command()
@click.confirmation_option(prompt="Are you sure you want to clear all data?")
def clear():
    """Clear all scan data from database"""
    try:
        database.clear_db()
        print("Database cleared successfully")
    except Exception as e:
        print(f"Failed to clear database: {e}")

@cli.command()
def interactive():
    """Start interactive mode for easier use"""
    print("Welcome to Aegis-Lite Interactive Mode!")
    print("This mode makes it easy to use all features.")
    print()

    while True:
        try:
            print("--- Main Menu ---")
            print("1. Scan a domain")
            print("2. View results")
            print("3. Generate report")
            print("4. Export data")
            print("5. Clear database")
            print("6. Exit")

            choice = input("\nEnter your choice (1-6): ").strip()

            if choice == "1":
                domain = input("Enter domain to scan (e.g., example.com): ").strip()
                if domain:
                    ethical = input("Use ethical mode? (Y/n): ").strip().lower() != 'n'
                    monitor = input("Monitor resources? (y/N): ").strip().lower() == 'y'

                    result = run_scan_logic(domain, ethical, monitor)
                    if not result.get("success", False):
                        print("Scan failed. Check output above.")
                else:
                    print("Please enter a domain name.")

            elif choice == "2":
                format_choice = input("Display format (table/json/csv) [table]: ").strip() or "table"
                if format_choice in ["table", "json", "csv"]:
                    # Use subprocess to call view command
                    subprocess.run(["python", "-m", "aegis.cli", "view", "--format", format_choice])
                else:
                    print("Invalid format. Using table.")
                    subprocess.run(["python", "-m", "aegis.cli", "view"])

            elif choice == "3":
                subprocess.run(["python", "-m", "aegis.cli", "report"])

            elif choice == "4":
                format_choice = input("Export format (json/csv) [json]: ").strip() or "json"
                filename = input("Filename (optional): ").strip()

                if filename:
                    subprocess.run(["python", "-m", "aegis.cli", "export", format_choice, "-o", filename])
                else:
                    subprocess.run(["python", "-m", "aegis.cli", "export", format_choice])

            elif choice == "5":
                confirm = input("Are you sure you want to clear all data? (yes/no): ").strip().lower()
                if confirm == "yes":
                    subprocess.run(["python", "-m", "aegis.cli", "clear", "--yes"])
                else:
                    print("Operation cancelled.")

            elif choice == "6":
                print("Thank you for using Aegis-Lite!")
                break

            else:
                print("Invalid choice. Please select 1-6.")

        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

        print()  # Add spacing

if __name__ == '__main__':
    cli()
