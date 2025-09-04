"""
Enhanced CLI Module for Aegis-Lite - FIXED VERSION
=================================================

Fixed version with proper threading, error handling, and consistent
data processing between scanners and database.
"""

import click
import os
import psutil
import time
import json
import csv
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List, Optional
import uuid

# Import the database and scanner modules
from aegis import database
from aegis.scanners import run_subfinder, run_nmap, resolve_ip, calculate_score, check_ssl_vulnerabilities, check_web_vulnerabilities

# --- Global/Configured Paths ---
COMPLIANCE_LOG_NAME = "compliance.log"
RESOURCE_LOG_NAME = "resource.log"

# FIXED: Use instance-based monitoring instead of global flags
class ResourceMonitor:
    """Thread-safe resource monitoring class"""

    def __init__(self, log_filename: str = RESOURCE_LOG_NAME):
        self.log_filename = log_filename
        self.stop_flag = threading.Event()
        self.monitor_thread = None
        self._lock = threading.Lock()

    def start(self) -> bool:
        """Start resource monitoring thread"""
        with self._lock:
            if self.monitor_thread and self.monitor_thread.is_alive():
                return False  # Already running

            self.stop_flag.clear()
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
            return True

    def stop(self, timeout: int = 3) -> bool:
        """Stop resource monitoring gracefully"""
        with self._lock:
            if not self.monitor_thread or not self.monitor_thread.is_alive():
                return True

            self.stop_flag.set()
            self.monitor_thread.join(timeout=timeout)

            if self.monitor_thread.is_alive():
                click.echo(click.style("Warning: Resource monitor thread did not stop cleanly", fg="yellow"))
                return False

            return True

    def _monitor_loop(self):
        """Main monitoring loop"""
        try:
            # Initialize log file with headers
            with open(self.log_filename, "w") as f:
                f.write("timestamp,cpu_percent,ram_percent,disk_usage\n")

            while not self.stop_flag.is_set():
                try:
                    cpu = psutil.cpu_percent(interval=None)
                    ram = psutil.virtual_memory().percent
                    disk = psutil.disk_usage('/').percent if os.name != 'nt' else psutil.disk_usage('C:').percent

                    with open(self.log_filename, "a") as f:
                        f.write(f"{time.ctime()},{cpu:.1f},{ram:.1f},{disk:.1f}\n")

                    # Check for resource exhaustion
                    if ram > 85 or cpu > 90:
                        click.echo(click.style(f"WARNING: High resource usage - RAM: {ram:.1f}%, CPU: {cpu:.1f}%", fg="yellow"))

                except Exception as e:
                    click.echo(click.style(f"Resource monitoring error: {e}", fg="yellow"))
                    break

                # Check stop flag every second
                if self.stop_flag.wait(2.0):  # 2-second intervals
                    break

        except Exception as e:
            click.echo(click.style(f"Failed to start resource monitoring: {e}", fg="red"))

# Initialize the database when the CLI application starts
try:
    database.init_db()
    click.echo(click.style("Database initialized successfully", fg="green"))
except Exception as e:
    click.echo(click.style(f"Database initialization failed: {e}", fg="red"))
    exit(1)

@click.group()
def cli():
    """Aegis-Lite: Ethical Attack Surface Scanner for SMEs."""
    pass

def validate_scan_inputs(domain: str) -> tuple[bool, str]:
    """Validate scan inputs before processing"""
    if not domain:
        return False, "Domain cannot be empty"

    # Basic domain format validation
    import re
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$', domain):
        return False, "Invalid domain format"

    if len(domain) > 253:
        return False, "Domain too long"

    return True, "Valid"

def run_scan_logic(domain: str, ethical: bool, monitor: bool) -> Dict[str, Any]:
    """
    FIXED: Enhanced scan logic with proper error handling and return values
    """
    scan_id = str(uuid.uuid4())[:8]  # Unique scan identifier
    click.echo(click.style(f"Starting scan {scan_id} for {domain}", fg="blue", bold=True))

    # Validate inputs
    is_valid, error_msg = validate_scan_inputs(domain)
    if not is_valid:
        click.echo(click.style(f"Invalid input: {error_msg}", fg="red"))
        return {"success": False, "error": error_msg}

    # Initialize resource monitor if requested
    resource_monitor = None
    if monitor:
        resource_monitor = ResourceMonitor(f"scan_{scan_id}_{RESOURCE_LOG_NAME}")
        if resource_monitor.start():
            click.echo(click.style(f"Resource monitoring started for scan {scan_id}", fg="cyan"))
        else:
            click.echo(click.style("Failed to start resource monitoring", fg="yellow"))

    scan_stats = {
        "domain": domain,
        "scan_id": scan_id,
        "start_time": time.time(),
        "subdomains_found": 0,
        "subdomains_resolved": 0,
        "successful_scans": 0,
        "failed_scans": 0,
        "errors": []
    }

    try:
        # Phase 1: Subdomain Enumeration
        click.echo(click.style("Phase 1: Enumerating subdomains...", fg="blue"))

        # Adjust timeout based on domain size/complexity
        if domain in ['google.com', 'microsoft.com', 'amazon.com', 'facebook.com', 'apple.com']:
            timeout = 300  # 5 minutes for very large domains
            click.echo(click.style(f"Using extended timeout ({timeout}s) for large domain", fg="yellow"))
        elif ethical:
            timeout = 120  # 2 minutes for ethical scans
        else:
            timeout = 180  # 3 minutes for regular scans

        try:
            subdomains = run_subfinder(domain, timeout=timeout)
            scan_stats["subdomains_found"] = len(subdomains)
        except Exception as e:
            error_msg = f"Subdomain enumeration failed: {e}"
            click.echo(click.style(error_msg, fg="red"))
            scan_stats["errors"].append(error_msg)
            return _finalize_scan(scan_stats, resource_monitor, success=False)

        if not subdomains:
            click.echo(click.style(f"No subdomains found for {domain}.", fg="yellow"))
            click.echo("This might be due to:")
            click.echo("  - Domain has very few public subdomains")
            click.echo("  - Network restrictions or rate limiting")
            click.echo("  - Timeout too short for large domains")
            return _finalize_scan(scan_stats, resource_monitor, success=True)

        click.echo(click.style(f"Found {len(subdomains)} subdomains", fg="green"))

        # Phase 2: IP Resolution
        click.echo(click.style("Phase 2: Resolving IP addresses...", fg="blue"))
        resolved_targets = []

        try:
            with ThreadPoolExecutor(max_workers=min(10, len(subdomains))) as executor:
                future_to_subdomain = {
                    executor.submit(resolve_ip, sub, 15): sub
                    for sub in subdomains
                }

                for future in as_completed(future_to_subdomain):
                    sub = future_to_subdomain[future]
                    try:
                        ip = future.result(timeout=20)
                        if ip and ip != "Unknown":
                            resolved_targets.append({'subdomain': sub, 'ip': ip})
                            click.echo(f"  Resolved {sub} -> {ip}")
                    except Exception as e:
                        scan_stats["errors"].append(f"Failed to resolve {sub}: {e}")
                        click.echo(click.style(f"  Failed to resolve {sub}: {e}", fg="yellow"))

        except Exception as e:
            error_msg = f"IP resolution phase failed: {e}"
            click.echo(click.style(error_msg, fg="red"))
            scan_stats["errors"].append(error_msg)
            return _finalize_scan(scan_stats, resource_monitor, success=False)

        scan_stats["subdomains_resolved"] = len(resolved_targets)
        click.echo(click.style(f"Resolved {len(resolved_targets)} subdomains to IP addresses", fg="green"))

        if not resolved_targets:
            click.echo(click.style("No reachable subdomains found", fg="yellow"))
            return _finalize_scan(scan_stats, resource_monitor, success=True)

        # Phase 3: Vulnerability Scanning
        click.echo(click.style("Phase 3: Running security scans...", fg="blue"))

        for i, target in enumerate(resolved_targets, 1):
            sub = target['subdomain']
            ip = target['ip']

            click.echo(click.style(f"Scanning {i}/{len(resolved_targets)}: {sub}", fg="cyan"))

            try:
                # Run all scans for this target
                ports = run_nmap(ip, sub, ethical)
                ssl_findings = check_ssl_vulnerabilities(sub)
                web_findings = check_web_vulnerabilities(f"https://{sub}")

                # FIXED: Handle the new return format from web scanner
                if isinstance(web_findings, dict):
                    web_json = json.dumps(web_findings)
                else:
                    web_json = json.dumps({"error": "Invalid scanner response"})

                ssl_json = json.dumps(ssl_findings)

                # Calculate risk score
                score = calculate_score(ports)

                # Store results in database
                success = database.insert_asset(
                    sub,
                    ip=ip,
                    ports=ports,
                    score=score,
                    ssl_vulnerabilities=ssl_json,
                    web_vulnerabilities=web_json
                )

                if success:
                    scan_stats["successful_scans"] += 1
                    click.echo(click.style(f"  ✓ Completed {sub} (Score: {score}, Ports: {ports or 'none'})", fg="green"))
                else:
                    scan_stats["failed_scans"] += 1
                    click.echo(click.style(f"  ✗ Failed to store results for {sub}", fg="yellow"))

            except Exception as e:
                scan_stats["failed_scans"] += 1
                error_msg = f"Scan failed for {sub}: {e}"
                scan_stats["errors"].append(error_msg)
                click.echo(click.style(f"  ✗ {error_msg}", fg="red"))
                continue

        return _finalize_scan(scan_stats, resource_monitor, success=True)

    except KeyboardInterrupt:
        click.echo(click.style("\nScan interrupted by user", fg="yellow"))
        return _finalize_scan(scan_stats, resource_monitor, success=False)
    except Exception as e:
        error_msg = f"Unexpected scan error: {e}"
        click.echo(click.style(error_msg, fg="red"))
        scan_stats["errors"].append(error_msg)
        return _finalize_scan(scan_stats, resource_monitor, success=False)

def _finalize_scan(scan_stats: Dict[str, Any], resource_monitor: Optional[ResourceMonitor], success: bool) -> Dict[str, Any]:
    """Helper function to finalize scan and cleanup resources"""
    scan_stats["end_time"] = time.time()
    scan_stats["duration"] = scan_stats["end_time"] - scan_stats["start_time"]
    scan_stats["success"] = success

    # Stop resource monitoring
    if resource_monitor:
        if resource_monitor.stop():
            click.echo(click.style("Resource monitoring stopped", fg="cyan"))

    # Display final summary
    click.echo(click.style("\n" + "="*60, fg="cyan"))
    click.echo(click.style(f"Scan {scan_stats['scan_id']} Summary:", fg="cyan", bold=True))
    click.echo(f"Domain: {scan_stats['domain']}")
    click.echo(f"Duration: {scan_stats['duration']:.1f} seconds")
    click.echo(f"Subdomains found: {scan_stats['subdomains_found']}")
    click.echo(f"Subdomains resolved: {scan_stats['subdomains_resolved']}")
    click.echo(f"Successful scans: {scan_stats['successful_scans']}")
    click.echo(f"Failed scans: {scan_stats['failed_scans']}")

    if scan_stats.get("errors"):
        click.echo(click.style(f"Errors encountered: {len(scan_stats['errors'])}", fg="yellow"))

    if success and scan_stats["successful_scans"] > 0:
        click.echo(click.style("✓ Scan completed successfully!", fg="green", bold=True))
    elif success:
        click.echo(click.style("✓ Scan completed (no assets found)", fg="yellow"))
    else:
        click.echo(click.style("✗ Scan completed with errors", fg="red"))

    click.echo(click.style("="*60, fg="cyan"))

    return scan_stats

@cli.command()
@click.argument("domain")
@click.option("--ethical", is_flag=True, help="Respect robots.txt and apply rate limiting.")
@click.option("--monitor", is_flag=True, help="Monitor system resources during the scan.")
def scan(domain, ethical, monitor):
    """Scan a domain for subdomains and open ports."""
    result = run_scan_logic(domain, ethical, monitor)

    # Exit with appropriate code
    if not result.get("success", False):
        exit(1)

@cli.command()
@click.option("--format", "output_format", type=click.Choice(["table", "json", "csv"]), default="table", help="Output format")
@click.option("--limit", type=int, help="Limit number of results shown")
def view(output_format, limit):
    """View all assets currently in the database."""
    try:
        assets = database.get_all_assets()
    except Exception as e:
        click.echo(click.style(f"Database error: {e}", fg="red"))
        return

    if not assets:
        click.echo(click.style("No assets found in the database.", fg="yellow"))
        return

    # Apply limit if specified
    if limit and limit > 0:
        assets = assets[:limit]
        click.echo(click.style(f"Showing first {len(assets)} assets", fg="cyan"))

    if output_format == "json":
        click.echo(json.dumps([dict(asset) for asset in assets], indent=2))
        return
    elif output_format == "csv":
        if assets:
            fieldnames = assets[0].keys()
            import io
            output = io.StringIO()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(assets)
            click.echo(output.getvalue())
        return

    # Default table format
    click.echo(click.style("-" * 130, fg="cyan"))
    click.echo(click.style(f"| {'ID':<4} | {'Domain':<35} | {'IP':<15} | {'Ports':<20} | {'Score':<6} | {'SSL':<10} | {'Web':<10} | {'Last Scanned':<18} |", fg="cyan"))
    click.echo(click.style("-" * 130, fg="cyan"))

    for asset in assets:
        try:
            # FIXED: Safer JSON parsing with error handling
            ssl_vulns = {}
            web_vulns = {}

            try:
                ssl_vulns = json.loads(asset.get('ssl_vulnerabilities', '{}'))
            except (json.JSONDecodeError, TypeError):
                ssl_vulns = {}

            try:
                web_vulns = json.loads(asset.get('web_vulnerabilities', '{}'))
            except (json.JSONDecodeError, TypeError):
                web_vulns = {}

            # Determine SSL status
            if ssl_vulns.get('has_ssl'):
                ssl_status = "Valid" if ssl_vulns.get('valid_cert') else "Issues"
            else:
                ssl_status = "None"

            # Determine web status
            web_status = "Admin" if web_vulns.get('has_admin_panel') else "Clean"
            if web_vulns.get('vulnerabilities') and len(web_vulns['vulnerabilities']) > 0:
                web_status = f"Vulns({len(web_vulns['vulnerabilities'])})"

            # Truncate long values for display
            domain = asset['domain'][:35] if len(asset['domain']) > 35 else asset['domain']
            ports = asset.get('ports', '')[:20] if asset.get('ports') else ''

            click.echo(f"| {asset['id']:<4} | {domain:<35} | {asset.get('ip', 'Unknown'):<15} | {ports:<20} | {asset.get('score', 0):<6} | {ssl_status:<10} | {web_status:<10} | {asset.get('last_scanned', 'Unknown'):<18} |")

        except Exception as e:
            click.echo(click.style(f"Error displaying asset {asset.get('id', 'unknown')}: {e}", fg="red"))

    click.echo(click.style("-" * 130, fg="cyan"))
    click.echo(click.style(f"Total assets: {len(assets)}", fg="green"))

@cli.command()
@click.option("--detailed", is_flag=True, help="Include detailed vulnerability information")
def report(detailed):
    """Generate a comprehensive security report."""
    try:
        assets = database.get_all_assets()
        stats = database.get_db_stats()
    except Exception as e:
        click.echo(click.style(f"Database error: {e}", fg="red"))
        return

    if not assets:
        click.echo(click.style("No assets found in the database to generate a report.", fg="yellow"))
        return

    # Generate report
    click.echo(click.style("="*60, fg="cyan"))
    click.echo(click.style(" " * 20 + "AEGIS-LITE SECURITY REPORT", fg="cyan", bold=True))
    click.echo(click.style("="*60, fg="cyan"))
    click.echo(f"Report generated: {time.ctime()}")
    click.echo(f"Total assets analyzed: {stats['total_assets']}")
    click.echo(f"Average risk score: {stats['avg_score']:.1f}/100")
    click.echo()

    # Risk distribution
    click.echo(click.style("RISK DISTRIBUTION:", fg="magenta", bold=True))
    click.echo(f"  High risk (>50):    {stats['high_risk_assets']:>3} assets")
    click.echo(f"  Medium risk (20-50): {stats['medium_risk_assets']:>3} assets")
    click.echo(f"  Low risk (≤20):      {stats['low_risk_assets']:>3} assets")
    click.echo()

    # Critical findings
    critical_issues = []
    ssl_issues = 0
    web_issues = 0

    for asset in assets:
        try:
            ssl_vulns = json.loads(asset.get('ssl_vulnerabilities', '{}'))
            web_vulns = json.loads(asset.get('web_vulnerabilities', '{}'))

            # SSL Issues
            if ssl_vulns.get('has_ssl') and not ssl_vulns.get('valid_cert'):
                critical_issues.append(f"CRITICAL: Invalid SSL certificate on {asset['domain']}")
                ssl_issues += 1
            elif ssl_vulns.get('is_expired'):
                critical_issues.append(f"CRITICAL: Expired SSL certificate on {asset['domain']}")
                ssl_issues += 1
            elif not ssl_vulns.get('has_ssl') and asset.get('ports', '').find('80') != -1:
                critical_issues.append(f"WARNING: HTTP without HTTPS on {asset['domain']}")

            # Web Issues
            if web_vulns.get('has_admin_panel'):
                critical_issues.append(f"HIGH: Admin panel exposed on {asset['domain']}")
                web_issues += 1

            if web_vulns.get('vulnerabilities'):
                vuln_count = len(web_vulns['vulnerabilities'])
                if vuln_count > 0:
                    critical_issues.append(f"MEDIUM: {vuln_count} vulnerabilities found on {asset['domain']}")
                    web_issues += vuln_count

        except (json.JSONDecodeError, TypeError):
            continue

    click.echo(click.style("SECURITY FINDINGS:", fg="magenta", bold=True))
    if critical_issues:
        for issue in critical_issues[:10]:  # Limit to first 10 issues
            severity = issue.split(':')[0]
            color = "red" if severity == "CRITICAL" else "yellow" if severity == "HIGH" else "white"
            click.echo(click.style(f"  {issue}", fg=color))

        if len(critical_issues) > 10:
            click.echo(f"  ... and {len(critical_issues) - 10} more issues")
    else:
        click.echo(click.style("  No critical security issues found.", fg="green"))

    click.echo()
    click.echo(click.style("SUMMARY:", fg="magenta", bold=True))
    click.echo(f"  SSL/TLS issues: {ssl_issues}")
    click.echo(f"  Web vulnerabilities: {web_issues}")
    click.echo(f"  Total security issues: {len(critical_issues)}")

    if detailed and critical_issues:
        click.echo()
        click.echo(click.style("RECOMMENDATIONS:", fg="magenta", bold=True))
        click.echo("  1. Address all CRITICAL issues immediately")
        click.echo("  2. Implement SSL certificates for HTTP-only services")
        click.echo("  3. Secure or remove exposed admin panels")
        click.echo("  4. Apply security patches for identified vulnerabilities")
        click.echo("  5. Conduct regular security assessments")

    click.echo(click.style("="*60, fg="cyan"))

@cli.command()
@click.argument("format", type=click.Choice(["json", "csv"]), default="json")
@click.option("--output", "-o", help="Output filename (optional)")
def export(format, output):
    """Export all assets to a specified format (JSON or CSV)."""
    try:
        assets = database.get_all_assets()
    except Exception as e:
        click.echo(click.style(f"Database error: {e}", fg="red"))
        return

    if not assets:
        click.echo(click.style("No assets found to export.", fg="yellow"))
        return

    # Determine output filename
    if output:
        output_filename = output
        if not output_filename.endswith(f".{format}"):
            output_filename += f".{format}"
    else:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        output_filename = f"aegis_export_{timestamp}.{format}"

    try:
        if format == "json":
            with open(output_filename, "w") as f:
                json.dump([dict(asset) for asset in assets], f, indent=2)
        elif format == "csv":
            with open(output_filename, "w", newline='') as f:
                if assets:
                    fieldnames = assets[0].keys()
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows([dict(asset) for asset in assets])

        click.echo(click.style(f"Successfully exported {len(assets)} assets to {output_filename}", fg="green"))

    except Exception as e:
        click.echo(click.style(f"Export failed: {e}", fg="red"))

@cli.command()
@click.confirmation_option(prompt="Are you sure you want to clear all scan data?")
def clear():
    """Remove the entire database file."""
    try:
        database.clear_db()
        click.echo(click.style("Database cleared successfully.", fg="green"))
    except Exception as e:
        click.echo(click.style(f"Failed to clear database: {e}", fg="red"))

@cli.command()
@click.pass_context
def interactive(ctx):
    """Start interactive mode with improved error handling."""
    click.echo(click.style("Welcome to Aegis-Lite Interactive Mode!", fg="green", bold=True))
    click.echo(click.style("Type 'help' for available commands or 'quit' to exit.\n", fg="cyan"))

    while True:
        try:
            click.echo(click.style("--- Main Menu ---", fg="magenta"))
            menu_options = [
                "1. Scan a domain",
                "2. View scan results",
                "3. Generate security report",
                "4. Export data",
                "5. Clear database",
                "6. Database statistics",
                "7. Exit"
            ]

            for option in menu_options:
                click.echo(click.style(option, fg="yellow"))

            choice = click.prompt(click.style("\nEnter your choice", fg="white", bold=True), type=int)

            if choice == 1:
                domain = click.prompt("Enter the domain to scan (e.g., example.com)")
                ethical = click.confirm("Enable ethical scan mode?", default=True)
                monitor = click.confirm("Monitor system resources?", default=False)

                result = run_scan_logic(domain, ethical, monitor)
                if not result.get("success", False):
                    click.echo(click.style("Scan failed. Check the output above for details.", fg="red"))

            elif choice == 2:
                output_format = click.prompt(
                    "Choose format",
                    type=click.Choice(["table", "json", "csv"]),
                    default="table"
                )
                limit = click.prompt("Limit results (0 for all)", type=int, default=0)
                limit = limit if limit > 0 else None
                ctx.invoke(view, output_format=output_format, limit=limit)

            elif choice == 3:
                detailed = click.confirm("Include detailed analysis?", default=False)
                ctx.invoke(report, detailed=detailed)

            elif choice == 4:
                export_format = click.prompt(
                    "Choose format",
                    type=click.Choice(["json", "csv"]),
                    default="json"
                )
                output_file = click.prompt("Output filename (Enter for auto)", default="", show_default=False)
                output_file = output_file if output_file.strip() else None
                ctx.invoke(export, format=export_format, output=output_file)

            elif choice == 5:
                if click.confirm("Are you sure you want to clear all scan data?"):
                    ctx.invoke(clear)

            elif choice == 6:
                try:
                    stats = database.get_db_stats()
                    click.echo(click.style("\nDatabase Statistics:", fg="cyan", bold=True))
                    for key, value in stats.items():
                        click.echo(f"  {key.replace('_', ' ').title()}: {value}")
                except Exception as e:
                    click.echo(click.style(f"Failed to get statistics: {e}", fg="red"))

            elif choice == 7:
                click.echo(click.style("Thank you for using Aegis-Lite! Goodbye!", fg="green"))
                break

            else:
                click.echo(click.style("Invalid choice. Please select 1-7.", fg="red"))

        except (ValueError, EOFError):
            click.echo(click.style("\nInvalid input or EOF received.", fg="yellow"))
        except KeyboardInterrupt:
            click.echo(click.style("\nExiting interactive mode...", fg="yellow"))
            break
        except Exception as e:
            click.echo(click.style(f"\nUnexpected error: {e}", fg="red"))
            if click.confirm("Continue running?"):
                continue
            else:
                break

        # Add spacing between operations
        click.echo()

if __name__ == '__main__':
    cli()
