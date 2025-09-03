import click
import os
import psutil
import time
import json
import csv
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import the database and scanner modules
from aegis import database
from aegis.scanners import run_subfinder, run_nmap, resolve_ip, calculate_score, check_ssl_vulnerabilities, check_web_vulnerabilities

# --- Global/Configured Paths ---
COMPLIANCE_LOG_NAME = "compliance.log"
RESOURCE_LOG_NAME = "resource.log"

# Global variable to control resource monitoring
monitor_stop_flag = threading.Event()

# Initialize the database when the CLI application starts
database.init_db()

# Main command group for the CLI
@click.group()
def cli():
    """Aegis-Lite: Ethical Attack Surface Scanner for SMEs."""
    pass

# Helper function to run the core scan logic
def run_scan_logic(domain, ethical, monitor):
    """
    Enhanced scan logic with simplified threading and better error handling
    """
    click.echo(click.style("Enumerating subdomains...", fg="blue"))

    # Use different timeouts based on domain complexity
    if domain in ['google.com', 'microsoft.com', 'amazon.com', 'facebook.com']:
        timeout = 300  # 5 minutes for very large domains
        click.echo(click.style(f"Using extended timeout ({timeout}s) for large domain", fg="yellow"))
    elif ethical:
        timeout = 120  # 2 minutes for ethical scans
    else:
        timeout = 180  # 3 minutes for regular scans

    try:
        subdomains = run_subfinder(domain, timeout=timeout)
    except Exception as e:
        click.echo(click.style(f"Subdomain enumeration failed: {e}", fg="red"))
        return

    click.echo(click.style(f"Found {len(subdomains)} subdomains.", fg="green"))

    if not subdomains:
        click.echo(click.style(f"No subdomains found for {domain}. This might be due to:", fg="yellow"))
        click.echo("  - Domain has very few subdomains")
        click.echo("  - Timeout too short for large domains")
        click.echo("  - Network issues or rate limiting")
        click.echo("  - Try running with a smaller test domain first")
        return

    # Start resource monitoring if enabled
    monitor_thread = None
    if monitor:
        monitor_stop_flag.clear()
        monitor_thread = start_resource_monitoring()

    # Resolve IPs for all subdomains first
    click.echo(click.style("Resolving IPs...", fg="blue"))
    resolved_targets = []

    try:
        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_subdomain = {executor.submit(resolve_ip, sub): sub for sub in subdomains}
            for future in as_completed(future_to_subdomain):
                sub = future_to_subdomain[future]
                try:
                    ip = future.result()
                    if ip != "Unknown":
                        resolved_targets.append({'subdomain': sub, 'ip': ip})
                except Exception as e:
                    click.echo(click.style(f"Failed to resolve {sub}: {e}", fg="yellow"))
                    continue
    except Exception as e:
        click.echo(click.style(f"IP resolution failed: {e}", fg="red"))
        return

    click.echo(click.style(f"Resolved {len(resolved_targets)} subdomains to IP addresses.", fg="green"))

    if not resolved_targets:
        click.echo(click.style(f"No reachable subdomains found for {domain}. Exiting scan.", fg="yellow"))
        stop_resource_monitoring(monitor_thread)
        return

    click.echo(click.style("Starting vulnerability scans...", fg="blue"))

    # Sequential scanning for better reliability and resource management
    successful_scans = 0
    failed_scans = 0

    for i, target in enumerate(resolved_targets, 1):
        sub = target['subdomain']
        ip = target['ip']

        click.echo(click.style(f"Scanning {i}/{len(resolved_targets)}: {sub}", fg="cyan"))

        try:
            # Run all scans for this target
            ports = run_nmap(ip, sub, ethical)
            ssl_findings = check_ssl_vulnerabilities(sub)
            web_findings = check_web_vulnerabilities(f"http://{sub}")

            # Calculate risk score
            score = calculate_score(ports)

            # Store results in database
            success = database.insert_asset(
                sub,
                ip=ip,
                ports=ports,
                score=score,
                ssl_vulnerabilities=json.dumps(ssl_findings),
                web_vulnerabilities=json.dumps(web_findings)
            )

            if success:
                successful_scans += 1
                click.echo(click.style(f"  ✓ Completed {sub} (Score: {score})", fg="green"))
            else:
                failed_scans += 1
                click.echo(click.style(f"  ✗ Failed to store results for {sub}", fg="yellow"))

        except Exception as e:
            failed_scans += 1
            click.echo(click.style(f"  ✗ Scan failed for {sub}: {e}", fg="red"))
            # Continue with next target instead of stopping
            continue

    # Stop resource monitoring
    stop_resource_monitoring(monitor_thread)

    click.echo(click.style(f"\nScan complete! Successfully scanned: {successful_scans}, Failed: {failed_scans}", fg="green"))

def start_resource_monitoring():
    """Start resource monitoring in a separate thread"""
    def monitor_resources():
        try:
            with open(RESOURCE_LOG_NAME, "w") as f:
                f.write("timestamp,cpu_percent,ram_percent\n")

            while not monitor_stop_flag.is_set():
                try:
                    cpu = psutil.cpu_percent(interval=None)
                    ram = psutil.virtual_memory().percent
                    with open(RESOURCE_LOG_NAME, "a") as f:
                        f.write(f"{time.ctime()},{cpu},{ram}\n")
                except Exception as e:
                    click.echo(click.style(f"Resource monitoring error: {e}", fg="yellow"))
                    break

                # Check stop flag every second
                if monitor_stop_flag.wait(1):
                    break
        except Exception as e:
            click.echo(click.style(f"Failed to start resource monitoring: {e}", fg="red"))

    monitor_thread = threading.Thread(target=monitor_resources, daemon=True)
    monitor_thread.start()
    click.echo(click.style(f"System resource monitoring started, logging to {RESOURCE_LOG_NAME}.", fg="cyan"))
    return monitor_thread

def stop_resource_monitoring(monitor_thread):
    """Stop resource monitoring gracefully"""
    if monitor_thread and monitor_thread.is_alive():
        monitor_stop_flag.set()
        monitor_thread.join(timeout=2)  # Wait max 2 seconds for cleanup
        click.echo(click.style("Resource monitoring stopped.", fg="cyan"))

# Command to scan a single domain
@cli.command()
@click.argument("domain")
@click.option("--ethical", is_flag=True, help="Respect robots.txt and apply rate limiting.")
@click.option("--monitor", is_flag=True, help="Monitor system resources during the scan.")
def scan(domain, ethical, monitor):
    """Scan a domain for subdomains and open ports."""
    run_scan_logic(domain, ethical, monitor)

# Command to view all assets in the database
@cli.command()
def view():
    """View all assets currently in the database."""
    assets = database.get_all_assets()
    if not assets:
        click.echo(click.style("No assets found in the database.", fg="yellow"))
        return

    click.echo(click.style("-" * 120, fg="cyan"))
    click.echo(click.style(f"| {'ID':<4} | {'Domain':<30} | {'IP':<15} | {'Ports':<15} | {'Score':<6} | {'SSL':<10} | {'Web':<10} | {'Last Scanned':<18} |", fg="cyan"))
    click.echo(click.style("-" * 120, fg="cyan"))

    for asset in assets:
        # Parse vulnerability data
        ssl_vulns = json.loads(asset.get('ssl_vulnerabilities', '{}'))
        web_vulns = json.loads(asset.get('web_vulnerabilities', '{}'))

        ssl_status = "Valid" if ssl_vulns.get('valid_cert') else "Issues" if ssl_vulns.get('has_ssl') else "None"
        web_status = "Admin" if web_vulns.get('has_admin_panel') else "Clean"

        click.echo(f"| {asset['id']:<4} | {asset['domain']:<30} | {asset['ip']:<15} | {asset['ports']:<15} | {asset['score']:<6} | {ssl_status:<10} | {web_status:<10} | {asset['last_scanned']:<18} |")

    click.echo(click.style("-" * 120, fg="cyan"))
    click.echo(click.style(f"Total assets: {len(assets)}", fg="green"))

# Command to generate a report
@cli.command()
def report():
    """Generates a business-focused summary report."""
    assets = database.get_all_assets()
    if not assets:
        click.echo(click.style("No assets found in the database to generate a report.", fg="yellow"))
        return

    total_assets = len(assets)
    total_score = sum(asset['score'] for asset in assets)
    avg_score = total_score / total_assets if total_assets > 0 else 0

    click.echo(click.style("-" * 50, fg="cyan"))
    click.echo(click.style(" " * 15 + "SECURITY REPORT", fg="cyan", bold=True))
    click.echo(click.style("-" * 50, fg="cyan"))

    click.echo(f"Total assets scanned: {total_assets}")
    click.echo(f"Average risk score: {avg_score:.2f}")

    # Risk categorization
    high_risk = [a for a in assets if a['score'] > 50]
    medium_risk = [a for a in assets if 20 < a['score'] <= 50]
    low_risk = [a for a in assets if a['score'] <= 20]

    click.echo(f"High risk assets (>50): {len(high_risk)}")
    click.echo(f"Medium risk assets (20-50): {len(medium_risk)}")
    click.echo(f"Low risk assets (≤20): {len(low_risk)}")

    click.echo(click.style("\n--- SSL and Web Vulnerability Findings ---", fg="magenta"))

    critical_issues = 0
    for asset in assets:
        ssl_vulns = json.loads(asset.get('ssl_vulnerabilities', '{}'))
        web_vulns = json.loads(asset.get('web_vulnerabilities', '{}'))

        if ssl_vulns.get('has_ssl') and not ssl_vulns.get('valid_cert'):
            click.echo(click.style(f"CRITICAL: SSL certificate is invalid or expired on {asset['domain']}.", fg="red"))
            critical_issues += 1

        if web_vulns.get('has_admin_panel'):
            click.echo(click.style(f"HIGH: Common admin panel found on {asset['domain']}.", fg="yellow"))
            critical_issues += 1

        if not ssl_vulns.get('has_ssl', False):
            click.echo(click.style(f"WARNING: No SSL found on {asset['domain']}.", fg="yellow"))

    if critical_issues == 0:
        click.echo(click.style("No critical security issues found.", fg="green"))

    click.echo(click.style("-" * 50, fg="cyan"))

# Command to export data to JSON or CSV
@cli.command()
@click.argument("format", type=click.Choice(["json", "csv"]), default="json")
def export(format):
    """Exports all assets to a specified format (JSON or CSV)."""
    assets = database.get_all_assets()
    if not assets:
        click.echo(click.style("No assets found to export.", fg="yellow"))
        return

    output_filename = f"aegis_export.{format}"

    try:
        if format == "json":
            with open(output_filename, "w") as f:
                # Convert the list of sqlite3.Row objects to a list of dictionaries
                assets_dict = [dict(asset) for asset in assets]
                json.dump(assets_dict, f, indent=4)
            click.echo(click.style(f"Successfully exported {len(assets)} assets to {output_filename}", fg="green"))

        elif format == "csv":
            with open(output_filename, "w", newline='') as f:
                fieldnames = assets[0].keys() if assets else []
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(assets)
            click.echo(click.style(f"Successfully exported {len(assets)} assets to {output_filename}", fg="green"))
    except Exception as e:
        click.echo(click.style(f"Export failed: {e}", fg="red"))

# Command to clear all data
@cli.command()
def clear():
    """Removes the entire database file."""
    try:
        database.clear_db()
        click.echo(click.style("Database cleared.", fg="green"))
    except Exception as e:
        click.echo(click.style(f"Failed to clear database: {e}", fg="red"))

# Command for interactive mode
@cli.command()
@click.pass_context
def interactive(ctx):
    """Starts the interactive mode."""
    click.echo(click.style("Welcome to Aegis Interactive Mode!", fg="green", bold=True))
    while True:
        click.echo(click.style("\n--- Main Menu ---", fg="magenta"))
        click.echo(click.style("1. Scan a domain", fg="yellow"))
        click.echo(click.style("2. View scan results", fg="yellow"))
        click.echo(click.style("3. Generate a report", fg="yellow"))
        click.echo(click.style("4. Export data", fg="yellow"))
        click.echo(click.style("5. Clear database", fg="yellow"))
        click.echo(click.style("6. Exit", fg="red"))

        try:
            choice = click.prompt(click.style("Enter your choice", fg="white", bold=True), type=int)

            if choice == 1:
                domain = click.prompt("Enter the domain to scan (e.g., example.com)")
                ethical = click.confirm("Enable ethical scan mode (limits to 80,443 and rate limits)?")
                monitor = click.confirm("Monitor system resources during scan?")
                run_scan_logic(domain, ethical, monitor)  # FIXED: removed underscore

            elif choice == 2:
                ctx.invoke(view)
            elif choice == 3:
                ctx.invoke(report)
            elif choice == 4:
                export_format = click.prompt("Choose export format (json or csv)", type=click.Choice(["json", "csv"]), default="json")
                ctx.invoke(export, format=export_format)
            elif choice == 5:
                if click.confirm("Are you sure you want to clear all data?"):
                    ctx.invoke(clear)
            elif choice == 6:
                click.echo(click.style("Exiting Aegis. Goodbye!", fg="green"))
                break
            else:
                click.echo(click.style("Invalid choice. Please try again.", fg="red"))

        except (ValueError, EOFError, KeyboardInterrupt):
            click.echo(click.style("\nExiting interactive mode.", fg="red"))
            break
        except Exception as e:
            click.echo(click.style(f"\nAn error occurred: {e}", fg="red"))

if __name__ == '__main__':
    cli()
