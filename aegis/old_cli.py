import click
import os
import psutil
import time
import json
import csv
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import the database and scanner modules
from aegis import database
from aegis.scanners import run_subfinder, run_nmap, resolve_ip, calculate_score, RateLimiter

# --- Global/Configured Paths ---
COMPLIANCE_LOG_NAME = "compliance.log"
RESOURCE_LOG_NAME = "resource.log"

# Initialize the database when the CLI application starts
database.init_db()

# Main command group for the CLI
@click.group()
def cli():
    """Aegis-Lite: Ethical Attack Surface Scanner for SMEs."""
    pass

# Helper function to run the core scan logic
def _run_scan_logic(domain, ethical, monitor):
    """
    Core logic for performing the scan, abstracted for better code organization.
    """

    database.init_db()

    click.echo(click.style("Enumerating subdomains...", fg="blue"))
    subdomains = run_subfinder(domain)
    click.echo(click.style(f"Found {len(subdomains)} subdomains.", fg="green"))

    if not subdomains:
        click.echo(click.style(f"No subdomains found for {domain}. Exiting scan.", fg="yellow"))
        return

    max_workers = 4
    processed_count = 0

    targets_to_scan = subdomains[:50]
    if len(subdomains) > 50:
        click.echo(click.style(f"Warning: Only scanning first {len(targets_to_scan)} assets as per guardrail.", fg="yellow"), err=True)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Step 1: Resolve IPs in parallel
        resolution_futures = {executor.submit(resolve_ip, sub): sub for sub in targets_to_scan}
        resolved_targets = []
        for future in as_completed(resolution_futures):
            subdomain = resolution_futures[future]
            ip_address = future.result()
            if ip_address != "Unknown":
                resolved_targets.append({'subdomain': subdomain, 'ip': ip_address})
            else:
                database.insert_asset(subdomain, ip="Unknown", ports="")
                click.echo(click.style(f"Warning: Could not resolve IP for {subdomain}. Skipping port scan.", fg="yellow"))

        # Step 2: Scan ports for resolved IPs in parallel
        scan_futures = {
            executor.submit(
                run_nmap,
                target['subdomain'],
                '80,443' if ethical else '1-1000',
                2 if ethical else None
            ): target['subdomain'] for target in resolved_targets
        }

        with click.progressbar(
            length=len(scan_futures),
            label="Scanning ports and storing assets",
            show_percent=True
        ) as bar:
            for future in as_completed(scan_futures):
                sub = scan_futures[future]
                ip = next(t['ip'] for t in resolved_targets if t['subdomain'] == sub)
                try:
                    ports = future.result()
                    if ports:
                        score = calculate_score(ports)
                        database.insert_asset(sub, ip=ip, ports=ports, score=score)
                        processed_count += 1
                except subprocess.CalledProcessError as exc:
                    click.echo(click.style(f"\nError processing {sub}: {exc.stderr}", fg="red"), err=True)
                except Exception as exc:
                    click.echo(click.style(f"\nAn unexpected error occurred processing {sub}: {exc}", fg="red"), err=True)

                bar.update(1)

                if monitor:
                    try:
                        cpu_percent = psutil.cpu_percent(interval=None)
                        ram_percent = psutil.virtual_memory().percent
                        with open(resource_log_path, "a") as f:
                            f.write(f"{time.ctime()},{cpu_percent},{ram_percent}\n")
                    except Exception as res_exc:
                        click.echo(click.style(f"Warning: Failed to log resource usage: {res_exc}", fg="yellow"), err=True)

    click.echo(click.style(f"\nSuccessfully processed {processed_count} assets.", fg="green"))
    click.echo(click.style("Scan complete. View results in the database.", fg="green"))


@cli.command()
@click.argument("domain")
@click.option("--ethical", is_flag=True, help="Respect robots.txt and apply rate limiting (2 reqs/sec).")
@click.option("--compliance-check", is_flag=True, help=f"Validate robots.txt and rate limits, log to {COMPLIANCE_LOG_NAME}.")
@click.option("--monitor", is_flag=True, help=f"Log CPU and RAM usage to {RESOURCE_LOG_NAME} during scan.")
def scan(domain, ethical, compliance_check, monitor):
    """Performs asset discovery (subdomains and open ports) for a given domain."""
    click.echo(click.style(f"Starting scan for {domain}...", fg="blue"))

    compliance_log_path = os.path.join(os.getcwd(), COMPLIANCE_LOG_NAME)
    resource_log_path = os.path.join(os.getcwd(), RESOURCE_LOG_NAME)

    if monitor:
        try:
            with open(resource_log_path, "a") as f:
                f.write(f"\n--- Scan for {domain} started at {time.ctime()} ---\n")
                f.write("Time,CPU_Percent,RAM_Percent\n")
            click.echo(click.style(f"Resource usage being logged to {resource_log_path}", fg="blue"))
        except IOError as e:
            click.echo(click.style(f"Warning: Could not open resource log file '{resource_log_path}': {e}", fg="yellow"), err=True)
            monitor = False

    if compliance_check:
        try:
            with open(compliance_log_path, "a") as f:
                f.write(f"\n--- Compliance check for {domain} started at {time.ctime()} ---\n")
                f.write(f"Domain: {domain}, Ethical mode: {ethical}\n")
                f.write(f"Rate Limit Applied: {2 if ethical else 'None'} reqs/sec\n")
                f.write("Robots.txt validation: (Not yet implemented - placeholder)\n")
                f.write("Rate limiting check: (Not yet implemented - placeholder)\n")
            click.echo(click.style(f"Compliance details logged to {compliance_log_path}", fg="blue"))
        except IOError as e:
            click.echo(click.style(f"Warning: Could not open compliance log file '{compliance_log_path}': {e}", fg="yellow"), err=True)
            compliance_check = False

    try:
        _run_scan_logic(domain, ethical, monitor)
    except Exception as e:
        click.echo(click.style(f"An unexpected error occurred during scan: {e}", fg="red"), err=True)
    finally:
        if monitor:
            try:
                with open(resource_log_path, "a") as f:
                    f.write(f"--- Scan for {domain} finished at {time.ctime()} ---\n")
            except IOError as e:
                click.echo(click.style(f"Warning: Could not finalize resource log file '{resource_log_path}': {e}", fg="yellow"), err=True)

# New view command
@cli.command()
def view():
    """Displays all scanned assets currently stored in the database."""
    assets = database.get_all_assets()
    if not assets:
        click.echo(click.style("No scanned assets found in the database.", fg="yellow"))
        return

    click.echo(click.style(f"Found {len(assets)} assets in the database.", fg="green"))
    click.echo("-" * 50)
    for asset in assets:
        click.echo(f"Domain: {asset['domain']}")
        click.echo(f"  IP: {asset['ip']}")
        click.echo(f"  Ports: {asset['ports']}")
        click.echo(f"  Score: {asset['score']}")
        click.echo(f"  Last Scanned: {asset['last_scanned']}")
        click.echo("-" * 50)

# New report command
@cli.command()
def report():
    """Generates a summary report of all assets in the database."""
    assets = database.get_all_assets()
    if not assets:
        click.echo(click.style("No assets found in the database to generate a report.", fg="yellow"))
        return

    total_assets = len(assets)
    total_ports_found = sum(len(a['ports'].split(',')) for a in assets if a['ports'])
    
    click.echo(click.style("-" * 50, fg="cyan"))
    click.echo(click.style(" " * 15 + "AEGIS-LITE SCAN REPORT", fg="cyan", bold=True))
    click.echo(click.style("-" * 50, fg="cyan"))
    click.echo(click.style(f"Total Assets Scanned: {total_assets}", fg="white"))
    click.echo(click.style(f"Total Open Ports Found: {total_ports_found}", fg="white"))
    click.echo(click.style("-" * 50, fg="cyan"))

    sorted_assets = sorted(assets, key=lambda a: a['score'], reverse=True)
    top_5_assets = sorted_assets[:5]

    click.echo(click.style("TOP 5 HIGHEST-RISK ASSETS", fg="red", bold=True))
    if top_5_assets and top_5_assets[0]['score'] > 0:
        for i, asset in enumerate(top_5_assets, 1):
            click.echo(click.style(f"\n{i}. Domain: {asset['domain']}", fg="red"))
            click.echo(f"   IP: {asset['ip']}")
            click.echo(f"   Score: {asset['score']}")
            click.echo(f"   Ports: {asset['ports']}")
    else:
        click.echo(click.style("\nNo high-risk assets with open ports found.", fg="green"))
    click.echo(click.style("-" * 50, fg="cyan"))

    port_counts = {}
    for asset in assets:
        if asset['ports']:
            ports = asset['ports'].split(',')
            for port in ports:
                port = port.strip()
                port_counts[port] = port_counts.get(port, 0) + 1
    
    sorted_ports = sorted(port_counts.items(), key=lambda item: item[1], reverse=True)

    click.echo(click.style("COMMON OPEN PORTS SUMMARY", fg="blue", bold=True))
    if sorted_ports:
        for port, count in sorted_ports:
            click.echo(f"  Port {port}: Found on {count} asset(s)")
    else:
        click.echo(click.style("  No open ports were found across all assets.", fg="yellow"))
    click.echo(click.style("-" * 50, fg="cyan"))

# Old export command
#@cli.command()
#@click.option("--format", type=click.Choice(["json", "csv"]), default="json", help="Choose the export format: json or csv.")
#def export(format):
#    """Exports all scanned assets from the database to a file."""
#    assets = database.get_all_assets()
#    if not assets:
#        click.echo(click.style("No scanned assets to export.", fg="yellow"))
#        return
#
#    filename = f"aegis_export.{format}"
#    
#    if format == "json":
#        with open(filename, "w") as f:
#            json_assets = [dict(row) for row in assets]
#            json.dump(json_assets, f, indent=4)
#        click.echo(click.style(f"Successfully exported {len(assets)} assets to {filename} (JSON format).", fg="green"))
#
#    elif format == "csv":
#        with open(filename, "w", newline="") as f:
#            if assets:
#                fieldnames = list(assets[0].keys())
#                writer = csv.DictWriter(f, fieldnames=fieldnames)
#                writer.writeheader()
#                writer.writerows(assets)
#                click.echo(click.style(f"Successfully exported {len(assets)} assets to {filename} (CSV format).", fg="green"))
#            else:
#                click.echo(click.style("No assets to export to CSV.", fg="yellow"))


# New export cmd fn(csv -fix)

@cli.command()
@click.option("--format", type=click.Choice(["json", "csv"]), default="json", help="Choose the export format: json or csv.")
def export(format):
    """Exports all scanned assets from the database to a file."""
    assets = database.get_all_assets()
    if not assets:
        click.echo(click.style("No scanned assets to export.", fg="yellow"))
        return

    filename = f"aegis_export.{format}"

    if format == "json":
        with open(filename, "w") as f:
            json_assets = [dict(row) for row in assets]
            json.dump(json_assets, f, indent=4)
        click.echo(click.style(f"Successfully exported {len(assets)} assets to {filename} (JSON format).", fg="green"))

    elif format == "csv":
        with open(filename, "w", newline="") as f:
            if assets:
                # FIX: Define fieldnames explicitly for robustness
                fieldnames = ['id', 'domain', 'ip', 'ports', 'score', 'last_scanned']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(assets)
                click.echo(click.style(f"Successfully exported {len(assets)} assets to {filename} (CSV format).", fg="green"))
            else:
                click.echo(click.style("No assets to export to CSV.", fg="yellow"))

# New clear command
@cli.command()
def clear():
    """Deletes the local database file to clear all scan data."""
    try:
        database.clear_db()
        click.echo(click.style("Database file has been successfully deleted.", fg="green"))
    except FileNotFoundError:
        click.echo(click.style("Database file not found. Nothing to clear.", fg="yellow"))

# --- New Interactive Mode ---
@cli.command()
def start():
    """Starts the interactive, menu-based user interface."""
    
    # ASCII Art Banner
    banner = """
  _   _                 _       
 | | | |               | |      
 | |_| | ___   ___ __ _|_|_ __  
 |  _  |/ _ \\ / __/ _` | | '_ \\ 
 | | | | (_) | (__| (_| | | |_) |
 \\_| |_/\\___/ \\___\\__,_|_| .__/ 
                         | |    
                         |_|    
    Aegis: Ethical Attack Surface Scanner
    """
    click.echo(click.style(banner, fg="cyan", bold=True))
    ctx = click.get_current_context()

    while True:
        click.echo(click.style("\n--- Main Menu ---", fg="magenta"))
        click.echo(click.style("1. Scan a domain", fg="yellow"))
        click.echo(click.style("2. View scan results", fg="yellow"))
        click.echo(click.style("3. Generate a report", fg="yellow"))
        click.echo(click.style("4. Export data", fg="yellow"))
        click.echo(click.style("5. Clear database", fg="yellow"))
        click.echo(click.style("6. Exit", fg="red"))
        
        choice = click.prompt(click.style("Enter your choice", fg="white", bold=True), type=int)

        if choice == 1:
            domain = click.prompt("Enter the domain to scan (e.g., example.com)")
            ethical = click.confirm("Enable ethical scan mode (limits to 80,443 and rate limits)?")
            monitor = click.confirm("Monitor system resources during scan?")
            _run_scan_logic(domain, ethical, monitor)

        elif choice == 2:
            ctx.invoke(view)
        elif choice == 3:
            ctx.invoke(report)
        elif choice == 4:
            export_format = click.prompt("Choose export format (json or csv)", type=click.Choice(["json", "csv"]), default="json")
            ctx.invoke(export, format=export_format)
        elif choice == 5:
            ctx.invoke(clear)
        elif choice == 6:
            click.echo(click.style("Exiting Aegis. Goodbye!", fg="green"))
            break
        else:
            click.echo(click.style("Invalid choice. Please enter a number from 1 to 6.", fg="red"))

if __name__ == "__main__":
    cli()
