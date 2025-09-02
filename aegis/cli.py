import click
import os
import psutil
import time
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import your database and scanner modules
from aegis import database
# Import the real scanner functions directly
from aegis.scanners import run_subfinder, run_nmap, resolve_ip, calculate_score

# --- Global/Configured Paths ---
COMPLIANCE_LOG_NAME = "compliance.log"
RESOURCE_LOG_NAME = "resource.log"

# Initialize the database when the CLI application starts
database.init_db()

@click.group()
def cli():
    """Aegis-Lite: Ethical Attack Surface Scanner for SMEs.

    This is the main command group for the Aegis-Lite application.
    It provides various subcommands to perform different tasks.
    """
    pass

def _run_scan_logic(domain, ethical, monitor):
    """
    Core logic for performing the scan, abstracted for better code organization.
    """
    click.echo("Enumerating subdomains...")
    subdomains = run_subfinder(domain)
    click.echo(f"Found {len(subdomains)} subdomains.")

    if not subdomains:
        click.echo(f"No subdomains found for {domain}. Exiting scan.")
        return

    max_workers = 4
    processed_count = 0

    targets_to_scan = subdomains[:50]
    if len(subdomains) > 50:
        click.echo(f"Warning: Only scanning first {len(targets_to_scan)} assets as per guardrail.", err=True)

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
                click.echo(f"Warning: Could not resolve IP for {subdomain}. Skipping port scan.")

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
                except Exception as exc:
                    click.echo(f"\nError processing {sub}: {exc}", err=True)

                bar.update(1)

                if monitor:
                    try:
                        cpu_percent = psutil.cpu_percent(interval=None)
                        ram_percent = psutil.virtual_memory().percent
                        with open(resource_log_path, "a") as f:
                            f.write(f"{time.ctime()},{cpu_percent},{ram_percent}\n")
                    except Exception as res_exc:
                        click.echo(f"Warning: Failed to log resource usage: {res_exc}", err=True)

    click.echo(f"\nSuccessfully processed {processed_count} assets.")
    click.echo("Scan complete. View results in the database.")


@cli.command()
@click.argument("domain")
@click.option(
    "--ethical",
    is_flag=True,
    help="Respect robots.txt and apply rate limiting (2 reqs/sec).",
)
@click.option(
    "--compliance-check",
    is_flag=True,
    help=f"Validate robots.txt and rate limits, log to {COMPLIANCE_LOG_NAME}.",
)
@click.option(
    "--monitor",
    is_flag=True,
    help=f"Log CPU and RAM usage to {RESOURCE_LOG_NAME} during scan.",
)
def scan(domain, ethical, compliance_check, monitor):
    """
    Performs asset discovery (subdomains and open ports) for a given domain.
    """
    click.echo(f"Starting scan for {domain}...")

    compliance_log_path = os.path.join(os.getcwd(), COMPLIANCE_LOG_NAME)
    resource_log_path = os.path.join(os.getcwd(), RESOURCE_LOG_NAME)

    # Logging setup
    if monitor:
        try:
            with open(resource_log_path, "a") as f:
                f.write(f"\n--- Scan for {domain} started at {time.ctime()} ---\n")
                f.write("Time,CPU_Percent,RAM_Percent\n")
            click.echo(f"Resource usage being logged to {resource_log_path}")
        except IOError as e:
            click.echo(f"Warning: Could not open resource log file '{resource_log_path}': {e}", err=True)
            monitor = False

    if compliance_check:
        try:
            with open(compliance_log_path, "a") as f:
                f.write(f"\n--- Compliance check for {domain} started at {time.ctime()} ---\n")
                f.write(f"Domain: {domain}, Ethical mode: {ethical}\n")
                f.write(f"Rate Limit Applied: {2 if ethical else 'None'} reqs/sec\n")
                f.write("Robots.txt validation: (Not yet implemented - placeholder)\n")
                f.write("Rate limiting check: (Not yet implemented - placeholder)\n")
            click.echo(f"Compliance details logged to {compliance_log_path}")
        except IOError as e:
            click.echo(f"Warning: Could not open compliance log file '{compliance_log_path}': {e}", err=True)
            compliance_check = False

    try:
        _run_scan_logic(domain, ethical, monitor)
    except Exception as e:
        click.echo(f"An unexpected error occurred during scan: {e}", err=True)
    finally:
        if monitor:
            try:
                with open(resource_log_path, "a") as f:
                    f.write(f"--- Scan for {domain} finished at {time.ctime()} ---\n")
            except IOError as e:
                click.echo(f"Warning: Could not finalize resource log file '{resource_log_path}': {e}", err=True)


# New view command
@cli.command()
def view():
    """
    Displays all scanned assets currently stored in the database.
    """
    assets = database.get_all_assets()
    if not assets:
        click.echo("No scanned assets found in the database.")
        return

    click.echo(f"Found {len(assets)} assets in the database.")
    click.echo("-" * 50)
    for asset in assets:
        click.echo(f"Domain: {asset['domain']}")
        click.echo(f"  IP: {asset['ip']}")
        click.echo(f"  Ports: {asset['ports']}")
        click.echo(f"  Score: {asset['score']}")
        click.echo(f"  Last Scanned: {asset['last_scanned']}")
        click.echo("-" * 50)

@cli.command()
def report():
    """
    Generates a summary report of all assets in the database.
    
    This report includes a summary of findings, a list of the top
    highest-risk assets, and a breakdown of common open ports.
    """
    assets = database.get_all_assets()
    if not assets:
        click.echo("No assets found in the database to generate a report.")
        return

    # 1. General Summary
    total_assets = len(assets)
    total_ports_found = sum(len(a['ports'].split(',')) for a in assets if a['ports'])
    
    click.echo("-" * 50)
    click.echo(" " * 15 + "AEGIS-LITE SCAN REPORT")
    click.echo("-" * 50)
    click.echo(f"Total Assets Scanned: {total_assets}")
    click.echo(f"Total Open Ports Found: {total_ports_found}")
    click.echo("-" * 50)

    # 2. Top 5 High-Risk Assets
    # Sort assets by score in descending order
    sorted_assets = sorted(assets, key=lambda a: a['score'], reverse=True)
    top_5_assets = sorted_assets[:5]

    click.echo("TOP 5 HIGHEST-RISK ASSETS")
    if top_5_assets and top_5_assets[0]['score'] > 0:
        for i, asset in enumerate(top_5_assets, 1):
            click.echo(f"\n{i}. Domain: {asset['domain']}")
            click.echo(f"   IP: {asset['ip']}")
            click.echo(f"   Score: {asset['score']}")
            click.echo(f"   Ports: {asset['ports']}")
    else:
        click.echo("\nNo high-risk assets with open ports found.")
    click.echo("-" * 50)

    # 3. Common Open Ports
    port_counts = {}
    for asset in assets:
        if asset['ports']:
            ports = asset['ports'].split(',')
            for port in ports:
                port = port.strip()
                port_counts[port] = port_counts.get(port, 0) + 1
    
    # Sort ports by frequency
    sorted_ports = sorted(port_counts.items(), key=lambda item: item[1], reverse=True)

    click.echo("COMMON OPEN PORTS SUMMARY")
    if sorted_ports:
        for port, count in sorted_ports:
            click.echo(f"  Port {port}: Found on {count} asset(s)")
    else:
        click.echo("  No open ports were found across all assets.")
    click.echo("-" * 50)

# New export command
@cli.command()
@click.option(
    "--format",
    type=click.Choice(["json", "csv"]),
    default="json",
    help="Choose the export format: json or csv.",
)
def export(format):
    """
    Exports all scanned assets from the database to a file.
    """
    assets = database.get_all_assets()
    if not assets:
        click.echo("No scanned assets to export.")
        return

    filename = f"aegis_export.{format}"
    
    if format == "json":
        with open(filename, "w") as f:
            # Convert each Row object to a dictionary for JSON serialization
            json_assets = [dict(row) for row in assets]
            json.dump(json_assets, f, indent=4)
        click.echo(f"Successfully exported {len(assets)} assets to {filename} (JSON format).")

    elif format == "csv":
        with open(filename, "w", newline="") as f:
            # Get column names from the first asset's keys
	    if assets:
	    	fieldnames = list(assets[0].keys())
            	writer = csv.DictWriter(f, fieldnames=fieldnames)
            	writer.writeheader()
            	writer.writerows(assets)
        	click.echo(f"Successfully exported {len(assets)} assets to {filename} (CSV).")
	    else:
		click.echo("No assets to export.")

# New clear command
@cli.command()
def clear():
    """
    Deletes the local database file to clear all scan data.
    """
    try:
        database.clear_db()
        click.echo("Database file has been successfully deleted.")
    except FileNotFoundError:
        click.echo("Database file not found. Nothing to clear.")

if __name__ == "__main__":
    cli()
