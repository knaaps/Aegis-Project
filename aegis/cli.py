import click
import os
import psutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import your database and scanner modules
from aegis import database
# Import the real scanner functions directly
from aegis.scanners import run_subfinder, run_nmap

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

    This command initiates a full scan, including subdomain enumeration and
    port scanning on discovered subdomains. It supports optional flags for
    ethical scanning, compliance logging, and resource monitoring.

    Args:
        domain (str): The primary domain to scan.
        ethical (bool): A flag to enable ethical scanning mode.
        compliance_check (bool): A flag to enable compliance logging.
        monitor (bool): A flag to log system resource usage.
    """
    click.echo(f"Starting scan for {domain}...")

    compliance_log_path = os.path.join(os.getcwd(), COMPLIANCE_LOG_NAME)
    resource_log_path = os.path.join(os.getcwd(), RESOURCE_LOG_NAME)

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
        click.echo("Enumerating subdomains...")
        # Now using the real run_subfinder function
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
            futures = []
            for sub in targets_to_scan:
                # Now using the real run_nmap function
                future = executor.submit(
                    run_nmap,
                    sub,
                    '80,443' if ethical else '1-1000', # More comprehensive scan for non-ethical
                    2 if ethical else None
                )
                futures.append((future, sub))

            with click.progressbar(
                length=len(futures),
                label="Scanning ports and storing assets",
                show_percent=True
            ) as bar:
                for future, sub in futures:
                    try:
                        ports = future.result()
                        click.echo(f"DEBUG: Received ports for {sub}: {ports}", err=True)

                        if ports:
                            database.insert_asset(sub, ip="TBD", ports=ports)
                            processed_count += 1
                        
                    except Exception as exc:
                        click.echo(f"\nError processing {sub}: {exc}", err=True)
                        continue

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

    except Exception as e:
        click.echo(f"An unexpected error occurred during scan: {e}", err=True)

    finally:
        if monitor:
            try:
                with open(resource_log_path, "a") as f:
                    f.write(f"--- Scan for {domain} finished at {time.ctime()} ---\n")
            except IOError as e:
                click.echo(f"Warning: Could not finalize resource log file '{resource_log_path}': {e}", err=True)

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

if __name__ == "__main__":
    cli()
