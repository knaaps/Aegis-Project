"""
Enhanced CLI Module for Aegis-Lite with Thread Pool Support
===========================================================
Integrated concurrent scanning while maintaining simplicity
"""

import click
import time
import json
import csv
import subprocess
from typing import Dict, Any
import uuid

from aegis import database
from aegis.utils import validate_domain, clean_input
from aegis.scanners import (
    run_subfinder, scan_domains_concurrent, show_system_resources,
    monitor_system_resources, get_optimal_thread_count
)

def run_scan_logic(domain: str, ethical: bool, monitor: bool, max_subdomains: int = None,
                   max_workers: int = None, use_threading: bool = True) -> Dict[str, Any]:
    """Enhanced scan logic with thread pool support"""
    scan_id = str(uuid.uuid4())[:8]
    print(f"\n{'='*50}")
    print(f"Starting scan {scan_id} for {domain}")
    if use_threading:
        workers = max_workers or get_optimal_thread_count()
        if ethical:
            workers = min(workers, 3)  # Conservative for ethical mode
        print(f"Using {workers} worker threads for concurrent scanning")
    print(f"{'='*50}")

    # Validate and clean input
    domain = clean_input(domain)
    if not validate_domain(domain):
        error_msg = f"Invalid domain format: {domain}"
        print(f"Error: {error_msg}")
        return {"success": False, "error": error_msg}

    # Initialize scan statistics
    scan_stats = {
        "domain": domain,
        "scan_id": scan_id,
        "start_time": time.time(),
        "subdomains_found": 0,
        "successful_scans": 0,
        "failed_scans": 0,
        "threading_enabled": use_threading,
        "max_workers": max_workers or get_optimal_thread_count()
    }

    try:
        # Initial system resource check
        if monitor:
            print("\n📊 Initial System Resources:")
            show_system_resources()
            resource_status = monitor_system_resources()
            if not resource_status.get("system_healthy", True):
                print("⚠️  Warning: High system load detected!")
                if click.confirm("Continue with scan?"):
                    pass
                else:
                    return finalize_scan(scan_stats, False, "Scan cancelled due to high system load")

        # Phase 1: Find subdomains
        print(f"\n[1/4] Finding subdomains for {domain}...")
        if ethical:
            print("(Using ethical mode - slower but respectful)")

        subdomains = run_subfinder(domain, timeout=120)

        if max_subdomains and len(subdomains) > max_subdomains:
            subdomains = subdomains[:max_subdomains]
            print(f"Limited to first {max_subdomains} subdomains")

        scan_stats["subdomains_found"] = len(subdomains)

        # Include input domain in scan list
        domains_to_scan = [domain] + subdomains
        print(f"[2/4] Found {len(subdomains)} subdomains. Total {len(domains_to_scan)} domains to scan")

        if not domains_to_scan:
            print("No domains to scan.")
            return finalize_scan(scan_stats, True)

        # Phase 2: Concurrent domain scanning
        print(f"\n[3/4] {'Concurrent' if use_threading else 'Sequential'} domain scanning...")

        if use_threading:
            # Use thread pool for concurrent scanning
            scan_results = scan_domains_concurrent(
                domains_to_scan,
                ethical=ethical,
                max_workers=max_workers
            )

            # Update statistics
            scan_stats["successful_scans"] = len(scan_results)
            scan_stats["failed_scans"] = len(domains_to_scan) - len(scan_results)

            # Phase 3: Save results to database
            print(f"\n[4/4] Saving {len(scan_results)} results to database...")
            saved_count = 0

            for result in scan_results:
                try:
                    success = database.save_asset(
                        result["domain"],
                        ip=result["ip"],
                        ports=result["ports"],
                        score=result["score"],
                        ssl_vulnerabilities=result["ssl_vulnerabilities"],
                        web_vulnerabilities=result["web_vulnerabilities"]
                    )
                    if success:
                        saved_count += 1
                except Exception as e:
                    print(f"Error saving {result['domain']}: {e}")
                    continue

            print(f"Successfully saved {saved_count}/{len(scan_results)} assets to database")

        else:
            # Original sequential scanning logic
            from aegis.scanners import resolve_ip, run_nmap, check_https, check_web_vulnerabilities, calculate_score, simple_rate_limit

            for i, current_domain in enumerate(domains_to_scan, 1):
                print(f"\nScanning {i}/{len(domains_to_scan)}: {current_domain}")

                try:
                    if ethical and i > 1:
                        print("  Waiting 2 seconds (ethical mode)...")
                        simple_rate_limit()

                    # Resolve IP
                    print("  → Resolving IP...")
                    ip = resolve_ip(current_domain, timeout=10)
                    if ip == "Unknown":
                        print("  ✗ Could not resolve IP")
                        scan_stats["failed_scans"] += 1
                        continue

                    print(f"  → IP: {ip}")

                    # Scan ports
                    print("  → Scanning ports...")
                    ports = run_nmap(ip, current_domain, ethical)

                    # Check HTTPS
                    print("  → Checking HTTPS...")
                    https_result = check_https(current_domain)

                    # Check web vulnerabilities if HTTP/HTTPS is available
                    web_result = {"vulnerabilities": [], "has_admin_panel": False}
                    if ports and ('80' in ports or '443' in ports):
                        print("  → Checking vulnerabilities...")
                        protocol = "https" if '443' in ports else "http"
                        web_result = check_web_vulnerabilities(f"{protocol}://{current_domain}")

                    # Calculate risk score
                    score = calculate_score(ports)

                    # Save to database
                    success = database.save_asset(
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

        # Final resource monitoring
        if monitor:
            print("\n📊 Final System Resources:")
            show_system_resources()

        print(f"\n[4/4] Scan completed!")
        return finalize_scan(scan_stats, True)

    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        return finalize_scan(scan_stats, False, "User interrupted")
    except Exception as e:
        print(f"Unexpected error during scan: {e}")
        return finalize_scan(scan_stats, False, f"Error: {e}")

def finalize_scan(scan_stats: Dict[str, Any], success: bool, error_msg: str = None) -> Dict[str, Any]:
    """Enhanced scan summary with threading information"""
    scan_stats["end_time"] = time.time()
    scan_stats["duration"] = scan_stats["end_time"] - scan_stats["start_time"]
    scan_stats["success"] = success

    # Display summary
    print(f"\n{'='*60}")
    print(f"Scan {scan_stats['scan_id']} Summary")
    print(f"{'='*60}")
    print(f"Domain: {scan_stats['domain']}")
    print(f"Duration: {scan_stats['duration']:.1f} seconds")
    print(f"Subdomains found: {scan_stats['subdomains_found']}")
    print(f"Successful scans: {scan_stats['successful_scans']}")
    print(f"Failed scans: {scan_stats['failed_scans']}")

    if scan_stats.get("threading_enabled"):
        print(f"Threading: Enabled ({scan_stats.get('max_workers', 'auto')} workers)")
    else:
        print("Threading: Disabled (sequential mode)")

    if error_msg:
        print(f"Error: {error_msg}")
    elif success and scan_stats["successful_scans"] > 0:
        print("✅ Scan completed successfully!")
        efficiency = scan_stats["successful_scans"] / scan_stats["duration"] * 60
        print(f"Performance: {efficiency:.1f} domains/minute")
    elif success:
        print("✅ Scan completed (no reachable assets found)")
    else:
        print("❌ Scan completed with errors")

    print(f"{'='*60}")
    return scan_stats

# Initialize database
try:
    database.init_db()
    print("Database initialized successfully")
except Exception as e:
    print(f"Database initialization failed: {e}")
    exit(1)

@click.group()
def cli():
    """Aegis-Lite: Ethical Security Scanner for SMEs"""
    pass

@cli.command()
@click.argument("domain")
@click.option("--ethical", is_flag=True, default=True, help="Use ethical scanning mode")
@click.option("--monitor", is_flag=True, help="Show system resource usage")
@click.option("--max-subdomains", type=int, help="Limit number of subdomains to scan")
@click.option("--max-workers", type=int, help="Maximum number of worker threads")
@click.option("--sequential", is_flag=True, help="Use sequential scanning instead of threading")
def scan(domain, ethical, monitor, max_subdomains, max_workers, sequential):
    """Scan a domain for subdomains and security issues"""

    # Show threading information
    if not sequential:
        optimal_threads = get_optimal_thread_count()
        actual_threads = max_workers or optimal_threads
        if ethical:
            actual_threads = min(actual_threads, 3)

        print(f"💫 Thread Pool Scanning Enabled")
        print(f"   System optimal: {optimal_threads} threads")
        print(f"   Using: {actual_threads} threads")
        print(f"   Ethical mode: {'ON' if ethical else 'OFF'}")
    else:
        print("🔄 Sequential Scanning Mode")

    result = run_scan_logic(
        domain,
        ethical,
        monitor,
        max_subdomains,
        max_workers,
        use_threading=not sequential
    )

    if not result.get("success", False):
        exit(1)

@cli.command()
@click.option("--format", "output_format", type=click.Choice(["table", "json", "csv"]),
              default="table", help="Output format")
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
    print(f"  Critical (70+):    {stats['critical_risk_assets']} assets")
    print(f"  High (50-69):      {stats['high_risk_assets']} assets")
    print(f"  Medium (30-49):    {stats['medium_risk_assets']} assets")
    print(f"  Low (1-29):        {stats['low_risk_assets']} assets")
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

    if stats['critical_risk_assets'] > 0:
        print(f"  WARNING: {stats['critical_risk_assets']} critical-risk assets need attention")
    else:
        print("  No critical-risk assets found")

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
    filename = output or f"aegis_export_{time.strftime('%Y%m%d_%H%M%S')}.{format}"
    if not filename.endswith(f".{format}"):
        filename += f".{format}"

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
def benchmark():
    """Benchmark sequential vs threaded scanning performance"""
    test_domains = ['google.com', 'github.com', 'stackoverflow.com']

    print("🚀 Aegis-Lite Performance Benchmark")
    print("=" * 50)

    # Test sequential scanning
    print("\n📊 Testing Sequential Scanning...")
    start_time = time.time()
    result_seq = run_scan_logic("example.com", ethical=True, monitor=False,
                               max_subdomains=3, use_threading=False)
    seq_duration = time.time() - start_time

    # Clear database for fair comparison
    try:
        database.clear_db()
        database.init_db()
    except:
        pass

    # Test threaded scanning
    print("\n🧵 Testing Threaded Scanning...")
    start_time = time.time()
    result_thread = run_scan_logic("example.com", ethical=True, monitor=False,
                                  max_subdomains=3, use_threading=True)
    thread_duration = time.time() - start_time

    # Results
    print("\n📈 Benchmark Results:")
    print(f"Sequential: {seq_duration:.2f}s")
    print(f"Threaded:   {thread_duration:.2f}s")

    if thread_duration > 0:
        speedup = seq_duration / thread_duration
        print(f"Speedup:    {speedup:.2f}x")

        if speedup > 1.2:
            print("✅ Threading provides significant performance improvement!")
        elif speedup > 1.0:
            print("✅ Threading provides modest performance improvement")
        else:
            print("⚠️  Threading overhead may not be worth it for small scans")

@cli.command()
def system_info():
    """Display detailed system information for optimal threading"""
    try:
        import psutil

        print("💻 System Information for Threading Optimization")
        print("=" * 60)

        # CPU Information
        cpu_count = psutil.cpu_count(logical=False)
        cpu_count_logical = psutil.cpu_count(logical=True)
        cpu_freq = psutil.cpu_freq()

        print(f"🔧 CPU Cores:")
        print(f"   Physical: {cpu_count}")
        print(f"   Logical:  {cpu_count_logical}")
        if cpu_freq:
            print(f"   Frequency: {cpu_freq.current:.2f} MHz")

        # Memory Information
        memory = psutil.virtual_memory()
        print(f"\n💾 Memory:")
        print(f"   Total:     {memory.total / (1024**3):.2f} GB")
        print(f"   Available: {memory.available / (1024**3):.2f} GB")
        print(f"   Usage:     {memory.percent:.1f}%")

        # Threading Recommendations
        optimal_threads = get_optimal_thread_count()
        print(f"\n🧵 Threading Recommendations:")
        print(f"   Optimal threads: {optimal_threads}")
        print(f"   Ethical mode:    {min(optimal_threads, 3)} (recommended)")
        print(f"   Aggressive mode: {optimal_threads}")

        # Disk Information
        disk = psutil.disk_usage('.')
        print(f"\n💿 Disk Space:")
        print(f"   Total:     {disk.total / (1024**3):.2f} GB")
        print(f"   Available: {disk.free / (1024**3):.2f} GB")
        print(f"   Usage:     {(disk.used/disk.total)*100:.1f}%")

        # Network interfaces
        net_interfaces = psutil.net_if_addrs()
        print(f"\n🌐 Network Interfaces: {len(net_interfaces)} detected")

        print("\n💡 Performance Tips:")
        if memory.percent > 80:
            print("   ⚠️  High memory usage - consider reducing thread count")
        if cpu_count < 4:
            print("   ⚠️  Limited CPU cores - threading benefit may be minimal")
        if optimal_threads >= 6:
            print("   ✅ Good multi-core system - threading will be beneficial")

    except ImportError:
        print("❌ psutil not installed - install with: pip install psutil")
    except Exception as e:
        print(f"❌ Error getting system info: {e}")

@cli.command()
def interactive():
    """Start interactive mode for easier use"""
    print("Welcome to Aegis-Lite Interactive Mode!")
    print("Enhanced with Threading Support 🧵")
    print()

    while True:
        try:
            print("--- Main Menu ---")
            print("1. Scan a domain")
            print("2. View results")
            print("3. Generate report")
            print("4. Export data")
            print("5. Clear database")
            print("6. System information")
            print("7. Performance benchmark")
            print("8. Exit")

            choice = input("\nEnter your choice (1-8): ").strip()

            if choice == "1":
                domain = input("Enter domain to scan (e.g., example.com): ").strip()
                if domain:
                    ethical = input("Use ethical mode? (Y/n): ").strip().lower() != 'n'
                    monitor = input("Monitor resources? (y/N): ").strip().lower() == 'y'
                    threading = input("Enable threading? (Y/n): ").strip().lower() != 'n'

                    if threading:
                        max_workers = input("Max worker threads (press Enter for auto): ").strip()
                        max_workers = int(max_workers) if max_workers.isdigit() else None
                    else:
                        max_workers = None

                    result = run_scan_logic(domain, ethical, monitor,
                                          use_threading=threading, max_workers=max_workers)
                    if not result.get("success", False):
                        print("Scan failed. Check output above.")
                else:
                    print("Please enter a domain name.")

            elif choice == "2":
                format_choice = input("Display format (table/json/csv) [table]: ").strip() or "table"
                subprocess.run(["python", "-m", "aegis.cli", "view", "--format", format_choice])

            elif choice == "3":
                subprocess.run(["python", "-m", "aegis.cli", "report"])

            elif choice == "4":
                format_choice = input("Export format (json/csv) [json]: ").strip() or "json"
                filename = input("Filename (optional): ").strip()
                cmd = ["python", "-m", "aegis.cli", "export", format_choice]
                if filename:
                    cmd.extend(["-o", filename])
                subprocess.run(cmd)

            elif choice == "5":
                confirm = input("Are you sure you want to clear all data? (yes/no): ").strip().lower()
                if confirm == "yes":
                    subprocess.run(["python", "-m", "aegis.cli", "clear", "--yes"])
                else:
                    print("Operation cancelled.")

            elif choice == "6":
                subprocess.run(["python", "-m", "aegis.cli", "system-info"])

            elif choice == "7":
                print("Running performance benchmark...")
                subprocess.run(["python", "-m", "aegis.cli", "benchmark"])

            elif choice == "8":
                print("Thank you for using Aegis-Lite!")
                break

            else:
                print("Invalid choice. Please select 1-8.")

        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"Error: {e}")

        print()  # Add spacing

if __name__ == '__main__':
    cli()
