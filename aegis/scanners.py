"""
Enhanced Scanner Module for Aegis-Lite with Thread Pool Support
===============================================================
Added concurrent processing while maintaining ethical scanning practices
"""

#nuclei expansion
import os
import shlex

import socket
import time
import subprocess
import json
import re
import requests
import ssl
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import psutil
from .utils import validate_domain, validate_ip, clean_input

# Global locks for thread safety
print_lock = Lock()
stats_lock = Lock()

def safe_print(message: str, prefix: str = ""):
    """Thread-safe printing"""
    with print_lock:
        print(f"{prefix}{message}")

def simple_rate_limit():
    """Simple 2-second delay for ethical scanning"""
    time.sleep(2)

def run_subfinder(domain: str, timeout: int = 120) -> List[str]:
    """Run subfinder to find subdomains"""
    if not validate_domain(domain):
        safe_print(f"Invalid domain: {domain}")
        return []

    safe_print(f"Finding subdomains for: {domain}")

    try:
        subprocess.run(['subfinder', '-h'], capture_output=True, timeout=5)
    except:
        safe_print("Error: Subfinder not installed")
        return []

    command = ['subfinder', '-d', clean_input(domain), '-silent']

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)

        if result.stdout.strip():
            subdomains = []
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and validate_domain(line):
                    subdomains.append(line)

            subdomains = sorted(list(set(subdomains)))
            safe_print(f"Found {len(subdomains)} subdomains")
            return subdomains
        else:
            safe_print(f"No subdomains found for {domain}")
            return []

    except subprocess.TimeoutExpired:
        safe_print(f"Subfinder timed out after {timeout} seconds")
        return []
    except Exception as e:
        safe_print(f"Subfinder error: {e}")
        return []

def run_nmap(ip: str, domain: str, ethical: bool = True) -> str:
    """Run nmap port scan"""
    if not validate_ip(ip):
        safe_print(f"Invalid IP: {ip}", f"[{domain}] ")
        return ""

    safe_print(f"Scanning ports for: {domain} ({ip})", f"[{domain}] ")

    try:
        subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
    except:
        safe_print("Error: Nmap not installed", f"[{domain}] ")
        return ""

    # Port selection based on ethical mode
    ports = "80,443" if ethical else "22,25,53,80,135,443,445,3306,3389,5432,8080"

    command = [
        "nmap", "-sT", "-Pn", "--open", "-p", ports,
        "--host-timeout", "60s", clean_input(ip)
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)

        open_ports = []
        for line in result.stdout.split('\n'):
            if '/tcp' in line and 'open' in line:
                port_match = re.match(r'^(\d+)/tcp', line.strip())
                if port_match:
                    port = port_match.group(1)
                    if 1 <= int(port) <= 65535:
                        open_ports.append(port)

        ports_str = ','.join(sorted(open_ports, key=int))
        safe_print(f"Open ports found: {ports_str}", f"[{domain}] ")
        return ports_str

    except subprocess.TimeoutExpired:
        safe_print(f"Nmap scan timed out for {domain}", f"[{domain}] ")
        return ""
    except Exception as e:
        safe_print(f"Nmap error: {e}", f"[{domain}] ")
        return ""

def resolve_ip(domain: str, timeout: int = 10) -> str:
    """Resolve domain to IP address"""
    if not validate_domain(domain):
        return "Unknown"

    try:
        socket.setdefaulttimeout(timeout)
        ip_address = socket.gethostbyname(clean_input(domain))
        return ip_address if validate_ip(ip_address) else "Unknown"
    except Exception:
        return "Unknown"
    finally:
        socket.setdefaulttimeout(None)

def calculate_score(ports: str, vulns: list = None) -> int:
    """
    Calculate risk score using CVSS (preferred) or fallback to port-based scoring.
    """
    # If we have CVSS scores from vulnerabilities, use them
    if vulns:
        cvss_scores = [v.get("cvss_score") for v in vulns if v.get("cvss_score")]
        if cvss_scores:
            return int(max(cvss_scores) * 10)  # normalize 0–10 → 0–100

    # Otherwise, fallback: simpler heuristic
    if not ports:
        return 0

    port_list = [p.strip() for p in ports.split(',') if p.strip()]
    # Simple baseline: each risky service adds 10 points
    risky_ports = {"21", "23", "25", "135", "445", "3389"}
    score = sum(10 if p not in risky_ports else 20 for p in port_list)

    return min(100, score)


def check_https(domain: str) -> Dict[str, Any]:
    """Check HTTPS availability and certificate status"""
    result = {
        "has_https": False,
        "valid_cert": False,
        "cert_expires_soon": False,
        "days_until_expiry": None,
        "error": None
    }

    if not validate_domain(domain):
        result["error"] = "Invalid domain"
        return result

    try:
        # Check HTTPS connectivity
        response = requests.get(
            f"https://{clean_input(domain)}",
            timeout=15, verify=True, allow_redirects=True
        )

        if response.status_code == 200:
            result["has_https"] = True
            result["valid_cert"] = True

            # Check certificate expiry
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        expiry_str = cert['notAfter']
                        expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                        expiry_date = expiry_date.replace(tzinfo=timezone.utc)

                        now = datetime.now(timezone.utc)
                        days_left = (expiry_date - now).days

                        result["days_until_expiry"] = days_left
                        result["cert_expires_soon"] = days_left < 30

            except Exception as cert_error:
                result["error"] = f"Certificate check failed: {cert_error}"

    except requests.exceptions.SSLError:
        result["has_https"] = True
        result["valid_cert"] = False
        result["error"] = "SSL certificate error"
    except requests.exceptions.ConnectionError:
        result["error"] = "Connection failed"
    except requests.exceptions.Timeout:
        result["error"] = "Request timed out"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"

    return result

def update_nuclei_templates() -> Dict[str, Any]:
    """
    Try to update nuclei templates via CLI. Returns status dict.
    """
    try:
        result = subprocess.run(["nuclei", "-ut"], capture_output=True, text=True, timeout=120)
        return {"updated": result.returncode == 0, "stdout": result.stdout, "stderr": result.stderr}
    except Exception as e:
        return {"updated": False, "error": str(e)}

def check_web_vulnerabilities(url: str,
                              tags: str = "cves,exposed-panels,vulnerabilities,misconfiguration",
                              severity: str = None,
                              templates_dir: str = None,
                              timeout: int = 180) -> Dict[str, Any]:
    """
    Run nuclei against 'url' with optional tag/severity filters and return parsed results.
    - tags: comma-separated tags to restrict templates (None => all)
    - severity: comma-separated severity filter (e.g. 'critical,high')
    - templates_dir: optional path to nuclei templates (overrides default)
    """
    result = {
        "vulnerabilities": [],
        "has_admin_panel": False,
        "scan_completed": False,
        "error": None,
        "raw": ""
    }

    if not url or not url.startswith(('http://', 'https://')):
        result["error"] = "Invalid URL"
        return result

    # Prefer explicit templates_dir -> else rely on nuclei builtin locations
    templates_dir = templates_dir or os.environ.get("NUCLEI_TEMPLATES_DIR")

    cmd = ["nuclei", "-target", url, "-json", "-silent", "-retries", "1", "-timeout", "10"]
    # If templates_dir supplied, point nuclei at it
    if templates_dir:
        cmd.extend(["-t", templates_dir])

    # tags filter (prefer tags over templates list)
    if tags:
        cmd.extend(["-tags", tags])

    if severity:
        cmd.extend(["-severity", severity])

    # Consider adding a rate limit if you want: cmd.extend(["-rate-limit", "10"])

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        result["raw"] = proc.stdout
        result["scan_completed"] = True

        seen = set()
        for line in proc.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                vuln_data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = vuln_data.get("info", {}) or {}
            template_id = vuln_data.get("template-id") or info.get("name") or vuln_data.get("id")
            severity_field = info.get("severity", "") or vuln_data.get("severity", "")
            # Attempt to find cvss from different possible fields
            cvss_score = None
            for key in ("cvss", "cvss-score", "cvss_v3", "cvss_v2"):
                v = info.get(key) or vuln_data.get(key)
                if v:
                    try:
                        cvss_score = float(v)
                        break
                    except Exception:
                        # some templates embed cvss vectors; leave as None
                        pass

            vuln_key = f"{template_id}:{vuln_data.get('matched-at', '')}"
            if vuln_key in seen:
                continue
            seen.add(vuln_key)

            vulnerability = {
                "name": info.get("name", template_id),
                "severity": (severity_field or "info").lower(),
                "template": template_id,
                "cvss_score": cvss_score  # may be None
            }

            # Heuristic: template id / name may indicate admin panels / dashboards
            tlow = (template_id or "").lower()
            nlow = (vulnerability["name"] or "").lower()
            if any(k in tlow or k in nlow for k in ["admin", "panel", "login", "dashboard"]):
                result["has_admin_panel"] = True

            result["vulnerabilities"].append(vulnerability)

    except subprocess.TimeoutExpired:
        result["error"] = "Scan timed out"
    except Exception as e:
        result["error"] = f"Scan error: {str(e)}"

    return result


def show_system_resources():
    """Simple system resource display"""
    try:
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        safe_print(f"System Resources - CPU: {cpu:.1f}%, RAM: {ram:.1f}%")
    except ImportError:
        safe_print("System resource monitoring not available")

def get_optimal_thread_count() -> int:
    """Calculate optimal thread count based on system resources"""
    try:
        # Get system info
        cpu_count = psutil.cpu_count()
        memory_gb = psutil.virtual_memory().total / (1024**3)

        # Conservative approach for SMEs
        # Use fewer threads to avoid overwhelming target servers
        if memory_gb < 4:
            return min(3, cpu_count)
        elif memory_gb < 8:
            return min(5, cpu_count)
        else:
            return min(8, cpu_count)
    except:
        return 3  # Safe default

def scan_single_domain(domain: str, ethical: bool, scan_stats: Dict[str, Any],
                      domain_index: int, total_domains: int) -> Optional[Dict[str, Any]]:
    """Scan a single domain - thread worker function"""
    thread_prefix = f"[{domain_index:02d}/{total_domains:02d}] "

    try:
        # Ethical rate limiting
        if ethical and domain_index > 1:
            safe_print("Waiting 2 seconds (ethical mode)...", thread_prefix)
            simple_rate_limit()

        safe_print(f"Starting scan: {domain}", thread_prefix)

        # Resolve IP
        safe_print("→ Resolving IP...", thread_prefix)
        ip = resolve_ip(domain, timeout=10)
        if ip == "Unknown":
            safe_print("✗ Could not resolve IP", thread_prefix)
            with stats_lock:
                scan_stats["failed_scans"] += 1
            return None

        safe_print(f"→ IP: {ip}", thread_prefix)

        # Scan ports
        safe_print("→ Scanning ports...", thread_prefix)
        ports = run_nmap(ip, domain, ethical)

        # Check HTTPS
        safe_print("→ Checking HTTPS...", thread_prefix)
        https_result = check_https(domain)

        # Check web vulnerabilities if HTTP/HTTPS is available
        web_result = {"vulnerabilities": [], "has_admin_panel": False}
        if ports and ('80' in ports or '443' in ports):
            safe_print("→ Checking vulnerabilities...", thread_prefix)
            protocol = "https" if '443' in ports else "http"
            web_result = check_web_vulnerabilities(f"{protocol}://{domain}")

        # Calculate risk score
        score = calculate_score(ports)

        # Prepare result data
        result_data = {
            "domain": domain,
            "ip": ip,
            "ports": ports,
            "score": score,
            "ssl_vulnerabilities": json.dumps(https_result),
            "web_vulnerabilities": json.dumps(web_result)
        }

        safe_print(f"✓ Completed: Score {score}, Ports: {ports or 'none'}", thread_prefix)

        with stats_lock:
            scan_stats["successful_scans"] += 1

        return result_data

    except Exception as e:
        safe_print(f"✗ Error scanning {domain}: {e}", thread_prefix)
        with stats_lock:
            scan_stats["failed_scans"] += 1
        return None

def scan_domains_concurrent(domains_to_scan: List[str], ethical: bool,
                          max_workers: Optional[int] = None) -> List[Dict[str, Any]]:
    """
    Scan multiple domains concurrently using ThreadPoolExecutor

    Args:
        domains_to_scan: List of domains to scan
        ethical: Whether to use ethical scanning mode
        max_workers: Maximum number of worker threads (auto-calculated if None)

    Returns:
        List of scan results
    """
    if not domains_to_scan:
        return []

    # Calculate optimal thread count if not specified
    if max_workers is None:
        max_workers = get_optimal_thread_count()

    # Adjust for ethical scanning (reduce concurrent requests)
    if ethical:
        max_workers = min(max_workers, 3)

    safe_print(f"Using {max_workers} worker threads for concurrent scanning")

    # Initialize shared statistics
    scan_stats = {
        "successful_scans": 0,
        "failed_scans": 0
    }

    results = []

    # Use ThreadPoolExecutor for concurrent scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all scan tasks
        future_to_domain = {
            executor.submit(
                scan_single_domain,
                domain,
                ethical,
                scan_stats,
                i,
                len(domains_to_scan)
            ): domain
            for i, domain in enumerate(domains_to_scan, 1)
        }

        # Collect results as they complete
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                safe_print(f"Thread exception for {domain}: {e}")
                with stats_lock:
                    scan_stats["failed_scans"] += 1

    safe_print(f"\nConcurrent scan completed:")
    safe_print(f"  Successful: {scan_stats['successful_scans']}")
    safe_print(f"  Failed: {scan_stats['failed_scans']}")

    return results

def monitor_system_resources(threshold_cpu: float = 80.0, threshold_ram: float = 85.0) -> Dict[str, Any]:
    """
    Monitor system resources during scanning

    Args:
        threshold_cpu: CPU usage threshold (%)
        threshold_ram: RAM usage threshold (%)

    Returns:
        Dictionary with resource status
    """
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()

        status = {
            "cpu_percent": cpu_percent,
            "ram_percent": memory.percent,
            "available_ram_gb": memory.available / (1024**3),
            "cpu_overloaded": cpu_percent > threshold_cpu,
            "ram_overloaded": memory.percent > threshold_ram,
            "system_healthy": cpu_percent <= threshold_cpu and memory.percent <= threshold_ram
        }

        if not status["system_healthy"]:
            safe_print("⚠️  System resources are under high load!")
            safe_print(f"   CPU: {cpu_percent:.1f}% | RAM: {memory.percent:.1f}%")

        return status

    except Exception as e:
        safe_print(f"Resource monitoring error: {e}")
        return {"system_healthy": True, "error": str(e)}

def test_scanners():
    """Enhanced test function for scanners including thread pool"""
    print("Testing Aegis-Lite scanners with thread pool...")

    # Test DNS resolution
    print("Testing DNS resolution...")
    ip = resolve_ip('google.com')
    print(f"Google.com resolves to: {ip}")

    # Test risk score calculation
    print("Testing risk score calculation...")
    score_low = calculate_score("443")
    score_high = calculate_score("22,23,80,3389")

    print(f"HTTPS-only risk score: {score_low}")
    print(f"High-risk ports score: {score_high}")

    assert score_high > score_low, "High-risk ports should have higher score"

    # Test thread pool functionality
    print("Testing thread pool with dummy domains...")
    test_domains = ['google.com', 'github.com']
    results = scan_domains_concurrent(test_domains, ethical=True, max_workers=2)
    print(f"Thread pool test completed: {len(results)} results")

    # Test resource monitoring
    print("Testing resource monitoring...")
    resources = monitor_system_resources()
    print(f"System status: {'Healthy' if resources.get('system_healthy') else 'Overloaded'}")

    print("All tests completed successfully!")

if __name__ == "__main__":
    test_scanners()
