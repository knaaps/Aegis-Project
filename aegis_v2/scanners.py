"""
Scanner Module for Aegis
=========================================================

Fixed version with corrected risk scoring logic,
basic SSL certificate expiry checks, and expanded nuclei templates.
"""

import socket
import time
import subprocess
import json
import re
import requests
import ssl
from datetime import datetime, timezone
from typing import List, Dict, Any

def simple_rate_limit():
    """Simple 3-second delay for ethical scanning"""
    time.sleep(3)

def validate_domain(domain: str) -> bool:
    """Check if domain format is valid"""
    if not domain or len(domain) > 253:
        return False

    # Basic domain pattern check
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain))

def validate_ip(ip: str) -> bool:
    """Check if IP format is valid"""
    if ip in ["Unknown", "TBD"]:
        return True

    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(part) <= 255 for part in parts)
    except:
        return False

def clean_input(user_input: str) -> str:
    """Basic input cleaning"""
    if not user_input:
        return ""

    # Remove dangerous characters
    cleaned = re.sub(r'[;&|`$()\\<>"\']', '', str(user_input)[:255])
    return cleaned.strip()

def run_subfinder(domain: str, timeout: int = 120) -> List[str]:
    """
    Run subfinder to find subdomains
    Simplified version with basic error handling
    """
    if not validate_domain(domain):
        print(f"Invalid domain: {domain}")
        return []

    print(f"Finding subdomains for: {domain}")

    # Check if subfinder is available
    try:
        subprocess.run(['subfinder', '-h'], capture_output=True, timeout=5)
    except:
        print("Error: Subfinder not installed or not found")
        return []

    # Simple subfinder command
    command = ['subfinder', '-d', domain, '-silent']

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.stdout.strip():
            subdomains = []
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and validate_domain(line):
                    subdomains.append(line)

            # Remove duplicates and sort
            subdomains = sorted(list(set(subdomains)))
            print(f"Found {len(subdomains)} subdomains")
            return subdomains
        else:
            print(f"No subdomains found for {domain}")
            return []

    except subprocess.TimeoutExpired:
        print(f"Subfinder timed out after {timeout} seconds")
        return []
    except Exception as e:
        print(f"Subfinder error: {e}")
        return []

def run_nmap(ip: str, domain: str, ethical: bool = False) -> str:
    """
    Run nmap port scan
    Simplified version focusing on common ports
    """
    if not validate_ip(ip):
        print(f"Invalid IP: {ip}")
        return ""

    print(f"Scanning ports for: {domain} ({ip})")

    # Check if nmap is available
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
    except:
        print("Error: Nmap not installed")
        return ""

    # Simple port selection
    if ethical:
        ports = "80,443"  # Only HTTP/HTTPS for ethical scans
    else:
        ports = "22,25,53,80,135,443,445,3306,3389,5432,8080"  # Common ports

    # Basic nmap command
    command = [
        "nmap",
        "-sT",  # TCP connect scan (no root needed)
        "-Pn",  # Skip ping
        "--open",  # Only show open ports
        "-p", ports,
        "--host-timeout", "60s",
        ip
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=120
        )

        # Extract open ports
        open_ports = []
        for line in result.stdout.split('\n'):
            if '/tcp' in line and 'open' in line:
                port_match = re.match(r'^(\d+)/tcp', line.strip())
                if port_match:
                    port = port_match.group(1)
                    if 1 <= int(port) <= 65535:
                        open_ports.append(port)

        ports_str = ','.join(sorted(open_ports, key=int))
        print(f"Open ports found: {ports_str}")
        return ports_str

    except subprocess.TimeoutExpired:
        print(f"Nmap scan timed out for {domain}")
        return ""
    except Exception as e:
        print(f"Nmap error: {e}")
        return ""

def resolve_ip(domain: str, timeout: int = 10) -> str:
    """
    Resolve domain to IP address
    Simplified DNS resolution
    """
    if not validate_domain(domain):
        return "Unknown"

    try:
        # Set socket timeout
        socket.setdefaulttimeout(timeout)
        ip_address = socket.gethostbyname(domain)

        if validate_ip(ip_address):
            return ip_address
        else:
            return "Unknown"

    except Exception:
        return "Unknown"
    finally:
        socket.setdefaulttimeout(None)

def calculate_score(ports: str) -> int:
    """
    Calculate basic risk score (0-100)
    FIXED: Higher scores now indicate HIGHER RISK (not lower risk)
    """
    if not ports:
        return 0

    # Start with baseline risk score
    risk_score = 10

    # Port-based risk scoring (higher score = higher risk)
    port_list = [p.strip() for p in ports.split(',') if p.strip()]

    for port in port_list:
        if port == '443':  # HTTPS - secure, low additional risk
            risk_score += 5
        elif port == '80':  # HTTP - insecure, moderate risk
            risk_score += 15
        elif port in ['22', '23', '135', '445', '3389']:  # High-risk administrative ports
            risk_score += 25
        elif port in ['21', '25', '53', '110', '143']:  # Other risky services
            risk_score += 20
        else:  # Unknown services - moderate risk
            risk_score += 10

    # Additional risk for HTTP without HTTPS
    if '80' in port_list and '443' not in port_list:
        risk_score += 15  # No encryption available

    # Risk penalty for too many open ports (attack surface)
    if len(port_list) > 5:
        risk_score += 20

    # Keep score in valid range
    return max(0, min(100, risk_score))

def check_https(domain: str) -> Dict[str, Any]:
    """
    Enhanced HTTPS check with certificate expiry
    """
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
        # First, check basic HTTPS connectivity
        response = requests.get(
            f"https://{domain}",
            timeout=15,
            verify=True,
            allow_redirects=True
        )

        if response.status_code == 200:
            result["has_https"] = True
            result["valid_cert"] = True

            # Now check certificate expiry
            try:
                # Get SSL certificate info
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()

                        # Parse expiry date
                        expiry_str = cert['notAfter']
                        # Format: 'Mar 15 12:00:00 2024 GMT'
                        expiry_date = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                        expiry_date = expiry_date.replace(tzinfo=timezone.utc)

                        # Calculate days until expiry
                        now = datetime.now(timezone.utc)
                        days_left = (expiry_date - now).days

                        result["days_until_expiry"] = days_left
                        result["cert_expires_soon"] = days_left < 30  # Less than 30 days

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

def check_web_vulnerabilities(url: str) -> Dict[str, Any]:
    """
    Enhanced web vulnerability check with expanded nuclei templates
    """
    result = {
        "vulnerabilities": [],
        "has_admin_panel": False,
        "scan_completed": False,
        "error": None
    }

    if not url or not url.startswith(('http://', 'https://')):
        result["error"] = "Invalid URL"
        return result

    # Check if nuclei is available
    try:
        subprocess.run(['nuclei', '-version'], capture_output=True, timeout=5)
    except:
        result["error"] = "Nuclei not installed"
        return result

    # Expanded nuclei command with more templates
    # Still keeping it simple but covering more ground
    command = [
        "nuclei",
        "-target", url,
        "-json",
        "-silent",
        "-t", "cves,exposed-panels,vulnerabilities,misconfiguration,default-logins",  # Expanded templates
        "-timeout", "10",
        "-retries", "1"  # Single retry to keep it fast
    ]

    try:
        print(f"Checking vulnerabilities for: {url}")

        result_process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180  # 3 minute timeout for expanded scan
        )

        result["scan_completed"] = True

        # Process results
        for line in result_process.stdout.strip().split('\n'):
            if line.strip():
                try:
                    vuln_data = json.loads(line)
                    vulnerability = {
                        "name": vuln_data.get("info", {}).get("name", "Unknown"),
                        "severity": vuln_data.get("info", {}).get("severity", "info"),
                        "template": vuln_data.get("template-id", "unknown")
                    }
                    result["vulnerabilities"].append(vulnerability)

                    # Check for admin panels
                    template_id = vuln_data.get("template-id", "").lower()
                    vuln_name = vulnerability["name"].lower()
                    if any(keyword in template_id or keyword in vuln_name
                           for keyword in ["admin", "panel", "login", "dashboard"]):
                        result["has_admin_panel"] = True

                except json.JSONDecodeError:
                    continue  # Skip invalid JSON lines

    except subprocess.TimeoutExpired:
        result["error"] = "Scan timed out"
    except Exception as e:
        result["error"] = f"Scan error: {str(e)}"

    return result

def show_system_resources():
    """Simple system resource display"""
    try:
        import psutil
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        print(f"System Resources - CPU: {cpu:.1f}%, RAM: {ram:.1f}%")
    except ImportError:
        print("System resource monitoring not available (psutil not installed)")

def test_scanners():
    """Simple test function for all scanners"""
    print("Testing Aegis-Lite scanners...")

    # Test domain validation
    print("Testing domain validation...")
    assert validate_domain('example.com') == True
    assert validate_domain('invalid..domain') == False

    # Test IP validation
    print("Testing IP validation...")
    assert validate_ip('192.168.1.1') == True
    assert validate_ip('999.1.1.1') == False

    # Test DNS resolution
    print("Testing DNS resolution...")
    ip = resolve_ip('google.com')
    print(f"Google.com resolves to: {ip}")

    # Test FIXED score calculation
    print("Testing FIXED risk score calculation...")
    score_https_only = calculate_score("443")
    score_http_only = calculate_score("80")
    score_risky_ports = calculate_score("22,23,80,3389")

    print(f"HTTPS-only risk score: {score_https_only}")
    print(f"HTTP-only risk score: {score_http_only}")
    print(f"Risky ports risk score: {score_risky_ports}")

    # Verify the logic is correct
    assert score_http_only > score_https_only, "HTTP should be riskier than HTTPS"
    assert score_risky_ports > score_http_only, "Multiple risky ports should have highest risk"

    # Test enhanced HTTPS check
    print("Testing enhanced HTTPS check with certificate expiry...")
    https_result = check_https('google.com')
    print(f"Google.com HTTPS result: {https_result}")

    print("All tests completed successfully!")

if __name__ == "__main__":
    test_scanners()
