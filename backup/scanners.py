"""
Enhanced Scanner Module for Aegis-Lite - FIXED VERSION
=====================================================

Corrected version with proper imports, fixed function signatures, and improved error handling.
"""

import socket
import time
import subprocess
import threading
import json
import logging
import re
import requests
import ssl
import sys
from datetime import datetime  # FIXED: Missing import
from typing import List, Optional, Dict, Any, Tuple
from collections import defaultdict

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logging.getLogger("aegis.scanners").setLevel(logging.ERROR)

class RateLimiter:
    """Thread-safe rate limiter for ethical scanning"""
    def __init__(self, requests_per_second: int = 2):
        self.delay = 1.0 / requests_per_second
        self.last_request = 0
        self._lock = threading.Lock()  # FIXED: Thread safety

    def wait_if_needed(self) -> None:
        """Thread-safe rate limiting with fixed delay"""
        with self._lock:
            elapsed = time.time() - self.last_request
            if elapsed < self.delay:
                sleep_time = self.delay - elapsed
                time.sleep(sleep_time)
            self.last_request = time.time()

# Global rate limiter for ethical scanning
rate_limiter = RateLimiter(requests_per_second=2)

def validate_domain_strict(domain: str) -> bool:
    """Strict domain validation"""
    if not domain or len(domain) > 253:  # RFC compliant
        return False

    # Check for valid domain pattern
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', domain):
        return False

    # Additional checks
    if domain.startswith('.') or domain.endswith('.') or '..' in domain:
        return False

    return True

def validate_input(user_input: str, input_type: str = "domain") -> str:
    """
    FIXED: Improved input validation with strict checking
    """
    if not user_input:
        return ""

    # Convert to string and limit length
    cleaned = str(user_input)[:255].strip()

    # Type-specific validation
    if input_type == "domain":
        if not validate_domain_strict(cleaned):
            return ""
        return cleaned
    elif input_type == "ip":
        # Strict IP validation
        if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', cleaned):
            return ""
        parts = cleaned.split('.')
        if any(int(part) > 255 for part in parts):
            return ""
        return cleaned
    elif input_type == "ports":
        # Only allow numbers, commas, and hyphens
        cleaned = re.sub(r'[^0-9,-]', '', cleaned)
        return cleaned

    return re.sub(r'[;&|`$()\\<>"\']', '', cleaned)

def run_subfinder(domain: str, timeout: int = 120) -> List[str]:
    """
    FIXED: Improved subfinder with better validation and error handling
    """
    clean_domain = validate_input(domain, "domain")
    if not clean_domain:
        logger.error(f"Invalid domain: {domain}")
        return []

    logger.info(f"Starting subdomain enumeration for: {clean_domain}")

    # Use absolute path or check if tool exists
    try:
        subprocess.run(['subfinder', '-h'], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.error("Subfinder not found or not responding")
        return []

    command = [
        'subfinder',
        '-d', clean_domain,
        '-silent',
        '-timeout', '10',
        '-t', '20',
        '-max-time', str(timeout)
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout + 10,  # Buffer for cleanup
            check=False
        )

        if result.returncode != 0 and result.returncode != 1:  # 1 is often "no results"
            logger.warning(f"Subfinder returned code {result.returncode}")

        if result.stdout.strip():
            subdomains = []
            for line in result.stdout.strip().split('\n'):
                line = line.strip()
                if line and not line.startswith('[') and validate_domain_strict(line):
                    subdomains.append(line)

            # Remove duplicates and sort
            subdomains = sorted(list(set(subdomains)))
            logger.info(f"Found {len(subdomains)} valid subdomains for {clean_domain}")
            return subdomains
        else:
            logger.info(f"No subdomains found for {clean_domain}")
            return []

    except subprocess.TimeoutExpired:
        logger.error(f"Subfinder timed out after {timeout} seconds for {clean_domain}")
        return []
    except Exception as e:
        logger.error(f"Subfinder error: {e}")
        return []

def run_nmap(ip: str, domain: str, ethical: bool = False) -> str:
    """
    FIXED: Improved nmap scanning with better validation
    """
    logger.info(f"Starting Nmap scan for: {ip} ({domain})")

    # Strict IP validation
    clean_ip = validate_input(ip, "ip")
    if not clean_ip:
        logger.error(f"Invalid IP address: {ip}")
        return ""

    # Check if nmap is available
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        logger.error("Nmap not found or not responding")
        return ""

    # Determine ports based on ethical mode
    if ethical:
        ports_to_scan = "80,443"
        scan_options = ["-T3", "--scan-delay", "1s"]
    else:
        ports_to_scan = "22,23,25,53,80,135,139,443,445,993,995,3306,3389,5432,5900,8080,8443"
        scan_options = ["-T4"]

    command = [
        "nmap",
        "-sT",  # TCP Connect scan
        "-Pn",  # Skip ping
        "--open",  # Only show open ports
        "-p", ports_to_scan,
        "--host-timeout", "180s",
        "--max-retries", "1"
    ] + scan_options + [clean_ip]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=220,  # Slightly longer than host timeout
            check=False
        )

        # Parse open ports from output
        open_ports = []
        for line in result.stdout.split('\n'):
            if '/tcp' in line and 'open' in line:
                port_match = re.match(r'^(\d+)/tcp', line.strip())
                if port_match:
                    port = port_match.group(1)
                    if 1 <= int(port) <= 65535:  # Valid port range
                        open_ports.append(port)

        ports_str = ','.join(sorted(open_ports, key=int)) if open_ports else ""
        logger.info(f"Nmap completed for {domain}: {ports_str}")
        return ports_str

    except subprocess.TimeoutExpired:
        logger.warning(f"Nmap timed out for {domain}")
        return ""
    except Exception as e:
        logger.error(f"Nmap error for {domain}: {e}")
        return ""

def resolve_ip(target: str, timeout: int = 10) -> str:
    """
    FIXED: Improved DNS resolution with proper timeout handling
    """
    clean_target = validate_input(target, "domain")
    if not clean_target:
        return "Unknown"

    try:
        # Use socket with proper timeout
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)

        ip_address = socket.gethostbyname(clean_target)

        # Validate the returned IP
        if validate_input(ip_address, "ip"):
            return ip_address
        else:
            logger.warning(f"Invalid IP returned for {clean_target}: {ip_address}")
            return "Unknown"

    except (socket.gaierror, socket.timeout, OSError) as e:
        logger.debug(f"DNS resolution failed for {clean_target}: {e}")
        return "Unknown"
    except Exception as e:
        logger.error(f"Unexpected DNS error for {clean_target}: {e}")
        return "Unknown"
    finally:
        # Always restore timeout
        socket.setdefaulttimeout(old_timeout)

def calculate_score(ports: str) -> int:
    """
    FIXED: Improved scoring algorithm with better logic
    """
    if not ports or not isinstance(ports, str):
        return 0

    # Start with base security score
    base_score = 50

    # Risk penalties for different services
    port_penalties = {
        '21': 20,   # FTP
        '22': 15,   # SSH
        '23': 40,   # Telnet (very dangerous)
        '25': 10,   # SMTP
        '53': 5,    # DNS
        '80': 5,    # HTTP
        '135': 25,  # Windows RPC
        '139': 30,  # NetBIOS
        '443': 0,   # HTTPS (secure)
        '445': 35,  # SMB (high risk)
        '993': 5,   # IMAPS
        '995': 5,   # POP3S
        '3306': 25, # MySQL
        '3389': 30, # RDP
        '5432': 25, # PostgreSQL
        '5900': 30, # VNC
        '8080': 15, # HTTP Proxy
        '8443': 5   # HTTPS Alternate
    }

    port_list = [p.strip() for p in ports.split(',') if p.strip()]

    if not port_list:
        return 0

    # Calculate penalties
    total_penalty = 0
    for port in port_list:
        if port.isdigit():
            total_penalty += port_penalties.get(port, 10)  # Default penalty for unknown ports

    # Additional penalties
    if '443' not in port_list and ('80' in port_list or '8080' in port_list):
        total_penalty += 15  # HTTP without HTTPS

    if len(port_list) > 5:
        total_penalty += 10  # Too many open ports

    # Calculate final score
    final_score = max(0, base_score - total_penalty)
    return min(100, final_score)  # Cap at 100

def check_ssl_vulnerabilities(domain: str) -> Dict[str, Any]:
    """
    FIXED: Improved SSL checking with proper error handling
    """
    findings = {
        "has_ssl": False,
        "valid_cert": False,
        "is_expired": False,
        "days_left": 0,
        "is_weak_cipher": False,
        "cipher_details": "",
        "cert_error": None
    }

    clean_domain = validate_input(domain, "domain")
    if not clean_domain:
        findings["cert_error"] = "Invalid domain"
        return findings

    try:
        rate_limiter.wait_if_needed()

        # Create SSL context with verification
        context = ssl.create_default_context()

        with socket.create_connection((clean_domain, 443), timeout=15) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                findings["has_ssl"] = True

                try:
                    cert = ssock.getpeercert()

                    # Verify hostname matches certificate
                    ssl.match_hostname(cert, clean_domain)
                    findings["valid_cert"] = True

                    # Check expiration
                    if cert and 'notAfter' in cert:
                        try:
                            expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                            days_left = (expiry_date - datetime.now()).days
                            findings["days_left"] = days_left
                            findings["is_expired"] = days_left < 0
                        except ValueError as e:
                            logger.warning(f"Could not parse certificate date for {clean_domain}: {e}")

                    # Check cipher strength
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        findings["cipher_details"] = cipher_name

                        # Check for weak ciphers
                        weak_indicators = ['RC4', 'DES', 'MD5', 'NULL']
                        findings["is_weak_cipher"] = any(weak in cipher_name for weak in weak_indicators)

                except ssl.CertificateError as e:
                    findings["valid_cert"] = False
                    findings["cert_error"] = str(e)
                except Exception as e:
                    findings["cert_error"] = f"Certificate processing error: {str(e)}"

    except (socket.timeout, ConnectionRefusedError, OSError):
        # These are expected for domains without HTTPS
        pass
    except Exception as e:
        findings["cert_error"] = f"SSL check error: {str(e)}"
        logger.error(f"SSL check error for {clean_domain}: {e}")

    return findings

def check_web_vulnerabilities(url: str, templates: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    FIXED: Changed return type to Dict to match CLI expectations
    """
    if not templates:
        templates = ["cves", "exposed-panels", "misconfigurations", "vulnerabilities"]

    # Initialize findings structure
    findings = {
        "has_admin_panel": False,
        "vulnerabilities": [],
        "error": None,
        "scan_completed": False
    }

    # Basic URL validation
    if not url or not url.startswith(('http://', 'https://')):
        findings["error"] = "Invalid URL format"
        return findings

    # Check if nuclei is available
    try:
        result = subprocess.run(['nuclei', '-version'], capture_output=True, timeout=5)
        if result.returncode != 0:
            raise FileNotFoundError()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        findings["error"] = "Nuclei not found"
        return findings

    command = [
        "nuclei",
        "-target", url,
        "-json",
        "-silent",
        "-t", ",".join(templates),
        "-rate-limit", "10",  # Rate limiting for ethical scanning
        "-timeout", "10"
    ]

    try:
        logger.info(f"Starting Nuclei scan for: {url}")

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,
            check=False
        )

        findings["scan_completed"] = True

        # Process results
        vulnerabilities = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                try:
                    vuln_data = json.loads(line)
                    vulnerabilities.append({
                        "template_id": vuln_data.get("template-id", "unknown"),
                        "name": vuln_data.get("info", {}).get("name", "Unknown"),
                        "severity": vuln_data.get("info", {}).get("severity", "info"),
                        "host": vuln_data.get("host", url)
                    })

                    # Check for admin panels
                    template_id = vuln_data.get("template-id", "")
                    if "admin" in template_id.lower() or "panel" in template_id.lower():
                        findings["has_admin_panel"] = True

                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse Nuclei output line")
                    continue

        findings["vulnerabilities"] = vulnerabilities

        if result.stderr and "No templates loaded" in result.stderr:
            findings["error"] = "No templates loaded - run 'nuclei -update-templates'"

    except subprocess.TimeoutExpired:
        findings["error"] = "Scan timed out"
        logger.warning(f"Nuclei scan timed out for {url}")
    except Exception as e:
        findings["error"] = f"Scan error: {str(e)}"
        logger.error(f"Nuclei scan error for {url}: {e}")

    return findings

# Utility functions remain the same but with improved validation
def is_valid_domain(domain: str) -> bool:
    """FIXED: Use the strict validation function"""
    return validate_domain_strict(domain)

def is_valid_ip(ip: str) -> bool:
    """FIXED: Improved IP validation"""
    if ip in ["Unknown", "TBD"]:
        return True
    return bool(validate_input(ip, "ip"))

def test_scanners():
    """Test all scanner functions with better error reporting"""
    print("Testing scanner functions...")

    test_results = {}

    # Test domain validation
    test_results["domain_validation"] = is_valid_domain('example.com')
    print(f"Domain validation: {test_results['domain_validation']}")

    # Test IP validation
    test_results["ip_validation"] = is_valid_ip('192.168.1.1')
    print(f"IP validation: {test_results['ip_validation']}")

    # Test DNS resolution
    test_results["dns_resolution"] = resolve_ip('google.com')
    print(f"DNS resolve for google.com: {test_results['dns_resolution']}")

    # Only proceed with further tests if basic validation works
    if test_results["dns_resolution"] != "Unknown":
        # Test Nmap (only if we have a valid IP)
        test_results["nmap_scan"] = run_nmap(test_results["dns_resolution"], 'google.com', True)
        print(f"Nmap scan for google.com: {test_results['nmap_scan']}")

        # Test SSL check
        test_results["ssl_check"] = check_ssl_vulnerabilities('google.com')
        print(f"SSL check for google.com: {json.dumps(test_results['ssl_check'], indent=2)}")

        # Test score calculation
        test_results["score_calculation"] = calculate_score("80,443,22")
        print(f"Score for ports 80,443,22: {test_results['score_calculation']}")

    return test_results

if __name__ == "__main__":
    test_scanners()
