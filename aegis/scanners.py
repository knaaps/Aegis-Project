"""
Enhanced Scanner Module for Aegis-Lite
======================================

Fixed version with corrected function signatures, simplified logic,
and better error handling.
"""

import socket
import time
import subprocess
import json
import logging
import re
import requests
import ssl
from typing import List, Optional, Dict, Any
from collections import defaultdict

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
logging.getLogger("aegis.scanners").setLevel(logging.ERROR)

class RateLimiter:
    """Simplified rate limiter for ethical scanning"""

    def __init__(self, requests_per_second: int = 2):
        self.delay = 1.0 / requests_per_second
        self.last_request = 0

    def wait_if_needed(self) -> None:
        """Simple rate limiting with fixed delay"""
        elapsed = time.time() - self.last_request
        if elapsed < self.delay:
            sleep_time = self.delay - elapsed
            time.sleep(sleep_time)
        self.last_request = time.time()

# Global rate limiter for ethical scanning
rate_limiter = RateLimiter(requests_per_second=2)

def validate_input(user_input: str, input_type: str = "domain") -> str:
    """
    Simplified input validation
    """
    if not user_input:
        return ""

    # Remove dangerous characters
    cleaned = re.sub(r'[;&|`$()]', '', str(user_input)).strip()

    validation_patterns = {
        "domain": r'[^a-zA-Z0-9.-]',
        "ports": r'[^0-9,-]',
        "ip": r'[^0-9.]'
    }

    if input_type in validation_patterns:
        cleaned = re.sub(validation_patterns[input_type], '', cleaned)

    return cleaned[:255]  # Limit length

def run_subfinder(domain: str, timeout: int = 120) -> List[str]:
    """
    Use Subfinder tool to find subdomains - SIMPLIFIED VERSION
    """
    clean_domain = validate_input(domain, "domain")
    if not clean_domain or not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$', clean_domain):
        logger.error(f"Invalid domain: {domain}")
        return []

    logger.info(f"Starting subdomain enumeration for: {clean_domain}")

    # Simplified subfinder command
    command = [
        'subfinder',
        '-d', clean_domain,
        '-silent',
        '-timeout', '10',
        '-t', '20'
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False  # Don't raise on non-zero exit
        )

        if result.stdout.strip():
            subdomains = [
                line.strip() for line in result.stdout.strip().split('\n')
                if line.strip() and not line.startswith('[')
            ]

            # Remove duplicates and sort
            subdomains = sorted(list(set(subdomains)))
            logger.info(f"Found {len(subdomains)} subdomains for {clean_domain}")
            return subdomains
        else:
            logger.info(f"No subdomains found for {clean_domain}")
            return []

    except subprocess.TimeoutExpired:
        logger.error(f"Subfinder timed out after {timeout} seconds for {clean_domain}")
        return []
    except FileNotFoundError:
        logger.error("Subfinder not found. Install with: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        return []
    except Exception as e:
        logger.error(f"Subfinder error: {e}")
        return []

def run_nmap(ip: str, domain: str, ethical: bool = False) -> str:
    """
    FIXED: Corrected function signature and simplified implementation
    Returns comma-separated string of open ports
    """
    logger.info(f"Starting Nmap scan for: {ip} ({domain})")

    # Validate inputs
    if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
        logger.error(f"Invalid IP address: {ip}")
        return ""

    # Determine ports to scan based on ethical mode
    if ethical:
        ports_to_scan = "80,443"  # Only web ports for ethical scans
        scan_delay = "1s"
    else:
        ports_to_scan = "22,23,25,53,80,135,139,443,445,993,995,3306,3389,5432,5900,8080,8443"
        scan_delay = "0.5s"

    command = [
        "nmap",
        "-sT",  # TCP Connect scan (no root required)
        "-T4",  # Aggressive timing
        "-Pn",  # Skip ping
        "--open",  # Only show open ports
        "-p", ports_to_scan,
        "--host-timeout", "180s",  # Per-host timeout
        ip
    ]

    if ethical:
        command.extend(["--scan-delay", scan_delay])

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=200,  # Overall timeout
            check=False
        )

        # Parse open ports from output
        open_ports = []
        for line in result.stdout.split('\n'):
            if '/tcp' in line and 'open' in line:
                port = line.split('/')[0].strip()
                if port.isdigit():
                    open_ports.append(port)

        ports_str = ','.join(sorted(open_ports, key=int)) if open_ports else ""
        logger.info(f"Nmap completed for {domain}: {ports_str}")
        return ports_str

    except subprocess.TimeoutExpired:
        logger.warning(f"Nmap timed out for {domain}")
        return ""
    except FileNotFoundError:
        logger.error("Nmap not found. Please install nmap.")
        return ""
    except Exception as e:
        logger.error(f"Nmap error for {domain}: {e}")
        return ""

def resolve_ip(target: str, timeout: int = 10) -> str:
    """
    Simplified DNS resolution with better error handling
    """
    clean_target = validate_input(target, "domain")
    if not clean_target:
        return "Unknown"

    try:
        # Set temporary timeout
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)

        ip_address = socket.gethostbyname(clean_target)

        # Basic IP validation
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip_address):
            return ip_address
        else:
            return "Unknown"

    except (socket.gaierror, socket.timeout):
        return "Unknown"
    except Exception:
        return "Unknown"
    finally:
        socket.setdefaulttimeout(old_timeout)

def calculate_score(ports: str) -> int:
    """
    Simplified risk scoring based on open ports
    """
    if not ports or not isinstance(ports, str):
        return 0

    # Risk scores for different services
    port_risks = {
        '22': 30,    # SSH
        '23': 50,    # Telnet (very risky)
        '25': 20,    # SMTP
        '53': 15,    # DNS
        '80': 10,    # HTTP
        '135': 25,   # Windows RPC
        '139': 30,   # NetBIOS
        '443': 10,   # HTTPS
        '445': 40,   # SMB (high risk)
        '993': 15,   # IMAPS
        '995': 15,   # POP3S
        '3306': 60,  # MySQL (critical if exposed)
        '3389': 45,  # RDP
        '5432': 60,  # PostgreSQL
        '5900': 35,  # VNC
        '8080': 15,  # HTTP Alt
        '8443': 15,  # HTTPS Alt
    }

    total_score = 0
    try:
        open_ports = ports.split(',')
        for port in open_ports:
            port = port.strip()
            if port:
                total_score += port_risks.get(port, 5)  # Default 5 for unknown ports
    except Exception:
        return 0

    return min(total_score, 100)  # Cap at 100

def check_ssl_vulnerabilities(domain: str, timeout: float = 6.0) -> Dict[str, Any]:
    """
    Simplified SSL/TLS vulnerability check
    """
    findings = {
        'has_ssl': False,
        'valid_cert': False,
        'error': None
    }

    clean_domain = validate_input(domain, "domain")
    if not clean_domain:
        findings['error'] = "Invalid domain"
        return findings

    try:
        # Create SSL context with default settings
        context = ssl.create_default_context()

        # Connect and verify certificate
        with socket.create_connection((clean_domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=clean_domain) as ssock:
                findings['has_ssl'] = True
                findings['valid_cert'] = True
                # Get certificate info
                cert = ssock.getpeercert()
                findings['cert_subject'] = cert.get('subject', 'Unknown')
                findings['cert_issuer'] = cert.get('issuer', 'Unknown')

    except ssl.SSLError as e:
        findings['has_ssl'] = True  # SSL exists but has issues
        findings['valid_cert'] = False
        findings['error'] = f"SSL Error: {str(e)[:100]}"
    except (socket.gaierror, socket.timeout, ConnectionRefusedError):
        findings['error'] = "Connection failed"
    except Exception as e:
        findings['error'] = f"Unexpected error: {str(e)[:100]}"

    return findings

def check_web_vulnerabilities(url: str, timeout: int = 5) -> Dict[str, Any]:
    """
    Simplified web vulnerability check
    """
    findings = {
        'has_admin_panel': False,
        'server_header': None,
        'response_code': None,
        'error': None
    }

    # Clean URL
    if not url.startswith(('http://', 'https://')):
        url = f"http://{url}"

    try:
        # Rate limiting for ethical scanning
        rate_limiter.wait_if_needed()

        # Initial request to get basic info
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={'User-Agent': 'Aegis-Lite Security Scanner'}
        )

        findings['response_code'] = response.status_code
        findings['server_header'] = response.headers.get('Server', 'Unknown')

        # Check for common admin panels (simplified)
        if response.status_code == 200:
            admin_indicators = ['/admin', '/login', '/dashboard', '/wp-admin', '/administrator']
            content = response.text.lower()

            for indicator in admin_indicators:
                if indicator in content:
                    findings['has_admin_panel'] = True
                    break

    except requests.exceptions.Timeout:
        findings['error'] = "Request timeout"
    except requests.exceptions.ConnectionError:
        findings['error'] = "Connection failed"
    except requests.exceptions.RequestException as e:
        findings['error'] = f"Request error: {str(e)[:100]}"
    except Exception as e:
        findings['error'] = f"Unexpected error: {str(e)[:100]}"

    return findings

# Simple validation functions
def is_valid_domain(domain: str) -> bool:
    """Check if domain format is valid"""
    if not domain or len(domain) > 255:
        return False
    return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$', domain))

def is_valid_ip(ip: str) -> bool:
    """Check if IP format is valid"""
    if ip in ["Unknown", "TBD"]:
        return True
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False

# Test function for development
def test_scanners():
    """Test all scanner functions"""
    print("Testing scanner functions...")

    # Test domain validation
    print(f"Domain validation: {is_valid_domain('example.com')}")
    print(f"IP validation: {is_valid_ip('192.168.1.1')}")

    # Test DNS resolution
    ip = resolve_ip('google.com')
    print(f"DNS resolution: google.com -> {ip}")

    # Test SSL check
    ssl_result = check_ssl_vulnerabilities('google.com')
    print(f"SSL check: {ssl_result}")

    print("Scanner tests completed.")

if __name__ == "__main__":
    test_scanners()
