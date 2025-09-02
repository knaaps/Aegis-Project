import socket
import time
import random
import subprocess
import json

class MockScanner:
    """
    A class that provides mock implementations for external scanning tools.
    
    This class is used for testing and development purposes to simulate the
    behavior of real-world tools like Subfinder and Nmap without making
    actual network requests. In a production environment, these methods
    would be replaced by functions that execute actual CLI tools.
    """
    # existing mock methods remain here for testing
    def enumerate_subdomains(self, domain: str) -> list[str]:
        """
        Mocks subdomain enumeration for a given domain.
        
        Args:
            domain (str): The domain to enumerate subdomains for.
        
        Returns:
            list[str]: A list of mock subdomains for the given domain.
        """
        time.sleep(0.5)
        if "example.com" in domain:
            return [f"www.{domain}", f"blog.{domain}", f"shop.{domain}", f"dev.{domain}"]
        else:
            return [f"www.{domain}"]

    def scan_ports(self, target: str, rate_limit: int = None) -> str:
        """
        Mocks port scanning for a given target (subdomain or IP).
        
        This method simulates scanning common ports and returns a string
        of comma-separated open ports.
        
        Args:
            target (str): The subdomain or IP address to scan.
            rate_limit (int, optional): An optional rate limit in requests
                                        per second. Defaults to None.
        
        Returns:
            str: A comma-separated string of mock open ports.
        """
        time.sleep(0.2)
        if "www." in target:
            return "80,443"
        elif "blog." in target:
            return "443"
        else:
            return "443"

def run_subfinder(domain: str) -> list[str]:
    """
    Runs Subfinder to enumerate subdomains for a given domain.

    Args:
        domain (str): The domain to scan.

    Returns:
        list[str]: A list of discovered subdomains.
    """
    try:
        # Use subprocess to run the command, capturing stdout
        result = subprocess.run(
            ['subfinder', '-d', domain, '-silent'],
            capture_output=True,
            text=True,
            check=True
        )
        # Split the output by newlines to get a list of subdomains
        subdomains = result.stdout.strip().split('\n')
        return subdomains if subdomains != [''] else []
    except subprocess.CalledProcessError as e:
        print(f"Subfinder failed with error: {e.stderr}")
        return []
    except FileNotFoundError:
        print("Subfinder not found. Please ensure it's installed and in your PATH.")
        return []

def run_nmap(target: str, ports: str = '80,443', rate_limit: int = None) -> str:
    """
    Runs Nmap to scan for open ports on a given target.

    Args:
        target (str): The host or IP to scan.
        ports (str, optional): A comma-separated string of ports to scan.
                               Defaults to '80,443'.
        rate_limit (int, optional): An optional rate limit in packets per second.

    Returns:
        str: A comma-separated string of open ports.
    """
    command = ['nmap', '-p', ports, '-sS', '--open', '-T4', target, '-oG', '-']
    if rate_limit:
        command.append(f"--max-rate={rate_limit}")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True
        )
        
        # Parse Nmap's grepable output to find open ports
        open_ports = []
        for line in result.stdout.split('\n'):
            if "Status: Up" in line:
                parts = line.split("Ports: ")
                if len(parts) > 1:
                    ports_section = parts[1].split(' ')[0]
                    for port_info in ports_section.split(','):
                        port_number = port_info.split('/')[0]
                        if '/open/' in port_info:
                             open_ports.append(port_number)
        
        return ",".join(open_ports)
    except subprocess.CalledProcessError as e:
        print(f"Nmap failed with error: {e.stderr}")
        return ""
    except FileNotFoundError:
        print("Nmap not found. Please ensure it's installed and in your PATH.")
        return ""

def resolve_ip(target: str) -> str:
    """
    Performs a DNS lookup to get the IP address for a given target.

    Args:
        target (str): The domain or subdomain to resolve.

    Returns:
        str: The IP address of the target, or "Unknown" if resolution fails.
    """
    try:
        ip_address = socket.gethostbyname(target)
        return ip_address
    except socket.gaierror:
        return "Unknown"

def calculate_score(ports: str) -> int:
    """
    Calculates a risk score based on open ports.

    Args:
        ports (str): A comma-separated string of open ports.

    Returns:
        int: The calculated risk score.
    """
    score = 0
    if not ports:
        return score

    # Define high-risk ports with specific point values
    high_risk_ports = {
        '22': 50,    # SSH - often a target for brute force attacks
        '23': 40,    # Telnet - unencrypted, highly vulnerable
        '80': 10,    # HTTP - common attack vector
        '443': 10,   # HTTPS - common attack vector
        '3306': 30,  # MySQL - database access
        '5432': 30,  # PostgreSQL - database access
        '27017': 30, # MongoDB - database access
        '5900': 20,  # VNC - remote desktop access
    }

    # Split the string of ports into a list
    open_ports = ports.split(',')
    
    # Calculate score based on the number and type of open ports
    for port in open_ports:
        port = port.strip()
        score += high_risk_ports.get(port, 5) # Default to 5 points for any other open port

    return score

# Instantiate the mock scanner for use in cli.py
mock_scanner = MockScanner()
