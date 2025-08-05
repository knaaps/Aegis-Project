import time
import random

class MockScanner:
    """
    Mocks external scanning tools like Subfinder and port scanners.
    In a real scenario, these methods would execute actual CLI tools
    or leverage more sophisticated Python libraries for network scanning.
    """
    def enumerate_subdomains(self, domain: str) -> list[str]:
        """
        Mocks subdomain enumeration for a given domain.
        Returns a list of subdomains.
        """
        # print(f"DEBUG: Mocking subdomain enumeration for {domain}") # Moved to cli.py for better control
        time.sleep(0.5) # Simulate some work

        if "example.com" in domain:
            return [
                f"www.{domain}",
                f"blog.{domain}",
                f"shop.{domain}",
                f"dev.{domain}",
                f"mail.{domain}",
                f"test.{domain}" # Added one more for variety
            ]
        elif "google.com" in domain:
            # For google.com, we'll return a single, common subdomain
            return [f"www.{domain}"]
        elif "test.org" in domain:
            return [
                f"test.{domain}",
                f"staging.{domain}"
            ]
        else:
            return [f"www.{domain}"] # Default for any other domain

    def scan_ports(self, target: str, rate_limit: int = None) -> str:
        """
        Mocks port scanning for a given target (subdomain or IP).
        Returns a comma-separated string of open ports.
        Ensures a non-None string is always returned.
        """
        # print(f"DEBUG: Mocking port scan for {target} (rate_limit: {rate_limit})") # Moved to cli.py
        time.sleep(0.2) # Simulate some work

        # Introduce a small random chance of 'failure' for robustness testing
        # if random.random() < 0.05: # 5% chance of mock failure
        #     raise RuntimeError(f"Mock port scan failed for {target} due to network error.")

        if "www." in target:
            return "80,443" # Common web ports
        elif "blog." in target:
            return "443"
        elif "shop." in target:
            return "80,443,8080"
        elif "mail." in target:
            return "25,110,143,993,995"
        elif "dev." in target or "staging." in target:
            return "22,80,443,3306" # Common dev/staging ports
        else:
            return "443" # Default HTTPS


# Instantiate the mock scanner for use in cli.py
mock_scanner = MockScanner()
