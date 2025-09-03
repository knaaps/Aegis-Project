import sys
import json
# Add the project directory to the Python path to find the modules
sys.path.append('..')
from aegis.scanners import check_ssl_vulnerabilities, check_web_vulnerabilities

print("--- Running Unit Tests ---")

# Test 1: Check a secure domain (e.g., Google)
print("\nTesting SSL for google.com...")
ssl_result_secure = check_ssl_vulnerabilities("google.com")
print(f"SSL Findings: {json.dumps(ssl_result_secure, indent=2)}")
assert ssl_result_secure.get('has_ssl') is True
assert ssl_result_secure.get('valid_cert') is True

# Test 2: Check a non-secure domain (e.g., a dummy domain)
print("\nTesting SSL for non-SSL domain...")
ssl_result_insecure = check_ssl_vulnerabilities("insecure.example.com")
print(f"SSL Findings: {json.dumps(ssl_result_insecure, indent=2)}")
assert ssl_result_insecure.get('has_ssl') is False

# Test 3: Check a website for web vulnerabilities
print("\nTesting web vulnerabilities for example.com...")
web_result = check_web_vulnerabilities("http://example.com")
print(f"Web Findings: {json.dumps(web_result, indent=2)}")

# Use .get() to prevent KeyError if the key is missing
assert web_result.get('has_admin_panel') is False

# Check for the presence of the 'headers' key before checking for the 'Content-Security-Policy' header
headers = web_result.get('headers', {})
assert 'Content-Security-Policy' not in headers

print("\n--- All tests passed! ---")
