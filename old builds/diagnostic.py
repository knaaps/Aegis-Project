#!/usr/bin/env python3
"""
Aegis Diagnostic Script
======================
Run this script to diagnose issues with your Aegis scanner setup.
"""

import subprocess
import os
import sys
import socket
import time
import logging
from pathlib import Path

def print_header(title):
    print("\n" + "="*50)
    print(f" {title}")
    print("="*50)

def check_command_exists(command):
    """Check if a command exists in the system PATH."""
    try:
        result = subprocess.run(['which', command], capture_output=True, text=True)
        return result.returncode == 0, result.stdout.strip()
    except Exception as e:
        return False, str(e)

def test_dns_resolution(domain):
    """Test basic DNS resolution."""
    try:
        start_time = time.time()
        ip = socket.gethostbyname(domain)
        resolution_time = time.time() - start_time
        return True, ip, resolution_time
    except Exception as e:
        return False, str(e), 0

def run_diagnostic():
    """Run comprehensive diagnostic checks."""

    print_header("AEGIS SCANNER DIAGNOSTICS")
    print("This script will help diagnose issues with your Aegis scanner setup.\n")

    # 1. Check Python environment
    print_header("PYTHON ENVIRONMENT")
    print(f"Python version: {sys.version}")
    print(f"Python executable: {sys.executable}")

    # Check if we're in a virtual environment
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print("✓ Running in virtual environment")
    else:
        print("⚠ Not running in virtual environment")

    # 2. Check required tools
    print_header("REQUIRED TOOLS")

    tools = ['subfinder', 'nmap']
    for tool in tools:
        exists, path = check_command_exists(tool)
        if exists:
            print(f"✓ {tool}: {path}")
        else:
            print(f"✗ {tool}: Not found in PATH")

    # 3. Test subfinder specifically
    print_header("SUBFINDER TESTING")

    exists, path = check_command_exists('subfinder')
    if exists:
        print(f"Subfinder location: {path}")

        # Check version
        try:
            result = subprocess.run(['subfinder', '-version'],
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                print(f"Version: {result.stdout.strip()}")
            else:
                print(f"Version check failed: {result.stderr}")
        except subprocess.TimeoutExpired:
            print("⚠ Version check timed out")
        except Exception as e:
            print(f"Version check error: {e}")

        # Check config directory
        config_dir = Path.home() / ".config" / "subfinder"
        if config_dir.exists():
            print(f"✓ Config directory exists: {config_dir}")

            # Check for config files
            config_file = config_dir / "provider-config.yaml"
            if config_file.exists():
                print("✓ Provider config file found")
            else:
                print("⚠ No provider config file (may limit results)")
        else:
            print("⚠ No config directory found")

        # Test subfinder with a simple domain
        print("\nTesting subfinder with example.com...")
        try:
            start_time = time.time()
            result = subprocess.run([
                'subfinder', '-d', 'example.com', '-silent', '-timeout', '10'
            ], capture_output=True, text=True, timeout=30)

            execution_time = time.time() - start_time
            print(f"Execution time: {execution_time:.2f} seconds")

            if result.returncode == 0:
                subdomains = [line.strip() for line in result.stdout.split('\n') if line.strip()]
                print(f"✓ Found {len(subdomains)} subdomains")
                if subdomains:
                    print(f"Sample: {subdomains[0]}")
            else:
                print(f"✗ Subfinder failed: {result.stderr}")

        except subprocess.TimeoutExpired:
            print("✗ Subfinder test timed out (30s)")
        except Exception as e:
            print(f"✗ Subfinder test error: {e}")

    else:
        print("✗ Subfinder not found - this is the main issue!")
        print("\nTo install subfinder:")
        print("1. Install Go: https://golang.org/dl/")
        print("2. Run: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        print("3. Make sure ~/go/bin is in your PATH")

    # 4. Test network connectivity
    print_header("NETWORK CONNECTIVITY")

    test_domains = ['google.com', 'example.com', '8.8.8.8']
    for domain in test_domains:
        success, result, time_taken = test_dns_resolution(domain)
        if success:
            print(f"✓ {domain} -> {result} ({time_taken:.3f}s)")
        else:
            print(f"✗ {domain}: {result}")

    # 5. Check system resources
    print_header("SYSTEM RESOURCES")

    try:
        import psutil
        print(f"CPU usage: {psutil.cpu_percent(interval=1)}%")
        print(f"Memory usage: {psutil.virtual_memory().percent}%")
        print(f"Available memory: {psutil.virtual_memory().available // (1024*1024)} MB")
    except ImportError:
        print("psutil not available - install with: pip install psutil")

    # 6. Check file permissions
    print_header("FILE PERMISSIONS")

    current_dir = Path.cwd()
    print(f"Current directory: {current_dir}")
    print(f"Directory writable: {os.access(current_dir, os.W_OK)}")

    # Check if aegis database exists and is writable
    aegis_db = current_dir / "aegis.db"
    if aegis_db.exists():
        print(f"✓ Database exists: {aegis_db}")
        print(f"Database writable: {os.access(aegis_db, os.W_OK)}")
    else:
        print("Database doesn't exist yet (will be created)")

    # 7. Suggested fixes
    print_header("SUGGESTED FIXES")

    # Check if subfinder exists
    exists, _ = check_command_exists('subfinder')
    if not exists:
        print("1. CRITICAL: Install subfinder")
        print("   Go to: https://github.com/projectdiscovery/subfinder")
        print("   Or run: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        print("   Make sure ~/go/bin is in your PATH")

    print("\n2. For better results, configure API keys:")
    print("   - Create ~/.config/subfinder/provider-config.yaml")
    print("   - Add API keys for services like Shodan, VirusTotal, etc.")
    print("   - See: https://github.com/projectdiscovery/subfinder#post-installation-instructions")

    print("\n3. If subfinder is slow:")
    print("   - Try increasing timeout in cli.py")
    print("   - Use ethical mode (--ethical flag)")
    print("   - Check your internet connection")

    print("\n4. Alternative approach:")
    print("   - Use the fallback subdomain enumeration")
    print("   - Modify cli.py to use enhanced scanning functions")

    print_header("DIAGNOSTIC COMPLETE")
    print("Review the results above to identify and fix issues.")

if __name__ == "__main__":
    run_diagnostic()
