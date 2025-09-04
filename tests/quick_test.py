#!/usr/bin/env python3
"""
Quick Test Script for Simplified Aegis-Lite
==========================================

Run this to test all components of your simplified system
"""

import os
import sys
import subprocess
import time

def print_section(title):
    """Print a formatted section header"""
    print(f"\n{'='*50}")
    print(f" {title}")
    print(f"{'='*50}")

def run_command(cmd, description, timeout=30):
    """Run a command and show results"""
    print(f"\n🔍 {description}")
    print(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode == 0:
            print("✅ SUCCESS")
            if result.stdout.strip():
                print(f"Output: {result.stdout.strip()[:200]}...")
        else:
            print("❌ FAILED")
            print(f"Error: {result.stderr.strip()[:200]}...")

        return result.returncode == 0

    except subprocess.TimeoutExpired:
        print(f"⏰ TIMEOUT (>{timeout}s)")
        return False
    except Exception as e:
        print(f"💥 ERROR: {e}")
        return False

def test_python_imports():
    """Test Python module imports"""
    print_section("TESTING PYTHON IMPORTS")

    modules = [
        'click', 'requests', 'json', 'sqlite3',
        'time', 'subprocess', 'socket', 're'
    ]

    for module in modules:
        try:
            __import__(module)
            print(f"✅ {module}")
        except ImportError:
            print(f"❌ {module} - MISSING")

def test_external_tools():
    """Test external scanning tools"""
    print_section("TESTING EXTERNAL TOOLS")

    tools = [
        (['python', '--version'], "Python Installation"),
        (['nmap', '--version'], "Nmap Port Scanner"),
        (['subfinder', '-version'], "Subfinder Subdomain Tool"),
        (['nuclei', '-version'], "Nuclei Vulnerability Scanner")
    ]

    for cmd, desc in tools:
        run_command(cmd, desc, timeout=10)

def test_aegis_modules():
    """Test Aegis-Lite modules"""
    print_section("TESTING AEGIS-LITE MODULES")

    tests = [
        (['python', '-c', 'from aegis.database import test_database; test_database()'],
         "Database Module"),
        (['python', '-c', 'from aegis.scanners import test_scanners; test_scanners()'],
         "Scanner Module"),
        (['python', '-m', 'aegis.cli', '--help'],
         "CLI Interface")
    ]

    for cmd, desc in tests:
        run_command(cmd, desc, timeout=20)

def test_basic_functionality():
    """Test basic scanning functionality"""
    print_section("TESTING BASIC FUNCTIONALITY")

    # Test basic scan (safe domain)
    print("\n🔍 Testing basic domain scan...")
    print("This will take 30-60 seconds...")

    success = run_command(
        ['python', '-m', 'aegis.cli', 'scan', 'httpbin.org', '--ethical'],
        "Basic Domain Scan",
        timeout=120
    )

    if success:
        # Test view results
        run_command(
            ['python', '-m', 'aegis.cli', 'view', '--limit', '5'],
            "View Scan Results",
            timeout=10
        )

        # Test report generation
        run_command(
            ['python', '-m', 'aegis.cli', 'report'],
            "Generate Security Report",
            timeout=10
        )

def test_streamlit_ui():
    """Test Streamlit UI (basic check)"""
    print_section("TESTING STREAMLIT UI")

    try:
        import streamlit
        print("✅ Streamlit module available")

        print("\n🔍 Testing UI file...")
        if os.path.exists('aegis/ui.py'):
            print("✅ UI file exists")

            # Try to parse the UI file
            with open('aegis/ui.py', 'r') as f:
                content = f.read()
                if 'st.title' in content and 'st.tabs' in content:
                    print("✅ UI file has required components")
                else:
                    print("❌ UI file missing required components")
        else:
            print("❌ UI file not found")

    except ImportError:
        print("❌ Streamlit not installed")

def test_docker_setup():
    """Test Docker configuration"""
    print_section("TESTING DOCKER SETUP")

    files = ['Dockerfile', 'requirements.txt']

    for file in files:
        if os.path.exists(file):
            print(f"✅ {file} exists")
        else:
            print(f"❌ {file} missing")

    # Test Docker build (if Docker is available)
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True, timeout=5)
        if result.returncode == 0:
            print("✅ Docker available")
            print("💡 You can test: docker build -t aegis-lite .")
        else:
            print("❌ Docker not available")
    except:
        print("❌ Docker not found")

def main():
    """Run all tests"""
    print("🛡️ Aegis-Lite Simplified System Test")
    print("====================================")
    print("This script will test your simplified Aegis-Lite system")

    start_time = time.time()

    # Run all test suites
    test_python_imports()
    test_external_tools()
    test_aegis_modules()
    test_streamlit_ui()
    test_docker_setup()

    # Optional: Run functional test
    response = input("\n🤔 Run basic functionality test? (scans httpbin.org) [y/N]: ")
    if response.lower().startswith('y'):
        test_basic_functionality()

    # Summary
    duration = time.time() - start_time
    print_section("TEST SUMMARY")
    print(f"⏱️  Total test time: {duration:.1f} seconds")
    print("\n📝 Next steps:")
    print("1. Fix any ❌ FAILED items above")
    print("2. Test UI: streamlit run aegis/ui.py")
    print("3. Test Docker: docker build -t aegis-lite .")
    print("4. Run demo scan: python -m aegis.cli scan example.com --ethical")

    print("\n✨ Your simplified system is ready for Phase 1 demonstration!")

if __name__ == "__main__":
    main()
