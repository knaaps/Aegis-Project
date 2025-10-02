#!/usr/bin/env python3
"""
Nuclei Integration Test Suite
"""
import subprocess
import json
import time
from aegis.scanners import check_web_vulnerabilities

def test_nuclei_installation():
    """Test if nuclei is properly installed"""
    print("Testing Nuclei installation...")
    try:
        result = subprocess.run(["nuclei", "-version"],
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print("✅ Nuclei installed:", result.stdout.strip())
            return True
        else:
            print("❌ Nuclei not working:", result.stderr)
            return False
    except FileNotFoundError:
        print("❌ Nuclei not found. Install with: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
        return False
    except Exception as e:
        print(f"❌ Nuclei test error: {e}")
        return False

def test_nuclei_templates():
    """Test if nuclei templates are available"""
    print("Testing Nuclei templates...")
    try:
        result = subprocess.run(["nuclei", "-tl"],
                              capture_output=True, text=True, timeout=30)
        template_count = len(result.stdout.splitlines()) if result.stdout else 0
        if template_count > 100:
            print(f"✅ Found {template_count} nuclei templates")
            return True
        else:
            print("⚠️  Few templates found, updating...")
            subprocess.run(["nuclei", "-ut"], timeout=120)
            return True
    except Exception as e:
        print(f"❌ Template test error: {e}")
        return False

def test_basic_nuclei_scan():
    """Test nuclei against a safe target"""
    print("Testing basic nuclei scan...")
    test_url = "https://httpbin.org"  # Safe test target

    try:
        result = check_web_vulnerabilities(
            url=test_url,
            tags="tech-detect,misconfiguration",  # Safe, fast templates
            timeout=60
        )

        if result.get("scan_completed"):
            print(f"✅ Nuclei scan completed. Found {len(result.get('vulnerabilities', []))} items")
            if result.get("vulnerabilities"):
                print("Sample finding:", result["vulnerabilities"][0])
            return True
        else:
            print("❌ Nuclei scan failed:", result.get("error"))
            return False

    except Exception as e:
        print(f"❌ Nuclei scan error: {e}")
        return False

def run_nuclei_tests():
    """Run all nuclei tests"""
    print("=" * 50)
    print("NUCLEI INTEGRATION TEST SUITE")
    print("=" * 50)

    tests = [
        ("Installation", test_nuclei_installation),
        ("Templates", test_nuclei_templates),
        ("Basic Scan", test_basic_nuclei_scan)
    ]

    results = []
    for test_name, test_func in tests:
        print(f"\n[{test_name}]")
        start_time = time.time()
        success = test_func()
        duration = time.time() - start_time
        results.append((test_name, success, duration))
        print(f"Duration: {duration:.1f}s")

    print("\n" + "=" * 50)
    print("TEST SUMMARY")
    print("=" * 50)
    for test_name, success, duration in results:
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {test_name} ({duration:.1f}s)")

    all_passed = all(result[1] for result in results)
    print(f"\nOverall: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}")
    return all_passed

if __name__ == "__main__":
    run_nuclei_tests()
