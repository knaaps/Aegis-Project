#!/usr/bin/env python3
"""
Comprehensive test runner for Aegis-Lite
Run with: python tests/run_all_tests.py
"""
import subprocess
import sys

def run_tests():
    print("🧪 Running Aegis-Lite Test Suite")
    print("=" * 50)
    
    test_modules = [
        "tests.test_core",
        "tests.database_test", 
        "tests.thread_test",
        "tests.nuclei_test"
    ]
    
    all_passed = True
    
    for module in test_modules:
        print(f"\n📋 Testing: {module}")
        try:
            result = subprocess.run([
                sys.executable, "-m", "pytest", f"{module.replace('.', '/')}.py", "-v"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ PASSED")
            else:
                print("❌ FAILED")
                print(result.stdout)
                all_passed = False
                
        except Exception as e:
            print(f"❌ ERROR: {e}")
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 ALL TESTS PASSED! - Aegis-Lite is ready for submission")
        return True
    else:
        print("⚠️  Some tests failed - please review above")
        return False

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)