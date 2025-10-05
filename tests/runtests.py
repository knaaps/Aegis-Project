#!/usr/bin/env python3
"""
Simple Test Runner for Aegis-Lite
"""
import pytest
import sys

def run_tests():
    print("🧪 Running Aegis-Lite Test Suite")
    print("=" * 50)
    
    # Run all tests
    result = pytest.main([
        "tests/",
        "-v",
        "--cov=aegis",
        "--cov-report=html",
        "--cov-report=term-missing",
        "--cov-config=.coveragerc"  # Use coverage config
    ])
    
    sys.exit(result)

if __name__ == "__main__":
    run_tests()