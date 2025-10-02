#!/usr/bin/env python3
"""
Database Operations Test Suite
"""
import os
import tempfile
import sqlite3
from aegis import database
from aegis.database import save_asset, get_all_assets, get_db_stats

def test_database_initialization():
    """Test database initialization"""
    print("Testing database initialization...")

    try:
        database.init_db()

        # Check if database file exists
        if os.path.exists(database.DB_FILE):
            print("✅ Database file created")
        else:
            print("❌ Database file not found")
            return False

        # Check table structure
        with sqlite3.connect(database.DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()

            if ('assets',) in tables:
                print("✅ Assets table exists")
                return True
            else:
                print("❌ Assets table missing")
                return False

    except Exception as e:
        print(f"❌ Database init error: {e}")
        return False

def test_asset_operations():
    """Test asset save/retrieve operations"""
    print("Testing asset operations...")

    # Test data
    test_domain = "test-domain.example.com"
    test_ip = "192.168.1.100"
    test_ports = "80,443"
    test_score = 25

    try:
        # Save asset
        success = save_asset(
            domain=test_domain,
            ip=test_ip,
            ports=test_ports,
            score=test_score,
            ssl_vulnerabilities='{"has_https": true}',
            web_vulnerabilities='{"vulnerabilities": []}'
        )

        if not success:
            print("❌ Failed to save asset")
            return False

        # Retrieve assets
        assets = get_all_assets()

        # Find our test asset
        test_asset = None
        for asset in assets:
            if asset['domain'] == test_domain:
                test_asset = asset
                break

        if test_asset:
            print(f"✅ Asset saved and retrieved: {test_asset['domain']}")
            return True
        else:
            print("❌ Asset not found after save")
            return False

    except Exception as e:
        print(f"❌ Asset operations error: {e}")
        return False

def test_database_stats():
    """Test statistics generation"""
    print("Testing database statistics...")

    try:
        stats = get_db_stats()

        required_keys = ['total_assets', 'avg_score', 'critical_risk_assets',
                        'high_risk_assets', 'medium_risk_assets', 'low_risk_assets']

        for key in required_keys:
            if key not in stats:
                print(f"❌ Missing stat key: {key}")
                return False

        print(f"✅ Stats generated: {stats['total_assets']} total assets")
        return True

    except Exception as e:
        print(f"❌ Stats error: {e}")
        return False

def test_database_cleanup():
    """Test database cleanup"""
    print("Testing database cleanup...")

    try:
        # Clean up test data
        database.clear_db()
        print("✅ Database cleared")
        return True

    except Exception as e:
        print(f"❌ Cleanup error: {e}")
        return False

def run_database_tests():
    """Run all database tests"""
    print("=" * 50)
    print("DATABASE TEST SUITE")
    print("=" * 50)

    tests = [
        ("Initialization", test_database_initialization),
        ("Asset Operations", test_asset_operations),
        ("Statistics", test_database_stats),
        ("Cleanup", test_database_cleanup)
    ]

    for test_name, test_func in tests:
        print(f"\n[{test_name}]")
        success = test_func()
        print(f"Result: {'✅ PASS' if success else '❌ FAIL'}")

if __name__ == "__main__":
    run_database_tests()
