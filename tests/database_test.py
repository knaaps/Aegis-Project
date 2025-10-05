#!/usr/bin/env python3
"""
Database Operations Test Suite - FIXED
All functions now use assertions instead of return statements
"""
import os
import sqlite3
from aegis import database
from aegis.database import save_asset, get_all_assets, get_db_stats, clear_db

def test_database_initialization():
    """Test database initialization"""
    print("Testing database initialization...")
    
    database.init_db()
    
    # Assert database file exists
    assert os.path.exists(database.DB_FILE), "Database file should be created"
    print("✅ Database file created")
    
    # Assert table structure is correct
    with sqlite3.connect(database.DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        assert ('assets',) in tables, "Assets table should exist"
    
    print("✅ Assets table exists")

def test_asset_operations():
    """Test asset save/retrieve operations"""
    print("Testing asset operations...")
    
    # Test data
    test_domain = "test-domain.example.com"
    test_ip = "192.168.1.100"
    test_ports = "80,443"
    test_score = 25
    
    # Save asset
    success = save_asset(
        domain=test_domain,
        ip=test_ip,
        ports=test_ports,
        score=test_score,
        ssl_vulnerabilities='{"has_https": true}',
        web_vulnerabilities='{"vulnerabilities": []}'
    )
    
    assert success == True, "Asset save should succeed"
    
    # Retrieve assets
    assets = get_all_assets()
    
    # Find our test asset
    test_asset = None
    for asset in assets:
        if asset['domain'] == test_domain:
            test_asset = asset
            break
    
    assert test_asset is not None, "Saved asset should be retrievable"
    assert test_asset['domain'] == test_domain, "Domain should match"
    assert test_asset['ip'] == test_ip, "IP should match"
    
    print(f"✅ Asset saved and retrieved: {test_asset['domain']}")

def test_database_stats():
    """Test statistics generation"""
    print("Testing database statistics...")
    
    stats = get_db_stats()
    
    required_keys = [
        'total_assets', 'avg_score', 'critical_risk_assets',
        'high_risk_assets', 'medium_risk_assets', 'low_risk_assets'
    ]
    
    for key in required_keys:
        assert key in stats, f"Stats should contain {key}"
    
    assert isinstance(stats['total_assets'], int), "total_assets should be integer"
    assert stats['total_assets'] >= 0, "total_assets should be non-negative"
    
    print(f"✅ Stats generated: {stats['total_assets']} total assets")

def test_database_cleanup():
    """Test database cleanup"""
    print("Testing database cleanup...")
    
    # Ensure database exists first
    database.init_db()
    assert os.path.exists(database.DB_FILE), "Database should exist before cleanup"
    
    # Clean up test data
    success = clear_db()
    assert success == True, "Database cleanup should succeed"
    
    # Verify database was removed
    assert not os.path.exists(database.DB_FILE), "Database file should be removed"
    
    print("✅ Database cleared")

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
        try:
            test_func()
            print(f"Result: ✅ PASS")
        except AssertionError as e:
            print(f"Result: ❌ FAIL - {e}")
        except Exception as e:
            print(f"Result: ❌ ERROR - {e}")

if __name__ == "__main__":
    run_database_tests()