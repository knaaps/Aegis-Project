import pytest
import tempfile
import os
import sqlite3
from aegis.database import init_db, save_asset, get_asset_by_domain, delete_asset, get_db_stats, get_all_assets

class TestDatabaseComprehensive:
    def test_database_initialization(self):
        """Test database initialization"""
        try:
            init_db()

            if os.path.exists("aegis.db"):
                print("✅ Database file created")
            else:
                print("❌ Database file not found")
                return False

            with sqlite3.connect("aegis.db") as conn:
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

    def test_save_asset_with_all_fields(self):
        """Test saving asset with complete data"""
        success = save_asset(
            domain="test-all-fields.com",
            ip="192.168.1.100", 
            ports="80,443,8080",
            score=75,
            ssl_vulnerabilities='{"has_https": true, "valid_cert": false}',
            web_vulnerabilities='{"vulnerabilities": [{"name": "XSS", "severity": "high"}]}'
        )
        assert success == True
        
        asset = get_asset_by_domain("test-all-fields.com")
        assert asset['domain'] == "test-all-fields.com"
        assert asset['score'] == 75
        assert "80,443,8080" in asset['ports']

    def test_get_assets_with_filters(self):
        """Test asset retrieval with score filters"""
        save_asset("low-risk.com", score=10)
        save_asset("medium-risk.com", score=40) 
        save_asset("high-risk.com", score=70)
        
        high_risk_assets = [a for a in get_all_assets() if a['score'] >= 50]
        assert len(high_risk_assets) >= 1

    def test_delete_nonexistent_asset(self):
        """Test deleting asset that doesn't exist"""
        success = delete_asset("nonexistent-domain-12345.com")
        assert success == False

    def test_database_stats_comprehensive(self):
        """Test stats with various risk levels"""
        init_db()
        test_assets = [
            ("critical-test.com", 85),
            ("high-test.com", 65), 
            ("medium-test.com", 45),
            ("low-test.com", 15)
        ]
        
        for domain, score in test_assets:
            save_asset(domain, score=score)
            
        stats = get_db_stats()
        assert stats['critical_risk_assets'] >= 1
        assert stats['high_risk_assets'] >= 1
        assert stats['total_assets'] >= 4

    def test_asset_operations(self):
        """Test asset save/retrieve operations"""
        test_domain = "test-domain.example.com"
        test_ip = "192.168.1.100"
        test_ports = "80,443"
        test_score = 25

        success = save_asset(
            domain=test_domain,
            ip=test_ip,
            ports=test_ports,
            score=test_score,
            ssl_vulnerabilities='{"has_https": true}',
            web_vulnerabilities='{"vulnerabilities": []}'
        )

        assert success == True

        assets = get_all_assets()
        test_asset = None
        for asset in assets:
            if asset['domain'] == test_domain:
                test_asset = asset
                break

        assert test_asset is not None
        print(f"✅ Asset saved and retrieved: {test_asset['domain']}")

    def test_database_stats(self):
        """Test statistics generation"""
        stats = get_db_stats()

        required_keys = ['total_assets', 'avg_score', 'critical_risk_assets',
                        'high_risk_assets', 'medium_risk_assets', 'low_risk_assets']

        for key in required_keys:
            assert key in stats

        print(f"✅ Stats generated: {stats['total_assets']} total assets")

if __name__ == "__main__":
    pytest.main([__file__, "-v"])