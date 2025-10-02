import pytest
import tempfile
import os
from aegis.database import init_db, save_asset, get_asset_by_domain, delete_asset, get_db_stats

class TestDatabaseComprehensive:
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
        
        # Verify retrieval
        asset = get_asset_by_domain("test-all-fields.com")
        assert asset['domain'] == "test-all-fields.com"
        assert asset['score'] == 75
        assert "80,443,8080" in asset['ports']

    def test_get_assets_with_filters(self):
        """Test asset retrieval with score filters"""
        # Create test assets with different scores
        save_asset("low-risk.com", score=10)
        save_asset("medium-risk.com", score=40) 
        save_asset("high-risk.com", score=70)
        
        # Test critical assets filter
        from aegis.database import get_critical_assets
        critical = get_critical_assets()
        assert len([a for a in critical if a['score'] >= 70]) > 0

    def test_delete_nonexistent_asset(self):
        """Test deleting asset that doesn't exist"""
        success = delete_asset("nonexistent-domain-12345.com")
        assert success == False

    def test_database_stats_comprehensive(self):
        """Test stats with various risk levels"""
        # Clear and create fresh test data
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