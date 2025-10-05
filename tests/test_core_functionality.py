"""
Core Functionality Tests - Merged from test_core.py, test_database.py, test_scanners.py
"""
import pytest
import sqlite3
import os
from unittest.mock import patch, MagicMock

from aegis.utils import validate_domain, validate_ip, get_risk_level, safe_json_parse
from aegis.database import init_db, save_asset, get_all_assets, get_db_stats, get_asset_by_domain, delete_asset, clear_db
from aegis.scanners import calculate_score, resolve_ip, check_https, discover_directories

class TestCoreUtilities:
    """Merged utility tests from test_core.py and test_core_functionality.py"""
    
    def test_domain_validation(self):
        assert validate_domain("example.com") == True
        assert validate_domain("invalid..com") == False
        assert validate_domain("") == False

    def test_ip_validation(self):
        assert validate_ip("192.168.1.1") == True
        assert validate_ip("256.256.256.256") == False
        assert validate_ip("Unknown") == True

    def test_risk_scoring(self):
        assert "Critical" in get_risk_level(75)
        assert "High" in get_risk_level(55)
        assert "Medium" in get_risk_level(35)
        assert "Low" in get_risk_level(10)

    def test_safe_json_parse(self):
        assert safe_json_parse('{"key": "value"}') == {"key": "value"}
        assert safe_json_parse('invalid') == {}

class TestCoreDatabase:
    """Merged database tests from test_database.py"""
    
    @pytest.fixture(autouse=True)
    def setup_and_teardown(self):
        clear_db()
        init_db()
        yield
        clear_db()

    def test_database_initialization(self):
        assert os.path.exists("aegis.db")
        with sqlite3.connect("aegis.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = cursor.fetchall()
            assert ('assets',) in tables

    def test_save_and_retrieve_asset(self):
        success = save_asset(
            domain="test.com",
            ip="192.168.1.1",
            ports="80,443",
            score=50
        )
        assert success == True
        
        asset = get_asset_by_domain("test.com")
        assert asset is not None
        assert asset['domain'] == "test.com"

    def test_database_stats(self):
        save_asset("critical.com", score=85)
        save_asset("high.com", score=65)
        
        stats = get_db_stats()
        assert stats['total_assets'] >= 2
        assert stats['critical_risk_assets'] >= 1

class TestCoreScanners:
    """Merged scanner tests from test_scanners.py"""
    
    def test_calculate_score_basic(self):
        score_https = calculate_score("443")
        score_dangerous = calculate_score("21,22,23,135,445")
        assert score_dangerous > score_https

    def test_calculate_score_with_vulnerabilities(self):
        vulns = [{"cvss_score": 9.0, "severity": "critical"}]
        score = calculate_score("80,443", vulns=vulns)
        assert score >= 70

    @patch('aegis.scanners.requests.get')
    def test_check_https(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = check_https("example.com")
        assert result['has_https'] == True

    def test_resolve_ip_valid_domain(self):
        ip = resolve_ip("google.com", timeout=5)
        assert ip != "Unknown"
        assert validate_ip(ip)

if __name__ == "__main__":
    pytest.main([__file__, "-v"])