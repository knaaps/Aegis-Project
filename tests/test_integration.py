"""
Integration Tests - End-to-end workflows
"""
import pytest
from aegis.database import init_db, get_all_assets, clear_db
from aegis.cli import run_scan_logic, finalize_scan

class TestIntegrationWorkflows:
    """End-to-end workflow tests"""
    
    def test_full_scan_workflow(self):
        clear_db()
        init_db()
        
        result = run_scan_logic(
            domain="example.com",
            ethical=True,
            monitor=False,
            max_subdomains=5,
            use_threading=False
        )
        
        assert result is not None
        assert result.get('success') == True
        assert result.get('successful_scans', 0) >= 1
        
        assets = get_all_assets()
        assert len(assets) >= 1

    def test_scan_with_threading(self):
        clear_db()
        init_db()
        
        result = run_scan_logic(
            domain="example.com",
            ethical=True,
            monitor=False,
            max_subdomains=3,
            max_workers=2,
            use_threading=True
        )
        
        assert result is not None
        assert result.get('threading_enabled') == True

    def test_finalize_scan(self):
        scan_stats = {
            "domain": "test.com",
            "scan_id": "test123",
            "start_time": 1000,
            "subdomains_found": 5,
            "successful_scans": 3,
            "failed_scans": 2,
            "threading_enabled": True,
            "max_workers": 4
        }
        
        result = finalize_scan(scan_stats, True)
        assert result is not None
        assert result['success'] == True
        assert 'duration' in result

if __name__ == "__main__":
    pytest.main([__file__, "-v"])