"""
External Tools Tests - Nuclei, threading, etc.
"""
import pytest
import subprocess
import time
import threading
from aegis.scanners import check_web_vulnerabilities, scan_domains_concurrent, get_optimal_thread_count

class TestExternalTools:
    """Tests for external tool integration"""
    
    def test_nuclei_installation(self):
        try:
            result = subprocess.run(
                ["nuclei", "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            assert result.returncode == 0
        except FileNotFoundError:
            pytest.skip("Nuclei not installed")

    def test_basic_nuclei_scan(self):
        test_url = "https://httpbin.org"
        
        result = check_web_vulnerabilities(
            url=test_url,
            tags="tech-detect,misconfiguration",
            timeout=60
        )
        
        assert result is not None
        assert isinstance(result, dict)
        assert "scan_completed" in result

    def test_thread_pool_basic(self):
        test_domains = ["httpbin.org", "example.com", "github.com"]
        
        start_time = time.time()
        results = scan_domains_concurrent(
            domains_to_scan=test_domains,
            ethical=True,
            max_workers=2
        )
        duration = time.time() - start_time
        
        assert isinstance(results, list)
        assert duration < 300

    def test_thread_safety(self):
        shared_counter = {"value": 0}
        lock = threading.Lock()
        
        def worker():
            for _ in range(100):
                with lock:
                    shared_counter["value"] += 1
        
        threads = []
        for _ in range(5):
            t = threading.Thread(target=worker)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        assert shared_counter["value"] == 500

    def test_optimal_thread_count(self):
        optimal = get_optimal_thread_count()
        assert isinstance(optimal, int)
        assert optimal >= 1
        assert optimal <= 32

if __name__ == "__main__":
    pytest.main([__file__, "-v"])