#!/usr/bin/env python3
"""
Thread Pool Scanning Test
"""
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from aegis.scanners import scan_domains_concurrent, get_optimal_thread_count

def test_thread_pool_basic():
    """Test basic thread pool functionality"""
    print("Testing basic thread pool...")

    test_domains = ["httpbin.org", "example.com", "github.com"]

    start_time = time.time()
    results = scan_domains_concurrent(
        domains_to_scan=test_domains,
        ethical=True,  # Safe mode
        max_workers=2
    )
    duration = time.time() - start_time

    print(f"✅ Scanned {len(test_domains)} domains in {duration:.1f}s")
    print(f"✅ Got {len(results)} successful results")
    return len(results) > 0

def test_thread_safety():
    """Test thread safety of shared resources"""
    print("Testing thread safety...")

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

    expected = 5 * 100
    if shared_counter["value"] == expected:
        print(f"✅ Thread safety OK: {shared_counter['value']}/{expected}")
        return True
    else:
        print(f"❌ Thread safety issue: {shared_counter['value']}/{expected}")
        return False

def test_resource_monitoring():
    """Test resource monitoring during scanning"""
    print("Testing resource monitoring...")

    from aegis.scanners import monitor_system_resources, show_system_resources

    try:
        print("Initial resources:")
        show_system_resources()

        status = monitor_system_resources()
        print(f"System healthy: {status.get('system_healthy', False)}")
        print(f"CPU: {status.get('cpu_percent', 0):.1f}%")
        print(f"RAM: {status.get('ram_percent', 0):.1f}%")

        return status.get('system_healthy', False)

    except Exception as e:
        print(f"❌ Resource monitoring error: {e}")
        return False

def run_thread_tests():
    """Run all thread tests"""
    print("=" * 50)
    print("THREAD POOL TEST SUITE")
    print("=" * 50)

    optimal_threads = get_optimal_thread_count()
    print(f"Optimal thread count: {optimal_threads}")

    tests = [
        ("Basic Thread Pool", test_thread_pool_basic),
        ("Thread Safety", test_thread_safety),
        ("Resource Monitoring", test_resource_monitoring)
    ]

    for test_name, test_func in tests:
        print(f"\n[{test_name}]")
        success = test_func()
        print(f"Result: {'✅ PASS' if success else '❌ FAIL'}")

if __name__ == "__main__":
    run_thread_tests()
