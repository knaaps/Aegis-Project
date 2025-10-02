import pytest
from aegis.utils import validate_domain, validate_ip, get_risk_level
from aegis.database import init_db, save_asset, get_all_assets

def test_domain_validation():
    assert validate_domain("example.com") == True
    assert validate_domain("sub.example.com") == True
    assert validate_domain("invalid..com") == False  # should now pass
    assert validate_domain("") == False

def test_ip_validation():
    assert validate_ip("192.168.1.1") == True
    assert validate_ip("256.256.256.256") == False
    assert validate_ip("Unknown") == True

def test_risk_scoring():
    assert "Critical" in get_risk_level(75)
    assert "High" in get_risk_level(55)
    assert "Medium" in get_risk_level(35)
    assert "Low" in get_risk_level(10)

def test_database_operations():
    init_db()
    success = save_asset("test.com", ip="192.168.1.1", score=50)
    assert success == True
    assets = get_all_assets()
    assert len(assets) > 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])