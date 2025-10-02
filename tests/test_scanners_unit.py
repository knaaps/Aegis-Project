import pytest
from aegis.scanners import calculate_score, resolve_ip
from aegis.utils import validate_domain, validate_ip, get_risk_level 
class TestScannersUnit:
    def test_calculate_score_various_ports(self):
        """Test risk scoring with different port combinations"""
        # Test common port combinations - UPDATED VALUES
        assert calculate_score("80") == 10  # HTTP only (was 20)
        assert calculate_score("443") == 10  # HTTPS only (was 20)  
        assert calculate_score("80,443") == 20  # Web services
        assert calculate_score("22,80,443") == 30  # SSH + Web (was 40)
        assert calculate_score("21,22,23,135,445,3389") > 50  # High risk ports

    def test_resolve_ip_valid_domains(self):
        """Test DNS resolution for known domains"""
        # These should resolve to real IPs
        ip = resolve_ip("google.com")
        assert ip != "Unknown"
        assert validate_ip(ip) == True

    def test_risk_level_boundaries(self):
        """Test risk level classification at boundaries"""
        assert "Critical" in get_risk_level(70)  # Lower boundary
        assert "Critical" in get_risk_level(100) # Upper boundary
        assert "High" in get_risk_level(50)      # Lower boundary  
        assert "High" in get_risk_level(69)      # Upper boundary
        assert "Medium" in get_risk_level(30)    # Lower boundary
        assert "Medium" in get_risk_level(49)    # Upper boundary
        assert "Low" in get_risk_level(1)        # Lower boundary
        assert "Low" in get_risk_level(29)       # Upper boundary
        assert "None" in get_risk_level(0)       # No risk

    def test_domain_validation_edge_cases(self):
        """Test domain validation with edge cases"""
        assert validate_domain("a.com") == True        # Short domain
        assert validate_domain("test-domain.com") == True  # Hyphen
        assert validate_domain("sub.domain.co.uk") == True # Multi-level
        assert validate_domain("123.com") == True       # Numbers
        assert validate_domain("") == False             # Empty
        assert validate_domain(".com") == False         # No hostname
        assert validate_domain("test..com") == False    # Double dots