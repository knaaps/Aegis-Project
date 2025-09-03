import pytest
from unittest.mock import patch, MagicMock
from aegis.scanners import (
    validate_input,
    resolve_ip,
    calculate_score,
    validate_domain_strict
)

class TestValidation:
    def test_validate_domain_strict_valid(self):
        assert validate_domain_strict("example.com") == True
        assert validate_domain_strict("sub.example.com") == True
        assert validate_domain_strict("test-site.example.org") == True

    def test_validate_domain_strict_invalid(self):
        assert validate_domain_strict("") == False
        assert validate_domain_strict(".example.com") == False
        assert validate_domain_strict("example.com.") == False
        assert validate_domain_strict("ex..ample.com") == False

    def test_validate_input_ip(self):
        assert validate_input("192.168.1.1", "ip") == "192.168.1.1"
        assert validate_input("256.1.1.1", "ip") == ""
        assert validate_input("not-ip", "ip") == ""

class TestScoring:
    def test_calculate_score_https_only(self):
        score = calculate_score("443")
        assert score >= 45  # Should be high for HTTPS only

    def test_calculate_score_http_only(self):
        score = calculate_score("80")
        assert score <= 35  # Should be lower for HTTP only

    def test_calculate_score_dangerous_ports(self):
        score = calculate_score("23,445,3389")  # Telnet, SMB, RDP
        assert score <= 20  # Should be very low for dangerous ports

@pytest.fixture
def mock_socket():
    with patch('socket.gethostbyname') as mock:
        yield mock

class TestDNSResolution:
    def test_resolve_ip_success(self, mock_socket):
        mock_socket.return_value = "93.184.216.34"
        result = resolve_ip("example.com")
        assert result == "93.184.216.34"

    def test_resolve_ip_failure(self, mock_socket):
        mock_socket.side_effect = Exception("DNS failure")
        result = resolve_ip("nonexistent.domain")
        assert result == "Unknown"
