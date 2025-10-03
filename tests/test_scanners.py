import pytest
from unittest.mock import patch, MagicMock
from aegis.scanners import calculate_score, resolve_ip, run_nmap, check_https, check_web_vulnerabilities
from aegis.utils import validate_domain, validate_ip, get_risk_level

class TestScannersComprehensive:
    def test_calculate_score_various_ports(self):
        """Test risk scoring with different port combinations"""
        with sqlite3.connect(DB_FILE) as conn:
            assert calculate_score("80") == 10
            assert calculate_score("443") == 10  
            assert calculate_score("80,443") == 20
            assert calculate_score("22,80,443") == 30
            assert calculate_score("21,22,23,135,445,3389") > 50

    def test_resolve_ip_valid_domains(self):
        """Test DNS resolution for known domains"""
        with sqlite3.connect(DB_FILE) as conn:
            ip = resolve_ip("google.com")
            assert ip != "Unknown"
            assert validate_ip(ip) == True

    def test_risk_level_boundaries(self):
        """Test risk level classification at boundaries"""
        with sqlite3.connect(DB_FILE) as conn:
            assert "Critical" in get_risk_level(70)
            assert "Critical" in get_risk_level(100)
            assert "High" in get_risk_level(50)  
            assert "High" in get_risk_level(69)
            assert "Medium" in get_risk_level(30)
            assert "Medium" in get_risk_level(49)
            assert "Low" in get_risk_level(1)
            assert "Low" in get_risk_level(29)
            assert "None" in get_risk_level(0)

    def test_domain_validation_edge_cases(self):
        """Test domain validation with edge cases"""
        with sqlite3.connect(DB_FILE) as conn:
            assert validate_domain("a.com") == True
            assert validate_domain("test-domain.com") == True
            assert validate_domain("sub.domain.co.uk") == True
            assert validate_domain("123.com") == True
            assert validate_domain("") == False
            assert validate_domain(".com") == False
            assert validate_domain("test..com") == False

    @patch('aegis.scanners.subprocess.run')
    def test_run_nmap_ethical_mode(self, mock_subprocess):
        """Test nmap with ethical mode using mocking"""
        with sqlite3.connect(DB_FILE) as conn:
            mock_result = MagicMock()
            mock_result.stdout = """
            PORT    STATE SERVICE
            80/tcp  open  http
            443/tcp open  https
            """
            mock_result.returncode = 0
            mock_subprocess.return_value = mock_result
            
            ports = run_nmap("192.168.1.1", "example.com", ethical=True)
            assert ports == "80,443"
        
    @patch('aegis.scanners.requests.get')
    def test_check_https_valid_cert(self, mock_requests):
        """Test HTTPS checking with valid certificate"""
        with sqlite3.connect(DB_FILE) as conn:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_requests.return_value = mock_response
            
            result = check_https("example.com")
            assert result['has_https'] == True
            assert result['valid_cert'] == True

    @patch('aegis.scanners.subprocess.run') 
    def test_check_web_vulnerabilities_safe(self, mock_subprocess):
        """Test web vulnerability scanning with no findings"""
        with sqlite3.connect(DB_FILE) as conn:
            mock_result = MagicMock()
            mock_result.stdout = ""
            mock_result.returncode = 0
            mock_subprocess.return_value = mock_result
            
            result = check_web_vulnerabilities("http://example.com")
            assert result['scan_completed'] == True
            assert len(result['vulnerabilities']) == 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])