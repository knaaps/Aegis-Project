import pytest
from unittest.mock import patch, MagicMock
from aegis.scanners import run_nmap, check_https, check_web_vulnerabilities

class TestScannersMocked:
    @patch('aegis.scanners.subprocess.run')
    def test_run_nmap_ethical_mode(self, mock_subprocess):
        """Test nmap with ethical mode using mocking"""
        # Mock successful nmap output
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
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_requests.return_value = mock_response
        
        result = check_https("example.com")
        assert result['has_https'] == True
        assert result['valid_cert'] == True

    @patch('aegis.scanners.subprocess.run') 
    def test_check_web_vulnerabilities_safe(self, mock_subprocess):
        """Test web vulnerability scanning with no findings"""
        mock_result = MagicMock()
        mock_result.stdout = ""  # No vulnerabilities found
        mock_result.returncode = 0
        mock_subprocess.return_value = mock_result
        
        result = check_web_vulnerabilities("http://example.com")
        assert result['scan_completed'] == True
        assert len(result['vulnerabilities']) == 0