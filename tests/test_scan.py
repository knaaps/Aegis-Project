import os
import pytest
from click.testing import CliRunner
from aegis.cli import cli
from aegis.scanners import mock_scanner

@pytest.fixture
def runner():
    """Fixture to provide a CLI runner for testing."""
    return CliRunner()

@pytest.fixture
def mock_scanners(monkeypatch):
    """Mocks the scanner methods to return predictable data."""
    def mock_enumerate_subdomains(domain: str) -> list[str]:
        # Remove 'self' parameter since we're patching the instance method
        return ["www.example.com", "blog.example.com"]
    
    def mock_scan_ports(target: str, rate_limit: int = None) -> str:
        # Remove 'self' parameter since we're patching the instance method
        return "80,443"
    
    # Patch the methods on the mock_scanner instance
    monkeypatch.setattr(mock_scanner, "enumerate_subdomains", mock_enumerate_subdomains)
    monkeypatch.setattr(mock_scanner, "scan_ports", mock_scan_ports)

def test_monitor_log_file_is_created(runner, mock_scanners, tmp_path):
    """
    Test that a 'resource.log' file is created when the --monitor flag is used.
    """
    os.chdir(tmp_path)
    result = runner.invoke(cli, ["scan", "example.com", "--monitor"])
    assert result.exit_code == 0
    assert (tmp_path / "resource.log").exists()

def test_compliance_log_file_is_created(runner, mock_scanners, tmp_path):
    """
    Test that a 'compliance.log' file is created when the --compliance-check flag is used.
    """
    os.chdir(tmp_path)
    result = runner.invoke(cli, ["scan", "example.com", "--compliance-check"])
    assert result.exit_code == 0
    assert (tmp_path / "compliance.log").exists()

def test_scan_command_with_no_options(runner, mock_scanners):
    """
    Test the basic 'aegis scan' command without any optional flags.
    """
    result = runner.invoke(cli, ["scan", "example.com"])
    assert result.exit_code == 0
    assert "Found 2 subdomains." in result.output
    assert "Successfully processed 2 assets." in result.output
    assert "Scan complete. View results in the database." in result.output

def test_scan_command_with_all_options(runner, mock_scanners):
    """
    Test the 'aegis scan' command with all options enabled.
    """
    result = runner.invoke(cli, ["scan", "example.com", "--ethical", "--compliance-check", "--monitor"])
    assert result.exit_code == 0
    assert "Starting scan for example.com..." in result.output
    assert "Resource usage being logged to" in result.output
    assert "Compliance details logged to" in result.output
    assert "Found 2 subdomains." in result.output
    assert "Successfully processed 2 assets." in result.output
