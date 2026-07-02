"""Tests for Service Audit Scanner."""

from unittest.mock import patch, MagicMock

from core.config import AgentConfig, Severity
from scanners.service_audit_scanner import ServiceAuditScanner


def _make_config():
    return AgentConfig()


def _make_service(name, display_name="", status="running", start_type="auto", pid=0, user=""):
    svc = MagicMock()
    svc.name = name
    svc.display_name = display_name or name
    svc.status = status
    svc.start_type = start_type
    svc.pid = pid
    svc.user = user
    return svc


def test_scanner_properties():
    scanner = ServiceAuditScanner(_make_config())
    assert scanner.name == "Service Audit Scanner"
    assert "all" in scanner.supported_platforms


def test_risky_windows_service_detected():
    """Known risky Windows service should be flagged."""
    scanner = ServiceAuditScanner(_make_config())

    services = [
        _make_service("TlntSvr", "Telnet Server"),
        _make_service("Spooler", "Print Spooler"),
    ]

    findings = scanner._audit_windows_services(services)
    risky = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(risky) >= 1
    assert "telnet" in risky[0].title.lower()


def test_risky_linux_service_detected():
    """Known risky Linux service should be flagged."""
    scanner = ServiceAuditScanner(_make_config())

    services = [
        _make_service("telnet", "Telnet"),
        _make_service("sshd", "SSH Daemon"),
    ]

    findings = scanner._audit_linux_services(services)
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) >= 1


def test_clean_services_no_risky_findings():
    """Normal services should not trigger risky findings."""
    scanner = ServiceAuditScanner(_make_config())

    services = [
        _make_service("sshd", "SSH Daemon"),
        _make_service("nginx", "Nginx Web Server"),
    ]

    findings = scanner._audit_linux_services(services)
    risky = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    assert len(risky) == 0


def test_scan_returns_inventory():
    """Scan should always include a service inventory INFO finding."""
    scanner = ServiceAuditScanner(_make_config())

    with patch("scanners.service_audit_scanner.load_os_module") as mock_loader:
        mock_module = MagicMock()
        mock_module.get_running_services.return_value = [
            _make_service("sshd"),
        ]
        mock_loader.return_value = mock_module

        with patch("scanners.service_audit_scanner.platform") as mock_platform:
            mock_platform.system.return_value = "Linux"
            findings = scanner.scan()
            info = [f for f in findings if f.severity == Severity.INFO]
            assert any("inventory" in f.title.lower() for f in info)


if __name__ == "__main__":
    test_scanner_properties()
    test_risky_windows_service_detected()
    test_risky_linux_service_detected()
    test_clean_services_no_risky_findings()
    test_scan_returns_inventory()
    print("All service audit scanner tests passed!")
