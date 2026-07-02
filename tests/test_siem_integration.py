"""Tests for SIEM/Webhook Integration module."""

import sys
import json
import socket
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, call
from dataclasses import dataclass, field
from enum import Enum

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from reporting.siem_integration import SIEMIntegration, SIEMConfig
from edr.event_types import EDREvent, EDREventType
from core.config import Severity


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _MockSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class _MockFinding:
    title: str = "Open SSH port"
    description: str = "Port 22 is open and accessible from outside"
    severity: _MockSeverity = _MockSeverity.HIGH
    category: str = "Network Security"
    scanner: str = "NetworkScanner"
    evidence: dict = field(default_factory=dict)
    remediation: str = "Close the port or restrict access"


def _make_event(**kwargs) -> EDREvent:
    defaults = dict(
        event_type=EDREventType.NETWORK_CONNECT,
        source_process="curl.exe",
        source_pid=1234,
        target="10.0.0.1:443",
        severity="medium",
        details={"protocol": "tcp"},
    )
    defaults.update(kwargs)
    return EDREvent(**defaults)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_finding_to_payload():
    """Verify payload structure from _finding_to_payload."""
    siem = SIEMIntegration()
    finding = _MockFinding()
    device_info = {"hostname": "test-host", "os": "Windows"}

    payload = siem._finding_to_payload(finding, device_info)

    assert payload["event_type"] == "security_finding"
    assert "timestamp" in payload
    assert payload["finding"]["title"] == "Open SSH port"
    assert payload["finding"]["severity"] == "high"
    assert payload["finding"]["category"] == "Network Security"
    assert payload["finding"]["scanner"] == "NetworkScanner"
    assert payload["finding"]["remediation"] == "Close the port or restrict access"
    assert payload["device"]["hostname"] == "test-host"


def test_finding_to_payload_no_device_info():
    """Payload with no device info should have empty device dict."""
    siem = SIEMIntegration()
    payload = siem._finding_to_payload(_MockFinding(), None)
    assert payload["device"] == {}


def test_cef_format():
    """Verify CEF string format."""
    siem = SIEMIntegration(SIEMConfig(syslog_format="cef"))
    finding = _MockFinding(severity=_MockSeverity.CRITICAL)

    cef = siem._format_cef(finding, None)

    assert cef.startswith("CEF:0|Sentinel|SecurityAgent|4.0|")
    assert "Network Security" in cef
    assert "Open SSH port" in cef
    # Critical severity maps to 10
    assert "|10|" in cef
    assert "msg=" in cef
    assert "cat=Network Security" in cef


def test_cef_pipe_escaping():
    """Pipes in title/category are replaced with underscores."""
    siem = SIEMIntegration()
    finding = _MockFinding(title="Pipe|Test", category="Cat|egory")

    cef = siem._format_cef(finding, None)

    assert "Pipe_Test" in cef
    assert "Cat_egory" in cef


def test_leef_format():
    """Verify LEEF string format."""
    siem = SIEMIntegration(SIEMConfig(syslog_format="leef"))
    finding = _MockFinding(severity=_MockSeverity.MEDIUM)

    leef = siem._format_leef(finding, None)

    assert leef.startswith("LEEF:2.0|Sentinel|SecurityAgent|4.0|")
    assert "sev=4" in leef
    assert "title=Open SSH port" in leef
    assert "msg=" in leef


def test_forward_finding_below_threshold():
    """Low severity finding skipped when forward_min_severity is high."""
    config = SIEMConfig(
        webhook_url="https://example.com/hook",
        forward_min_severity="high",
    )
    siem = SIEMIntegration(config)
    finding = _MockFinding(severity=_MockSeverity.LOW)

    result = siem.forward_finding(finding)

    assert result is False
    assert siem._forwarded_count == 0


def test_forward_finding_at_threshold():
    """Finding at the threshold severity should be forwarded (mocked)."""
    config = SIEMConfig(
        webhook_url="https://example.com/hook",
        forward_min_severity="medium",
    )
    siem = SIEMIntegration(config)
    finding = _MockFinding(severity=_MockSeverity.MEDIUM)

    with patch.object(siem, '_send_webhook', return_value=True) as mock_wh:
        result = siem.forward_finding(finding)

    assert result is True
    assert siem._forwarded_count == 1
    mock_wh.assert_called_once()


def test_webhook_send():
    """Mock urllib and verify POST sent with correct payload."""
    config = SIEMConfig(
        webhook_url="https://siem.example.com/api/events",
        webhook_auth_header="Authorization: Bearer tok123",
    )
    siem = SIEMIntegration(config)

    mock_response = MagicMock()
    mock_response.status = 200

    with patch("urllib.request.urlopen", return_value=mock_response) as mock_open:
        payload = {"event_type": "test", "data": "value"}
        result = siem._send_webhook(payload)

    assert result is True
    mock_open.assert_called_once()
    req_arg = mock_open.call_args[0][0]
    assert req_arg.full_url == "https://siem.example.com/api/events"
    assert req_arg.get_header("Content-type") == "application/json"
    assert req_arg.get_header("Authorization") == "Bearer tok123"
    body = json.loads(req_arg.data.decode("utf-8"))
    assert body["event_type"] == "test"


def test_webhook_retry():
    """Mock urllib to fail twice then succeed, verify 3 attempts."""
    config = SIEMConfig(
        webhook_url="https://siem.example.com/api",
        retry_attempts=3,
        retry_delay=0.01,  # fast retries for test
    )
    siem = SIEMIntegration(config)

    call_count = 0

    def side_effect(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise ConnectionError("Connection refused")
        return MagicMock()

    with patch("urllib.request.urlopen", side_effect=side_effect):
        result = siem._send_webhook({"test": True})

    assert result is True
    assert call_count == 3


def test_webhook_all_retries_fail():
    """All retry attempts fail — returns False and increments error count."""
    config = SIEMConfig(
        webhook_url="https://siem.example.com/api",
        retry_attempts=2,
        retry_delay=0.01,
    )
    siem = SIEMIntegration(config)

    with patch("urllib.request.urlopen", side_effect=ConnectionError("fail")):
        result = siem._send_webhook({"test": True})

    assert result is False
    assert siem._error_count == 1


def test_syslog_udp():
    """Mock socket and verify UDP send."""
    config = SIEMConfig(
        syslog_host="10.0.0.50",
        syslog_port=514,
        syslog_protocol="udp",
    )
    siem = SIEMIntegration(config)

    mock_sock = MagicMock()
    with patch("socket.socket", return_value=mock_sock):
        result = siem._send_syslog("CEF:0|Test|Agent|1.0|test|Test Event|5|msg=hello")

    assert result is True
    mock_sock.sendto.assert_called_once()
    sent_data, addr = mock_sock.sendto.call_args[0]
    assert b"CEF:0" in sent_data
    assert addr == ("10.0.0.50", 514)
    mock_sock.close.assert_called_once()


def test_syslog_tcp():
    """Mock socket and verify TCP connect+send."""
    config = SIEMConfig(
        syslog_host="10.0.0.50",
        syslog_port=1514,
        syslog_protocol="tcp",
    )
    siem = SIEMIntegration(config)

    mock_sock = MagicMock()
    with patch("socket.socket", return_value=mock_sock):
        result = siem._send_syslog("CEF:0|Test|Agent|1.0|test|Test Event|5|msg=hello")

    assert result is True
    mock_sock.connect.assert_called_once_with(("10.0.0.50", 1514))
    mock_sock.sendall.assert_called_once()
    assert b"CEF:0" in mock_sock.sendall.call_args[0][0]
    mock_sock.close.assert_called_once()


def test_syslog_failure():
    """Socket error returns False and increments error count."""
    config = SIEMConfig(syslog_host="10.0.0.50", syslog_protocol="udp")
    siem = SIEMIntegration(config)

    with patch("socket.socket", side_effect=OSError("Network unreachable")):
        result = siem._send_syslog("test message")

    assert result is False
    assert siem._error_count == 1


def test_forward_event():
    """Verify EDR event forwarding produces correct payload."""
    config = SIEMConfig(webhook_url="https://siem.example.com/events")
    siem = SIEMIntegration(config)
    event = _make_event()
    device_info = {"hostname": "workstation-1"}

    with patch.object(siem, '_send_webhook', return_value=True) as mock_wh:
        result = siem.forward_event(event, device_info)

    assert result is True
    payload = mock_wh.call_args[0][0]
    assert payload["event_type"] == "edr_event"
    assert payload["type"] == "network_connect"
    assert payload["source_process"] == "curl.exe"
    assert payload["source_pid"] == 1234
    assert payload["target"] == "10.0.0.1:443"
    assert payload["device"]["hostname"] == "workstation-1"


def test_forward_event_cef():
    """Verify CEF formatting for EDR events."""
    siem = SIEMIntegration()
    event = _make_event(severity="high")

    cef = siem._format_cef_event(event)

    assert cef.startswith("CEF:0|Sentinel|EDR|4.0|")
    assert "network_connect" in cef
    assert "EDR Event" in cef
    assert "src=curl.exe" in cef
    assert "dst=10.0.0.1:443" in cef
    assert "pid=1234" in cef


def test_get_stats():
    """Verify counter tracking."""
    config = SIEMConfig(
        webhook_url="https://siem.example.com/api",
        syslog_host="10.0.0.50",
    )
    siem = SIEMIntegration(config)

    # Initial state
    stats = siem.get_stats()
    assert stats["forwarded"] == 0
    assert stats["errors"] == 0

    # Simulate successful forward
    finding = _MockFinding(severity=_MockSeverity.HIGH)
    with patch.object(siem, '_send_webhook', return_value=True), \
         patch.object(siem, '_send_syslog', return_value=True):
        siem.forward_finding(finding)

    stats = siem.get_stats()
    assert stats["forwarded"] == 1
    assert stats["errors"] == 0


def test_format_syslog_selects_cef():
    """_format_syslog selects CEF by default."""
    siem = SIEMIntegration(SIEMConfig(syslog_format="cef"))
    finding = _MockFinding()
    msg = siem._format_syslog(finding, None)
    assert msg.startswith("CEF:0|")


def test_format_syslog_selects_leef():
    """_format_syslog selects LEEF when configured."""
    siem = SIEMIntegration(SIEMConfig(syslog_format="leef"))
    finding = _MockFinding()
    msg = siem._format_syslog(finding, None)
    assert msg.startswith("LEEF:2.0|")


if __name__ == "__main__":
    test_finding_to_payload()
    test_finding_to_payload_no_device_info()
    test_cef_format()
    test_cef_pipe_escaping()
    test_leef_format()
    test_forward_finding_below_threshold()
    test_forward_finding_at_threshold()
    test_webhook_send()
    test_webhook_retry()
    test_webhook_all_retries_fail()
    test_syslog_udp()
    test_syslog_tcp()
    test_syslog_failure()
    test_forward_event()
    test_forward_event_cef()
    test_get_stats()
    test_format_syslog_selects_cef()
    test_format_syslog_selects_leef()
    print("All SIEM integration tests passed!")
