"""Tests for the Live IOC Correlator scanner.

Every system call (psutil, subprocess, file I/O) is mocked so that tests
run without real system access.
"""

from __future__ import annotations

from collections import namedtuple
from unittest.mock import MagicMock, patch, mock_open

import pytest

from core.config import AgentConfig, Severity
from scanners.ioc_scanner import IOCScanner, KNOWN_MALWARE_PORTS
from threat_intel.models import IOCEntry, IOCType, ThreatCategory


# ── Fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture
def config():
    return AgentConfig()


@pytest.fixture
def scanner(config):
    return IOCScanner(config)


def _make_ioc_entry(
    value: str = "abc123",
    ioc_type: IOCType = IOCType.FILE_HASH_SHA256,
    category: ThreatCategory = ThreatCategory.MALWARE,
    source: str = "test_feed",
    confidence: int = 90,
) -> IOCEntry:
    return IOCEntry(
        value=value,
        ioc_type=ioc_type,
        threat_category=category,
        source=source,
        confidence=confidence,
        description="test indicator",
    )


# Lightweight named-tuple stand-ins for psutil connection / address objects
_Addr = namedtuple("_Addr", ["ip", "port"])
_Conn = namedtuple("_Conn", ["status", "raddr", "laddr", "pid"])
_MMap = namedtuple("_MMap", ["path"])


# ── TestIOCScannerProperties ────────────────────────────────────────────────

class TestIOCScannerProperties:
    def test_name(self, scanner):
        assert scanner.name == "IOCScanner"

    def test_description(self, scanner):
        assert "threat intelligence" in scanner.description.lower()

    def test_supported_platforms(self, scanner):
        assert scanner.supported_platforms == ["all"]


# ── TestProcessHashCheck ────────────────────────────────────────────────────

class TestProcessHashCheck:
    """Check 1: Process executable hash check."""

    def test_matching_hash_found(self, scanner):
        """A process whose SHA-256 matches the IOC database produces a CRITICAL finding."""
        mock_db = MagicMock()
        mock_db.lookup_hash.return_value = _make_ioc_entry()
        scanner._ioc_db = mock_db

        proc = MagicMock()
        proc.exe.return_value = "C:\\malware.exe"
        proc.name.return_value = "malware.exe"
        proc.pid = 1234

        fake_hash = "d" * 64
        with patch("scanners.ioc_scanner.psutil") as mock_psutil, \
             patch.object(scanner, "_hash_file", return_value=fake_hash):
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.AccessDenied = Exception
            mock_psutil.NoSuchProcess = Exception
            mock_psutil.ZombieProcess = Exception

            findings = scanner._check_process_hashes()

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].evidence["pid"] == 1234
        assert findings[0].evidence["sha256"] == fake_hash
        assert findings[0].category == "Threat Intelligence"

    def test_no_match(self, scanner):
        """Clean executables produce no findings."""
        mock_db = MagicMock()
        mock_db.lookup_hash.return_value = None
        scanner._ioc_db = mock_db

        proc = MagicMock()
        proc.exe.return_value = "C:\\safe.exe"
        proc.name.return_value = "safe.exe"
        proc.pid = 10

        with patch("scanners.ioc_scanner.psutil") as mock_psutil, \
             patch.object(scanner, "_hash_file", return_value="a" * 64):
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.AccessDenied = Exception
            mock_psutil.NoSuchProcess = Exception
            mock_psutil.ZombieProcess = Exception

            findings = scanner._check_process_hashes()

        assert findings == []

    def test_access_denied_handling(self, scanner):
        """Processes that raise AccessDenied are silently skipped."""
        mock_db = MagicMock()
        scanner._ioc_db = mock_db

        proc = MagicMock()
        proc.exe.side_effect = PermissionError("access denied")

        with patch("scanners.ioc_scanner.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.AccessDenied = PermissionError
            mock_psutil.NoSuchProcess = ProcessLookupError
            mock_psutil.ZombieProcess = ChildProcessError

            findings = scanner._check_process_hashes()

        assert findings == []

    def test_empty_process_list(self, scanner):
        """No processes yields no findings."""
        mock_db = MagicMock()
        scanner._ioc_db = mock_db

        with patch("scanners.ioc_scanner.psutil") as mock_psutil:
            mock_psutil.process_iter.return_value = []
            mock_psutil.AccessDenied = Exception
            mock_psutil.NoSuchProcess = Exception
            mock_psutil.ZombieProcess = Exception

            findings = scanner._check_process_hashes()

        assert findings == []


# ── TestConnectionIPCheck ───────────────────────────────────────────────────

class TestConnectionIPCheck:
    """Check 2: Active connection IP check."""

    def test_malicious_ip_found(self, scanner):
        """An ESTABLISHED connection to a known-bad IP produces a CRITICAL finding."""
        entry = _make_ioc_entry(
            value="10.0.0.99",
            ioc_type=IOCType.IP_ADDRESS,
            category=ThreatCategory.C2_SERVER,
        )
        mock_db = MagicMock()
        mock_db.lookup_ip.return_value = entry
        scanner._ioc_db = mock_db

        conn = _Conn(
            status="ESTABLISHED",
            raddr=_Addr(ip="10.0.0.99", port=443),
            laddr=_Addr(ip="192.168.1.10", port=54321),
            pid=5678,
        )
        mock_proc = MagicMock()
        mock_proc.name.return_value = "evil.exe"

        with patch("scanners.ioc_scanner.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = [conn]
            mock_psutil.Process.return_value = mock_proc
            mock_psutil.AccessDenied = Exception
            mock_psutil.NoSuchProcess = Exception

            findings = scanner._check_active_connections()

        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].evidence["remote_ip"] == "10.0.0.99"
        assert findings[0].evidence["process_name"] == "evil.exe"

    def test_clean_connections(self, scanner):
        """Connections to benign IPs produce no findings."""
        mock_db = MagicMock()
        mock_db.lookup_ip.return_value = None
        scanner._ioc_db = mock_db

        conn = _Conn(
            status="ESTABLISHED",
            raddr=_Addr(ip="8.8.8.8", port=53),
            laddr=_Addr(ip="192.168.1.10", port=12345),
            pid=100,
        )

        with patch("scanners.ioc_scanner.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = [conn]
            mock_psutil.AccessDenied = Exception
            mock_psutil.NoSuchProcess = Exception

            findings = scanner._check_active_connections()

        assert findings == []

    def test_no_connections(self, scanner):
        """Empty connection list produces no findings."""
        mock_db = MagicMock()
        scanner._ioc_db = mock_db

        with patch("scanners.ioc_scanner.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = []
            mock_psutil.AccessDenied = Exception

            findings = scanner._check_active_connections()

        assert findings == []

    def test_process_lookup_failure(self, scanner):
        """Process lookup failure still produces a finding with 'unknown' name."""
        entry = _make_ioc_entry(
            value="10.0.0.99",
            ioc_type=IOCType.IP_ADDRESS,
            category=ThreatCategory.BOTNET,
        )
        mock_db = MagicMock()
        mock_db.lookup_ip.return_value = entry
        scanner._ioc_db = mock_db

        conn = _Conn(
            status="SYN_SENT",
            raddr=_Addr(ip="10.0.0.99", port=80),
            laddr=_Addr(ip="192.168.1.10", port=9999),
            pid=9999,
        )

        with patch("scanners.ioc_scanner.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = [conn]
            mock_psutil.Process.side_effect = ProcessLookupError("gone")
            mock_psutil.AccessDenied = Exception
            mock_psutil.NoSuchProcess = ProcessLookupError

            findings = scanner._check_active_connections()

        assert len(findings) == 1
        assert findings[0].evidence["process_name"] == "unknown"


# ── TestDNSCacheCheck ───────────────────────────────────────────────────────

class TestDNSCacheCheck:
    """Check 3: DNS cache domain check."""

    def test_malicious_domain_in_windows_cache(self, scanner):
        """A malicious domain in ipconfig /displaydns output triggers HIGH."""
        entry = _make_ioc_entry(
            value="evil.example.com",
            ioc_type=IOCType.DOMAIN,
            category=ThreatCategory.PHISHING,
        )
        mock_db = MagicMock()
        mock_db.lookup_domain.side_effect = lambda d: entry if d == "evil.example.com" else None
        scanner._ioc_db = mock_db

        dns_output = (
            "    Record Name . . . . . : evil.example.com\n"
            "    Record Type . . . . . : 1\n"
            "    A (Host) Record . . . : 10.0.0.50\n"
            "\n"
            "    Record Name . . . . . : safe.example.com\n"
            "    Record Type . . . . . : 1\n"
            "    A (Host) Record . . . : 1.1.1.1\n"
            "\n"
        )

        mock_result = MagicMock()
        mock_result.stdout = dns_output

        with patch("scanners.ioc_scanner.platform") as mock_platform, \
             patch("scanners.ioc_scanner.subprocess") as mock_subprocess:
            mock_platform.system.return_value = "Windows"
            mock_subprocess.run.return_value = mock_result
            mock_subprocess.TimeoutExpired = subprocess_TimeoutExpired_stub
            mock_subprocess.SubprocessError = Exception

            findings = scanner._check_dns_cache()

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["domain"] == "evil.example.com"
        assert findings[0].evidence["resolved_ip"] == "10.0.0.50"

    def test_clean_cache(self, scanner):
        """No matching domains produce no findings."""
        mock_db = MagicMock()
        mock_db.lookup_domain.return_value = None
        scanner._ioc_db = mock_db

        dns_output = (
            "    Record Name . . . . . : safe.example.com\n"
            "    Record Type . . . . . : 1\n"
            "    A (Host) Record . . . : 1.1.1.1\n"
            "\n"
        )

        mock_result = MagicMock()
        mock_result.stdout = dns_output

        with patch("scanners.ioc_scanner.platform") as mock_platform, \
             patch("scanners.ioc_scanner.subprocess") as mock_subprocess:
            mock_platform.system.return_value = "Windows"
            mock_subprocess.run.return_value = mock_result
            mock_subprocess.TimeoutExpired = subprocess_TimeoutExpired_stub
            mock_subprocess.SubprocessError = Exception

            findings = scanner._check_dns_cache()

        assert findings == []

    def test_dns_command_failure(self, scanner):
        """Subprocess failure returns empty findings, no exception."""
        mock_db = MagicMock()
        scanner._ioc_db = mock_db

        with patch("scanners.ioc_scanner.platform") as mock_platform, \
             patch("scanners.ioc_scanner.subprocess") as mock_subprocess:
            mock_platform.system.return_value = "Windows"
            mock_subprocess.run.side_effect = FileNotFoundError("ipconfig not found")
            mock_subprocess.TimeoutExpired = subprocess_TimeoutExpired_stub
            mock_subprocess.SubprocessError = Exception

            findings = scanner._check_dns_cache()

        assert findings == []


# Stub exception class for subprocess.TimeoutExpired mock
class subprocess_TimeoutExpired_stub(Exception):
    pass


# ── TestMalwarePortCheck ────────────────────────────────────────────────────

class TestMalwarePortCheck:
    """Check 5: Known malware port check."""

    def test_listening_on_4444(self, scanner):
        """A process listening on port 4444 triggers a MEDIUM finding."""
        mock_db = MagicMock()
        scanner._ioc_db = mock_db

        conn = _Conn(
            status="LISTEN",
            raddr=None,
            laddr=_Addr(ip="0.0.0.0", port=4444),
            pid=777,
        )
        mock_proc = MagicMock()
        mock_proc.name.return_value = "handler.exe"

        with patch("scanners.ioc_scanner.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = [conn]
            mock_psutil.Process.return_value = mock_proc
            mock_psutil.AccessDenied = Exception
            mock_psutil.NoSuchProcess = Exception

            findings = scanner._check_malware_ports()

        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].evidence["port"] == 4444
        assert findings[0].evidence["known_threat"] == "Metasploit default handler"

    def test_clean_ports(self, scanner):
        """Listening on non-suspicious ports produces no findings."""
        mock_db = MagicMock()
        scanner._ioc_db = mock_db

        conn = _Conn(
            status="LISTEN",
            raddr=None,
            laddr=_Addr(ip="0.0.0.0", port=80),
            pid=100,
        )

        with patch("scanners.ioc_scanner.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = [conn]
            mock_psutil.AccessDenied = Exception
            mock_psutil.NoSuchProcess = Exception

            findings = scanner._check_malware_ports()

        assert findings == []

    def test_no_listeners(self, scanner):
        """No listening sockets produces no findings."""
        mock_db = MagicMock()
        scanner._ioc_db = mock_db

        with patch("scanners.ioc_scanner.psutil") as mock_psutil:
            mock_psutil.net_connections.return_value = []
            mock_psutil.AccessDenied = Exception

            findings = scanner._check_malware_ports()

        assert findings == []


# ── TestFullScan ────────────────────────────────────────────────────────────

class TestFullScan:
    """Integration-level tests for the scan() entry point."""

    def test_scan_aggregates_all_checks(self, scanner):
        """scan() should call every sub-check and aggregate results."""
        mock_db = MagicMock()
        mock_db.load.return_value = None
        scanner._ioc_db = mock_db

        # Stub individual checks to return one finding each
        f1 = MagicMock(spec_set=["title", "description", "severity", "category",
                                  "scanner", "evidence", "remediation",
                                  "cve_ids", "timestamp"])
        f1.severity = Severity.CRITICAL

        with patch.object(scanner, "_init_ioc_db") as mock_init, \
             patch.object(scanner, "_check_process_hashes", return_value=[f1]), \
             patch.object(scanner, "_check_active_connections", return_value=[f1]), \
             patch.object(scanner, "_check_dns_cache", return_value=[f1]), \
             patch.object(scanner, "_check_loaded_modules", return_value=[f1]), \
             patch.object(scanner, "_check_malware_ports", return_value=[f1]), \
             patch("scanners.ioc_scanner.psutil", new=MagicMock()):
            findings = scanner.scan()

        assert len(findings) == 5
        mock_init.assert_called_once()

    def test_empty_ioc_database_returns_no_findings(self, scanner):
        """When the IOC database has no entries, no findings are produced."""
        mock_db = MagicMock()
        mock_db.load.return_value = None
        mock_db.lookup_hash.return_value = None
        mock_db.lookup_ip.return_value = None
        mock_db.lookup_domain.return_value = None
        scanner._ioc_db = mock_db

        # Process check: one safe process
        proc = MagicMock()
        proc.exe.return_value = "C:\\safe.exe"
        proc.name.return_value = "safe.exe"
        proc.pid = 1
        proc.memory_maps.return_value = []

        # Connection check: one clean connection
        conn = _Conn(
            status="ESTABLISHED",
            raddr=_Addr(ip="8.8.8.8", port=53),
            laddr=_Addr(ip="192.168.1.10", port=12345),
            pid=1,
        )
        # Listen check: standard port
        listen_conn = _Conn(
            status="LISTEN",
            raddr=None,
            laddr=_Addr(ip="0.0.0.0", port=80),
            pid=1,
        )

        with patch("scanners.ioc_scanner.psutil") as mock_psutil, \
             patch.object(scanner, "_init_ioc_db"), \
             patch.object(scanner, "_hash_file", return_value="b" * 64), \
             patch("scanners.ioc_scanner.platform") as mock_platform, \
             patch("scanners.ioc_scanner.subprocess") as mock_subprocess:

            mock_psutil.process_iter.return_value = [proc]
            mock_psutil.net_connections.return_value = [conn, listen_conn]
            mock_psutil.Process.return_value = proc
            mock_psutil.AccessDenied = Exception
            mock_psutil.NoSuchProcess = Exception
            mock_psutil.ZombieProcess = Exception

            mock_platform.system.return_value = "Windows"
            mock_result = MagicMock()
            mock_result.stdout = ""
            mock_subprocess.run.return_value = mock_result
            mock_subprocess.TimeoutExpired = subprocess_TimeoutExpired_stub
            mock_subprocess.SubprocessError = Exception

            findings = scanner.scan()

        assert findings == []
