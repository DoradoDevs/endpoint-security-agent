"""Tests for scanners.memory_scanner — Memory Scanner."""

from __future__ import annotations

from unittest.mock import patch, MagicMock, PropertyMock, mock_open

import psutil
import pytest

from core.config import AgentConfig, Severity
from scanners.memory_scanner import (
    MemoryScanner,
    JIT_PROCESSES,
    WINDOWS_SYSTEM_BINARIES,
    LINUX_SYSTEM_BINARIES,
    SUSPICIOUS_PARENT_CHILD,
)


@pytest.fixture
def scanner():
    return MemoryScanner(AgentConfig())


def _mock_process(name="app.exe", pid=1000, exe="C:\\Program Files\\app.exe",
                  cmdline=None, status="running"):
    """Build a MagicMock that behaves like a psutil.Process for process_iter."""
    proc = MagicMock()
    proc.info = {
        "pid": pid,
        "name": name,
        "exe": exe,
        "cmdline": cmdline or [exe],
        "status": status,
    }
    proc.pid = pid
    proc.name.return_value = name
    proc.exe.return_value = exe
    proc.status.return_value = status
    return proc


# ======================================================================
# Properties
# ======================================================================

class TestMemoryScannerProperties:

    def test_name(self, scanner):
        assert scanner.name == "MemoryScanner"

    def test_description(self, scanner):
        assert "fileless" in scanner.description.lower() or "memory" in scanner.description.lower()

    def test_supported_platforms(self, scanner):
        assert "all" in scanner.supported_platforms


# ======================================================================
# RWX Memory Detection
# ======================================================================

class TestRWXMemoryDetection:

    @patch("scanners.memory_scanner.platform.system", return_value="Linux")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_rwx_detected_linux(self, mock_iter, mock_sys, scanner):
        proc = _mock_process("suspicious", 1234, "/usr/bin/suspicious")
        mock_iter.return_value = [proc]

        maps_content = (
            "00400000-00401000 r-xp 00000000 fd:01 12345  /usr/bin/suspicious\n"
            "7f000000-7f001000 rwxp 00000000 00:00 0\n"
            "7f100000-7f200000 rw-p 00000000 00:00 0\n"
        )
        with patch("builtins.open", mock_open(read_data=maps_content)):
            findings = scanner._check_rwx_memory()

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["rwx_region_count"] == 1
        assert findings[0].evidence["process_name"] == "suspicious"

    @patch("scanners.memory_scanner.platform.system", return_value="Linux")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_rwx_clean_linux(self, mock_iter, mock_sys, scanner):
        proc = _mock_process("clean", 1234, "/usr/bin/clean")
        mock_iter.return_value = [proc]

        maps_content = (
            "00400000-00401000 r-xp 00000000 fd:01 12345  /usr/bin/clean\n"
            "7f100000-7f200000 rw-p 00000000 00:00 0\n"
        )
        with patch("builtins.open", mock_open(read_data=maps_content)):
            findings = scanner._check_rwx_memory()

        assert len(findings) == 0

    @patch("scanners.memory_scanner.platform.system", return_value="Linux")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_jit_process_excluded(self, mock_iter, mock_sys, scanner):
        proc = _mock_process("java", 5555, "/usr/bin/java")
        mock_iter.return_value = [proc]

        # Even if maps had rwx, java should be skipped entirely
        maps_content = "7f000000-7f001000 rwxp 00000000 00:00 0\n"
        with patch("builtins.open", mock_open(read_data=maps_content)):
            findings = scanner._check_rwx_memory()

        assert len(findings) == 0

    @patch("scanners.memory_scanner.platform.system", return_value="Linux")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_access_denied_handled(self, mock_iter, mock_sys, scanner):
        proc = MagicMock()
        proc.info.__getitem__ = MagicMock(side_effect=psutil.AccessDenied(pid=1))
        # Simulate AccessDenied when accessing proc.info
        type(proc).info = PropertyMock(side_effect=psutil.AccessDenied(pid=1))
        mock_iter.return_value = [proc]

        # Must not raise
        findings = scanner._check_rwx_memory()
        assert isinstance(findings, list)

    @patch("scanners.memory_scanner.platform.system", return_value="Linux")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_no_such_process_handled(self, mock_iter, mock_sys, scanner):
        proc = MagicMock()
        type(proc).info = PropertyMock(side_effect=psutil.NoSuchProcess(pid=999))
        mock_iter.return_value = [proc]

        findings = scanner._check_rwx_memory()
        assert isinstance(findings, list)


# ======================================================================
# Process Masquerading
# ======================================================================

class TestProcessMasquerading:

    @patch("scanners.memory_scanner.platform.system", return_value="Windows")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_svchost_wrong_path(self, mock_iter, mock_sys, scanner):
        proc = _mock_process("svchost.exe", 1000, "C:\\Users\\temp\\svchost.exe")
        mock_iter.return_value = [proc]

        findings = scanner._check_process_masquerading()

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "masquerading" in findings[0].title.lower()

    @patch("scanners.memory_scanner.platform.system", return_value="Windows")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_svchost_correct_path(self, mock_iter, mock_sys, scanner):
        proc = _mock_process("svchost.exe", 400, "c:\\windows\\system32\\svchost.exe")
        mock_iter.return_value = [proc]

        findings = scanner._check_process_masquerading()
        assert len(findings) == 0

    @patch("scanners.memory_scanner.platform.system", return_value="Windows")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_normal_process_ignored(self, mock_iter, mock_sys, scanner):
        proc = _mock_process("myapp.exe", 2000, "C:\\Users\\dev\\myapp.exe")
        mock_iter.return_value = [proc]

        findings = scanner._check_process_masquerading()
        assert len(findings) == 0

    @patch("scanners.memory_scanner.platform.system", return_value="Linux")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_linux_sshd_wrong_path(self, mock_iter, mock_sys, scanner):
        proc = _mock_process("sshd", 900, "/tmp/sshd")
        mock_iter.return_value = [proc]

        findings = scanner._check_process_masquerading()

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    @patch("scanners.memory_scanner.platform.system", return_value="Windows")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_case_insensitive_matching(self, mock_iter, mock_sys, scanner):
        # Process name reported in uppercase — should still be checked
        proc = _mock_process("SVCHOST.EXE", 500, "C:\\Users\\hacker\\SVCHOST.EXE")
        mock_iter.return_value = [proc]

        findings = scanner._check_process_masquerading()

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH


# ======================================================================
# Suspicious Parent-Child Relationships
# ======================================================================

class TestSuspiciousParentChild:

    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_word_spawns_powershell(self, mock_iter, scanner):
        child = _mock_process("powershell.exe", 2000, "C:\\Windows\\System32\\powershell.exe",
                              cmdline=["powershell.exe", "-enc", "base64stuff"])
        parent = MagicMock()
        parent.name.return_value = "WINWORD.EXE"
        parent.pid = 1500
        child.parent.return_value = parent
        mock_iter.return_value = [child]

        findings = scanner._check_suspicious_parent_child()

        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM
        assert "spawn" in findings[0].title.lower() or "chain" in findings[0].title.lower()
        assert findings[0].evidence["parent_name"] == "winword.exe"

    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_word_spawns_normal_child(self, mock_iter, scanner):
        child = _mock_process("calc.exe", 2001, "C:\\Windows\\System32\\calc.exe")
        parent = MagicMock()
        parent.name.return_value = "WINWORD.EXE"
        parent.pid = 1500
        child.parent.return_value = parent
        mock_iter.return_value = [child]

        findings = scanner._check_suspicious_parent_child()
        assert len(findings) == 0

    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_outlook_spawns_cmd(self, mock_iter, scanner):
        child = _mock_process("cmd.exe", 3000, "C:\\Windows\\System32\\cmd.exe",
                              cmdline=["cmd.exe", "/c", "whoami"])
        parent = MagicMock()
        parent.name.return_value = "outlook.exe"
        parent.pid = 2500
        child.parent.return_value = parent
        mock_iter.return_value = [child]

        findings = scanner._check_suspicious_parent_child()

        assert len(findings) == 1
        assert findings[0].evidence["parent_name"] == "outlook.exe"

    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_normal_parent_child(self, mock_iter, scanner):
        child = _mock_process("chrome.exe", 4000, "C:\\Program Files\\Chrome\\chrome.exe")
        parent = MagicMock()
        parent.name.return_value = "explorer.exe"
        parent.pid = 100
        child.parent.return_value = parent
        mock_iter.return_value = [child]

        findings = scanner._check_suspicious_parent_child()
        assert len(findings) == 0

    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_parent_access_denied(self, mock_iter, scanner):
        child = _mock_process("powershell.exe", 5000, "C:\\Windows\\System32\\powershell.exe")
        child.parent.side_effect = psutil.AccessDenied(pid=5000)
        mock_iter.return_value = [child]

        # Must not raise
        findings = scanner._check_suspicious_parent_child()
        assert isinstance(findings, list)


# ======================================================================
# Hidden Network Processes
# ======================================================================

class TestHiddenNetworkProcesses:

    @patch("scanners.memory_scanner.platform.system", return_value="Linux")
    @patch("scanners.memory_scanner.psutil.process_iter")
    @patch("scanners.memory_scanner.psutil.net_connections")
    def test_temp_process_with_connections(self, mock_conns, mock_iter, mock_sys, scanner):
        # Process running from /tmp with an outbound connection
        proc = _mock_process("beacon", 7000, "/tmp/beacon")
        mock_iter.return_value = [proc]

        conn = MagicMock()
        conn.status = "ESTABLISHED"
        conn.pid = 7000
        conn.raddr = MagicMock()
        conn.raddr.ip = "10.0.0.99"
        conn.raddr.port = 443
        mock_conns.return_value = [conn]

        findings = scanner._check_hidden_network_processes()

        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].evidence["remote_ip"] == "10.0.0.99"
        assert findings[0].evidence["remote_port"] == 443

    @patch("scanners.memory_scanner.platform.system", return_value="Windows")
    @patch("scanners.memory_scanner.psutil.process_iter")
    @patch("scanners.memory_scanner.psutil.net_connections")
    def test_system_process_with_connections(self, mock_conns, mock_iter, mock_sys, scanner):
        # svchost.exe is a known network service — should not be flagged
        proc = _mock_process("svchost.exe", 400, "C:\\Windows\\System32\\svchost.exe")
        mock_iter.return_value = [proc]

        conn = MagicMock()
        conn.status = "ESTABLISHED"
        conn.pid = 400
        conn.raddr = MagicMock()
        conn.raddr.ip = "8.8.8.8"
        conn.raddr.port = 53
        mock_conns.return_value = [conn]

        findings = scanner._check_hidden_network_processes()
        assert len(findings) == 0

    @patch("scanners.memory_scanner.platform.system", return_value="Linux")
    @patch("scanners.memory_scanner.psutil.process_iter")
    @patch("scanners.memory_scanner.psutil.net_connections")
    def test_process_without_connections(self, mock_conns, mock_iter, mock_sys, scanner):
        # Process in temp dir but no connections — should not be flagged
        proc = _mock_process("harmless", 8000, "/tmp/harmless")
        mock_iter.return_value = [proc]
        mock_conns.return_value = []

        findings = scanner._check_hidden_network_processes()
        assert len(findings) == 0

    @patch("scanners.memory_scanner.platform.system", return_value="Linux")
    @patch("scanners.memory_scanner.psutil.net_connections")
    def test_connection_enumeration_error(self, mock_conns, mock_sys, scanner):
        mock_conns.side_effect = psutil.AccessDenied(pid=0)

        # Must not raise
        findings = scanner._check_hidden_network_processes()
        assert isinstance(findings, list)
        assert len(findings) == 0


# ======================================================================
# Memory-Only Processes
# ======================================================================

class TestMemoryOnlyProcesses:

    @patch("scanners.memory_scanner.platform.system", return_value="Linux")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_memory_only_detected(self, mock_iter, mock_sys, scanner):
        proc = _mock_process("mystery", 9000, "", status="running")
        proc.exe.return_value = ""
        mock_iter.return_value = [proc]

        findings = scanner._check_memory_only_executables()

        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW
        assert findings[0].category == "Process Anomaly"
        assert findings[0].evidence["pid"] == 9000

    @patch("scanners.memory_scanner.platform.system", return_value="Linux")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_normal_process_not_flagged(self, mock_iter, mock_sys, scanner):
        proc = _mock_process("normal", 9001, "/usr/bin/normal", status="running")
        proc.exe.return_value = "/usr/bin/normal"
        mock_iter.return_value = [proc]

        findings = scanner._check_memory_only_executables()
        assert len(findings) == 0

    @patch("scanners.memory_scanner.platform.system", return_value="Windows")
    @patch("scanners.memory_scanner.psutil.process_iter")
    def test_kernel_threads_excluded(self, mock_iter, mock_sys, scanner):
        # PID 0 (System Idle) and PID 4 (System) should be excluded
        proc0 = _mock_process("System Idle Process", 0, "", status="running")
        proc0.exe.return_value = ""
        proc4 = _mock_process("System", 4, "", status="running")
        proc4.exe.return_value = ""
        mock_iter.return_value = [proc0, proc4]

        findings = scanner._check_memory_only_executables()
        assert len(findings) == 0


# ======================================================================
# Full Scan Integration
# ======================================================================

class TestFullScan:

    @patch.object(MemoryScanner, "_check_memory_only_executables", return_value=[])
    @patch.object(MemoryScanner, "_check_hidden_network_processes", return_value=[])
    @patch.object(MemoryScanner, "_check_suspicious_parent_child", return_value=[])
    @patch.object(MemoryScanner, "_check_process_masquerading", return_value=[])
    @patch.object(MemoryScanner, "_check_rwx_memory", return_value=[])
    def test_scan_aggregates_all_checks(
        self, mock_rwx, mock_masq, mock_parent, mock_network, mock_memonly, scanner
    ):
        findings = scanner.scan()

        assert isinstance(findings, list)
        mock_rwx.assert_called_once()
        mock_masq.assert_called_once()
        mock_parent.assert_called_once()
        mock_network.assert_called_once()
        mock_memonly.assert_called_once()

    @patch("scanners.memory_scanner.platform.system", return_value="Linux")
    @patch("scanners.memory_scanner.psutil.net_connections", return_value=[])
    @patch("scanners.memory_scanner.psutil.process_iter", return_value=[])
    def test_empty_system_returns_clean(self, mock_iter, mock_conns, mock_sys, scanner):
        findings = scanner.scan()
        assert isinstance(findings, list)
        assert len(findings) == 0
