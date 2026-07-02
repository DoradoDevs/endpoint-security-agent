"""Tests for os_modules.linux_server — Linux Server OS Module."""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest


class TestLinuxServerModule:

    @patch("os_modules.linux_server.module._detect_distro", return_value="unknown")
    def test_platform_name(self, _distro):
        from os_modules.linux_server.module import LinuxServerModule
        mod = LinuxServerModule()
        assert mod.platform_name == "linux"

    @patch("os_modules.linux_server.module._run_cmd")
    @patch("os_modules.linux_server.module._detect_distro", return_value="debian")
    def test_ufw_firewall_active(self, _distro, mock_cmd):
        from os_modules.linux_server.module import LinuxServerModule
        mock_cmd.return_value = "Status: active\n\nTo                         Action      From\n22/tcp                     ALLOW       Anywhere"

        mod = LinuxServerModule()
        status = mod.get_firewall_status()
        assert status.enabled is True

    @patch("os_modules.linux_server.module._run_cmd")
    @patch("os_modules.linux_server.module._detect_distro", return_value="debian")
    def test_ufw_firewall_inactive(self, _distro, mock_cmd):
        from os_modules.linux_server.module import LinuxServerModule
        mock_cmd.return_value = "Status: inactive"

        mod = LinuxServerModule()
        status = mod.get_firewall_status()
        assert status.enabled is False

    @patch("os_modules.linux_server.module._run_cmd")
    @patch("os_modules.linux_server.module._read_file")
    @patch("os_modules.linux_server.module._detect_distro", return_value="debian")
    def test_ssh_config_parsed(self, _distro, mock_read, mock_cmd):
        from os_modules.linux_server.module import LinuxServerModule
        mock_read.return_value = (
            "PermitRootLogin no\n"
            "PasswordAuthentication yes\n"
            "MaxAuthTries 6\n"
        )

        mod = LinuxServerModule()
        ssh_config = mod.get_ssh_config()
        assert ssh_config["PermitRootLogin"] == "no"
        assert ssh_config["PasswordAuthentication"] == "yes"

    @patch("os_modules.linux_server.module._run_cmd")
    @patch("os_modules.linux_server.module._read_file")
    @patch("os_modules.linux_server.module._detect_distro", return_value="debian")
    def test_password_policy(self, _distro, mock_read, mock_cmd):
        from os_modules.linux_server.module import LinuxServerModule
        mock_read.return_value = "PASS_MAX_DAYS\t90\nPASS_MIN_LEN\t8\n"

        mod = LinuxServerModule()
        policy = mod.get_password_policy()
        assert "PASS_MAX_DAYS" in policy
