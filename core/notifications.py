"""
Sentinel Agent — Desktop Notifications

Cross-platform desktop notification system for security alerts.

Windows: PowerShell toast notifications
macOS: osascript display notification
Linux: notify-send
"""

from __future__ import annotations

import platform
import subprocess

from core.logging import get_logger


class NotificationManager:
    """Cross-platform desktop notifications for security alerts."""

    def __init__(self):
        self.log = get_logger()

    def notify(self, title: str, message: str, severity: str = "info") -> bool:
        """Send a desktop notification. Returns True if successful."""
        system = platform.system().lower()
        try:
            if system == "windows":
                return self._windows_notify(title, message)
            elif system == "darwin":
                return self._macos_notify(title, message)
            elif system == "linux":
                return self._linux_notify(title, message)
            else:
                self.log.debug(f"Notifications not supported on {system}")
                return False
        except Exception as e:
            self.log.debug(f"Notification failed: {e}")
            return False

    def _windows_notify(self, title: str, message: str) -> bool:
        """Windows toast notification via PowerShell."""
        # Use BurntToast module if available, fall back to basic notification
        ps_script = (
            "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, "
            "ContentType = WindowsRuntime] | Out-Null; "
            "[Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom, "
            "ContentType = WindowsRuntime] | Out-Null; "
            "$template = [Windows.UI.Notifications.ToastNotificationManager]::"
            "GetTemplateContent([Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
            "$textNodes = $template.GetElementsByTagName('text'); "
            f"$textNodes.Item(0).AppendChild($template.CreateTextNode('{self._escape_ps(title)}')); "
            f"$textNodes.Item(1).AppendChild($template.CreateTextNode('{self._escape_ps(message)}')); "
            "$toast = [Windows.UI.Notifications.ToastNotification]::new($template); "
            "[Windows.UI.Notifications.ToastNotificationManager]::"
            "CreateToastNotifier('Sentinel Security').Show($toast)"
        )

        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Fallback: use msg.exe for a simple popup
        try:
            subprocess.run(
                ["msg", "*", f"{title}\n{message}"],
                capture_output=True, timeout=5,
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return False

    def _macos_notify(self, title: str, message: str) -> bool:
        """macOS notification via osascript."""
        script = (
            f'display notification "{self._escape_applescript(message)}" '
            f'with title "{self._escape_applescript(title)}" '
            f'subtitle "Security Alert"'
        )
        try:
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _linux_notify(self, title: str, message: str) -> bool:
        """Linux notification via notify-send."""
        try:
            result = subprocess.run(
                ["notify-send", "--urgency=critical", "--app-name=Sentinel", title, message],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    @staticmethod
    def _escape_ps(text: str) -> str:
        """Escape text for PowerShell string."""
        return text.replace("'", "''").replace('"', '`"')

    @staticmethod
    def _escape_applescript(text: str) -> str:
        """Escape text for AppleScript string."""
        return text.replace('\\', '\\\\').replace('"', '\\"')
