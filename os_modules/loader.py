"""
Sentinel Agent — OS Module Loader

Dynamically selects the correct OS module based on the current platform.
"""

from __future__ import annotations

import platform

from os_modules.base import BaseOSModule


def load_os_module() -> BaseOSModule:
    """Return the OS module for the current platform."""
    system = platform.system().lower()

    if system == "windows":
        from os_modules.windows.module import WindowsModule
        return WindowsModule()
    elif system == "darwin":
        from os_modules.macos.module import MacOSModule
        return MacOSModule()
    elif system == "linux":
        from os_modules.linux_server.module import LinuxServerModule
        return LinuxServerModule()
    else:
        raise RuntimeError(f"Unsupported platform: {system}")
