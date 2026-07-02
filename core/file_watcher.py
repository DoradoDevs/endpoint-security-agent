"""
Sentinel Agent — File Watcher

Monitors critical system files for unauthorized changes using
polling-based hash comparison. Cross-platform compatible.

Uses a polling approach (no external dependencies) for maximum
compatibility. Check interval is configurable.
"""

from __future__ import annotations

import hashlib
import platform
import threading
import time
from pathlib import Path

from core.config import AgentConfig
from core.logging import get_logger


# Critical files to monitor per platform
WATCH_PATHS_WINDOWS = [
    r"C:\Windows\System32\drivers\etc\hosts",
    r"C:\Windows\System32\config\SAM",
    r"C:\Windows\System32\config\SYSTEM",
]

WATCH_PATHS_MACOS = [
    "/etc/hosts",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
]

WATCH_PATHS_LINUX = [
    "/etc/hosts",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
]


def _hash_file(path: str) -> str | None:
    """Compute SHA-256 hash of a file."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


class FileWatcher:
    """Monitors critical files for unauthorized changes via polling."""

    def __init__(self, config: AgentConfig, callback=None, poll_interval: int = 60):
        self.config = config
        self.callback = callback
        self.poll_interval = poll_interval
        self.log = get_logger()
        self._baselines: dict[str, str | None] = {}
        self._watch_paths = self._get_watch_paths()

    def _get_watch_paths(self) -> list[str]:
        """Get platform-appropriate watch paths."""
        system = platform.system().lower()
        if system == "windows":
            return list(WATCH_PATHS_WINDOWS)
        elif system == "darwin":
            return list(WATCH_PATHS_MACOS)
        else:
            return list(WATCH_PATHS_LINUX)

    def _initialize_baselines(self) -> None:
        """Hash all watched files to establish baseline."""
        for path in self._watch_paths:
            self._baselines[path] = _hash_file(path)
        self.log.info(f"File watcher: monitoring {len(self._baselines)} files")

    def _check_for_changes(self) -> list[tuple[str, str]]:
        """Compare current hashes against baselines. Returns list of (path, change_type)."""
        changes: list[tuple[str, str]] = []

        for path in self._watch_paths:
            current_hash = _hash_file(path)
            baseline_hash = self._baselines.get(path)

            if baseline_hash is None and current_hash is not None:
                changes.append((path, "created"))
                self._baselines[path] = current_hash
            elif baseline_hash is not None and current_hash is None:
                changes.append((path, "deleted"))
                self._baselines[path] = None
            elif baseline_hash != current_hash:
                changes.append((path, "modified"))
                self._baselines[path] = current_hash

        return changes

    def start(self, stop_event: threading.Event | None = None) -> None:
        """Start polling for file changes. Blocks until stop_event is set."""
        self._initialize_baselines()

        while True:
            if stop_event and stop_event.is_set():
                break

            if stop_event:
                stop_event.wait(timeout=self.poll_interval)
                if stop_event.is_set():
                    break
            else:
                time.sleep(self.poll_interval)

            changes = self._check_for_changes()
            for filepath, change_type in changes:
                self.log.warning(f"File change: {filepath} was {change_type}")
                if self.callback:
                    try:
                        self.callback(filepath, change_type)
                    except Exception as e:
                        self.log.error(f"File watcher callback error: {e}")

        self.log.info("File watcher stopped")
