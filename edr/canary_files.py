"""
Sentinel Agent — Canary File Manager

Deploys hidden canary files to detect ransomware activity.
"""

from __future__ import annotations

import hashlib
import os
import platform
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from core.logging import get_logger


@dataclass
class CanaryFile:
    path: str
    sha256: str
    deployed_at: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "active"  # active, triggered, removed


class CanaryFileManager:
    """Deploys and monitors canary files for ransomware detection."""

    def __init__(self, canary_dir: Path | None = None):
        self.log = get_logger()
        self._canary_dir = canary_dir  # For testing; normally deploys to user dirs
        self._canaries: list[CanaryFile] = []

    def deploy_canaries(self, directories: list[str] | None = None) -> int:
        """Deploy canary files. Returns count deployed."""
        dirs = directories or self._default_dirs()
        count = 0

        for directory in dirs:
            try:
                dir_path = Path(directory)
                if not dir_path.exists():
                    continue

                # Create hidden canary file with random content
                random_suffix = secrets.token_hex(4)
                filename = f".~sentinel_canary_{random_suffix}.dat"
                canary_path = dir_path / filename

                content = secrets.token_bytes(256)
                canary_path.write_bytes(content)

                # Make hidden on Windows
                if platform.system().lower() == "windows":
                    try:
                        import ctypes
                        ctypes.windll.kernel32.SetFileAttributesW(
                            str(canary_path), 2
                        )  # FILE_ATTRIBUTE_HIDDEN
                    except Exception:
                        pass

                sha256 = hashlib.sha256(content).hexdigest()
                self._canaries.append(
                    CanaryFile(path=str(canary_path), sha256=sha256)
                )
                count += 1
            except (OSError, PermissionError) as e:
                self.log.debug(f"[Canary] Cannot deploy in {directory}: {e}")

        self.log.info(f"[Canary] Deployed {count} canary files")
        return count

    def check_canaries(self) -> list[CanaryFile]:
        """Check canaries for modifications/deletions. Returns triggered canaries."""
        triggered = []

        for canary in self._canaries:
            if canary.status != "active":
                continue

            path = Path(canary.path)

            if not path.exists():
                # File deleted — RANSOMWARE ALERT
                canary.status = "triggered"
                triggered.append(canary)
                self.log.critical(
                    f"[Canary] DELETED: {canary.path} — possible ransomware!"
                )
                continue

            # Check hash
            try:
                current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
                if current_hash != canary.sha256:
                    canary.status = "triggered"
                    triggered.append(canary)
                    self.log.critical(
                        f"[Canary] MODIFIED: {canary.path} — possible ransomware!"
                    )
            except (OSError, PermissionError):
                canary.status = "triggered"
                triggered.append(canary)

        return triggered

    def remove_canaries(self) -> int:
        """Clean up all canary files. Returns count removed."""
        count = 0
        for canary in self._canaries:
            try:
                path = Path(canary.path)
                if path.exists():
                    path.unlink()
                canary.status = "removed"
                count += 1
            except OSError:
                pass
        self._canaries.clear()
        return count

    def get_canaries(self) -> list[CanaryFile]:
        return list(self._canaries)

    @staticmethod
    def _default_dirs() -> list[str]:
        home = Path.home()
        dirs = []
        for name in ["Documents", "Desktop", "Downloads", "Pictures"]:
            d = home / name
            if d.exists():
                dirs.append(str(d))
        return dirs
