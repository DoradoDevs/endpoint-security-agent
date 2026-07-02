"""
Sentinel Agent — Auto-Updater

Checks for updates from a release server, downloads the latest version,
verifies integrity via SHA-256 checksum, and applies the update.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import sys
import tempfile
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.logging import get_logger
from core import __version__

log = get_logger()


@dataclass
class UpdateInfo:
    """Information about an available update."""

    available: bool = False
    current_version: str = ""
    latest_version: str = ""
    download_url: str = ""
    checksum_sha256: str = ""
    release_notes: str = ""
    file_size: int = 0


@dataclass
class UpdateResult:
    """Result of an update operation."""

    success: bool = False
    message: str = ""
    new_version: str = ""
    restart_required: bool = False


class AutoUpdater:
    """Checks for and applies agent updates.

    There is NO default update endpoint. To use the auto-updater you must
    supply your own release server, either by passing ``update_url`` or by
    setting the ``ENDPOINT_AGENT_UPDATE_URL`` environment variable. This avoids
    shipping a hardcoded update URL pointing at an unregistered domain (a
    supply-chain takeover risk if someone squats the name). If no URL is
    configured, update checks are a safe no-op.
    """

    def __init__(
        self,
        update_url: str = "",
        current_version: str = "",
    ):
        self.update_url = update_url or os.environ.get("ENDPOINT_AGENT_UPDATE_URL", "")
        self.current_version = current_version or __version__
        self._platform = platform.system().lower()
        self._arch = platform.machine().lower()

    def check_for_updates(self) -> UpdateInfo:
        """Check the configured release server for available updates.

        Returns UpdateInfo with details about any available update. If no
        update URL has been configured, this is a no-op and reports that no
        update is available.
        """
        info = UpdateInfo(current_version=self.current_version)

        if not self.update_url:
            info.message = (
                "No update URL configured. Set ENDPOINT_AGENT_UPDATE_URL or pass "
                "update_url to enable the auto-updater."
            )
            return info

        try:
            # Build platform-specific URL
            url = f"{self.update_url}?platform={self._platform}&arch={self._arch}&version={self.current_version}"

            req = urllib.request.Request(url, headers={
                "User-Agent": f"SentinelAgent/{self.current_version}",
            })

            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode())

            latest = data.get("version", "")
            if not latest:
                info.message = "No version info in server response"
                return info

            if self._version_compare(latest, self.current_version) > 0:
                info.available = True
                info.latest_version = latest
                info.download_url = data.get("download_url", "")
                info.checksum_sha256 = data.get("checksum_sha256", "")
                info.release_notes = data.get("release_notes", "")
                info.file_size = data.get("file_size", 0)
            else:
                info.latest_version = latest

            return info

        except urllib.error.URLError as e:
            log.warning(f"Update check failed: {e}")
            return info
        except Exception as e:
            log.error(f"Update check error: {e}")
            return info

    def download_and_apply(self, update_info: UpdateInfo) -> UpdateResult:
        """Download and apply an update.

        Verifies SHA-256 checksum before applying.
        """
        if not update_info.available or not update_info.download_url:
            return UpdateResult(
                success=False,
                message="No update available or no download URL",
            )

        try:
            # Download to temp file
            log.info(f"Downloading update v{update_info.latest_version}...")
            temp_dir = Path(tempfile.mkdtemp(prefix="sentinel_update_"))
            temp_file = temp_dir / f"sentinel_update_{update_info.latest_version}"

            req = urllib.request.Request(update_info.download_url, headers={
                "User-Agent": f"SentinelAgent/{self.current_version}",
            })

            with urllib.request.urlopen(req, timeout=300) as resp:
                with open(temp_file, "wb") as f:
                    shutil.copyfileobj(resp, f)

            log.info(f"Downloaded to {temp_file}")

            # Verify checksum
            if update_info.checksum_sha256:
                actual_hash = self._file_hash(temp_file)
                if actual_hash != update_info.checksum_sha256:
                    shutil.rmtree(temp_dir, ignore_errors=True)
                    return UpdateResult(
                        success=False,
                        message=f"Checksum mismatch: expected {update_info.checksum_sha256}, "
                                f"got {actual_hash}. Update aborted.",
                    )
                log.info("Checksum verified")

            # Apply update
            current_exe = Path(sys.executable)
            if hasattr(sys, "_MEIPASS"):
                # Running as PyInstaller bundle — replace the executable
                current_exe = Path(sys.argv[0]).resolve()

            backup_path = current_exe.with_suffix(current_exe.suffix + ".bak")

            # Backup current
            if current_exe.exists():
                shutil.copy2(current_exe, backup_path)
                log.info(f"Backed up current version to {backup_path}")

            # Replace with new version
            shutil.move(str(temp_file), str(current_exe))

            # Set executable permissions on Unix
            if self._platform != "windows":
                current_exe.chmod(current_exe.stat().st_mode | stat.S_IEXEC)

            # Cleanup
            shutil.rmtree(temp_dir, ignore_errors=True)

            log.info(f"Update applied: v{update_info.latest_version}")

            return UpdateResult(
                success=True,
                message=f"Updated from v{self.current_version} to v{update_info.latest_version}",
                new_version=update_info.latest_version,
                restart_required=True,
            )

        except PermissionError:
            return UpdateResult(
                success=False,
                message="Permission denied. Run with elevated privileges to update.",
            )
        except Exception as e:
            log.error(f"Update failed: {e}")
            return UpdateResult(
                success=False,
                message=f"Update failed: {e}",
            )

    def rollback(self) -> UpdateResult:
        """Roll back to the previous version using the backup file."""
        current_exe = Path(sys.argv[0]).resolve()
        backup_path = current_exe.with_suffix(current_exe.suffix + ".bak")

        if not backup_path.exists():
            return UpdateResult(
                success=False,
                message="No backup found. Cannot rollback.",
            )

        try:
            shutil.move(str(backup_path), str(current_exe))
            if self._platform != "windows":
                current_exe.chmod(current_exe.stat().st_mode | stat.S_IEXEC)

            return UpdateResult(
                success=True,
                message="Rolled back to previous version",
                restart_required=True,
            )
        except Exception as e:
            return UpdateResult(
                success=False,
                message=f"Rollback failed: {e}",
            )

    @staticmethod
    def _file_hash(path: Path) -> str:
        """Calculate SHA-256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def _version_compare(v1: str, v2: str) -> int:
        """Compare two version strings. Returns >0 if v1 > v2."""
        def parse(v: str) -> list[int]:
            return [int(x) for x in v.strip("v").split(".") if x.isdigit()]

        parts1 = parse(v1)
        parts2 = parse(v2)

        # Pad to same length
        max_len = max(len(parts1), len(parts2))
        parts1.extend([0] * (max_len - len(parts1)))
        parts2.extend([0] * (max_len - len(parts2)))

        for a, b in zip(parts1, parts2):
            if a != b:
                return a - b
        return 0
