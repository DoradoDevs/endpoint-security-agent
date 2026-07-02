"""
Sentinel Agent — Application Control

Monitors running applications against a whitelist.
Supports learning, alert, and enforce modes.
"""

from __future__ import annotations

import hashlib
import json
import platform
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from core.config import AgentConfig
from core.logging import get_logger
from edr.event_types import EDREvent, EDREventType


@dataclass
class WhitelistEntry:
    exe_hash: str = ""
    exe_path: str = ""
    exe_name: str = ""
    added_by: str = "system"  # system, learning, manual
    trusted: bool = True
    added_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "exe_hash": self.exe_hash,
            "exe_path": self.exe_path,
            "exe_name": self.exe_name,
            "added_by": self.added_by,
            "trusted": self.trusted,
            "added_at": self.added_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> WhitelistEntry:
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class ApplicationControl:
    """Application whitelist enforcement."""

    MODE_DISABLED = "disabled"
    MODE_LEARNING = "learning"
    MODE_ALERT = "alert"
    MODE_ENFORCE = "enforce"

    def __init__(self, config: AgentConfig | None = None, whitelist_path: Path | None = None):
        self.config = config
        self.log = get_logger()
        self._mode = self.MODE_DISABLED
        self._whitelist_path = whitelist_path or self._default_whitelist_path()
        self._whitelist_path.parent.mkdir(parents=True, exist_ok=True)
        self._whitelist: dict[str, WhitelistEntry] = {}  # keyed by exe_name
        self._load_whitelist()
        self._on_event = None

    @staticmethod
    def _default_whitelist_path() -> Path:
        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "appcontrol" / "whitelist.json"
        elif system == "darwin":
            return Path.home() / "Library" / "Application Support" / "Sentinel" / "appcontrol" / "whitelist.json"
        else:
            return Path.home() / ".sentinel" / "appcontrol" / "whitelist.json"

    def set_mode(self, mode: str) -> None:
        """Set app control mode."""
        if mode in (self.MODE_DISABLED, self.MODE_LEARNING, self.MODE_ALERT, self.MODE_ENFORCE):
            self._mode = mode
            self.log.info(f"[AppControl] Mode set to: {mode}")

    def get_mode(self) -> str:
        return self._mode

    def check_process(self, process_name: str, exe_path: str = "", exe_hash: str = "") -> dict[str, Any]:
        """Check a process against the whitelist. Returns result dict."""
        result = {
            "allowed": True,
            "reason": "",
            "mode": self._mode,
        }

        if self._mode == self.MODE_DISABLED:
            return result

        # Check whitelist
        is_whitelisted = self._is_whitelisted(process_name, exe_hash)

        if self._mode == self.MODE_LEARNING:
            if not is_whitelisted:
                self._add_to_whitelist(process_name, exe_path, exe_hash, added_by="learning")
            result["allowed"] = True
            return result

        if not is_whitelisted:
            result["allowed"] = False
            result["reason"] = f"Process '{process_name}' not in whitelist"

            if self._mode == self.MODE_ENFORCE:
                # Kill the process
                self._kill_process_by_name(process_name)
                result["action"] = "killed"
            elif self._mode == self.MODE_ALERT:
                result["action"] = "alert"

        return result

    def add_to_whitelist(self, exe_name: str, exe_path: str = "", exe_hash: str = "") -> WhitelistEntry:
        """Manually add a process to the whitelist."""
        return self._add_to_whitelist(exe_name, exe_path, exe_hash, added_by="manual")

    def remove_from_whitelist(self, exe_name: str) -> bool:
        """Remove a process from the whitelist."""
        if exe_name.lower() in self._whitelist:
            del self._whitelist[exe_name.lower()]
            self._save_whitelist()
            return True
        return False

    def get_whitelist(self) -> list[WhitelistEntry]:
        """Get all whitelist entries."""
        return list(self._whitelist.values())

    def get_whitelist_count(self) -> int:
        return len(self._whitelist)

    def _is_whitelisted(self, process_name: str, exe_hash: str = "") -> bool:
        """Check if process is whitelisted by name or hash."""
        name_lower = process_name.lower()
        if name_lower in self._whitelist:
            return True
        # Check by hash
        if exe_hash:
            for entry in self._whitelist.values():
                if entry.exe_hash and entry.exe_hash == exe_hash:
                    return True
        return False

    def _add_to_whitelist(self, exe_name: str, exe_path: str, exe_hash: str, added_by: str) -> WhitelistEntry:
        entry = WhitelistEntry(
            exe_name=exe_name,
            exe_path=exe_path,
            exe_hash=exe_hash,
            added_by=added_by,
        )
        self._whitelist[exe_name.lower()] = entry
        self._save_whitelist()
        return entry

    def _kill_process_by_name(self, process_name: str) -> None:
        """Kill processes matching the name."""
        try:
            import psutil
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() == process_name.lower():
                    try:
                        proc.kill()
                        self.log.warning(f"[AppControl] Killed non-whitelisted process: {process_name}")
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except ImportError:
            pass

    def _load_whitelist(self) -> None:
        """Load whitelist from disk."""
        if not self._whitelist_path.exists():
            self._populate_system_whitelist()
            return
        try:
            data = json.loads(self._whitelist_path.read_text())
            for entry_data in data.get("entries", []):
                entry = WhitelistEntry.from_dict(entry_data)
                self._whitelist[entry.exe_name.lower()] = entry
        except (json.JSONDecodeError, KeyError):
            self._populate_system_whitelist()

    def _save_whitelist(self) -> None:
        """Save whitelist to disk."""
        data = {"entries": [e.to_dict() for e in self._whitelist.values()]}
        self._whitelist_path.write_text(json.dumps(data, indent=2))

    def _populate_system_whitelist(self) -> None:
        """Auto-whitelist common system executables."""
        system = platform.system().lower()
        system_procs = [
            "explorer.exe", "svchost.exe", "csrss.exe", "wininit.exe", "services.exe",
            "lsass.exe", "winlogon.exe", "dwm.exe", "taskhostw.exe", "sihost.exe",
            "RuntimeBroker.exe", "SearchHost.exe", "StartMenuExperienceHost.exe",
            "python.exe", "python3.exe", "pythonw.exe",
            "bash", "sh", "zsh", "fish",
            "systemd", "init", "kthreadd",
            "WindowServer", "launchd", "loginwindow",
        ]
        for name in system_procs:
            self._whitelist[name.lower()] = WhitelistEntry(exe_name=name, added_by="system")
        self._save_whitelist()

    def get_status(self) -> dict:
        return {
            "mode": self._mode,
            "whitelist_count": len(self._whitelist),
            "whitelist_path": str(self._whitelist_path),
        }
