"""
Sentinel Agent — Real-Time File Guard

Monitors user directories for new or modified files and scans them
against malware rules in real time. Uses watchdog for filesystem events.

Gracefully degrades if watchdog is not installed.
"""

from __future__ import annotations

import hashlib
import os
import platform
import threading
import time
from pathlib import Path
from typing import Callable

from core.config import AgentConfig
from core.logging import get_logger


class FileGuardHandler:
    """Handles filesystem events and scans new/modified files."""

    def __init__(self, config: AgentConfig, on_threat: Callable | None = None):
        self.config = config
        self.log = get_logger()
        self._on_threat = on_threat
        self._debounce_ms = getattr(config.guard, 'debounce_ms', 100) if hasattr(config, 'guard') else 100
        self._last_events: dict[str, float] = {}  # path -> timestamp for debounce
        self._lock = threading.Lock()

    def handle_event(self, event_path: str, event_type: str) -> None:
        """Handle a filesystem event (created or modified)."""
        if not event_path or not os.path.isfile(event_path):
            return

        # Debounce: ignore repeated events for same file within debounce window
        now = time.time()
        with self._lock:
            last = self._last_events.get(event_path, 0)
            if (now - last) * 1000 < self._debounce_ms:
                return
            self._last_events[event_path] = now
            # Prune old entries
            if len(self._last_events) > 1000:
                cutoff = now - 60
                self._last_events = {k: v for k, v in self._last_events.items() if v > cutoff}

        # Skip files being written to (locked)
        if self._is_file_locked(event_path):
            return

        # Check allowlist first
        if self._is_allowlisted(event_path):
            return

        # Scan the file
        self._scan_file(event_path)

    def _is_file_locked(self, filepath: str) -> bool:
        """Check if a file is currently being written to."""
        try:
            with open(filepath, 'rb'):
                return False
        except (PermissionError, OSError):
            return True

    def _is_allowlisted(self, filepath: str) -> bool:
        """Check if file path is in allowlist."""
        try:
            from core.allowlist import AllowlistManager
            mgr = AllowlistManager()
            if mgr.is_path_excluded(filepath, "file_guard"):
                return True
            # Also check hash
            try:
                sha256 = hashlib.sha256(Path(filepath).read_bytes()).hexdigest()
                if mgr.is_hash_allowed(sha256, "file_guard"):
                    return True
            except (OSError, PermissionError):
                pass
        except ImportError:
            pass
        return False

    def _scan_file(self, filepath: str) -> None:
        """Scan a single file against malware rules."""
        try:
            from scanners.malware_rules import BUILTIN_RULES, calculate_entropy

            path = Path(filepath)

            # Size check
            try:
                file_size = path.stat().st_size
            except OSError:
                return

            if file_size == 0 or file_size > 50 * 1024 * 1024:  # Skip empty or >50MB
                return

            try:
                data = path.read_bytes()
            except (OSError, PermissionError):
                return

            text_content = None
            ext = path.suffix.lower()

            # Load merged rules if available
            try:
                from scanners.rule_manager import RuleManager
                rules = RuleManager().get_merged_rules()
            except ImportError:
                rules = BUILTIN_RULES

            for rule in rules:
                # Extension filter
                if rule.file_extensions and ext not in rule.file_extensions:
                    continue

                # Size filter
                if file_size > rule.max_file_size:
                    continue

                matches = 0

                # Byte patterns
                for pattern in rule.byte_patterns:
                    if pattern in data:
                        matches += 1

                # String patterns (case-insensitive)
                if rule.string_patterns:
                    if text_content is None:
                        try:
                            text_content = data.decode('utf-8', errors='ignore').lower()
                        except Exception:
                            text_content = ""
                    for pattern in rule.string_patterns:
                        if pattern.lower() in text_content:
                            matches += 1

                # Regex patterns
                if rule.regex_patterns:
                    import re
                    if text_content is None:
                        try:
                            text_content = data.decode('utf-8', errors='ignore')
                        except Exception:
                            text_content = ""
                    for pattern_str in rule.regex_patterns:
                        try:
                            if re.search(pattern_str, text_content, re.IGNORECASE):
                                matches += 1
                        except re.error:
                            pass

                if matches >= rule.min_matches:
                    # THREAT DETECTED
                    finding_info = {
                        "rule_name": rule.name,
                        "description": rule.description,
                        "severity": rule.severity.value,
                        "category": rule.category,
                        "filepath": filepath,
                        "matches": matches,
                    }
                    self.log.warning(
                        f"[FileGuard] THREAT: {rule.name} in {filepath} "
                        f"(severity={rule.severity.value}, matches={matches})"
                    )

                    if self._on_threat:
                        self._on_threat(finding_info)

                    # Auto-quarantine if enabled
                    if hasattr(self.config, 'guard') and self.config.guard.auto_quarantine:
                        self._auto_quarantine(filepath, finding_info)

                    break  # One match is enough per file

            # High entropy check
            entropy = calculate_entropy(data[:8192])  # Check first 8KB
            if entropy > 7.5 and ext not in ('.zip', '.gz', '.bz2', '.xz', '.7z',
                                               '.jpg', '.jpeg', '.png', '.gif', '.mp3',
                                               '.mp4', '.avi', '.mov', '.pdf', '.exe',
                                               '.dll', '.so', '.dylib'):
                self.log.info(f"[FileGuard] High entropy ({entropy:.2f}) in {filepath}")

        except ImportError:
            self.log.debug("Malware rules not available for file guard scanning")
        except Exception as e:
            self.log.debug(f"[FileGuard] Scan error for {filepath}: {e}")

    def _auto_quarantine(self, filepath: str, finding_info: dict) -> None:
        """Auto-quarantine a detected threat."""
        try:
            from response.actions.file_response import FileQuarantineManager
            mgr = FileQuarantineManager(config=self.config)
            success, msg = mgr.quarantine(
                filepath,
                finding_title=f"FileGuard: {finding_info['rule_name']}",
                finding_severity=finding_info['severity'],
            )
            if success:
                self.log.warning(f"[FileGuard] Auto-quarantined: {filepath}")
            else:
                self.log.warning(f"[FileGuard] Quarantine failed: {msg}")
        except Exception as e:
            self.log.error(f"[FileGuard] Auto-quarantine error: {e}")

    @staticmethod
    def default_watch_dirs() -> list[str]:
        """Get default directories to watch based on platform."""
        system = platform.system().lower()
        home = Path.home()
        dirs = []

        # Common user directories
        for name in ["Downloads", "Desktop"]:
            d = home / name
            if d.exists():
                dirs.append(str(d))

        if system == "windows":
            # Temp directories
            for env_var in ["TEMP", "TMP"]:
                tmp = os.environ.get(env_var, "")
                if tmp and Path(tmp).exists():
                    dirs.append(tmp)
                    break
            # Startup folder
            startup = home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if startup.exists():
                dirs.append(str(startup))
        elif system == "darwin":
            tmp_dir = "/tmp"
            if Path(tmp_dir).exists():
                dirs.append(tmp_dir)
            # LaunchAgents
            la = home / "Library" / "LaunchAgents"
            if la.exists():
                dirs.append(str(la))
        else:  # Linux
            tmp_dir = "/tmp"
            if Path(tmp_dir).exists():
                dirs.append(tmp_dir)
            # Cron
            cron = home / ".config" / "autostart"
            if cron.exists():
                dirs.append(str(cron))

        return dirs


class FileGuard:
    """Real-time file monitoring using watchdog (or polling fallback)."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.log = get_logger()
        self._handler = FileGuardHandler(config, on_threat=self._on_threat_detected)
        self._observer = None
        self._threats: list[dict] = []

    def start(self, stop_event: threading.Event) -> None:
        """Start monitoring. Blocks until stop_event is set."""
        watch_dirs = self._get_watch_dirs()

        if not watch_dirs:
            self.log.warning("[FileGuard] No directories to watch")
            stop_event.wait()
            return

        self.log.info(f"[FileGuard] Monitoring {len(watch_dirs)} directories")
        for d in watch_dirs:
            self.log.info(f"[FileGuard]   {d}")

        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent

            class _WatchdogHandler(FileSystemEventHandler):
                def __init__(self, guard_handler):
                    self._guard = guard_handler

                def on_created(self, event):
                    if not event.is_directory:
                        self._guard.handle_event(event.src_path, "created")

                def on_modified(self, event):
                    if not event.is_directory:
                        self._guard.handle_event(event.src_path, "modified")

            observer = Observer()
            handler = _WatchdogHandler(self._handler)

            for directory in watch_dirs:
                try:
                    observer.schedule(handler, directory, recursive=False)
                except Exception as e:
                    self.log.warning(f"[FileGuard] Cannot watch {directory}: {e}")

            observer.start()
            self._observer = observer

            # Block until stopped
            while not stop_event.is_set():
                stop_event.wait(timeout=1.0)

            observer.stop()
            observer.join(timeout=5)

        except ImportError:
            self.log.info("[FileGuard] watchdog not installed — using polling fallback")
            self._polling_fallback(watch_dirs, stop_event)

    def stop(self) -> None:
        """Stop the observer."""
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=5)

    def _get_watch_dirs(self) -> list[str]:
        """Get directories to watch from config or defaults."""
        if hasattr(self.config, 'guard') and self.config.guard.directories:
            return [d for d in self.config.guard.directories if Path(d).exists()]
        return FileGuardHandler.default_watch_dirs()

    def _on_threat_detected(self, finding_info: dict) -> None:
        """Callback when a threat is detected."""
        self._threats.append(finding_info)
        # Send notification
        try:
            from core.notifications import NotificationManager
            nm = NotificationManager()
            nm.notify(
                f"Sentinel: Threat detected in {Path(finding_info['filepath']).name}",
                f"{finding_info['description']} (Severity: {finding_info['severity'].upper()})",
                finding_info['severity'],
            )
        except (ImportError, Exception):
            pass

    def _polling_fallback(self, watch_dirs: list[str], stop_event: threading.Event) -> None:
        """Fallback polling when watchdog is not available."""
        known_files: dict[str, float] = {}  # path -> mtime

        # Initial snapshot
        for directory in watch_dirs:
            try:
                for entry in os.scandir(directory):
                    if entry.is_file():
                        try:
                            known_files[entry.path] = entry.stat().st_mtime
                        except OSError:
                            pass
            except OSError:
                pass

        while not stop_event.is_set():
            stop_event.wait(timeout=5.0)  # Poll every 5 seconds
            if stop_event.is_set():
                break

            for directory in watch_dirs:
                try:
                    for entry in os.scandir(directory):
                        if entry.is_file():
                            try:
                                mtime = entry.stat().st_mtime
                                prev_mtime = known_files.get(entry.path)
                                if prev_mtime is None:
                                    # New file
                                    known_files[entry.path] = mtime
                                    self._handler.handle_event(entry.path, "created")
                                elif mtime > prev_mtime:
                                    # Modified file
                                    known_files[entry.path] = mtime
                                    self._handler.handle_event(entry.path, "modified")
                            except OSError:
                                pass
                except OSError:
                    pass
