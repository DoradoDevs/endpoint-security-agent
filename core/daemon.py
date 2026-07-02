"""
Sentinel Agent — Daemon / Continuous Monitoring Service

Background service that runs scheduled security scans, monitors
critical files, and sends desktop notifications for alerts.

Usage:
    sentinel --daemon           Start continuous monitoring
    sentinel --stop-daemon      Stop the daemon
    sentinel --daemon-status    Check if daemon is running
"""

from __future__ import annotations

import json
import os
import platform
import signal
import sys
import threading
import time
from pathlib import Path

from core.config import AgentConfig
from core.logging import get_logger


def _pid_file() -> Path:
    """Get the PID file path."""
    system = platform.system().lower()
    if system == "windows":
        return Path.home() / "AppData" / "Local" / "Sentinel" / "sentinel.pid"
    elif system == "darwin":
        return Path.home() / "Library" / "Application Support" / "Sentinel" / "sentinel.pid"
    else:
        return Path("/var/run/sentinel.pid") if os.geteuid() == 0 else \
               Path.home() / ".sentinel" / "sentinel.pid"


class SentinelDaemon:
    """Background monitoring service with scheduled scans and file watching."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.log = get_logger()
        self.running = False
        self._stop_event = threading.Event()
        self._scan_thread: threading.Thread | None = None
        self._watcher_thread: threading.Thread | None = None
        self._guard_thread: threading.Thread | None = None
        self._scan_interval = self._get_scan_interval()

    def _get_scan_interval(self) -> int:
        """Get scan interval in seconds from profile config."""
        try:
            from core.profiles import SecurityProfile, get_profile
            profile_name = getattr(self.config, "profile", "standard")
            if profile_name and profile_name != "custom":
                spec = get_profile(SecurityProfile(profile_name))
                if spec.scan_interval_minutes > 0:
                    return spec.scan_interval_minutes * 60
        except (ValueError, KeyError, ImportError):
            pass
        return 3600  # Default: 1 hour

    def start(self) -> None:
        """Start the daemon (scheduled scans + file watcher)."""
        if self.is_running():
            self.log.info("Sentinel daemon is already running")
            return

        self.running = True
        self._stop_event.clear()
        self._write_pid()

        self.log.info("=" * 50)
        self.log.info("SENTINEL DAEMON — Starting")
        self.log.info(f"Scan interval: {self._scan_interval // 60} minutes")
        self.log.info("=" * 50)

        # Register signal handlers for graceful shutdown (main thread only)
        try:
            signal.signal(signal.SIGTERM, self._handle_signal)
            signal.signal(signal.SIGINT, self._handle_signal)
        except ValueError:
            pass  # Not in main thread — signals handled elsewhere

        # Start scheduled scan thread
        self._scan_thread = threading.Thread(
            target=self._scheduled_scan_loop,
            name="sentinel-scan-scheduler",
            daemon=True,
        )
        self._scan_thread.start()

        # Start file watcher thread
        self._watcher_thread = threading.Thread(
            target=self._file_watch_loop,
            name="sentinel-file-watcher",
            daemon=True,
        )
        self._watcher_thread.start()

        # Start real-time file guard if enabled
        if getattr(self.config, 'guard', None) and self.config.guard.enabled:
            self._guard_thread = threading.Thread(
                target=self._file_guard_loop,
                name="sentinel-file-guard",
                daemon=True,
            )
            self._guard_thread.start()
            self.log.info("Real-time file guard started")

        # Run initial scan
        self._run_scan()

        # Block until stop signal
        try:
            while not self._stop_event.is_set():
                self._stop_event.wait(timeout=1.0)
        finally:
            self.stop()

    def stop(self) -> None:
        """Gracefully stop all monitoring."""
        if not self.running:
            return

        self.log.info("Sentinel daemon stopping...")
        self.running = False
        self._stop_event.set()

        # Wait for threads to finish
        if self._scan_thread and self._scan_thread.is_alive():
            self._scan_thread.join(timeout=10)
        if self._watcher_thread and self._watcher_thread.is_alive():
            self._watcher_thread.join(timeout=10)
        if self._guard_thread and self._guard_thread.is_alive():
            self._guard_thread.join(timeout=10)

        self._remove_pid()
        self.log.info("Sentinel daemon stopped")

    def _handle_signal(self, signum, frame):
        """Handle shutdown signals gracefully."""
        self.log.info(f"Received signal {signum}, shutting down...")
        self._stop_event.set()

    def _scheduled_scan_loop(self) -> None:
        """Thread: run scans at configured intervals."""
        while not self._stop_event.is_set():
            self._stop_event.wait(timeout=self._scan_interval)
            if not self._stop_event.is_set():
                self._run_scan()

    def _file_watch_loop(self) -> None:
        """Thread: monitor critical files for changes using polling."""
        try:
            from core.file_watcher import FileWatcher
            watcher = FileWatcher(self.config, callback=self._on_file_change)
            watcher.start(stop_event=self._stop_event)
        except ImportError:
            self.log.debug("File watcher not available")
        except Exception as e:
            self.log.error(f"File watcher error: {e}")

    def _file_guard_loop(self) -> None:
        """Thread: real-time file guard using watchdog for malware detection."""
        try:
            from core.file_guard import FileGuard
            guard = FileGuard(self.config)
            guard.start(self._stop_event)
        except ImportError:
            self.log.debug("File guard not available (install watchdog for real-time monitoring)")
        except Exception as e:
            self.log.error(f"File guard error: {e}")

    def _run_scan(self) -> None:
        """Execute a security scan and handle results."""
        try:
            from core.agent import SentinelAgent
            agent = SentinelAgent(self.config)
            result = agent.scan()

            self.log.info(
                f"Scheduled scan complete: {len(result.findings)} findings, "
                f"Risk: {result.risk_score}/100 ({result.risk_grade})"
            )

            # Send notifications for critical/high findings
            critical_high = [f for f in result.findings
                           if f.severity.value in ("critical", "high")]
            if critical_high:
                self._send_alert(
                    f"Sentinel: {len(critical_high)} security issues detected",
                    f"Risk score: {result.risk_score}/100 ({result.risk_grade}). "
                    f"{len(critical_high)} critical/high findings require attention."
                )

            # Execute threat responses if enabled
            try:
                response_result = agent.respond(result)
                actions_taken = response_result.get("total_actions", 0)
                if actions_taken > 0:
                    self.log.info(f"Threat response: {actions_taken} actions executed")
                    self._send_alert(
                        f"Sentinel: {actions_taken} threat response actions taken",
                        f"Policy: {response_result.get('policy_level', 'unknown')}. "
                        f"See response audit log for details."
                    )
            except ImportError:
                self.log.debug("Response module not available")
            except Exception as e:
                self.log.warning(f"Threat response failed: {e}")

            # Generate reports
            try:
                agent.generate_reports(result)
            except Exception as e:
                self.log.error(f"Report generation failed: {e}")

            # Purge expired quarantine entries
            try:
                if getattr(self.config, 'quarantine', None) and self.config.quarantine.auto_purge:
                    from response.actions.file_response import FileQuarantineManager
                    qmgr = FileQuarantineManager(config=self.config)
                    purged = qmgr.purge_expired()
                    if purged:
                        self.log.info(f"Quarantine: purged {len(purged)} expired entries")
                    quota_purged = qmgr.purge_by_quota()
                    if quota_purged:
                        self.log.info(f"Quarantine: purged {len(quota_purged)} entries (quota)")
            except ImportError:
                pass
            except Exception as e:
                self.log.warning(f"Quarantine purge failed: {e}")

        except Exception as e:
            self.log.error(f"Scheduled scan failed: {e}")

    def _on_file_change(self, filepath: str, change_type: str) -> None:
        """Callback when a monitored file changes."""
        self.log.warning(f"File change detected: {filepath} ({change_type})")
        self._send_alert(
            "Sentinel: Critical file modified",
            f"File {filepath} was {change_type}. This may indicate unauthorized changes."
        )

    def _send_alert(self, title: str, message: str) -> None:
        """Send a desktop notification."""
        try:
            from core.notifications import NotificationManager
            nm = NotificationManager()
            nm.notify(title, message, "high")
        except ImportError:
            self.log.info(f"Alert: {title} — {message}")
        except Exception as e:
            self.log.error(f"Notification failed: {e}")

    def _write_pid(self) -> None:
        """Write PID file for daemon management."""
        pid_path = _pid_file()
        pid_path.parent.mkdir(parents=True, exist_ok=True)
        pid_path.write_text(str(os.getpid()))

    def _remove_pid(self) -> None:
        """Remove PID file."""
        try:
            _pid_file().unlink(missing_ok=True)
        except OSError:
            pass

    @staticmethod
    def is_running() -> bool:
        """Check if a daemon instance is already running."""
        pid_path = _pid_file()
        if not pid_path.exists():
            return False
        try:
            pid = int(pid_path.read_text().strip())
            # Check if process exists
            os.kill(pid, 0)
            return True
        except (ValueError, OSError):
            # PID file exists but process is dead — clean up
            try:
                pid_path.unlink(missing_ok=True)
            except OSError:
                pass
            return False

    @staticmethod
    def stop_running() -> bool:
        """Stop a running daemon instance."""
        pid_path = _pid_file()
        if not pid_path.exists():
            return False
        try:
            pid = int(pid_path.read_text().strip())
            if platform.system().lower() == "windows":
                import subprocess
                subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                             capture_output=True, timeout=10)
            else:
                os.kill(pid, signal.SIGTERM)
            pid_path.unlink(missing_ok=True)
            return True
        except (ValueError, OSError):
            return False
