"""
Sentinel Agent — Endpoint Isolation

Blocks all network traffic except DNS/DHCP/fleet server for
containing compromised endpoints.
"""

from __future__ import annotations

import json
import platform
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from core.config import AgentConfig
from core.logging import get_logger


@dataclass
class IsolationState:
    isolated: bool = False
    isolation_time: str = ""
    release_time: str = ""
    timeout_hours: int = 24
    allowed_ips: list[str] = field(default_factory=list)
    mode: str = "full"  # full or partial

    def to_dict(self) -> dict:
        return {
            "isolated": self.isolated,
            "isolation_time": self.isolation_time,
            "release_time": self.release_time,
            "timeout_hours": self.timeout_hours,
            "allowed_ips": self.allowed_ips,
            "mode": self.mode,
        }

    @classmethod
    def from_dict(cls, data: dict) -> IsolationState:
        return cls(
            isolated=data.get("isolated", False),
            isolation_time=data.get("isolation_time", ""),
            release_time=data.get("release_time", ""),
            timeout_hours=data.get("timeout_hours", 24),
            allowed_ips=data.get("allowed_ips", []),
            mode=data.get("mode", "full"),
        )


class EndpointIsolationManager:
    """Manages endpoint network isolation."""

    def __init__(self, config: AgentConfig | None = None):
        self.config = config
        self.log = get_logger()
        self._state_file = self._state_file_path()
        self._state_file.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _state_file_path() -> Path:
        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "isolation" / "state.json"
        elif system == "darwin":
            return Path.home() / "Library" / "Application Support" / "Sentinel" / "isolation" / "state.json"
        else:
            return Path.home() / ".sentinel" / "isolation" / "state.json"

    def isolate(self, mode: str = "full", timeout_hours: int = 24,
                allowed_ips: list[str] | None = None) -> tuple[bool, str]:
        """Isolate the endpoint from the network."""
        if self.is_isolated():
            return False, "Endpoint is already isolated"

        allowed = allowed_ips or []
        # Always allow DNS and DHCP

        state = IsolationState(
            isolated=True,
            isolation_time=datetime.now().isoformat(),
            timeout_hours=timeout_hours,
            allowed_ips=allowed,
            mode=mode,
        )

        system = platform.system().lower()
        try:
            if system == "windows":
                success, msg = self._isolate_windows(allowed)
            elif system == "linux":
                success, msg = self._isolate_linux(allowed)
            elif system == "darwin":
                success, msg = self._isolate_macos(allowed)
            else:
                return False, f"Unsupported platform: {system}"

            if success:
                self._save_state(state)
                self.log.warning(f"[Isolation] Endpoint isolated (mode={mode}, timeout={timeout_hours}h)")
                return True, f"Endpoint isolated. Auto-release in {timeout_hours} hours."
            return False, msg
        except Exception as e:
            return False, f"Isolation failed: {e}"

    def release(self) -> tuple[bool, str]:
        """Release endpoint from isolation."""
        if not self.is_isolated():
            return False, "Endpoint is not isolated"

        system = platform.system().lower()
        try:
            if system == "windows":
                success, msg = self._release_windows()
            elif system == "linux":
                success, msg = self._release_linux()
            elif system == "darwin":
                success, msg = self._release_macos()
            else:
                return False, f"Unsupported platform: {system}"

            if success:
                state = self._load_state()
                state.isolated = False
                state.release_time = datetime.now().isoformat()
                self._save_state(state)
                self.log.info("[Isolation] Endpoint released from isolation")
                return True, "Endpoint released from isolation"
            return False, msg
        except Exception as e:
            return False, f"Release failed: {e}"

    def is_isolated(self) -> bool:
        """Check if endpoint is currently isolated."""
        state = self._load_state()
        if not state.isolated:
            return False

        # Check timeout — clear state directly to avoid recursion with release()
        try:
            iso_time = datetime.fromisoformat(state.isolation_time)
            if datetime.now() > iso_time + timedelta(hours=state.timeout_hours):
                self._auto_release_timeout(state)
                return False
        except ValueError:
            pass

        return True

    def _auto_release_timeout(self, state) -> None:
        """Handle auto-release on timeout without recursion."""
        system = platform.system().lower()
        try:
            if system == "windows":
                self._release_windows()
            elif system == "linux":
                self._release_linux()
            elif system == "darwin":
                self._release_macos()
        except Exception as e:
            self.log.error(f"[Isolation] Auto-release failed: {e}")

        state.isolated = False
        state.release_time = datetime.now().isoformat()
        self._save_state(state)
        self.log.info("[Isolation] Endpoint auto-released (timeout expired)")

    def get_isolation_status(self) -> dict:
        """Get detailed isolation status."""
        state = self._load_state()
        status = state.to_dict()

        if state.isolated and state.isolation_time:
            try:
                iso_time = datetime.fromisoformat(state.isolation_time)
                remaining = (iso_time + timedelta(hours=state.timeout_hours)) - datetime.now()
                status["remaining_hours"] = max(0, remaining.total_seconds() / 3600)
            except ValueError:
                status["remaining_hours"] = 0

        return status

    def _isolate_windows(self, allowed_ips: list[str]) -> tuple[bool, str]:
        """Windows isolation using netsh firewall rules."""
        try:
            # Block all outbound except allowed
            rules = [
                'netsh advfirewall firewall add rule name="Sentinel-Isolate-BlockAll" dir=out action=block enable=yes',
                'netsh advfirewall firewall add rule name="Sentinel-Isolate-AllowDNS" dir=out action=allow protocol=UDP remoteport=53',
                'netsh advfirewall firewall add rule name="Sentinel-Isolate-AllowDHCP" dir=out action=allow protocol=UDP remoteport=67,68',
            ]
            for ip in allowed_ips:
                rules.append(f'netsh advfirewall firewall add rule name="Sentinel-Isolate-Allow-{ip}" dir=out action=allow remoteip={ip}')

            for rule in rules:
                subprocess.run(rule.split(), capture_output=True, timeout=10)
            return True, "Windows firewall isolation applied"
        except Exception as e:
            return False, f"Windows isolation failed: {e}"

    def _release_windows(self) -> tuple[bool, str]:
        """Remove Windows isolation rules."""
        try:
            subprocess.run(
                'netsh advfirewall firewall delete rule name=all dir=out'.split(),
                capture_output=True, timeout=10
            )
            # More targeted: delete only Sentinel rules
            rules = ["Sentinel-Isolate-BlockAll", "Sentinel-Isolate-AllowDNS", "Sentinel-Isolate-AllowDHCP"]
            for name in rules:
                subprocess.run(
                    f'netsh advfirewall firewall delete rule name="{name}"'.split(),
                    capture_output=True, timeout=10
                )
            return True, "Windows isolation released"
        except Exception as e:
            return False, f"Release failed: {e}"

    def _isolate_linux(self, allowed_ips: list[str]) -> tuple[bool, str]:
        """Linux isolation using iptables."""
        try:
            rules = [
                "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT -m comment --comment sentinel-isolate",
                "iptables -A OUTPUT -p udp --dport 67:68 -j ACCEPT -m comment --comment sentinel-isolate",
            ]
            for ip in allowed_ips:
                rules.append(f"iptables -A OUTPUT -d {ip} -j ACCEPT -m comment --comment sentinel-isolate")
            rules.append("iptables -A OUTPUT -j DROP -m comment --comment sentinel-isolate")

            for rule in rules:
                subprocess.run(rule.split(), capture_output=True, timeout=10)
            return True, "Linux iptables isolation applied"
        except Exception as e:
            return False, f"Linux isolation failed: {e}"

    def _release_linux(self) -> tuple[bool, str]:
        """Remove Linux isolation rules."""
        try:
            # Remove rules with sentinel-isolate comment
            subprocess.run(
                "iptables -S OUTPUT".split(),
                capture_output=True, timeout=10
            )
            # Flush and rebuild approach
            subprocess.run(
                "iptables -D OUTPUT -j DROP -m comment --comment sentinel-isolate".split(),
                capture_output=True, timeout=10
            )
            return True, "Linux isolation released"
        except Exception as e:
            return False, f"Release failed: {e}"

    def _isolate_macos(self, allowed_ips: list[str]) -> tuple[bool, str]:
        """macOS isolation using pfctl."""
        try:
            # Create PF rules
            rules = ["# Sentinel isolation rules\n"]
            rules.append("block out all\n")
            rules.append("pass out proto udp to any port 53\n")
            rules.append("pass out proto udp to any port {67, 68}\n")
            rules.append("pass out on lo0 all\n")
            for ip in allowed_ips:
                rules.append(f"pass out to {ip}\n")

            rules_path = Path("/tmp/sentinel_isolation.conf")
            rules_path.write_text("".join(rules))

            subprocess.run(["pfctl", "-f", str(rules_path)], capture_output=True, timeout=10)
            subprocess.run(["pfctl", "-e"], capture_output=True, timeout=10)
            return True, "macOS pfctl isolation applied"
        except Exception as e:
            return False, f"macOS isolation failed: {e}"

    def _release_macos(self) -> tuple[bool, str]:
        """Remove macOS isolation."""
        try:
            subprocess.run(["pfctl", "-d"], capture_output=True, timeout=10)
            rules_path = Path("/tmp/sentinel_isolation.conf")
            if rules_path.exists():
                rules_path.unlink()
            return True, "macOS isolation released"
        except Exception as e:
            return False, f"Release failed: {e}"

    def _save_state(self, state: IsolationState) -> None:
        """Persist isolation state."""
        self._state_file.write_text(json.dumps(state.to_dict(), indent=2))

    def _load_state(self) -> IsolationState:
        """Load isolation state."""
        if not self._state_file.exists():
            return IsolationState()
        try:
            data = json.loads(self._state_file.read_text())
            return IsolationState.from_dict(data)
        except (json.JSONDecodeError, KeyError):
            return IsolationState()
