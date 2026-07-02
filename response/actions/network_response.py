"""
Sentinel Agent — Network Response Handler

Blocks suspicious connections via OS firewall rules.
All rules are named with 'Sentinel-' prefix for easy identification and rollback.
"""

from __future__ import annotations

import platform
import subprocess

from core.logging import get_logger
from core.telemetry import Finding


class NetworkResponseHandler:
    """Block suspicious connections via OS firewall rules."""

    def __init__(self) -> None:
        self.log = get_logger()
        self._platform = platform.system().lower()

    def block_ip(self, ip: str, finding: Finding) -> tuple[bool, str]:
        """Add a firewall rule to block traffic to/from an IP."""
        rule_name = f"Sentinel-Block-{ip.replace('.', '-').replace(':', '-')}"

        if self._platform == "windows":
            return self._win_block_ip(ip, rule_name)
        elif self._platform == "darwin":
            return self._mac_block_ip(ip, rule_name)
        else:
            return self._linux_block_ip(ip, rule_name)

    def unblock_ip(self, ip: str) -> tuple[bool, str]:
        """Remove the block rule for an IP (rollback)."""
        rule_name = f"Sentinel-Block-{ip.replace('.', '-').replace(':', '-')}"

        if self._platform == "windows":
            return self._win_remove_rule(rule_name)
        elif self._platform == "darwin":
            return self._mac_unblock_ip(ip)
        else:
            return self._linux_unblock_ip(ip)

    def is_applicable(self, finding: Finding) -> bool:
        """Check if this handler applies to a given finding."""
        return (
            finding.category in ("Network Security", "Threat Intelligence")
            and any(k in finding.evidence for k in ("remote_ip", "ip", "address", "ioc_value"))
        )

    def get_ip_from_finding(self, finding: Finding) -> str | None:
        """Extract the IP address from a finding's evidence."""
        for key in ("remote_ip", "ip", "address", "ioc_value"):
            val = finding.evidence.get(key)
            if val and isinstance(val, str):
                # Basic check that it looks like an IP
                if "." in val or ":" in val:
                    return val
        return None

    # === Windows ===

    def _win_block_ip(self, ip: str, rule_name: str) -> tuple[bool, str]:
        """Block IP using netsh advfirewall."""
        try:
            # Block outbound
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}-out", "dir=out", "action=block",
                    f"remoteip={ip}", "enable=yes",
                ],
                capture_output=True, text=True, timeout=15, check=True,
            )
            # Block inbound
            subprocess.run(
                [
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}-in", "dir=in", "action=block",
                    f"remoteip={ip}", "enable=yes",
                ],
                capture_output=True, text=True, timeout=15, check=True,
            )
            return True, f"Blocked {ip} (Windows firewall rules: {rule_name})"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to block {ip}: {e.stderr}"
        except Exception as e:
            return False, f"Failed to block {ip}: {e}"

    def _win_remove_rule(self, rule_name: str) -> tuple[bool, str]:
        try:
            for suffix in ("-out", "-in"):
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule",
                     f"name={rule_name}{suffix}"],
                    capture_output=True, text=True, timeout=15,
                )
            return True, f"Removed firewall rules: {rule_name}"
        except Exception as e:
            return False, f"Failed to remove rules: {e}"

    # === Linux ===

    def _linux_block_ip(self, ip: str, rule_name: str) -> tuple[bool, str]:
        """Block IP using iptables."""
        try:
            subprocess.run(
                ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP",
                 "-m", "comment", "--comment", rule_name],
                capture_output=True, text=True, timeout=15, check=True,
            )
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP",
                 "-m", "comment", "--comment", rule_name],
                capture_output=True, text=True, timeout=15, check=True,
            )
            return True, f"Blocked {ip} (iptables rules: {rule_name})"
        except subprocess.CalledProcessError as e:
            return False, f"Failed to block {ip}: {e.stderr}"
        except FileNotFoundError:
            # Try ufw as fallback
            return self._linux_ufw_block(ip)
        except Exception as e:
            return False, f"Failed to block {ip}: {e}"

    def _linux_ufw_block(self, ip: str) -> tuple[bool, str]:
        try:
            subprocess.run(
                ["ufw", "deny", "from", ip],
                capture_output=True, text=True, timeout=15, check=True,
            )
            return True, f"Blocked {ip} via ufw"
        except Exception as e:
            return False, f"Failed to block {ip} via ufw: {e}"

    def _linux_unblock_ip(self, ip: str) -> tuple[bool, str]:
        try:
            subprocess.run(
                ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=15,
            )
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, text=True, timeout=15,
            )
            return True, f"Unblocked {ip} (iptables)"
        except Exception as e:
            return False, f"Failed to unblock {ip}: {e}"

    # === macOS ===

    def _mac_block_ip(self, ip: str, rule_name: str) -> tuple[bool, str]:
        """Block IP using pfctl anchor."""
        pf_rule = f"block drop quick on en0 from any to {ip}\nblock drop quick on en0 from {ip} to any\n"
        anchor_file = Path("/etc/pf.anchors/sentinel")

        try:
            # Append to sentinel anchor file
            existing = ""
            if anchor_file.exists():
                existing = anchor_file.read_text()
            if ip not in existing:
                anchor_file.write_text(existing + pf_rule)
                subprocess.run(
                    ["pfctl", "-a", "sentinel", "-f", "/etc/pf.anchors/sentinel"],
                    capture_output=True, text=True, timeout=15,
                )
            return True, f"Blocked {ip} (macOS pf)"
        except PermissionError:
            return False, f"Permission denied. Run with sudo to block {ip}."
        except Exception as e:
            return False, f"Failed to block {ip}: {e}"

    def _mac_unblock_ip(self, ip: str) -> tuple[bool, str]:
        """Remove IP from pf anchor."""
        anchor_file = Path("/etc/pf.anchors/sentinel")
        try:
            if anchor_file.exists():
                lines = anchor_file.read_text().splitlines()
                filtered = [l for l in lines if ip not in l]
                anchor_file.write_text("\n".join(filtered) + "\n")
                subprocess.run(
                    ["pfctl", "-a", "sentinel", "-f", "/etc/pf.anchors/sentinel"],
                    capture_output=True, text=True, timeout=15,
                )
            return True, f"Unblocked {ip} (macOS pf)"
        except Exception as e:
            return False, f"Failed to unblock {ip}: {e}"
