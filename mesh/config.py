"""
Sentinel Agent — Mesh Network Configuration

Configuration for the agent-to-agent LAN mesh. This feature is opt-in
and disabled by default. Agents use a pre-shared key (HMAC) for mutual
authentication and restrict peer discovery to RFC-1918 private subnets.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MeshConfig:
    """Configuration for the agent-to-agent mesh network.

    Attributes:
        enabled: Master switch — mesh networking is disabled by default.
        discovery_port: UDP port used for broadcast-based peer discovery.
        comm_port: TCP port used for authenticated peer communication.
        shared_key: Pre-shared key for HMAC-SHA256 authentication. All
            agents in the same mesh must share this key.
        allowed_subnets: CIDR blocks from which peer connections are
            accepted. Defaults to RFC-1918 private ranges.
        alert_severity_threshold: Minimum severity level for findings
            that are shared with mesh peers (``critical``, ``high``,
            ``medium``, ``low``, ``info``).
        heartbeat_interval: Seconds between heartbeat messages sent to
            active peers.
        peer_timeout: Seconds after which a peer with no heartbeat is
            considered stale and evicted from the registry.
    """

    enabled: bool = False
    discovery_port: int = 51337
    comm_port: int = 51338
    shared_key: str = ""  # Pre-shared key for HMAC auth
    allowed_subnets: list[str] = field(
        default_factory=lambda: [
            "192.168.0.0/16",
            "10.0.0.0/8",
            "172.16.0.0/12",
        ]
    )
    alert_severity_threshold: str = "high"  # Only share findings at this severity or above
    heartbeat_interval: int = 30  # seconds
    peer_timeout: int = 120  # seconds

    def to_dict(self) -> dict[str, object]:
        """Serialise the configuration to a plain dictionary."""
        return {
            "enabled": self.enabled,
            "discovery_port": self.discovery_port,
            "comm_port": self.comm_port,
            "shared_key": self.shared_key,
            "allowed_subnets": list(self.allowed_subnets),
            "alert_severity_threshold": self.alert_severity_threshold,
            "heartbeat_interval": self.heartbeat_interval,
            "peer_timeout": self.peer_timeout,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> MeshConfig:
        """Create a ``MeshConfig`` from a plain dictionary."""
        config = cls()
        for key in (
            "enabled",
            "discovery_port",
            "comm_port",
            "shared_key",
            "allowed_subnets",
            "alert_severity_threshold",
            "heartbeat_interval",
            "peer_timeout",
        ):
            if key in data:
                setattr(config, key, data[key])
        return config
