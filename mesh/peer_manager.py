"""
Sentinel Agent — Mesh Peer Manager

Thread-safe registry of discovered mesh peers with heartbeat-based
health monitoring and automatic stale-peer eviction.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class PeerInfo:
    """Metadata about a single mesh peer."""

    device_id: str
    ip_address: str
    comm_port: int
    first_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_seen: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    status: str = "active"

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary."""
        return {
            "device_id": self.device_id,
            "ip_address": self.ip_address,
            "comm_port": self.comm_port,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "status": self.status,
        }


class PeerManager:
    """Thread-safe manager for the mesh peer registry.

    Peers are keyed by their unique ``device_id``.  The manager supports
    heartbeat updates and automatic eviction of peers that have not been
    heard from within ``timeout_seconds``.
    """

    def __init__(self, timeout_seconds: int = 120) -> None:
        self.peers: dict[str, PeerInfo] = {}
        self._lock = threading.Lock()
        self._timeout = timeout_seconds

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    def register_peer(self, device_id: str, ip: str, port: int) -> PeerInfo:
        """Register or update a peer in the registry.

        If the peer already exists its ``last_seen`` and ``status`` are
        refreshed; otherwise a new ``PeerInfo`` is created.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if device_id in self.peers:
                peer = self.peers[device_id]
                peer.ip_address = ip
                peer.comm_port = port
                peer.last_seen = now
                peer.status = "active"
            else:
                peer = PeerInfo(
                    device_id=device_id,
                    ip_address=ip,
                    comm_port=port,
                    first_seen=now,
                    last_seen=now,
                )
                self.peers[device_id] = peer
            return peer

    # ------------------------------------------------------------------
    # Heartbeat
    # ------------------------------------------------------------------

    def update_heartbeat(self, device_id: str) -> None:
        """Refresh the ``last_seen`` timestamp for an existing peer."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            if device_id in self.peers:
                self.peers[device_id].last_seen = now
                self.peers[device_id].status = "active"

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_active_peers(self) -> list[PeerInfo]:
        """Return a snapshot of all peers with ``active`` status."""
        with self._lock:
            return [p for p in self.peers.values() if p.status == "active"]

    def get_peer(self, device_id: str) -> PeerInfo | None:
        """Look up a single peer by *device_id*."""
        with self._lock:
            return self.peers.get(device_id)

    # ------------------------------------------------------------------
    # Eviction
    # ------------------------------------------------------------------

    def evict_stale(self) -> list[str]:
        """Remove peers that have not sent a heartbeat within the timeout.

        Returns a list of device IDs that were evicted.
        """
        now = datetime.now(timezone.utc)
        evicted: list[str] = []
        with self._lock:
            for device_id, peer in list(self.peers.items()):
                try:
                    last = datetime.fromisoformat(peer.last_seen)
                    # Ensure 'last' is offset-aware
                    if last.tzinfo is None:
                        last = last.replace(tzinfo=timezone.utc)
                    age = (now - last).total_seconds()
                    if age > self._timeout:
                        del self.peers[device_id]
                        evicted.append(device_id)
                except (ValueError, TypeError):
                    # Unparseable timestamp — evict defensively
                    del self.peers[device_id]
                    evicted.append(device_id)
        return evicted

    def remove_peer(self, device_id: str) -> None:
        """Explicitly remove a peer from the registry."""
        with self._lock:
            self.peers.pop(device_id, None)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        with self._lock:
            return len(self.peers)

    def __contains__(self, device_id: str) -> bool:
        with self._lock:
            return device_id in self.peers
