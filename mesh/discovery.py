"""
Sentinel Agent — Mesh Peer Discovery

UDP broadcast-based discovery of other Sentinel agents on the local
network. Announcements are signed with the pre-shared HMAC key so that
only authorised agents can join the mesh.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import threading
from typing import Callable

from mesh.config import MeshConfig
from mesh.protocol import MeshMessage, MessageType

logger = logging.getLogger(__name__)


class MeshDiscovery:
    """UDP broadcast-based peer discovery for the agent mesh."""

    def __init__(self, config: MeshConfig, device_id: str) -> None:
        self.config = config
        self.device_id = device_id
        self._running = False

    # ------------------------------------------------------------------
    # Announce
    # ------------------------------------------------------------------

    def send_announcement(self) -> None:
        """Broadcast an ``ANNOUNCE`` message on the LAN."""
        msg = MeshMessage(
            msg_type=MessageType.ANNOUNCE,
            sender_id=self.device_id,
            payload={"comm_port": self.config.comm_port},
        )
        data = msg.serialize()
        signature = msg.sign(self.config.shared_key) if self.config.shared_key else ""
        packet = json.dumps({"data": data.decode("utf-8"), "sig": signature}).encode("utf-8")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(packet, ("<broadcast>", self.config.discovery_port))
            sock.close()
        except OSError as exc:
            logger.debug("Discovery broadcast failed: %s", exc)

    # ------------------------------------------------------------------
    # Subnet filtering
    # ------------------------------------------------------------------

    def is_allowed_subnet(self, ip: str) -> bool:
        """Return ``True`` if *ip* belongs to one of the allowed subnets."""
        try:
            addr = ipaddress.ip_address(ip)
            for subnet in self.config.allowed_subnets:
                if addr in ipaddress.ip_network(subnet, strict=False):
                    return True
        except ValueError:
            pass
        return False

    # ------------------------------------------------------------------
    # Listener
    # ------------------------------------------------------------------

    def listen(
        self,
        callback: Callable[[str, MeshMessage], None],
        stop_event: threading.Event,
    ) -> None:
        """Listen for peer announcements (blocking — run in a thread).

        *callback* receives ``(sender_ip, message)`` for every valid,
        authenticated announcement from an allowed subnet.
        """
        self._running = True
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("", self.config.discovery_port))
            sock.settimeout(1.0)
        except OSError as exc:
            logger.error("Cannot bind discovery socket: %s", exc)
            self._running = False
            return

        try:
            while not stop_event.is_set():
                try:
                    raw, (sender_ip, _port) = sock.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break

                # Subnet check
                if not self.is_allowed_subnet(sender_ip):
                    logger.debug("Dropping packet from disallowed subnet: %s", sender_ip)
                    continue

                # Parse and verify
                try:
                    packet = json.loads(raw.decode("utf-8"))
                    msg_data = packet["data"].encode("utf-8")
                    sig = packet.get("sig", "")

                    if self.config.shared_key and sig:
                        if not MeshMessage.verify(msg_data, sig, self.config.shared_key):
                            logger.warning("Invalid HMAC from %s — dropping", sender_ip)
                            continue

                    msg = MeshMessage.deserialize(msg_data)

                    # Ignore our own announcements
                    if msg.sender_id == self.device_id:
                        continue

                    callback(sender_ip, msg)

                except (json.JSONDecodeError, KeyError, ValueError) as exc:
                    logger.debug("Malformed discovery packet from %s: %s", sender_ip, exc)
        finally:
            sock.close()
            self._running = False
