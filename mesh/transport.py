"""
Sentinel Agent — Mesh Transport

TCP transport layer with length-prefixed JSON framing and HMAC-SHA256
authentication for reliable peer-to-peer communication.
"""

from __future__ import annotations

import json
import logging
import socket
import struct
from typing import Any

from mesh.config import MeshConfig
from mesh.protocol import MeshMessage

logger = logging.getLogger(__name__)

# Maximum accepted message size (1 MB).
_MAX_MESSAGE_SIZE = 1_000_000


class MeshTransport:
    """TCP transport with length-prefixed JSON and HMAC authentication."""

    def __init__(self, config: MeshConfig) -> None:
        self.config = config

    # ------------------------------------------------------------------
    # Send
    # ------------------------------------------------------------------

    def send_message(
        self, host: str, port: int, message: MeshMessage
    ) -> tuple[bool, str]:
        """Send a single *message* to the peer at *(host, port)*.

        Returns ``(success, detail)`` where *detail* is either
        ``"Message sent"`` or the error description.
        """
        data = message.serialize()
        sig = message.sign(self.config.shared_key) if self.config.shared_key else ""
        packet = json.dumps({"data": data.decode("utf-8"), "sig": sig}).encode("utf-8")

        # 4-byte big-endian length prefix
        length = struct.pack("!I", len(packet))

        try:
            with socket.create_connection((host, port), timeout=5) as sock:
                sock.sendall(length + packet)
            return True, "Message sent"
        except Exception as exc:  # noqa: BLE001
            logger.debug("Send failed to %s:%d — %s", host, port, exc)
            return False, str(exc)

    # ------------------------------------------------------------------
    # Receive
    # ------------------------------------------------------------------

    def _recv_exact(self, conn: socket.socket, size: int) -> bytes | None:
        """Read exactly *size* bytes from *conn*, or return ``None``."""
        buf = bytearray()
        while len(buf) < size:
            chunk = conn.recv(size - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def receive_message(self, conn: socket.socket) -> MeshMessage | None:
        """Receive a length-prefixed message from *conn*.

        Returns ``None`` on any protocol or authentication failure.
        """
        try:
            # Read the 4-byte length header
            length_data = self._recv_exact(conn, 4)
            if length_data is None or len(length_data) < 4:
                return None

            length = struct.unpack("!I", length_data)[0]
            if length > _MAX_MESSAGE_SIZE:
                logger.warning("Oversized message (%d bytes) — dropping", length)
                return None

            # Read the payload
            raw = self._recv_exact(conn, length)
            if raw is None:
                return None

            packet: dict[str, Any] = json.loads(raw.decode("utf-8"))
            msg_data = packet["data"].encode("utf-8")
            sig = packet.get("sig", "")

            # Verify HMAC signature when a shared key is configured
            if self.config.shared_key and sig:
                if not MeshMessage.verify(msg_data, sig, self.config.shared_key):
                    logger.warning("HMAC verification failed — dropping message")
                    return None

            return MeshMessage.deserialize(msg_data)

        except Exception as exc:  # noqa: BLE001
            logger.debug("receive_message error: %s", exc)
            return None
