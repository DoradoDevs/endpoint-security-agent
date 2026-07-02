"""
Sentinel Agent — Mesh Protocol

Wire-format definitions, HMAC signing / verification, and replay
protection for the agent-to-agent mesh.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class MessageType(str, Enum):
    """Types of messages exchanged between mesh peers."""

    ANNOUNCE = "announce"
    HEARTBEAT = "heartbeat"
    THREAT_ALERT = "threat_alert"
    ACK = "ack"
    PEER_LIST = "peer_list"


@dataclass
class MeshMessage:
    """A single message in the mesh protocol.

    Messages are serialised as JSON, optionally signed with HMAC-SHA256,
    and transmitted over the mesh transport layer.
    """

    msg_type: MessageType
    sender_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    nonce: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    timestamp: float = field(default_factory=time.time)

    def serialize(self) -> bytes:
        """Serialise the message to UTF-8 encoded JSON bytes."""
        data = {
            "msg_type": self.msg_type.value,
            "sender_id": self.sender_id,
            "payload": self.payload,
            "nonce": self.nonce,
            "timestamp": self.timestamp,
        }
        return json.dumps(data, separators=(",", ":")).encode("utf-8")

    @classmethod
    def deserialize(cls, data: bytes) -> MeshMessage:
        """Reconstruct a ``MeshMessage`` from raw JSON bytes."""
        d = json.loads(data.decode("utf-8"))
        return cls(
            msg_type=MessageType(d["msg_type"]),
            sender_id=d["sender_id"],
            payload=d.get("payload", {}),
            nonce=d.get("nonce", ""),
            timestamp=d.get("timestamp", 0),
        )

    def sign(self, key: str) -> str:
        """Sign the message with HMAC-SHA256 and return the hex digest."""
        return hmac.new(
            key.encode("utf-8"),
            self.serialize(),
            hashlib.sha256,
        ).hexdigest()

    @staticmethod
    def verify(data: bytes, signature: str, key: str) -> bool:
        """Verify an HMAC-SHA256 signature over *data*.

        Uses ``hmac.compare_digest`` to prevent timing side-channels.
        """
        expected = hmac.new(
            key.encode("utf-8"),
            data,
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)


# ------------------------------------------------------------------
# Replay protection
# ------------------------------------------------------------------

def is_replay(msg: MeshMessage, max_age: float = 300.0) -> bool:
    """Return ``True`` if the message timestamp is older than *max_age* seconds.

    This is a lightweight replay-protection heuristic — a production
    deployment should also track seen nonces within the validity window.
    """
    return (time.time() - msg.timestamp) > max_age
