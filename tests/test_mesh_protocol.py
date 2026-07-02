"""
Tests for mesh.protocol -- message serialization/deserialization, HMAC signing
and verification, nonce-based replay protection, and MessageType enum values.
"""

from __future__ import annotations

import json
import time
from unittest.mock import patch, MagicMock

import pytest

from mesh.protocol import MeshMessage, MessageType, is_replay


# ------------------------------------------------------------------
# MessageType enum values
# ------------------------------------------------------------------


class TestMessageTypeEnum:
    """Verify all expected enum members and their string values."""

    def test_announce_value(self) -> None:
        assert MessageType.ANNOUNCE.value == "announce"

    def test_heartbeat_value(self) -> None:
        assert MessageType.HEARTBEAT.value == "heartbeat"

    def test_threat_alert_value(self) -> None:
        assert MessageType.THREAT_ALERT.value == "threat_alert"

    def test_ack_value(self) -> None:
        assert MessageType.ACK.value == "ack"

    def test_peer_list_value(self) -> None:
        assert MessageType.PEER_LIST.value == "peer_list"

    def test_enum_completeness(self) -> None:
        expected = {"announce", "heartbeat", "threat_alert", "ack", "peer_list"}
        actual = {m.value for m in MessageType}
        assert actual == expected

    def test_enum_is_str_subclass(self) -> None:
        assert isinstance(MessageType.ANNOUNCE, str)


# ------------------------------------------------------------------
# MeshMessage dataclass fields
# ------------------------------------------------------------------


class TestMeshMessageFields:
    """Verify the dataclass defaults and field population."""

    def test_required_fields(self) -> None:
        msg = MeshMessage(msg_type=MessageType.ACK, sender_id="agent-x")
        assert msg.msg_type == MessageType.ACK
        assert msg.sender_id == "agent-x"

    def test_default_payload_is_empty_dict(self) -> None:
        msg = MeshMessage(msg_type=MessageType.ACK, sender_id="a")
        assert msg.payload == {}

    def test_nonce_auto_generated(self) -> None:
        msg = MeshMessage(msg_type=MessageType.ACK, sender_id="a")
        assert isinstance(msg.nonce, str)
        assert len(msg.nonce) == 16

    def test_timestamp_auto_generated(self) -> None:
        before = time.time()
        msg = MeshMessage(msg_type=MessageType.ACK, sender_id="a")
        after = time.time()
        assert before <= msg.timestamp <= after

    def test_custom_payload(self) -> None:
        payload = {"key": "value", "count": 42}
        msg = MeshMessage(
            msg_type=MessageType.THREAT_ALERT,
            sender_id="a",
            payload=payload,
        )
        assert msg.payload == payload

    def test_custom_nonce(self) -> None:
        msg = MeshMessage(
            msg_type=MessageType.ACK,
            sender_id="a",
            nonce="custom-nonce-1234",
        )
        assert msg.nonce == "custom-nonce-1234"


# ------------------------------------------------------------------
# Message serialization / deserialization
# ------------------------------------------------------------------


class TestSerializeDeserialize:
    """Round-trip serialization tests."""

    def test_serialize_returns_bytes(self) -> None:
        msg = MeshMessage(msg_type=MessageType.ACK, sender_id="a")
        assert isinstance(msg.serialize(), bytes)

    def test_serialize_is_valid_json(self) -> None:
        msg = MeshMessage(msg_type=MessageType.HEARTBEAT, sender_id="a")
        parsed = json.loads(msg.serialize().decode("utf-8"))
        assert parsed["msg_type"] == "heartbeat"
        assert parsed["sender_id"] == "a"

    def test_round_trip_basic(self) -> None:
        original = MeshMessage(
            msg_type=MessageType.HEARTBEAT,
            sender_id="agent-001",
        )
        raw = original.serialize()
        restored = MeshMessage.deserialize(raw)
        assert restored.msg_type == MessageType.HEARTBEAT
        assert restored.sender_id == "agent-001"
        assert restored.nonce == original.nonce
        assert restored.timestamp == original.timestamp
        assert restored.payload == {}

    def test_round_trip_with_payload(self) -> None:
        payload = {"comm_port": 51338, "version": "2.0.0"}
        original = MeshMessage(
            msg_type=MessageType.ANNOUNCE,
            sender_id="agent-002",
            payload=payload,
        )
        raw = original.serialize()
        restored = MeshMessage.deserialize(raw)
        assert restored.payload == payload

    def test_round_trip_threat_alert(self) -> None:
        payload = {"finding_title": "Open SSH port", "severity": "high"}
        original = MeshMessage(
            msg_type=MessageType.THREAT_ALERT,
            sender_id="agent-003",
            payload=payload,
        )
        restored = MeshMessage.deserialize(original.serialize())
        assert restored.msg_type == MessageType.THREAT_ALERT
        assert restored.payload["finding_title"] == "Open SSH port"

    def test_deserialize_invalid_json_raises(self) -> None:
        with pytest.raises(Exception):
            MeshMessage.deserialize(b"{invalid-json")

    def test_deserialize_missing_fields_raises(self) -> None:
        incomplete = json.dumps({"sender_id": "a"}).encode("utf-8")
        with pytest.raises((KeyError, ValueError)):
            MeshMessage.deserialize(incomplete)

    def test_serialize_compact_no_whitespace(self) -> None:
        msg = MeshMessage(msg_type=MessageType.ACK, sender_id="a")
        raw = msg.serialize()
        text = raw.decode("utf-8")
        # separators=(",", ":") means no spaces after , or :
        assert " " not in text


# ------------------------------------------------------------------
# Message signing and verification
# ------------------------------------------------------------------


class TestSignVerify:
    """HMAC-SHA256 signing and verification."""

    def test_sign_returns_hex_string(self) -> None:
        msg = MeshMessage(msg_type=MessageType.HEARTBEAT, sender_id="a")
        sig = msg.sign("secret")
        assert isinstance(sig, str)
        assert len(sig) == 64  # SHA-256 hex = 64 chars

    def test_sign_is_deterministic(self) -> None:
        msg = MeshMessage(
            msg_type=MessageType.ACK,
            sender_id="a",
            nonce="fixed-nonce",
            timestamp=1000000.0,
        )
        assert msg.sign("key") == msg.sign("key")

    def test_verify_correct_key(self) -> None:
        msg = MeshMessage(msg_type=MessageType.HEARTBEAT, sender_id="a")
        data = msg.serialize()
        sig = msg.sign("secret")
        assert MeshMessage.verify(data, sig, "secret") is True

    def test_verify_wrong_key_fails(self) -> None:
        msg = MeshMessage(msg_type=MessageType.HEARTBEAT, sender_id="a")
        data = msg.serialize()
        sig = msg.sign("correct-key")
        assert MeshMessage.verify(data, sig, "wrong-key") is False

    def test_verify_tampered_data_fails(self) -> None:
        msg = MeshMessage(msg_type=MessageType.HEARTBEAT, sender_id="a")
        data = msg.serialize()
        sig = msg.sign("secret")
        tampered = data + b"extra"
        assert MeshMessage.verify(tampered, sig, "secret") is False

    def test_verify_empty_signature_fails(self) -> None:
        msg = MeshMessage(msg_type=MessageType.HEARTBEAT, sender_id="a")
        data = msg.serialize()
        assert MeshMessage.verify(data, "", "secret") is False

    def test_different_payloads_produce_different_signatures(self) -> None:
        msg1 = MeshMessage(
            msg_type=MessageType.ACK,
            sender_id="a",
            payload={"x": 1},
            nonce="same",
            timestamp=1.0,
        )
        msg2 = MeshMessage(
            msg_type=MessageType.ACK,
            sender_id="a",
            payload={"x": 2},
            nonce="same",
            timestamp=1.0,
        )
        assert msg1.sign("key") != msg2.sign("key")


# ------------------------------------------------------------------
# Nonce-based replay protection
# ------------------------------------------------------------------


class TestNonceReplayProtection:
    """Nonce uniqueness and timestamp-based replay detection."""

    def test_nonce_uniqueness_across_messages(self) -> None:
        nonces = {
            MeshMessage(msg_type=MessageType.ACK, sender_id="a").nonce
            for _ in range(200)
        }
        assert len(nonces) == 200

    def test_fresh_message_is_not_replay(self) -> None:
        msg = MeshMessage(
            msg_type=MessageType.HEARTBEAT,
            sender_id="a",
            timestamp=time.time(),
        )
        assert is_replay(msg) is False

    def test_old_message_is_replay(self) -> None:
        msg = MeshMessage(
            msg_type=MessageType.HEARTBEAT,
            sender_id="a",
            timestamp=time.time() - 600,
        )
        assert is_replay(msg) is True

    def test_custom_max_age_short(self) -> None:
        msg = MeshMessage(
            msg_type=MessageType.HEARTBEAT,
            sender_id="a",
            timestamp=time.time() - 10,
        )
        assert is_replay(msg, max_age=5.0) is True

    def test_custom_max_age_long(self) -> None:
        msg = MeshMessage(
            msg_type=MessageType.HEARTBEAT,
            sender_id="a",
            timestamp=time.time() - 10,
        )
        assert is_replay(msg, max_age=30.0) is False

    def test_replay_detection_duplicate_nonce_scenario(self) -> None:
        """Simulate a duplicate nonce by creating two messages with the same
        nonce but different timestamps -- the old one should be flagged."""
        nonce = "shared-nonce-0001"
        fresh = MeshMessage(
            msg_type=MessageType.ACK,
            sender_id="a",
            nonce=nonce,
            timestamp=time.time(),
        )
        stale = MeshMessage(
            msg_type=MessageType.ACK,
            sender_id="a",
            nonce=nonce,
            timestamp=time.time() - 400,
        )
        assert is_replay(fresh) is False
        assert is_replay(stale) is True

    def test_boundary_returns_bool(self) -> None:
        msg = MeshMessage(
            msg_type=MessageType.HEARTBEAT,
            sender_id="a",
            timestamp=time.time() - 300,
        )
        result = is_replay(msg, max_age=300.0)
        assert isinstance(result, bool)
