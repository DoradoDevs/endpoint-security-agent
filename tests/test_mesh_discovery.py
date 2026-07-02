"""
Tests for mesh.discovery -- UDP broadcast peer discovery, subnet filtering,
signature verification, and announcement message handling.
"""

from __future__ import annotations

import json
import socket
import threading
from unittest.mock import MagicMock, patch

import pytest

from mesh.config import MeshConfig
from mesh.discovery import MeshDiscovery
from mesh.protocol import MeshMessage, MessageType


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------


@pytest.fixture
def default_config() -> MeshConfig:
    """A MeshConfig with sensible test defaults and a pre-shared key."""
    return MeshConfig(
        enabled=True,
        discovery_port=51337,
        comm_port=51338,
        shared_key="test-secret-key",
        allowed_subnets=["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
    )


@pytest.fixture
def discovery(default_config: MeshConfig) -> MeshDiscovery:
    return MeshDiscovery(config=default_config, device_id="agent-001")


# ------------------------------------------------------------------
# UDP broadcast message creation
# ------------------------------------------------------------------


class TestBroadcastMessageCreation:
    """Verify the structure and content of outbound announcement packets."""

    @patch("mesh.discovery.socket.socket")
    def test_announcement_packet_contains_data_and_sig(
        self, mock_socket_cls: MagicMock, discovery: MeshDiscovery
    ) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        discovery.send_announcement()

        raw_packet = mock_sock.sendto.call_args[0][0]
        packet = json.loads(raw_packet.decode("utf-8"))
        assert "data" in packet
        assert "sig" in packet

    @patch("mesh.discovery.socket.socket")
    def test_announcement_inner_message_is_announce_type(
        self, mock_socket_cls: MagicMock, discovery: MeshDiscovery
    ) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        discovery.send_announcement()

        raw_packet = mock_sock.sendto.call_args[0][0]
        packet = json.loads(raw_packet.decode("utf-8"))
        msg = MeshMessage.deserialize(packet["data"].encode("utf-8"))
        assert msg.msg_type == MessageType.ANNOUNCE

    @patch("mesh.discovery.socket.socket")
    def test_announcement_contains_sender_id(
        self, mock_socket_cls: MagicMock, discovery: MeshDiscovery
    ) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        discovery.send_announcement()

        raw_packet = mock_sock.sendto.call_args[0][0]
        packet = json.loads(raw_packet.decode("utf-8"))
        msg = MeshMessage.deserialize(packet["data"].encode("utf-8"))
        assert msg.sender_id == "agent-001"

    @patch("mesh.discovery.socket.socket")
    def test_announcement_payload_includes_comm_port(
        self, mock_socket_cls: MagicMock, discovery: MeshDiscovery
    ) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        discovery.send_announcement()

        raw_packet = mock_sock.sendto.call_args[0][0]
        packet = json.loads(raw_packet.decode("utf-8"))
        msg = MeshMessage.deserialize(packet["data"].encode("utf-8"))
        assert msg.payload["comm_port"] == 51338

    @patch("mesh.discovery.socket.socket")
    def test_broadcast_socket_options(
        self, mock_socket_cls: MagicMock, discovery: MeshDiscovery
    ) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        discovery.send_announcement()

        mock_socket_cls.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        mock_sock.setsockopt.assert_called_once_with(
            socket.SOL_SOCKET, socket.SO_BROADCAST, 1
        )
        mock_sock.close.assert_called_once()

    @patch("mesh.discovery.socket.socket")
    def test_broadcast_no_key_produces_empty_sig(
        self, mock_socket_cls: MagicMock
    ) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        cfg = MeshConfig(enabled=True, shared_key="")
        disc = MeshDiscovery(config=cfg, device_id="agent-002")
        disc.send_announcement()

        raw_packet = mock_sock.sendto.call_args[0][0]
        packet = json.loads(raw_packet.decode("utf-8"))
        assert packet["sig"] == ""

    @patch("mesh.discovery.socket.socket")
    def test_broadcast_os_error_does_not_raise(
        self, mock_socket_cls: MagicMock, default_config: MeshConfig
    ) -> None:
        mock_sock = MagicMock()
        mock_sock.sendto.side_effect = OSError("network unreachable")
        mock_socket_cls.return_value = mock_sock

        disc = MeshDiscovery(config=default_config, device_id="agent-001")
        disc.send_announcement()  # must not raise


# ------------------------------------------------------------------
# Subnet filtering (allowed / disallowed subnets)
# ------------------------------------------------------------------


class TestSubnetFiltering:
    """Verify that is_allowed_subnet correctly gates IP addresses."""

    def test_private_192_168_allowed(self, discovery: MeshDiscovery) -> None:
        assert discovery.is_allowed_subnet("192.168.1.50") is True

    def test_private_10_x_allowed(self, discovery: MeshDiscovery) -> None:
        assert discovery.is_allowed_subnet("10.0.0.5") is True

    def test_private_172_16_allowed(self, discovery: MeshDiscovery) -> None:
        assert discovery.is_allowed_subnet("172.16.5.10") is True

    def test_public_ip_rejected(self, discovery: MeshDiscovery) -> None:
        assert discovery.is_allowed_subnet("8.8.8.8") is False

    def test_documentation_range_rejected(self, discovery: MeshDiscovery) -> None:
        assert discovery.is_allowed_subnet("203.0.113.1") is False

    def test_loopback_rejected(self, discovery: MeshDiscovery) -> None:
        assert discovery.is_allowed_subnet("127.0.0.1") is False

    def test_invalid_ip_string_rejected(self, discovery: MeshDiscovery) -> None:
        assert discovery.is_allowed_subnet("not-an-ip") is False

    def test_empty_string_rejected(self, discovery: MeshDiscovery) -> None:
        assert discovery.is_allowed_subnet("") is False

    def test_custom_narrow_subnet(self) -> None:
        cfg = MeshConfig(allowed_subnets=["172.20.0.0/16"])
        disc = MeshDiscovery(config=cfg, device_id="agent-002")
        assert disc.is_allowed_subnet("172.20.1.1") is True
        assert disc.is_allowed_subnet("172.21.1.1") is False

    def test_single_host_subnet(self) -> None:
        cfg = MeshConfig(allowed_subnets=["10.99.0.7/32"])
        disc = MeshDiscovery(config=cfg, device_id="agent-003")
        assert disc.is_allowed_subnet("10.99.0.7") is True
        assert disc.is_allowed_subnet("10.99.0.8") is False


# ------------------------------------------------------------------
# Signature verification (HMAC-SHA256 in listen path)
# ------------------------------------------------------------------


class TestSignatureVerification:
    """Ensure that the listener validates HMAC signatures correctly."""

    def test_valid_signature_accepted(self, default_config: MeshConfig) -> None:
        msg = MeshMessage(
            msg_type=MessageType.ANNOUNCE,
            sender_id="agent-peer",
            payload={"comm_port": 51338},
        )
        data = msg.serialize()
        sig = msg.sign(default_config.shared_key)
        assert MeshMessage.verify(data, sig, default_config.shared_key) is True

    def test_wrong_key_signature_rejected(self, default_config: MeshConfig) -> None:
        msg = MeshMessage(
            msg_type=MessageType.ANNOUNCE,
            sender_id="agent-peer",
        )
        data = msg.serialize()
        sig = msg.sign("wrong-key")
        assert MeshMessage.verify(data, sig, default_config.shared_key) is False

    def test_tampered_data_signature_rejected(
        self, default_config: MeshConfig
    ) -> None:
        msg = MeshMessage(
            msg_type=MessageType.ANNOUNCE,
            sender_id="agent-peer",
        )
        data = msg.serialize()
        sig = msg.sign(default_config.shared_key)
        tampered = data + b"tampered"
        assert MeshMessage.verify(tampered, sig, default_config.shared_key) is False


# ------------------------------------------------------------------
# Announcement message format
# ------------------------------------------------------------------


class TestAnnouncementFormat:
    """Verify the wire format of announcement packets."""

    @patch("mesh.discovery.socket.socket")
    def test_packet_is_valid_json(
        self, mock_socket_cls: MagicMock, discovery: MeshDiscovery
    ) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        discovery.send_announcement()

        raw = mock_sock.sendto.call_args[0][0]
        packet = json.loads(raw.decode("utf-8"))
        assert isinstance(packet, dict)

    @patch("mesh.discovery.socket.socket")
    def test_inner_data_deserializes_to_mesh_message(
        self, mock_socket_cls: MagicMock, discovery: MeshDiscovery
    ) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        discovery.send_announcement()

        raw = mock_sock.sendto.call_args[0][0]
        packet = json.loads(raw.decode("utf-8"))
        msg = MeshMessage.deserialize(packet["data"].encode("utf-8"))
        assert hasattr(msg, "nonce")
        assert hasattr(msg, "timestamp")
        assert msg.msg_type == MessageType.ANNOUNCE


# ------------------------------------------------------------------
# Discovery message parsing (malformed / corrupted)
# ------------------------------------------------------------------


class TestDiscoveryMessageParsing:
    """Ensure resilience against malformed or corrupted discovery packets."""

    def test_deserialize_valid_json(self) -> None:
        msg = MeshMessage(
            msg_type=MessageType.ANNOUNCE,
            sender_id="agent-x",
            payload={"comm_port": 9999},
        )
        raw = msg.serialize()
        restored = MeshMessage.deserialize(raw)
        assert restored.sender_id == "agent-x"
        assert restored.payload["comm_port"] == 9999

    def test_deserialize_invalid_json_raises(self) -> None:
        with pytest.raises(Exception):
            MeshMessage.deserialize(b"not-json-at-all{{{")

    def test_deserialize_missing_msg_type_raises(self) -> None:
        bad = json.dumps({"sender_id": "a", "payload": {}}).encode("utf-8")
        with pytest.raises((KeyError, ValueError)):
            MeshMessage.deserialize(bad)

    def test_deserialize_unknown_msg_type_raises(self) -> None:
        bad = json.dumps(
            {"msg_type": "unknown_type", "sender_id": "a", "payload": {}}
        ).encode("utf-8")
        with pytest.raises(ValueError):
            MeshMessage.deserialize(bad)

    def test_deserialize_empty_bytes_raises(self) -> None:
        with pytest.raises(Exception):
            MeshMessage.deserialize(b"")


# ------------------------------------------------------------------
# Port configuration
# ------------------------------------------------------------------


class TestPortConfiguration:
    """Verify that custom ports propagate correctly."""

    @patch("mesh.discovery.socket.socket")
    def test_custom_discovery_port(self, mock_socket_cls: MagicMock) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        cfg = MeshConfig(enabled=True, discovery_port=60000, comm_port=60001)
        disc = MeshDiscovery(config=cfg, device_id="agent-001")
        disc.send_announcement()

        dest = mock_sock.sendto.call_args[0][1]
        assert dest == ("<broadcast>", 60000)

    @patch("mesh.discovery.socket.socket")
    def test_custom_comm_port_in_payload(self, mock_socket_cls: MagicMock) -> None:
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock

        cfg = MeshConfig(enabled=True, discovery_port=60000, comm_port=60001)
        disc = MeshDiscovery(config=cfg, device_id="agent-001")
        disc.send_announcement()

        raw = mock_sock.sendto.call_args[0][0]
        packet = json.loads(raw.decode("utf-8"))
        msg = MeshMessage.deserialize(packet["data"].encode("utf-8"))
        assert msg.payload["comm_port"] == 60001

    def test_config_default_discovery_port(self) -> None:
        cfg = MeshConfig()
        assert cfg.discovery_port == 51337

    def test_config_default_comm_port(self) -> None:
        cfg = MeshConfig()
        assert cfg.comm_port == 51338
