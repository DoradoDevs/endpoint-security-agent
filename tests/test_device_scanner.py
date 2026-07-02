"""Tests for the Device Scanner, Device Inventory, and Device Policy."""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

from core.config import AgentConfig, Severity
from scanners.device_inventory import DeviceInfo, DeviceInventory
from scanners.device_policy import DevicePolicy
from scanners.device_scanner import DeviceScanner


# ── Helper factories ────────────────────────────────────────────────


def _usb_device(
    name: str = "Generic USB",
    vendor_id: str = "1234",
    product_id: str = "5678",
    is_storage: bool = False,
    vendor: str = "",
) -> DeviceInfo:
    return DeviceInfo(
        name=name,
        device_type="usb",
        vendor=vendor,
        vendor_id=vendor_id,
        product_id=product_id,
        is_removable=True,
        is_storage=is_storage,
        bus="USB",
    )


def _bt_device(name: str = "BT Speaker") -> DeviceInfo:
    return DeviceInfo(
        name=name,
        device_type="bluetooth",
        is_wireless=True,
        bus="Bluetooth",
    )


def _make_config() -> AgentConfig:
    config = AgentConfig()
    config.scan.enable_device_scan = True
    return config


# ── Scanner Properties ──────────────────────────────────────────────


class TestDeviceScannerProperties:
    def test_name(self):
        scanner = DeviceScanner(_make_config())
        assert scanner.name == "DeviceScanner"

    def test_description(self):
        scanner = DeviceScanner(_make_config())
        assert "USB" in scanner.description
        assert "Bluetooth" in scanner.description


# ── DeviceInfo ──────────────────────────────────────────────────────


class TestDeviceInfo:
    def test_dataclass_creation(self):
        dev = DeviceInfo(name="Test", device_type="usb")
        assert dev.name == "Test"
        assert dev.device_type == "usb"
        assert dev.vendor == ""
        assert dev.is_removable is False
        assert dev.status == "connected"

    def test_to_dict(self):
        dev = _usb_device(name="Flash Drive", is_storage=True)
        d = dev.to_dict()
        assert d["name"] == "Flash Drive"
        assert d["is_storage"] is True
        assert d["device_type"] == "usb"


# ── DevicePolicy ────────────────────────────────────────────────────


class TestDevicePolicy:
    def test_allowed_vendor(self):
        """Device from allowed vendor should be compliant."""
        policy = DevicePolicy(allowed_usb_vendors=["1234", "ABCD"])
        dev = _usb_device(vendor_id="1234")
        compliant, reason = policy.check_device(dev)
        assert compliant is True
        assert reason == ""

    def test_blocked_vendor(self):
        """Device from blocked vendor should be non-compliant."""
        policy = DevicePolicy(blocked_usb_vendors=["DEAD"])
        dev = _usb_device(vendor_id="DEAD")
        compliant, reason = policy.check_device(dev)
        assert compliant is False
        assert "blocked" in reason.lower()

    def test_vendor_not_in_allowed_list(self):
        """Device from unknown vendor should be blocked when allow-list is set."""
        policy = DevicePolicy(allowed_usb_vendors=["AAAA"])
        dev = _usb_device(vendor_id="BBBB")
        compliant, reason = policy.check_device(dev)
        assert compliant is False
        assert "not in the allowed list" in reason.lower()

    def test_usb_storage_blocked(self):
        """USB storage device should be blocked when policy forbids it."""
        policy = DevicePolicy(block_usb_storage=True)
        dev = _usb_device(is_storage=True)
        compliant, reason = policy.check_device(dev)
        assert compliant is False
        assert "storage" in reason.lower()

    def test_usb_storage_allowed_by_default(self):
        """USB storage allowed when block_usb_storage is False."""
        policy = DevicePolicy(block_usb_storage=False)
        dev = _usb_device(is_storage=True)
        compliant, reason = policy.check_device(dev)
        assert compliant is True

    def test_max_usb_devices(self):
        """Exceeding max USB count should trigger a violation."""
        policy = DevicePolicy(max_usb_devices=2)
        devices = [_usb_device(name=f"USB{i}") for i in range(5)]
        violations = policy.check_device_counts(devices)
        assert len(violations) >= 1
        assert any("USB device count" in v[1] for v in violations)

    def test_max_bluetooth_devices(self):
        """Exceeding max Bluetooth count should trigger a violation."""
        policy = DevicePolicy(max_bluetooth_devices=1)
        devices = [_bt_device(name=f"BT{i}") for i in range(3)]
        violations = policy.check_device_counts(devices)
        assert len(violations) >= 1
        assert any("Bluetooth device count" in v[1] for v in violations)

    def test_bluetooth_blocked(self):
        """Bluetooth device should be non-compliant when BT is blocked."""
        policy = DevicePolicy(block_bluetooth=True)
        dev = _bt_device()
        compliant, reason = policy.check_device(dev)
        assert compliant is False
        assert "bluetooth" in reason.lower()

    def test_bluetooth_allowed_by_default(self):
        """Bluetooth devices are compliant when not explicitly blocked."""
        policy = DevicePolicy(block_bluetooth=False)
        dev = _bt_device()
        compliant, reason = policy.check_device(dev)
        assert compliant is True

    def test_to_dict_and_from_dict(self):
        """Round-trip serialization."""
        policy = DevicePolicy(
            block_usb_storage=True,
            max_usb_devices=5,
            blocked_usb_vendors=["DEAD"],
        )
        data = policy.to_dict()
        restored = DevicePolicy.from_dict(data)
        assert restored.block_usb_storage is True
        assert restored.max_usb_devices == 5
        assert "DEAD" in restored.blocked_usb_vendors


# ── Scanner with mocked inventory ───────────────────────────────────


class TestDeviceScannerScan:
    def test_empty_device_list(self):
        """Scanner with no devices should return only the inventory finding."""
        scanner = DeviceScanner(_make_config())
        inv = MagicMock(spec=DeviceInventory)
        inv.enumerate_all.return_value = []
        scanner.set_inventory(inv)

        findings = scanner.scan()
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
        assert "0 devices" in findings[0].description

    def test_usb_storage_detected(self):
        """Scanner should flag removable USB storage."""
        scanner = DeviceScanner(_make_config())
        inv = MagicMock(spec=DeviceInventory)
        inv.enumerate_all.return_value = [
            _usb_device(name="SanDisk Cruzer", is_storage=True, vendor_id="0781"),
        ]
        scanner.set_inventory(inv)

        findings = scanner.scan()
        storage_findings = [f for f in findings if "Storage" in f.title or "storage" in f.title.lower()]
        assert len(storage_findings) >= 1
        assert any(f.severity in (Severity.MEDIUM, Severity.HIGH) for f in storage_findings)

    def test_many_usb_devices_warning(self):
        """Exceeding USB device count should produce a warning finding."""
        scanner = DeviceScanner(_make_config())
        scanner.set_policy(DevicePolicy(max_usb_devices=3))
        inv = MagicMock(spec=DeviceInventory)
        inv.enumerate_all.return_value = [
            _usb_device(name=f"USB Device {i}") for i in range(10)
        ]
        scanner.set_inventory(inv)

        findings = scanner.scan()
        excess = [f for f in findings if "Excessive" in f.title or "exceeds" in f.description.lower()]
        assert len(excess) >= 1

    def test_bluetooth_devices_detected(self):
        """Scanner should report Bluetooth devices."""
        scanner = DeviceScanner(_make_config())
        inv = MagicMock(spec=DeviceInventory)
        inv.enumerate_all.return_value = [
            _bt_device("AirPods Pro"),
            _bt_device("Magic Mouse"),
        ]
        scanner.set_inventory(inv)

        findings = scanner.scan()
        bt_findings = [f for f in findings if f.category == "Bluetooth Security"]
        assert len(bt_findings) >= 1
        assert any("Bluetooth" in f.title for f in bt_findings)

    def test_policy_violation_blocked_vendor(self):
        """Devices from blocked vendors should produce HIGH findings."""
        scanner = DeviceScanner(_make_config())
        scanner.set_policy(DevicePolicy(blocked_usb_vendors=["DEAD"]))
        inv = MagicMock(spec=DeviceInventory)
        inv.enumerate_all.return_value = [
            _usb_device(name="Suspicious Device", vendor_id="DEAD"),
        ]
        scanner.set_inventory(inv)

        findings = scanner.scan()
        violations = [f for f in findings if "Policy Violation" in f.title]
        assert len(violations) >= 1
        assert violations[0].severity == Severity.HIGH

    def test_mixed_devices(self):
        """Scanner should handle a mix of USB and Bluetooth devices."""
        scanner = DeviceScanner(_make_config())
        inv = MagicMock(spec=DeviceInventory)
        inv.enumerate_all.return_value = [
            _usb_device(name="Keyboard", vendor_id="046D"),
            _usb_device(name="Flash Drive", vendor_id="0781", is_storage=True),
            _bt_device("Headphones"),
        ]
        scanner.set_inventory(inv)

        findings = scanner.scan()
        # At minimum: inventory + storage + bluetooth
        assert len(findings) >= 3
        categories = {f.category for f in findings}
        assert "Device Security" in categories
        assert "USB Security" in categories
        assert "Bluetooth Security" in categories


# ── DeviceInventory methods ─────────────────────────────────────────


class TestDeviceInventory:
    def test_enumerate_usb_returns_list(self):
        """enumerate_usb should return a list even on error."""
        inv = DeviceInventory()
        with patch("scanners.device_inventory.subprocess.run", side_effect=FileNotFoundError):
            result = inv.enumerate_usb()
        assert isinstance(result, list)

    def test_enumerate_bluetooth_returns_list(self):
        """enumerate_bluetooth should return a list even on error."""
        inv = DeviceInventory()
        with patch("scanners.device_inventory.subprocess.run", side_effect=FileNotFoundError):
            result = inv.enumerate_bluetooth()
        assert isinstance(result, list)

    def test_enumerate_all_returns_list(self):
        """enumerate_all should combine USB and Bluetooth."""
        inv = DeviceInventory()
        with patch.object(inv, "enumerate_usb", return_value=[_usb_device()]):
            with patch.object(inv, "enumerate_bluetooth", return_value=[_bt_device()]):
                result = inv.enumerate_all()
        assert len(result) == 2
        assert result[0].device_type == "usb"
        assert result[1].device_type == "bluetooth"

    @patch("scanners.device_inventory.platform.system", return_value="Windows")
    @patch("scanners.device_inventory.subprocess.run")
    def test_windows_usb_parsing(self, mock_run, mock_system):
        """Should parse Windows USB PowerShell output."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps([
                {
                    "FriendlyName": "USB Mass Storage Device",
                    "InstanceId": "USB\\VID_0781&PID_5583\\12345",
                    "Status": "OK",
                },
                {
                    "FriendlyName": "USB Composite Device",
                    "InstanceId": "USB\\VID_046D&PID_C534\\67890",
                    "Status": "OK",
                },
            ]),
        )
        inv = DeviceInventory()
        inv._platform = "windows"
        devices = inv.enumerate_usb()
        assert len(devices) == 2
        assert devices[0].name == "USB Mass Storage Device"
        assert devices[0].vendor_id == "0781"
        assert devices[0].product_id == "5583"
        assert devices[0].is_storage is True  # "mass storage" keyword
        assert devices[1].vendor_id == "046D"

    @patch("scanners.device_inventory.platform.system", return_value="Linux")
    @patch("scanners.device_inventory.subprocess.run")
    @patch("scanners.device_inventory.Path.exists", return_value=False)
    def test_linux_lsusb_parsing(self, mock_exists, mock_run, mock_system):
        """Should parse lsusb output on Linux."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub\n"
                "Bus 001 Device 003: ID 0781:5583 SanDisk Corp. Ultra Fit\n"
            ),
        )
        inv = DeviceInventory()
        inv._platform = "linux"
        devices = inv.enumerate_usb()
        assert len(devices) == 2
        assert devices[0].vendor_id == "1d6b"
        assert devices[0].product_id == "0002"
        assert devices[1].vendor_id == "0781"
        assert devices[1].product_id == "5583"

    @patch("scanners.device_inventory.platform.system", return_value="Windows")
    @patch("scanners.device_inventory.subprocess.run")
    def test_windows_bluetooth_parsing(self, mock_run, mock_system):
        """Should parse Windows Bluetooth PowerShell output."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps([
                {
                    "FriendlyName": "AirPods Pro",
                    "InstanceId": "BTHENUM\\{0000-0000}",
                    "Status": "OK",
                },
            ]),
        )
        inv = DeviceInventory()
        inv._platform = "windows"
        devices = inv.enumerate_bluetooth()
        assert len(devices) == 1
        assert devices[0].name == "AirPods Pro"
        assert devices[0].device_type == "bluetooth"
        assert devices[0].is_wireless is True

    @patch("scanners.device_inventory.platform.system", return_value="Linux")
    @patch("scanners.device_inventory.subprocess.run")
    def test_linux_bluetooth_parsing(self, mock_run, mock_system):
        """Should parse bluetoothctl output on Linux."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=(
                "Device AA:BB:CC:DD:EE:FF My Headphones\n"
                "Device 11:22:33:44:55:66 BT Keyboard\n"
            ),
        )
        inv = DeviceInventory()
        inv._platform = "linux"
        devices = inv.enumerate_bluetooth()
        assert len(devices) == 2
        assert devices[0].name == "My Headphones"
        assert devices[0].serial == "AA:BB:CC:DD:EE:FF"
        assert devices[1].name == "BT Keyboard"

    def test_parse_vid_pid(self):
        """Should extract VID/PID from Windows InstanceId."""
        vid, pid = DeviceInventory._parse_vid_pid("USB\\VID_0781&PID_5583\\12345")
        assert vid == "0781"
        assert pid == "5583"

    def test_parse_vid_pid_missing(self):
        """Should return empty strings for missing VID/PID."""
        vid, pid = DeviceInventory._parse_vid_pid("SOME\\RANDOM\\ID")
        assert vid == ""
        assert pid == ""

    def test_parse_lsusb_line(self):
        """Should parse a standard lsusb output line."""
        line = "Bus 001 Device 003: ID 0781:5583 SanDisk Corp. Ultra Fit"
        dev = DeviceInventory._parse_lsusb_line(line)
        assert dev.vendor_id == "0781"
        assert dev.product_id == "5583"
        assert "SanDisk" in dev.name
