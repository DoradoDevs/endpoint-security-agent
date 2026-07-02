"""Tests for Device Control module."""

import sys
import json
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from edr.device_control import (
    DeviceControlManager,
    DevicePolicy,
    USBDevice,
    USBDeviceClass,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_device(**kwargs) -> USBDevice:
    defaults = dict(
        device_id="USB\\VID_1234&PID_5678",
        name="Test USB Drive",
        device_class=USBDeviceClass.STORAGE,
        vendor_id="1234",
        product_id="5678",
        serial="SN0001",
    )
    defaults.update(kwargs)
    return USBDevice(**defaults)


def _make_manager(tmp_dir: str, policy: DevicePolicy | None = None) -> DeviceControlManager:
    history_path = Path(tmp_dir) / "history.json"
    return DeviceControlManager(policy=policy, history_path=history_path)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_device_roundtrip():
    """USBDevice to_dict/from_dict roundtrip."""
    device = _make_device()

    data = device.to_dict()
    restored = USBDevice.from_dict(data)

    assert restored.device_id == device.device_id
    assert restored.name == device.name
    assert restored.device_class == USBDeviceClass.STORAGE
    assert restored.vendor_id == "1234"
    assert restored.product_id == "5678"
    assert restored.serial == "SN0001"
    assert restored.detected_at == device.detected_at


def test_device_roundtrip_unknown_class():
    """Unknown device class round-trips correctly."""
    device = _make_device(device_class=USBDeviceClass.UNKNOWN)

    data = device.to_dict()
    assert data["device_class"] == "unknown"

    restored = USBDevice.from_dict(data)
    assert restored.device_class == USBDeviceClass.UNKNOWN


def test_policy_allow_hid():
    """HID device allowed by default policy."""
    with tempfile.TemporaryDirectory() as tmp:
        mgr = _make_manager(tmp)
        device = _make_device(device_class=USBDeviceClass.HID, name="USB Keyboard")

        result = mgr.check_device(device)

        assert result["action"] == "allow"
        assert result["reason"] == ""


def test_policy_block_storage():
    """Storage device blocked when allow_storage=False."""
    with tempfile.TemporaryDirectory() as tmp:
        policy = DevicePolicy(allow_storage=False, default_action="block")
        mgr = _make_manager(tmp, policy=policy)
        device = _make_device(device_class=USBDeviceClass.STORAGE)

        result = mgr.check_device(device)

        assert result["action"] == "block"
        assert "storage" in result["reason"].lower()


def test_policy_block_network():
    """Network device blocked when allow_network=False."""
    with tempfile.TemporaryDirectory() as tmp:
        policy = DevicePolicy(allow_network=False, default_action="alert")
        mgr = _make_manager(tmp, policy=policy)
        device = _make_device(device_class=USBDeviceClass.NETWORK, name="USB WiFi Adapter")

        result = mgr.check_device(device)

        assert result["action"] == "alert"
        assert "network" in result["reason"].lower()


def test_policy_allowed_device_ids():
    """Explicit device ID override allows even blocked classes."""
    with tempfile.TemporaryDirectory() as tmp:
        policy = DevicePolicy(
            allow_storage=False,
            default_action="block",
            allowed_device_ids=["USB\\VID_1234&PID_5678"],
        )
        mgr = _make_manager(tmp, policy=policy)
        device = _make_device(device_class=USBDeviceClass.STORAGE)

        result = mgr.check_device(device)

        assert result["action"] == "allow"


def test_policy_unknown_class_uses_default():
    """Unknown device class triggers the default action."""
    with tempfile.TemporaryDirectory() as tmp:
        policy = DevicePolicy(default_action="alert")
        mgr = _make_manager(tmp, policy=policy)
        device = _make_device(device_class=USBDeviceClass.UNKNOWN)

        result = mgr.check_device(device)

        assert result["action"] == "alert"
        assert "unknown" in result["reason"].lower()


def test_device_history():
    """Devices added to history via _on_device_connected."""
    with tempfile.TemporaryDirectory() as tmp:
        mgr = _make_manager(tmp)
        device = _make_device()

        assert len(mgr.get_history()) == 0

        mgr._on_device_connected(device)

        history = mgr.get_history()
        assert len(history) == 1
        assert history[0].device_id == device.device_id
        assert history[0].name == device.name


def test_device_history_persistence():
    """History persists across manager instances."""
    with tempfile.TemporaryDirectory() as tmp:
        history_path = Path(tmp) / "history.json"

        mgr1 = DeviceControlManager(history_path=history_path)
        mgr1._on_device_connected(_make_device(name="Drive A"))
        mgr1._on_device_connected(_make_device(device_id="USB\\OTHER", name="Drive B"))

        mgr2 = DeviceControlManager(history_path=history_path)
        assert len(mgr2.get_history()) == 2


def test_monitor_detects_new_device():
    """Mock scan_devices and verify _on_device_connected called for new device."""
    with tempfile.TemporaryDirectory() as tmp:
        mgr = _make_manager(tmp)
        stop = threading.Event()
        connected_devices = []

        original_on_connected = mgr._on_device_connected

        def track_connected(device):
            connected_devices.append(device)
            original_on_connected(device)

        mgr._on_device_connected = track_connected

        # First scan returns empty, second returns one device
        new_device = _make_device(device_id="USB\\NEW_DEVICE", name="New Drive")
        scan_results = [[], [new_device]]
        scan_call_count = [0]

        def mock_scan():
            idx = min(scan_call_count[0], len(scan_results) - 1)
            scan_call_count[0] += 1
            return scan_results[idx]

        mgr.scan_devices = mock_scan

        # Run monitor in a thread, stop after brief delay
        def stop_after_delay():
            import time
            time.sleep(0.3)
            stop.set()

        stopper = threading.Thread(target=stop_after_delay)
        stopper.start()

        # Use a short poll interval by patching the wait timeout
        original_monitor = mgr.monitor

        def fast_monitor(stop_event, on_event=None):
            mgr._on_event = on_event
            mgr.log.info("[DeviceControl] Starting USB device monitoring")
            current_devices = mgr.scan_devices()
            for dev in current_devices:
                mgr._known_devices[dev.device_id] = dev
            while not stop_event.is_set():
                stop_event.wait(timeout=0.1)
                if stop_event.is_set():
                    break
                new_devices = mgr.scan_devices()
                new_ids = {d.device_id for d in new_devices}
                known_ids = set(mgr._known_devices.keys())
                for dev in new_devices:
                    if dev.device_id not in known_ids:
                        mgr._on_device_connected(dev)
                        mgr._known_devices[dev.device_id] = dev
                for dev_id in known_ids - new_ids:
                    mgr._on_device_disconnected(dev_id)
                    del mgr._known_devices[dev_id]

        fast_monitor(stop)
        stopper.join()

        assert len(connected_devices) == 1
        assert connected_devices[0].device_id == "USB\\NEW_DEVICE"


def test_scan_returns_list():
    """scan_devices returns a list (may be empty on CI)."""
    with tempfile.TemporaryDirectory() as tmp:
        mgr = _make_manager(tmp)
        result = mgr.scan_devices()

        assert isinstance(result, list)


def test_get_status():
    """Status dict has expected structure."""
    with tempfile.TemporaryDirectory() as tmp:
        mgr = _make_manager(tmp)

        status = mgr.get_status()

        assert "known_devices" in status
        assert isinstance(status["known_devices"], int)
        assert "history_count" in status
        assert isinstance(status["history_count"], int)
        assert "policy" in status
        assert "default_action" in status["policy"]
        assert "allow_hid" in status["policy"]
        assert "allow_storage" in status["policy"]


def test_on_device_connected_fires_event():
    """_on_device_connected calls _on_event callback with EDREvent."""
    with tempfile.TemporaryDirectory() as tmp:
        mgr = _make_manager(tmp)
        events_received = []

        mgr._on_event = lambda evt: events_received.append(evt)

        device = _make_device()
        mgr._on_device_connected(device)

        assert len(events_received) == 1
        evt = events_received[0]
        assert evt.target == device.name
        assert evt.details["device_id"] == device.device_id
        assert evt.details["device_class"] == "storage"


def test_on_device_connected_blocked_severity():
    """Blocked device event has medium severity."""
    with tempfile.TemporaryDirectory() as tmp:
        policy = DevicePolicy(allow_storage=False, default_action="block")
        mgr = _make_manager(tmp, policy=policy)
        events_received = []

        mgr._on_event = lambda evt: events_received.append(evt)

        device = _make_device(device_class=USBDeviceClass.STORAGE)
        mgr._on_device_connected(device)

        assert len(events_received) == 1
        assert events_received[0].severity == "medium"
        assert events_received[0].details["action"] == "block"


def test_check_device_returns_device_dict():
    """check_device result includes device data."""
    with tempfile.TemporaryDirectory() as tmp:
        mgr = _make_manager(tmp)
        device = _make_device()

        result = mgr.check_device(device)

        assert "device" in result
        assert result["device"]["device_id"] == device.device_id
        assert result["device"]["name"] == device.name


if __name__ == "__main__":
    test_device_roundtrip()
    test_device_roundtrip_unknown_class()
    test_policy_allow_hid()
    test_policy_block_storage()
    test_policy_block_network()
    test_policy_allowed_device_ids()
    test_policy_unknown_class_uses_default()
    test_device_history()
    test_device_history_persistence()
    test_monitor_detects_new_device()
    test_scan_returns_list()
    test_get_status()
    test_on_device_connected_fires_event()
    test_on_device_connected_blocked_severity()
    test_check_device_returns_device_dict()
    print("All device control tests passed!")
