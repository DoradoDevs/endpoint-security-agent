"""
Sentinel Agent — Device Control

Monitors USB device connections and enforces policies.
"""

from __future__ import annotations

import json
import platform
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from core.config import AgentConfig
from core.logging import get_logger
from edr.event_types import EDREvent, EDREventType


class USBDeviceClass(str, Enum):
    STORAGE = "storage"
    HID = "hid"
    NETWORK = "network"
    AUDIO = "audio"
    UNKNOWN = "unknown"


@dataclass
class USBDevice:
    device_id: str
    name: str
    device_class: USBDeviceClass
    vendor_id: str = ""
    product_id: str = ""
    serial: str = ""
    detected_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "device_id": self.device_id,
            "name": self.name,
            "device_class": self.device_class.value,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial": self.serial,
            "detected_at": self.detected_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> USBDevice:
        return cls(
            device_id=data.get("device_id", ""),
            name=data.get("name", ""),
            device_class=USBDeviceClass(data.get("device_class", "unknown")),
            vendor_id=data.get("vendor_id", ""),
            product_id=data.get("product_id", ""),
            serial=data.get("serial", ""),
            detected_at=data.get("detected_at", ""),
        )


@dataclass
class DevicePolicy:
    default_action: str = "alert"  # allow, alert, block
    allow_hid: bool = True
    allow_storage: bool = True
    allow_network: bool = True
    allowed_device_ids: list[str] = field(default_factory=list)


class DeviceControlManager:
    """Monitors and controls USB device connections."""

    def __init__(self, config: AgentConfig | None = None, policy: DevicePolicy | None = None,
                 history_path: Path | None = None):
        self.config = config
        self.log = get_logger()
        self.policy = policy or DevicePolicy()
        self._known_devices: dict[str, USBDevice] = {}
        self._history: list[USBDevice] = []
        self._history_path = history_path or self._default_history_path()
        self._history_path.parent.mkdir(parents=True, exist_ok=True)
        self._on_event = None
        self._load_history()

    @staticmethod
    def _default_history_path() -> Path:
        system = platform.system().lower()
        if system == "windows":
            return Path.home() / "AppData" / "Local" / "Sentinel" / "devices" / "history.json"
        elif system == "darwin":
            return Path.home() / "Library" / "Application Support" / "Sentinel" / "devices" / "history.json"
        else:
            return Path.home() / ".sentinel" / "devices" / "history.json"

    def scan_devices(self) -> list[USBDevice]:
        """Scan for currently connected USB devices."""
        system = platform.system().lower()
        if system == "windows":
            return self._scan_windows()
        elif system == "linux":
            return self._scan_linux()
        elif system == "darwin":
            return self._scan_macos()
        return []

    def check_device(self, device: USBDevice) -> dict[str, Any]:
        """Check device against policy. Returns action dict."""
        result = {"device": device.to_dict(), "action": "allow", "reason": ""}

        # Check allowed device IDs
        if device.device_id in self.policy.allowed_device_ids:
            return result

        # Check by class
        if device.device_class == USBDeviceClass.HID and self.policy.allow_hid:
            return result
        if device.device_class == USBDeviceClass.STORAGE and self.policy.allow_storage:
            return result
        if device.device_class == USBDeviceClass.NETWORK and self.policy.allow_network:
            return result

        # Apply default action
        result["action"] = self.policy.default_action
        result["reason"] = f"Device class '{device.device_class.value}' not allowed by policy"

        return result

    def monitor(self, stop_event: threading.Event, on_event=None) -> None:
        """Monitor for USB device changes. Blocks until stop_event is set."""
        self._on_event = on_event
        self.log.info("[DeviceControl] Starting USB device monitoring")

        # Initial scan
        current_devices = self.scan_devices()
        for dev in current_devices:
            self._known_devices[dev.device_id] = dev

        while not stop_event.is_set():
            stop_event.wait(timeout=5.0)
            if stop_event.is_set():
                break

            new_devices = self.scan_devices()
            new_ids = {d.device_id for d in new_devices}
            known_ids = set(self._known_devices.keys())

            # New devices
            for dev in new_devices:
                if dev.device_id not in known_ids:
                    self._on_device_connected(dev)
                    self._known_devices[dev.device_id] = dev

            # Removed devices
            for dev_id in known_ids - new_ids:
                self._on_device_disconnected(dev_id)
                del self._known_devices[dev_id]

    def _on_device_connected(self, device: USBDevice) -> None:
        """Handle new device connection."""
        check = self.check_device(device)
        self._history.append(device)
        self._save_history()

        self.log.info(f"[DeviceControl] Device connected: {device.name} ({device.device_class.value}) — action: {check['action']}")

        if self._on_event:
            event = EDREvent(
                event_type=EDREventType.FILE_CREATE,  # Using as device event
                target=device.name,
                details={
                    "device_id": device.device_id,
                    "device_class": device.device_class.value,
                    "vendor_id": device.vendor_id,
                    "action": check["action"],
                },
                severity="info" if check["action"] == "allow" else "medium",
            )
            self._on_event(event)

    def _on_device_disconnected(self, device_id: str) -> None:
        """Handle device disconnection."""
        self.log.info(f"[DeviceControl] Device disconnected: {device_id}")

    def _scan_windows(self) -> list[USBDevice]:
        """Scan USB devices on Windows using WMI."""
        devices = []
        try:
            result = subprocess.run(
                ["wmic", "path", "Win32_USBControllerDevice", "get", "Dependent", "/format:list"],
                capture_output=True, text=True, timeout=10
            )
            # Parse output — simplified; real implementation would use WMI COM
            for line in result.stdout.strip().split('\n'):
                if "DeviceID" in line:
                    dev_id = line.split("=", 1)[-1].strip().strip('"')
                    devices.append(USBDevice(
                        device_id=dev_id,
                        name=dev_id.split("\\")[-1] if "\\" in dev_id else dev_id,
                        device_class=USBDeviceClass.UNKNOWN,
                    ))
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
            pass
        return devices

    def _scan_linux(self) -> list[USBDevice]:
        """Scan USB devices on Linux using /sys/bus/usb."""
        devices = []
        usb_path = Path("/sys/bus/usb/devices")
        if not usb_path.exists():
            return devices

        for dev_dir in usb_path.iterdir():
            try:
                product_file = dev_dir / "product"
                if product_file.exists():
                    name = product_file.read_text().strip()
                    vendor_id = ""
                    product_id = ""
                    vid_file = dev_dir / "idVendor"
                    pid_file = dev_dir / "idProduct"
                    if vid_file.exists():
                        vendor_id = vid_file.read_text().strip()
                    if pid_file.exists():
                        product_id = pid_file.read_text().strip()

                    # Determine class
                    class_file = dev_dir / "bDeviceClass"
                    dev_class = USBDeviceClass.UNKNOWN
                    if class_file.exists():
                        class_code = class_file.read_text().strip()
                        if class_code == "08":
                            dev_class = USBDeviceClass.STORAGE
                        elif class_code == "03":
                            dev_class = USBDeviceClass.HID

                    devices.append(USBDevice(
                        device_id=dev_dir.name,
                        name=name,
                        device_class=dev_class,
                        vendor_id=vendor_id,
                        product_id=product_id,
                    ))
            except (OSError, PermissionError):
                pass
        return devices

    def _scan_macos(self) -> list[USBDevice]:
        """Scan USB devices on macOS using system_profiler."""
        devices = []
        try:
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True, text=True, timeout=10
            )
            data = json.loads(result.stdout)
            for item in data.get("SPUSBDataType", []):
                name = item.get("_name", "Unknown")
                vendor_id = item.get("vendor_id", "")
                product_id = item.get("product_id", "")
                serial = item.get("serial_num", "")
                devices.append(USBDevice(
                    device_id=f"{vendor_id}:{product_id}",
                    name=name,
                    device_class=USBDeviceClass.UNKNOWN,
                    vendor_id=vendor_id,
                    product_id=product_id,
                    serial=serial,
                ))
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, Exception):
            pass
        return devices

    def _load_history(self) -> None:
        if self._history_path.exists():
            try:
                data = json.loads(self._history_path.read_text())
                self._history = [USBDevice.from_dict(d) for d in data.get("devices", [])]
            except (json.JSONDecodeError, KeyError):
                pass

    def _save_history(self) -> None:
        data = {"devices": [d.to_dict() for d in self._history[-100:]]}  # Keep last 100
        self._history_path.write_text(json.dumps(data, indent=2))

    def get_history(self) -> list[USBDevice]:
        return list(self._history)

    def get_status(self) -> dict:
        return {
            "known_devices": len(self._known_devices),
            "history_count": len(self._history),
            "policy": {
                "default_action": self.policy.default_action,
                "allow_hid": self.policy.allow_hid,
                "allow_storage": self.policy.allow_storage,
            },
        }
