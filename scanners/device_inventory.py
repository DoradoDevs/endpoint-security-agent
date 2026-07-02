"""
Sentinel Agent — Device Inventory

Cross-platform enumeration for USB, Bluetooth, and PCI devices.
Uses native OS tools to discover connected peripherals without
installing additional drivers or agents.
"""

from __future__ import annotations

import json
import platform
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.logging import get_logger

log = get_logger()


@dataclass
class DeviceInfo:
    """Represents a single discovered hardware device."""

    name: str
    device_type: str  # usb, bluetooth, pci
    vendor: str = ""
    vendor_id: str = ""
    product_id: str = ""
    serial: str = ""
    is_removable: bool = False
    is_storage: bool = False
    is_wireless: bool = False
    bus: str = ""
    status: str = "connected"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "device_type": self.device_type,
            "vendor": self.vendor,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "serial": self.serial,
            "is_removable": self.is_removable,
            "is_storage": self.is_storage,
            "is_wireless": self.is_wireless,
            "bus": self.bus,
            "status": self.status,
        }


class DeviceInventory:
    """Cross-platform device enumeration."""

    def __init__(self) -> None:
        self._platform = platform.system().lower()

    # ── USB enumeration ─────────────────────────────────────────────

    def enumerate_usb(self) -> list[DeviceInfo]:
        """List USB devices using OS-native tools."""
        if self._platform == "windows":
            return self._enumerate_usb_windows()
        elif self._platform == "darwin":
            return self._enumerate_usb_macos()
        else:
            return self._enumerate_usb_linux()

    def _enumerate_usb_windows(self) -> list[DeviceInfo]:
        """Enumerate USB devices on Windows via Get-PnpDevice."""
        devices: list[DeviceInfo] = []
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    "Get-PnpDevice -Class USB -Status OK "
                    "| Select-Object FriendlyName,InstanceId,Status "
                    "| ConvertTo-Json -Compress",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return devices

            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]

            for item in data:
                name = item.get("FriendlyName", "Unknown USB Device")
                instance_id = item.get("InstanceId", "")
                vid, pid = self._parse_vid_pid(instance_id)
                is_storage = any(
                    kw in name.lower()
                    for kw in ("mass storage", "disk", "flash", "thumb")
                )
                devices.append(DeviceInfo(
                    name=name,
                    device_type="usb",
                    vendor_id=vid,
                    product_id=pid,
                    is_removable=True,
                    is_storage=is_storage,
                    bus="USB",
                    status=item.get("Status", "connected"),
                ))
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as exc:
            log.debug(f"USB enumeration failed (Windows): {exc}")
        except Exception as exc:
            log.debug(f"USB enumeration unexpected error (Windows): {exc}")
        return devices

    def _enumerate_usb_macos(self) -> list[DeviceInfo]:
        """Enumerate USB devices on macOS via system_profiler."""
        devices: list[DeviceInfo] = []
        try:
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return devices

            data = json.loads(result.stdout)
            usb_items = data.get("SPUSBDataType", [])
            self._parse_macos_usb_tree(usb_items, devices)
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as exc:
            log.debug(f"USB enumeration failed (macOS): {exc}")
        except Exception as exc:
            log.debug(f"USB enumeration unexpected error (macOS): {exc}")
        return devices

    def _parse_macos_usb_tree(
        self, items: list[dict], out: list[DeviceInfo]
    ) -> None:
        """Recursively walk the macOS system_profiler USB tree."""
        for item in items:
            name = item.get("_name", "Unknown USB Device")
            vid = item.get("vendor_id", "")
            pid = item.get("product_id", "")
            serial = item.get("serial_num", "")
            is_storage = "storage" in name.lower() or "disk" in name.lower()
            out.append(DeviceInfo(
                name=name,
                device_type="usb",
                vendor=item.get("manufacturer", ""),
                vendor_id=str(vid),
                product_id=str(pid),
                serial=serial,
                is_removable=True,
                is_storage=is_storage,
                bus="USB",
            ))
            # Recurse into child hubs / devices
            for key in item:
                if isinstance(item[key], list):
                    self._parse_macos_usb_tree(item[key], out)

    def _enumerate_usb_linux(self) -> list[DeviceInfo]:
        """Enumerate USB devices on Linux via /sys or lsusb."""
        devices: list[DeviceInfo] = []
        sys_path = Path("/sys/bus/usb/devices")
        if sys_path.exists():
            return self._enumerate_usb_linux_sysfs(sys_path)

        # Fallback: lsusb
        try:
            result = subprocess.run(
                ["lsusb"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    devices.append(self._parse_lsusb_line(line))
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            log.debug(f"USB enumeration failed (Linux lsusb): {exc}")
        except Exception as exc:
            log.debug(f"USB enumeration unexpected error (Linux): {exc}")
        return devices

    def _enumerate_usb_linux_sysfs(self, sys_path: Path) -> list[DeviceInfo]:
        """Read USB devices from /sys/bus/usb/devices."""
        devices: list[DeviceInfo] = []
        try:
            for entry in sys_path.iterdir():
                product_file = entry / "product"
                if not product_file.exists():
                    continue
                name = product_file.read_text(errors="replace").strip()
                vid = (entry / "idVendor").read_text(errors="replace").strip() if (entry / "idVendor").exists() else ""
                pid = (entry / "idProduct").read_text(errors="replace").strip() if (entry / "idProduct").exists() else ""
                serial = (entry / "serial").read_text(errors="replace").strip() if (entry / "serial").exists() else ""
                manufacturer = (entry / "manufacturer").read_text(errors="replace").strip() if (entry / "manufacturer").exists() else ""
                is_storage = "storage" in name.lower()
                removable_file = entry / "removable"
                is_removable = False
                if removable_file.exists():
                    is_removable = removable_file.read_text(errors="replace").strip().lower() == "removable"
                devices.append(DeviceInfo(
                    name=name,
                    device_type="usb",
                    vendor=manufacturer,
                    vendor_id=vid,
                    product_id=pid,
                    serial=serial,
                    is_removable=is_removable,
                    is_storage=is_storage,
                    bus="USB",
                ))
        except OSError as exc:
            log.debug(f"Sysfs USB enumeration error: {exc}")
        return devices

    @staticmethod
    def _parse_lsusb_line(line: str) -> DeviceInfo:
        """Parse a single lsusb output line."""
        # Format: Bus 001 Device 002: ID 1234:5678 Device Name
        parts = line.split("ID ")
        vid, pid, name = "", "", line
        if len(parts) == 2:
            id_and_name = parts[1]
            id_part = id_and_name.split(" ", 1)
            if ":" in id_part[0]:
                vid, pid = id_part[0].split(":", 1)
            name = id_part[1] if len(id_part) > 1 else "Unknown USB Device"
        return DeviceInfo(
            name=name.strip(),
            device_type="usb",
            vendor_id=vid,
            product_id=pid,
            is_removable=True,
            bus="USB",
        )

    @staticmethod
    def _parse_vid_pid(instance_id: str) -> tuple[str, str]:
        """Extract VID/PID from a Windows PnP InstanceId like USB\\VID_1234&PID_5678\\..."""
        vid, pid = "", ""
        upper = instance_id.upper()
        if "VID_" in upper:
            start = upper.index("VID_") + 4
            vid = upper[start : start + 4]
        if "PID_" in upper:
            start = upper.index("PID_") + 4
            pid = upper[start : start + 4]
        return vid, pid

    # ── Bluetooth enumeration ───────────────────────────────────────

    def enumerate_bluetooth(self) -> list[DeviceInfo]:
        """List Bluetooth devices using OS-native tools."""
        if self._platform == "windows":
            return self._enumerate_bt_windows()
        elif self._platform == "darwin":
            return self._enumerate_bt_macos()
        else:
            return self._enumerate_bt_linux()

    def _enumerate_bt_windows(self) -> list[DeviceInfo]:
        """Enumerate Bluetooth devices on Windows."""
        devices: list[DeviceInfo] = []
        try:
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    "Get-PnpDevice -Class Bluetooth -Status OK "
                    "| Select-Object FriendlyName,InstanceId,Status "
                    "| ConvertTo-Json -Compress",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return devices

            data = json.loads(result.stdout)
            if isinstance(data, dict):
                data = [data]

            for item in data:
                name = item.get("FriendlyName", "Unknown Bluetooth Device")
                devices.append(DeviceInfo(
                    name=name,
                    device_type="bluetooth",
                    is_wireless=True,
                    bus="Bluetooth",
                    status=item.get("Status", "connected"),
                ))
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as exc:
            log.debug(f"Bluetooth enumeration failed (Windows): {exc}")
        except Exception as exc:
            log.debug(f"Bluetooth enumeration unexpected error (Windows): {exc}")
        return devices

    def _enumerate_bt_macos(self) -> list[DeviceInfo]:
        """Enumerate Bluetooth devices on macOS."""
        devices: list[DeviceInfo] = []
        try:
            result = subprocess.run(
                ["system_profiler", "SPBluetoothDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return devices

            data = json.loads(result.stdout)
            bt_data = data.get("SPBluetoothDataType", [])
            for section in bt_data:
                connected = section.get("device_connected", [])
                for dev_group in connected:
                    if isinstance(dev_group, dict):
                        for dev_name, dev_info in dev_group.items():
                            devices.append(DeviceInfo(
                                name=dev_name,
                                device_type="bluetooth",
                                vendor=dev_info.get("device_manufacturer", ""),
                                is_wireless=True,
                                bus="Bluetooth",
                            ))
        except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as exc:
            log.debug(f"Bluetooth enumeration failed (macOS): {exc}")
        except Exception as exc:
            log.debug(f"Bluetooth enumeration unexpected error (macOS): {exc}")
        return devices

    def _enumerate_bt_linux(self) -> list[DeviceInfo]:
        """Enumerate Bluetooth devices on Linux via bluetoothctl."""
        devices: list[DeviceInfo] = []
        try:
            result = subprocess.run(
                ["bluetoothctl", "devices"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                for line in result.stdout.strip().splitlines():
                    # Format: Device AA:BB:CC:DD:EE:FF DeviceName
                    parts = line.split(" ", 2)
                    if len(parts) >= 3 and parts[0] == "Device":
                        devices.append(DeviceInfo(
                            name=parts[2],
                            device_type="bluetooth",
                            serial=parts[1],  # MAC address
                            is_wireless=True,
                            bus="Bluetooth",
                        ))
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            log.debug(f"Bluetooth enumeration failed (Linux): {exc}")
        except Exception as exc:
            log.debug(f"Bluetooth enumeration unexpected error (Linux): {exc}")
        return devices

    # ── Aggregate ───────────────────────────────────────────────────

    def enumerate_all(self) -> list[DeviceInfo]:
        """Get all connected USB and Bluetooth devices."""
        devices: list[DeviceInfo] = []
        devices.extend(self.enumerate_usb())
        devices.extend(self.enumerate_bluetooth())
        return devices
