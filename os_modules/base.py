"""
Sentinel Agent — Base OS Module

Abstract interface that all platform-specific modules must implement.
This ensures consistent capability across platforms while allowing
each OS module to use native APIs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FirewallStatus:
    enabled: bool = False
    details: str = ""
    rules_count: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class EncryptionStatus:
    enabled: bool = False
    method: str = ""
    details: str = ""


@dataclass
class UpdateStatus:
    auto_updates_enabled: bool = False
    pending_updates: int = 0
    last_check: str = ""
    details: str = ""


@dataclass
class SecureBootStatus:
    supported: bool = False
    enabled: bool = False
    details: str = ""


@dataclass
class StartupEntry:
    name: str
    command: str
    location: str
    enabled: bool = True
    user: str = ""
    suspicious: bool = False
    reason: str = ""


@dataclass
class ServiceInfo:
    name: str
    display_name: str
    status: str
    start_type: str
    pid: int = 0
    user: str = ""


class BaseOSModule(ABC):
    """Abstract base for OS-specific security interrogation."""

    @property
    @abstractmethod
    def platform_name(self) -> str:
        ...

    @abstractmethod
    def get_firewall_status(self) -> FirewallStatus:
        ...

    @abstractmethod
    def get_encryption_status(self) -> EncryptionStatus:
        ...

    @abstractmethod
    def get_update_status(self) -> UpdateStatus:
        ...

    @abstractmethod
    def get_secure_boot_status(self) -> SecureBootStatus:
        ...

    @abstractmethod
    def get_startup_entries(self) -> list[StartupEntry]:
        ...

    @abstractmethod
    def get_running_services(self) -> list[ServiceInfo]:
        ...

    @abstractmethod
    def get_admin_users(self) -> list[str]:
        ...

    @abstractmethod
    def get_password_policy(self) -> dict[str, Any]:
        ...

    @abstractmethod
    def get_os_patch_level(self) -> dict[str, Any]:
        ...
