"""
Sentinel Agent — SSL/TLS Certificate Analyzer

Validates SSL certificates, cipher suites, and protocol versions.
Flags weak ciphers, expired certs, self-signed certs, and deprecated protocols.
"""

from __future__ import annotations

import ssl
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from core.logging import get_logger


WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon",
}

DEPRECATED_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


@dataclass
class SSLResult:
    """Result of an SSL/TLS analysis."""

    host: str
    port: int
    subject: dict[str, str] = field(default_factory=dict)
    issuer: dict[str, str] = field(default_factory=dict)
    version: str = ""
    serial_number: str = ""
    not_before: str = ""
    not_after: str = ""
    days_until_expiry: int = 0
    is_expired: bool = False
    is_self_signed: bool = False
    protocol_version: str = ""
    cipher_name: str = ""
    cipher_bits: int = 0
    weak_cipher: bool = False
    issues: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "subject": self.subject,
            "issuer": self.issuer,
            "not_after": self.not_after,
            "days_until_expiry": self.days_until_expiry,
            "is_expired": self.is_expired,
            "is_self_signed": self.is_self_signed,
            "protocol_version": self.protocol_version,
            "cipher_name": self.cipher_name,
            "cipher_bits": self.cipher_bits,
            "weak_cipher": self.weak_cipher,
            "issues": self.issues,
        }


class SSLAnalyzer:
    """Analyzes SSL/TLS certificates and configurations."""

    def __init__(self) -> None:
        self.log = get_logger()

    def analyze(self, host: str, port: int = 443, timeout: float = 5.0) -> SSLResult:
        """Perform SSL/TLS analysis on a host:port."""
        result = SSLResult(host=host, port=port)

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher_info = ssock.cipher()
                    protocol = ssock.version()

                    if cipher_info:
                        result.cipher_name = cipher_info[0]
                        result.protocol_version = cipher_info[1]
                        result.cipher_bits = cipher_info[2] if len(cipher_info) > 2 else 0

                    if protocol:
                        result.protocol_version = protocol

                    # Try to get cert with verification for self-signed check
                    try:
                        verify_ctx = ssl.create_default_context()
                        with socket.create_connection((host, port), timeout=timeout) as vsock:
                            with verify_ctx.wrap_socket(vsock, server_hostname=host) as vssock:
                                cert = vssock.getpeercert()
                    except ssl.SSLCertVerificationError:
                        result.is_self_signed = True
                        result.issues.append("Self-signed or untrusted certificate")
                    except Exception:
                        pass

                    if cert:
                        self._parse_cert(cert, result)

                    self._check_cipher(result)
                    self._check_protocol(result)

        except socket.timeout:
            result.issues.append(f"Connection timed out ({timeout}s)")
        except ConnectionRefusedError:
            result.issues.append("Connection refused")
        except ssl.SSLError as e:
            result.issues.append(f"SSL error: {e}")
        except OSError as e:
            result.issues.append(f"Connection error: {e}")

        return result

    def _parse_cert(self, cert: dict, result: SSLResult) -> None:
        """Parse certificate details."""
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        result.subject = subject
        result.issuer = issuer

        not_after = cert.get("notAfter", "")
        not_before = cert.get("notBefore", "")
        result.not_after = not_after
        result.not_before = not_before

        if not_after:
            try:
                expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                expiry = expiry.replace(tzinfo=timezone.utc)
                now = datetime.now(timezone.utc)
                delta = expiry - now
                result.days_until_expiry = delta.days

                if delta.days < 0:
                    result.is_expired = True
                    result.issues.append(f"Certificate expired {abs(delta.days)} days ago")
                elif delta.days < 30:
                    result.issues.append(f"Certificate expires in {delta.days} days")
            except ValueError:
                pass

        # Check self-signed
        if subject == issuer:
            result.is_self_signed = True
            if "Self-signed" not in " ".join(result.issues):
                result.issues.append("Self-signed certificate")

    def _check_cipher(self, result: SSLResult) -> None:
        """Check for weak ciphers."""
        cipher = result.cipher_name.upper()
        for weak in WEAK_CIPHERS:
            if weak.upper() in cipher:
                result.weak_cipher = True
                result.issues.append(f"Weak cipher: {result.cipher_name}")
                break

        if result.cipher_bits > 0 and result.cipher_bits < 128:
            result.weak_cipher = True
            result.issues.append(f"Weak cipher strength: {result.cipher_bits} bits")

    def _check_protocol(self, result: SSLResult) -> None:
        """Check for deprecated protocol versions."""
        proto = result.protocol_version
        if proto in DEPRECATED_PROTOCOLS:
            result.issues.append(f"Deprecated protocol: {proto}")
