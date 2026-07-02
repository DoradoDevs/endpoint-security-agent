"""
Sentinel Agent — Windows Service Installer

Installs Sentinel as a Windows Service using sc.exe (no extra dependencies).

Usage:
    python install_windows_service.py install     Install the service
    python install_windows_service.py uninstall   Remove the service
    python install_windows_service.py start       Start the service
    python install_windows_service.py stop        Stop the service
    python install_windows_service.py status      Check service status

Requires: Administrator privileges
"""

from __future__ import annotations

import subprocess
import sys

SERVICE_NAME = "SentinelAgent"
SERVICE_DISPLAY = "Sentinel Security Agent"
SERVICE_DESC = "Continuous security monitoring and hardening for Windows"


def _run(args: list[str], check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    if check and result.returncode != 0:
        print(f"Error: {result.stderr.strip() or result.stdout.strip()}")
    return result


def _find_sentinel_exe() -> str:
    """Locate the Sentinel executable."""
    import shutil
    exe = shutil.which("sentinel")
    if exe:
        return exe

    # Check common install locations
    from pathlib import Path
    candidates = [
        Path(r"C:\Program Files\Sentinel\sentinel.exe"),
        Path(r"C:\Program Files (x86)\Sentinel\sentinel.exe"),
        Path.home() / "AppData" / "Local" / "Sentinel" / "sentinel.exe",
    ]
    for p in candidates:
        if p.exists():
            return str(p)

    print("Error: Could not find sentinel executable.")
    print("Ensure Sentinel is installed and on PATH, or specify the path manually.")
    sys.exit(1)


def install() -> None:
    """Install Sentinel as a Windows Service."""
    exe = _find_sentinel_exe()
    binpath = f'"{exe}" --daemon --profile standard'

    print(f"Installing service '{SERVICE_NAME}'...")
    result = _run([
        "sc.exe", "create", SERVICE_NAME,
        f"binPath={binpath}",
        f"DisplayName={SERVICE_DISPLAY}",
        "start=auto",
    ])
    if result.returncode == 0:
        # Set description
        _run(["sc.exe", "description", SERVICE_NAME, SERVICE_DESC], check=False)
        # Configure recovery: restart after 30 seconds on failure
        _run([
            "sc.exe", "failure", SERVICE_NAME,
            "reset=86400", "actions=restart/30000/restart/60000/restart/120000",
        ], check=False)
        print(f"Service '{SERVICE_NAME}' installed successfully.")
        print(f"Start with: sc.exe start {SERVICE_NAME}")
    else:
        print("Service installation failed. Are you running as Administrator?")


def uninstall() -> None:
    """Remove the Sentinel Windows Service."""
    print(f"Stopping service '{SERVICE_NAME}'...")
    _run(["sc.exe", "stop", SERVICE_NAME], check=False)

    print(f"Removing service '{SERVICE_NAME}'...")
    result = _run(["sc.exe", "delete", SERVICE_NAME])
    if result.returncode == 0:
        print(f"Service '{SERVICE_NAME}' removed.")
    else:
        print("Service removal failed. Are you running as Administrator?")


def start() -> None:
    """Start the Sentinel service."""
    result = _run(["sc.exe", "start", SERVICE_NAME])
    if result.returncode == 0:
        print(f"Service '{SERVICE_NAME}' started.")


def stop() -> None:
    """Stop the Sentinel service."""
    result = _run(["sc.exe", "stop", SERVICE_NAME])
    if result.returncode == 0:
        print(f"Service '{SERVICE_NAME}' stopped.")


def status() -> None:
    """Check Sentinel service status."""
    result = _run(["sc.exe", "query", SERVICE_NAME], check=False)
    if result.returncode == 0:
        output = result.stdout
        if "RUNNING" in output:
            print(f"Service '{SERVICE_NAME}': RUNNING")
        elif "STOPPED" in output:
            print(f"Service '{SERVICE_NAME}': STOPPED")
        elif "PENDING" in output:
            print(f"Service '{SERVICE_NAME}': PENDING")
        else:
            print(output)
    else:
        print(f"Service '{SERVICE_NAME}' is not installed.")


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    command = sys.argv[1].lower()
    commands = {
        "install": install,
        "uninstall": uninstall,
        "start": start,
        "stop": stop,
        "status": status,
    }

    if command in commands:
        commands[command]()
    else:
        print(f"Unknown command: {command}")
        print(f"Available: {', '.join(commands)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
