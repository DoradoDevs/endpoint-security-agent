"""
Sentinel Agent — Windows Build Script

Creates a standalone Windows executable using PyInstaller.
"""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def build():
    print("=" * 50)
    print("Sentinel Agent — Windows Build")
    print("=" * 50)

    # Ensure PyInstaller is installed
    subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "sentinel",
        "--onefile",
        "--console",
        "--icon", "NONE",
        "--add-data", f"{PROJECT_ROOT / 'reporting' / 'templates'};reporting/templates",
        "--hidden-import", "core",
        "--hidden-import", "core.profiles",
        "--hidden-import", "core.daemon",
        "--hidden-import", "core.file_watcher",
        "--hidden-import", "core.notifications",
        "--hidden-import", "scanners",
        "--hidden-import", "scanners.file_integrity_scanner",
        "--hidden-import", "scanners.browser_scanner",
        "--hidden-import", "scanners.credential_scanner",
        "--hidden-import", "scanners.log_analysis_scanner",
        "--hidden-import", "scanners.privilege_scanner",
        "--hidden-import", "scanners.service_audit_scanner",
        "--hidden-import", "os_modules.windows",
        "--hidden-import", "vulnerability",
        "--hidden-import", "vulnerability.advisory_database",
        "--hidden-import", "vulnerability.nvd_cache",
        "--hidden-import", "remediation",
        "--hidden-import", "remediation.windows_hardening",
        "--hidden-import", "reporting",
        "--hidden-import", "fleet",
        "--hidden-import", "dashboard",
        "--distpath", str(PROJECT_ROOT / "dist"),
        "--workpath", str(PROJECT_ROOT / "build"),
        "--specpath", str(PROJECT_ROOT / "build"),
        str(PROJECT_ROOT / "cli" / "main.py"),
    ]

    print(f"Running: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

    exe_path = PROJECT_ROOT / "dist" / "sentinel.exe"
    if exe_path.exists():
        print(f"\nBuild successful: {exe_path}")
        print(f"Size: {exe_path.stat().st_size / 1024 / 1024:.1f} MB")
    else:
        print("Build failed — executable not found")
        sys.exit(1)


if __name__ == "__main__":
    build()
