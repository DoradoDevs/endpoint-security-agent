"""
Sentinel Agent — macOS Build Script

Creates a standalone macOS binary using PyInstaller.
Includes code signing guidance for distribution.
"""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def build():
    print("=" * 50)
    print("Sentinel Agent — macOS Build")
    print("=" * 50)

    # Ensure PyInstaller is installed
    subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)

    templates_dir = PROJECT_ROOT / "reporting" / "templates"
    add_data = f"{templates_dir}:reporting/templates"

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--name", "sentinel",
        "--onefile",
        "--console",
        "--add-data", add_data,
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
        "--hidden-import", "os_modules.macos",
        "--hidden-import", "vulnerability",
        "--hidden-import", "vulnerability.advisory_database",
        "--hidden-import", "vulnerability.nvd_cache",
        "--hidden-import", "remediation",
        "--hidden-import", "remediation.macos_hardening",
        "--hidden-import", "reporting",
        "--hidden-import", "fleet",
        "--hidden-import", "dashboard",
        "--distpath", str(PROJECT_ROOT / "dist"),
        "--workpath", str(PROJECT_ROOT / "build"),
        "--specpath", str(PROJECT_ROOT / "build"),
        str(PROJECT_ROOT / "cli" / "main.py"),
    ]

    print(f"Running PyInstaller...")
    subprocess.run(cmd, check=True)

    binary_path = PROJECT_ROOT / "dist" / "sentinel"
    if binary_path.exists():
        size_mb = binary_path.stat().st_size / 1024 / 1024
        print(f"\nBuild successful: {binary_path}")
        print(f"Size: {size_mb:.1f} MB")
        print()
        print("=== Code Signing (optional, for distribution) ===")
        print("Sign with Developer ID:")
        print(f"  codesign --deep --force --verify --verbose \\")
        print(f"    --sign 'Developer ID Application: YOUR NAME (TEAM_ID)' \\")
        print(f"    {binary_path}")
        print()
        print("Notarize for Gatekeeper:")
        print(f"  xcrun notarytool submit {binary_path} \\")
        print(f"    --apple-id your@email.com \\")
        print(f"    --password @keychain:notary \\")
        print(f"    --team-id TEAM_ID")
    else:
        print("Build failed — binary not found")
        sys.exit(1)


if __name__ == "__main__":
    build()
