"""
Sentinel Agent — Linux Build Script

Creates a standalone Linux binary using PyInstaller.
Includes deb/rpm packaging guidance.
"""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def build():
    print("=" * 50)
    print("Sentinel Agent — Linux Build")
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
        "--hidden-import", "scanners.credential_scanner",
        "--hidden-import", "scanners.log_analysis_scanner",
        "--hidden-import", "scanners.privilege_scanner",
        "--hidden-import", "scanners.service_audit_scanner",
        "--hidden-import", "os_modules.linux_server",
        "--hidden-import", "vulnerability",
        "--hidden-import", "vulnerability.advisory_database",
        "--hidden-import", "vulnerability.nvd_cache",
        "--hidden-import", "remediation",
        "--hidden-import", "remediation.linux_hardening",
        "--hidden-import", "reporting",
        "--hidden-import", "fleet",
        "--hidden-import", "dashboard",
        "--distpath", str(PROJECT_ROOT / "dist"),
        "--workpath", str(PROJECT_ROOT / "build"),
        "--specpath", str(PROJECT_ROOT / "build"),
        str(PROJECT_ROOT / "cli" / "main.py"),
    ]

    print("Running PyInstaller...")
    subprocess.run(cmd, check=True)

    binary_path = PROJECT_ROOT / "dist" / "sentinel"
    if binary_path.exists():
        size_mb = binary_path.stat().st_size / 1024 / 1024
        print(f"\nBuild successful: {binary_path}")
        print(f"Size: {size_mb:.1f} MB")
        print()
        print("=== Installation ===")
        print(f"  sudo cp {binary_path} /usr/local/bin/sentinel")
        print(f"  sudo chmod +x /usr/local/bin/sentinel")
        print()
        print("=== Systemd Service ===")
        print(f"  sudo cp {PROJECT_ROOT}/packaging/sentinel.service /etc/systemd/system/")
        print(f"  sudo systemctl daemon-reload")
        print(f"  sudo systemctl enable sentinel")
        print(f"  sudo systemctl start sentinel")
        print()
        print("=== Debian Package (requires fpm) ===")
        print(f"  fpm -s dir -t deb \\")
        print(f"    -n sentinel-agent -v 2.0.0 \\")
        print(f"    --description 'Endpoint Security Agent' \\")
        print(f"    --url 'https://github.com/DoradoDevs/endpoint-security-agent' \\")
        print(f"    --after-install packaging/postinst.sh \\")
        print(f"    {binary_path}=/usr/local/bin/sentinel \\")
        print(f"    packaging/sentinel.service=/etc/systemd/system/sentinel.service")
        print()
        print("=== RPM Package (requires fpm) ===")
        print(f"  fpm -s dir -t rpm \\")
        print(f"    -n sentinel-agent -v 2.0.0 \\")
        print(f"    --description 'Endpoint Security Agent' \\")
        print(f"    {binary_path}=/usr/local/bin/sentinel \\")
        print(f"    packaging/sentinel.service=/etc/systemd/system/sentinel.service")
    else:
        print("Build failed — binary not found")
        sys.exit(1)


if __name__ == "__main__":
    build()
