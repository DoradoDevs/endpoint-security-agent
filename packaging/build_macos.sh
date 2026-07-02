#!/bin/bash
# Sentinel Agent — macOS Build Script
# Creates a standalone macOS application bundle using PyInstaller.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=================================================="
echo "Sentinel Agent — macOS Build"
echo "=================================================="

cd "$PROJECT_ROOT"

# Ensure dependencies
pip3 install pyinstaller

python3 -m PyInstaller \
    --name sentinel \
    --onefile \
    --console \
    --add-data "reporting/templates:reporting/templates" \
    --hidden-import core \
    --hidden-import scanners \
    --hidden-import os_modules.macos \
    --hidden-import vulnerability \
    --hidden-import remediation \
    --hidden-import reporting \
    --distpath dist \
    --workpath build \
    --specpath build \
    cli/main.py

if [ -f "dist/sentinel" ]; then
    echo ""
    echo "Build successful: dist/sentinel"
    echo "Size: $(du -h dist/sentinel | cut -f1)"
    echo ""
    echo "=== Code Signing (optional) ==="
    echo "To sign with a Developer ID certificate:"
    echo "  codesign --deep --force --verify --verbose --sign 'Developer ID Application: YOUR NAME (TEAM_ID)' dist/sentinel"
    echo ""
    echo "To notarize (required for distribution):"
    echo "  xcrun notarytool submit dist/sentinel --apple-id your@email.com --password @keychain:notary --team-id TEAM_ID"
else
    echo "Build failed"
    exit 1
fi
