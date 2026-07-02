# Endpoint Security Agent — Setup Guide

## Prerequisites

- Python 3.11 or later
- pip (Python package manager)
- Admin/root privileges (required for full scan capabilities)

## Quick Start

### 1. Install Dependencies

```bash
git clone https://github.com/DoradoDevs/endpoint-security-agent.git
cd endpoint-security-agent
pip install -e .
```

Or install dependencies directly:

```bash
pip install psutil requests rich jinja2
```

### 2. Run a Scan

```bash
# Standard scan
python -m cli.main --scan

# Deep scan with reports
python -m cli.main --deep-scan --report

# Preview hardening changes
python -m cli.main --harden --dry-run

# Full auto: scan + harden + report
python -m cli.main --scan --harden --auto --report
```

### 3. View Reports

Reports are saved to `./sentinel_reports/` by default:
- `sentinel_report_YYYYMMDD_HHMMSS.html` — Interactive HTML report
- `sentinel_report_YYYYMMDD_HHMMSS.json` — Machine-readable JSON

## Platform-Specific Setup

### Windows

Run as Administrator for full capabilities:
```powershell
# Right-click PowerShell > "Run as Administrator"
python -m cli.main --scan --report
```

**Windows Defender Compatibility:**
- Sentinel is a read-only scanner and does not conflict with Defender
- If Defender flags the executable, add an exclusion or submit for false positive review

### macOS

Grant Full Disk Access for complete scanning:
1. System Preferences > Security & Privacy > Privacy > Full Disk Access
2. Add your terminal application (Terminal.app, iTerm2, etc.)

```bash
sudo python3 -m cli.main --scan --report
```

### Linux Server

```bash
# Install
sudo pip3 install -e .

# Run with server mode
sudo sentinel --scan --report --server-mode

# Install as systemd service (daily scans)
sudo cp packaging/sentinel.service /etc/systemd/system/
sudo cp packaging/sentinel.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel.timer
```

## Packaging

### Windows Executable

```bash
pip install pyinstaller
python packaging/build_windows.py
# Output: dist/sentinel.exe
```

### macOS Binary

```bash
pip3 install pyinstaller
bash packaging/build_macos.sh
# Output: dist/sentinel
```

### Linux Binary

```bash
pip3 install pyinstaller
python3 -m PyInstaller --onefile --name sentinel \
    --add-data "reporting/templates:reporting/templates" \
    cli/main.py
# Output: dist/sentinel
sudo cp dist/sentinel /usr/local/bin/
```

## Development

```bash
pip install -e ".[dev]"
pytest tests/
mypy core/ scanners/ reporting/
ruff check .
```

## CLI Reference

| Flag | Description |
|------|-------------|
| `--scan` | Standard security scan |
| `--deep-scan` | Extended scan with additional checks |
| `--harden` | Apply safe hardening recommendations |
| `--auto` | Apply changes without confirmation |
| `--dry-run` | Preview changes without applying |
| `--report` | Generate HTML and JSON reports |
| `--update` | Check/apply system updates |
| `--server-mode` | Enable Linux server checks (SSH, CIS) |
| `--output-dir PATH` | Custom report output directory |
| `--verbose` | Verbose logging output |
| `--version` | Show version |
