# Endpoint Security Agent

A cross-platform (Windows / macOS / Linux) **defensive** endpoint security agent
written in Python. It audits a host's security posture, hunts for malware and
persistence, correlates findings against CVE and threat-intelligence data, and
can run continuously as an EDR-style monitor with a ransomware shield.

The agent is strictly defensive. It performs no exploitation, no privilege
escalation, no lateral movement, and no data exfiltration. See
[`SECURITY_MODEL.md`](SECURITY_MODEL.md) for the full threat model and the list
of capabilities that are deliberately **out of scope**, and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for how the codebase fits together.

> **Authorized use only.** Run this agent only on systems you own or are
> explicitly authorized to assess. Hardening actions modify system
> configuration — always preview with `--dry-run` first.

> **Naming note:** the CLI command and internal product name is `sentinel`. This
> is unrelated to Microsoft Sentinel, SentinelOne, or HashiCorp Sentinel.

---

## Features

**Posture & vulnerability scanning (~21 scanners)**
- Process, network, startup, service, config, and package scanners
- Credential exposure, privilege, and browser-security scanners
- Malware / heuristic / memory / IOC / YARA / AMSI scanners
- File-integrity monitoring and log-analysis scanners
- Cloud posture checks (AWS / Azure / GCP config review)

**Vulnerability intelligence**
- NVD CVE lookup with a local cache (works keyless; optional API key raises the
  rate limit)
- Bundled advisory database for high-impact CVEs, correlated to installed
  package versions

**Threat intelligence**
- Pluggable feeds: abuse.ch (URLhaus, Feodo, MalwareBazaar), AlienVault OTX,
  Emerging Threats
- Local IOC and file-hash databases with an indicator matcher

**EDR-style realtime monitoring** (`--daemon`)
- Process / connection / DNS monitoring and process-tree tracking
- Ransomware shield with canary files and backup snapshots
- Event store, timeline query, and a correlation engine
- Optional Windows ETW / Sysmon parsing

**Response & remediation** (opt-in, reversible)
- Guided cleanup wizard, quarantine with restore, endpoint network isolation
- Response playbooks and a kill-chain analyzer
- Vendor-aligned hardening for Windows / macOS / Linux with rollback

**Compliance & reporting**
- CIS Benchmark, NIST 800-53, and SOC 2 assessment engines
- HTML and JSON reports, SIEM integration hooks, optional email delivery
- Tamper-evident structured audit log

**Operations**
- Security profiles: `minimal`, `standard`, `strict`, `fort_knox`, `custom`
- Terminal dashboard (TUI), optional Flask fleet dashboard/API
- Allowlist management, scheduler, PyInstaller packaging for standalone binaries

---

## Installation

Requires **Python 3.11+**.

```bash
git clone https://github.com/DoradoDevs/endpoint-security-agent.git
cd endpoint-security-agent
pip install -e .
```

Or install just the runtime dependencies:

```bash
pip install psutil requests rich jinja2
```

Optional extras are declared in `pyproject.toml`:

```bash
pip install -e ".[fleet]"       # Flask dashboard + API
pip install -e ".[daemon]"      # watchdog for realtime file guard
pip install -e ".[encryption]"  # cryptography for encrypted audit log
pip install -e ".[dev]"         # pytest, mypy, ruff
```

---

## Quick Start

```bash
# Standard read-only scan
python -m cli.main --scan

# Deep scan + threat hunting, then generate reports
python -m cli.main --deep-scan --hunt --report

# Preview hardening changes without applying them
python -m cli.main --harden --dry-run

# Apply safe hardening (requires admin/root)
python -m cli.main --harden --auto

# Continuous EDR-style monitoring
python -m cli.main --daemon --guard

# Compliance assessment
python -m cli.main --compliance cis

# Interactive terminal dashboard
python -m cli.main --tui
```

After `pip install -e .`, the same commands are available via the `sentinel`
entry point (e.g. `sentinel --scan --report`).

Reports are written to `./sentinel_reports/` by default (override with
`--output-dir`). See [`SETUP.md`](SETUP.md) for platform-specific setup,
packaging, and the full CLI reference.

---

## Configuration

The agent runs with **no configuration** out of the box. Optional settings:

**Environment variables** — copy [`.env.example`](.env.example) to `.env`. Only
two variables are read from the environment (both optional):

| Variable | Default | Purpose |
|---|---|---|
| `ENDPOINT_AGENT_LICENSE_KEY` | public non-secret dev key | HMAC key for the optional license module. Not needed in this open-source build — nothing is gated behind a paid tier. Set a strong random value only if you build a paid edition. |
| `ENDPOINT_AGENT_UPDATE_URL` | _(unset → updater is a no-op)_ | Base URL of **your own** release-metadata server for the auto-updater. There is no default; only set it if you host signed release metadata for your own distribution. |

**Everything else** — NVD/OTX API keys, SMTP for email delivery, threat-intel
feed keys, and fleet enrollment tokens — is supplied through the agent's **own
config** (JSON config file in your home directory, e.g. `~/.sentinel/`) and CLI
flags, **not** through environment variables. No secrets are hardcoded. See
[`SETUP.md`](SETUP.md) for the config file location and
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md#external-services--apis) for the
full list of external services and how each is authenticated.

---

## Project structure

```
endpoint-security-agent/
├── cli/            # sentinel CLI entry point + interactive cleanup wizard
├── core/           # Agent orchestrator, scheduler, config, telemetry models,
│                   #   profiles, daemon, allowlist, audit log, licensing
├── scanners/       # ~21 pluggable scanners (BaseScanner subclasses)
├── vulnerability/  # CVE lookup, local advisory DB, NVD API cache
├── threat_intel/   # IOC/hash databases, feed adapters (abuse.ch, OTX, ET), matcher
├── edr/            # Realtime monitors, correlation engine, event store,
│                   #   ransomware shield, app/device control, timeline
├── response/       # Threat-response engine, actions, playbooks, rollback, audit
├── remediation/    # Reversible OS hardening (win/mac/linux), firewall, updater
├── compliance/     # CIS / NIST 800-53 / SOC 2 evaluation engine
├── reporting/      # Risk scoring, HTML/JSON reports, SIEM + email delivery
├── fleet/          # Agent-side fleet client (registration, telemetry, policy)
├── dashboard/      # Optional Flask fleet dashboard + REST API (SQLite)
├── mesh/           # Optional peer-to-peer agent mesh (HMAC-signed, UDP discovery)
├── os_modules/     # Platform abstraction layer + loader
├── tui/            # Rich-based interactive terminal dashboard
├── packaging/      # PyInstaller builds, service/launchd/systemd units, auto-updater
├── tests/          # ~1,200 pytest tests
└── docs/           # Architecture documentation
```

See **[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)** for the full architecture:
entry points, component breakdown, scan/data flow (with diagram), data stores,
and external services.

---

## Security notes

- **Defensive by design.** No offensive capability, C2, stealth, or
  exfiltration. Read-only is the default; every write requires an explicit flag.
- **No hardcoded secrets.** The license module reads its signing key from the
  environment with a clearly-labeled public development default. The auto-updater
  has no default endpoint. Credential/SSH/AWS strings in `tests/` are synthetic
  fixtures used to test the credential scanner.
- **AV false positives.** EDR-style agents commonly trip antivirus heuristics.
  If Windows Defender flags a packaged build, add an exclusion or submit it for
  false-positive review (details in `SETUP.md`).
- **Reversible hardening.** Hardening records the before-state so changes can be
  rolled back. Always run `--dry-run` first.

---

## Development

```bash
pip install -e ".[dev]"
pytest tests/            # ~1,200 tests
ruff check .
mypy core/ scanners/ reporting/
```

---

## License

MIT — see [`LICENSE`](LICENSE).
