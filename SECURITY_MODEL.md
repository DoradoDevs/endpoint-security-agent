# Endpoint Security Agent — Security Model & Threat Analysis

## Security Model

### Core Principles

1. **Transparency** — Every action is logged. No hidden operations. The user can audit all agent activity via structured JSON logs.

2. **Least Privilege** — The agent requests only the minimum permissions needed for each scan. Read-only mode is the default. Write operations require explicit flags (`--harden`, `--auto`).

3. **No Stealth** — The agent does not conceal its presence, mask process names, or hide from system monitoring tools. It runs as a visible process.

4. **No Exfiltration** — All data stays local. No telemetry is sent externally. The CVE lookup module uses the public NIST NVD API only when explicitly enabled, and only sends product name/version.

5. **Vendor-Aligned Remediation** — All hardening actions use vendor-recommended settings (Microsoft-documented PowerShell commands, Apple-recommended defaults, CIS benchmark settings for Linux).

6. **Reversibility** — Hardening actions are designed to be reversible. The agent logs the before-state so changes can be undone.

### What Sentinel Does NOT Do

| Prohibited Capability | Reason |
|---|---|
| Exploit code / PoC payloads | Offensive capability — not in scope |
| Privilege escalation | Offensive technique |
| Lateral movement | Offensive / network attack capability |
| Remote command execution | Not a RAT — no C2 functionality |
| Hidden persistence | No hidden services, rootkits, or concealment |
| Data harvesting / exfiltration | No data leaves the system without explicit API opt-in |
| Kernel driver loading | Out of scope; creates stability/trust risks |
| Signature database replication | We use heuristics, not AV signatures |
| Process injection / hooking | Offensive/rootkit technique |
| Network scanning of remote hosts | Only local port/connection analysis |

### Permission Model

| Operation | Permission Required | Flag |
|---|---|---|
| Read-only scan | Standard user (limited); Admin (full) | `--scan` |
| Deep scan | Admin recommended | `--deep-scan` |
| Report generation | Standard user | `--report` |
| Hardening preview | Standard user | `--harden --dry-run` |
| Hardening apply | Admin required | `--harden --auto` |
| System updates | Admin required | `--update --auto` |

### Data Flow

```
System State (read-only)
    ↓
Scanner Modules (process/network/config/package/startup)
    ↓
Findings (structured data objects)
    ↓
Risk Engine (scoring algorithm)
    ↓
Reports (HTML/JSON — local filesystem only)
    ↓
[Optional] Hardening Engine (explicit opt-in only)
```

---

## Threat Model

### Assets Protected

1. The host system's security posture
2. User privacy (no data exfiltration)
3. System stability (no destructive operations)

### Threat Actors Considered

| Actor | Capability | Sentinel's Defense |
|---|---|---|
| Commodity malware | Process persistence, crypto-mining, info-stealers | Heuristic detection of suspicious processes, startup persistence, known C2 ports |
| Script kiddies | Common tools, default exploits | Detection of known tool names, suspicious ports, weak configurations |
| Insider threats | Unauthorized privilege escalation | Admin account auditing, SSH hardening checks, password policy audit |
| Supply chain compromise | Compromised packages | Package version checking, CVE correlation |
| Opportunistic attackers | Scanning for exposed services | Open port audit, firewall verification, service hardening |

### Threats NOT Addressed (Known Limitations)

| Threat | Reason |
|---|---|
| APT/nation-state actors | Requires EDR-grade kernel telemetry, behavioral AI, and threat intelligence feeds |
| Zero-day exploits | No signature/heuristic can reliably detect truly novel attacks |
| Fileless malware (advanced) | Memory-only analysis requires kernel-level instrumentation |
| Encrypted C2 channels | Would require TLS inspection, which is invasive |
| Hardware-level attacks | Out of scope (Evil Maid, hardware implants) |
| Anti-forensics | Skilled adversaries can evade userspace-only detection |

### Agent Self-Protection

- The agent does not implement self-defense mechanisms (no tamper protection)
- This is intentional: tamper protection requires kernel drivers, which conflicts with our transparency principle
- Enterprise deployment should pair Sentinel with OS-native integrity monitoring

---

## Known Limitations

1. **Userspace only** — Cannot detect kernel-level threats or rootkits
2. **Point-in-time** — Scans show current state, not continuous monitoring
3. **No memory analysis** — Cannot inspect process memory for injected code
4. **No file content scanning** — Does not scan file contents for malware signatures
5. **Limited CVE coverage** — Local advisory database covers high-impact CVEs only; enable API for broader coverage
6. **Platform coverage** — Some checks are platform-specific and may not have equivalent depth across all OSes
7. **Rate limiting** — NVD API is rate-limited without an API key (5 requests per 30 seconds)
8. **Requires privileges** — Full scanning capability requires admin/root; limited results as standard user

---

## Enterprise Expansion Roadmap

### Phase 2: Active Protection
- Safe hardening with rollback capability
- Scheduled scanning with drift detection
- Email/webhook alerting on critical findings
- Integration with existing patch management

### Phase 3: Fleet Management
- Central management console (web dashboard)
- Multi-device enrollment and fleet scanning
- Aggregated risk scoring across fleet
- Role-based access control
- Compliance reporting (CIS, NIST, SOC 2)

### Phase 4: Advanced Detection
- Behavioral baselining (process/network norms)
- File integrity monitoring (FIM)
- Real-time event correlation
- Threat intelligence feed integration
- SIEM integration (Splunk, Elastic, Sentinel)

### Phase 5: Enterprise Features
- Custom policy engine
- Automated compliance workflows
- API for third-party integrations
- Multi-tenant support
- Audit trail and chain-of-custody reporting
