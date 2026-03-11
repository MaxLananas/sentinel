

# SENTINEL

## Windows Security Monitor and Threat Detection Tool

SENTINEL is a real-time security monitoring and threat detection tool for Windows, written in Go. It operates as an interactive command-line application that combines file scanning, process monitoring, network analysis, and system integrity checks into a single self-contained binary.

---

## Overview

SENTINEL runs as a persistent terminal application that deploys multiple background monitoring routines ("guards") and provides on-demand scanning capabilities through an interactive shell. It is designed to detect common threats targeting Windows users, with particular emphasis on Discord token stealers, browser credential theft, clipboard hijacking, and persistence mechanisms.

The tool does not require installation of external dependencies. It uses native Windows APIs and built-in system utilities to perform its analysis.

---

## Features

### Real-Time Monitoring (Background Guards)

SENTINEL starts nine background monitors on launch:

- **ProcessGuard** — Watches for new processes with suspicious names, known malware naming patterns, fake system process names (e.g., `svch0st.exe` impersonating `svchost.exe`), and runtime interpreters executing suspicious scripts. Polls every 5 seconds.
- **DiscordGuard** — Monitors Discord's `desktop_core/index.js` for code injection, a common technique used by token stealers. Checks file integrity via MD5 hashing every 30 seconds.
- **StartupGuard** — Tracks Windows registry Run/RunOnce keys for new persistence entries. Polls every 2 minutes.
- **TempGuard** — Watches the TEMP directory for browser database files (`Login Data`, `Cookies`, `Web Data`, etc.) that indicate active credential theft. Polls every 8 seconds.
- **ClipboardGuard** — Detects clipboard hijacking ("clipper" malware) by monitoring for cryptocurrency address replacement. Polls every 2 seconds.
- **HostsGuard** — Monitors the Windows hosts file for unauthorized modifications, such as blocking security vendor domains. Polls every 30 seconds.
- **FileWatcher** — Scans recently created or modified files in user directories for malicious patterns. Polls every 10 seconds.
- **Honeypot** — Deploys decoy files (`passwords.txt`, `crypto_wallet_backup.txt`, etc.) in user directories and monitors them for access or deletion, indicating active information-stealing malware. Polls every 5 seconds.
- **BeaconDetector** — Analyzes established network connections over time to identify C2 beaconing behavior based on connection interval regularity. Polls every 30 seconds.

### Blitz Scan (20 Modules)

The `blitz` command runs a comprehensive system audit across 20 modules in parallel and produces a security score from 0 to 100:

| Module | Description |
|---|---|
| Files | Scans user directories for malicious scripts and binaries using pattern matching, PE analysis, name matching, and IOC hash lookup |
| Discord | Checks all Discord installations for `index.js` injection and embedded webhooks |
| Startup | Audits registry Run keys and the Startup folder for suspicious entries |
| Hosts | Checks the hosts file for blocked security domains |
| Tasks | Inspects scheduled tasks for suspicious executables or keywords |
| PS History | Scans PowerShell command history for indicators of compromise |
| Temp | Checks the TEMP directory for stolen browser databases |
| Network | Analyzes active connections for suspicious ports, fake process names, and LOLBin network activity |
| Clipboard | Checks clipboard content for cryptocurrency addresses |
| Services | Audits running services for suspicious names |
| Drivers | Inspects loaded drivers for rootkit indicators |
| DNS Cache | Analyzes the DNS resolver cache for suspicious domains and TLDs |
| Registry Deep | Checks IFEO debugger hijacking, Winlogon shell/userinit modifications, and logon scripts |
| Certificates | Scans the root certificate store for MITM proxy certificates (Fiddler, Burp, Charles, etc.) |
| Named Pipes | Enumerates named pipes and checks for known malicious pipe names (Cobalt Strike, Meterpreter, etc.) |
| WMI Persistence | Checks for WMI event subscription persistence |
| Firewall | Verifies firewall profile state and audits rules for suspicious entries |
| Browser Extensions | Inspects Chrome extensions for suspicious permission combinations |
| PS Profile | Checks PowerShell profile scripts for backdoor indicators |
| ADS Hidden | Scans for Alternate Data Streams on files in user directories |

### Pattern Detection Engine

The scanning engine uses regular expressions to detect threats in two categories:

**Script patterns** (applied to `.py`, `.js`, `.bat`, `.ps1`, `.vbs`, and similar files):
- Discord webhooks and Telegram bot exfiltration endpoints
- Discord tokens and MFA tokens
- `CryptUnprotectData` calls (credential decryption)
- Browser database theft patterns
- Discord LevelDB access (token stealing)
- Keylogger code patterns
- Obfuscated execution (base64 decode + exec)
- Registry persistence via Run keys
- AMSI bypass techniques
- PowerShell download cradles
- Mimikatz command patterns
- Shellcode loaders and process injection APIs
- WMI persistence
- Credential harvesting commands
- Antivirus disabling commands
- Reverse shell patterns
- UAC bypass techniques
- Shadow copy deletion (ransomware indicator)
- COM hijacking
- DNS exfiltration
- Clipboard, screen capture, and webcam access
- SSH key and cryptocurrency wallet theft
- Browser cookie theft
- DLL persistence mechanisms
- Named pipe C2 communication

**Binary patterns** (applied to `.exe`, `.dll`, `.scr`, and similar files):
- Embedded Discord webhooks and Telegram endpoints
- Suspicious paste/upload service URLs
- C2 framework signatures
- Cryptocurrency miner indicators

### PE Analysis

For Windows executables, SENTINEL performs lightweight PE header analysis:
- Architecture detection (x86/x64)
- Section enumeration with entropy calculation
- Detection of RWX (writable + executable) sections
- High-entropy section detection (potential encryption or packing)
- Packer identification (UPX, VMProtect, Themida, Enigma, ASPack, NSIS)
- Suspicious import detection (process injection, keylogging, debugging, credential access APIs)
- Timestamp validation

### Development Project Awareness

The scanner reduces alert severity for Discord tokens and webhooks found within development project directories (bot frameworks, projects containing `discord.Client`, `commands.Bot`, environment variable token loading, etc.) to avoid false positives from legitimate bot development.

### Caching

Scanned files are cached by path, size, and modification time. Unchanged files are skipped on subsequent scans, significantly reducing scan time for repeated runs.

### Quarantine

Files can be moved to a quarantine directory with metadata tracking. Quarantined files can be listed and restored.

### IOC Hash Matching

The engine supports loading a JSON file of known-bad SHA256 hashes from `~/.sentinel/ioc_hashes.json` for hash-based detection.

---

## Interactive Commands

```
blitz                   Full 20-module scan with security score
scan <path>             Scan a file or directory
info <path>             File details: hashes, entropy, PE analysis, detections
forensic                Full forensic analysis (blitz + recent files + USB + logins)

processes               List processes with fake name and suspicious name detection
services                List non-Microsoft running services
network                 Show established connections with threat indicators
top                     Group connections by process
dns                     Show DNS cache with suspicious domain/TLD flagging
drivers                 List loaded non-Microsoft drivers
investigate <pid>       Deep process investigation (PE, signature, connections, DNS)
timeline                Forensic event timeline

kill <pid>              Terminate a process
fix                     Repair Discord injection, clean TEMP, flush DNS, fix hosts
quarantine [path]       Quarantine a file
quarantine list         List quarantined files
quarantine restore <n>  Restore a quarantined file
whitelist <dir>         Exclude a directory from scanning
export                  Export JSON and HTML reports

status                  Show uptime, memory, alert count, goroutines
alerts [n]              Show last n alerts
cache [clear]           View or clear the scan cache
quit                    Exit
```

---

## Requirements

- Windows 10 or later
- No external dependencies; the tool uses native Windows APIs and built-in system utilities (`netstat`, `tasklist`, `schtasks`, `reg`, `ipconfig`, `driverquery`, `wmic`, `netsh`, `powershell`, `attrib`)
- Some features (firewall audit, certificate inspection, WMI queries, event log access) may require elevated privileges for full results

---

## Installation

Build from source:

```
go build -o sentinel.exe -ldflags="-s -w"
```

Optional auto-start registration:

```
sentinel.exe --install
```

Remove from auto-start:

```
sentinel.exe --uninstall
```

These commands add or remove a registry entry under `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.

---

## Data Storage

All persistent data is stored in `%USERPROFILE%\.sentinel\`:

| File | Purpose |
|---|---|
| `sentinel.log` | Append-only alert log |
| `scancache.json` | File scan cache |
| `quarantine/` | Quarantined files and metadata |
| `ioc_hashes.json` | User-supplied IOC hash database (optional) |
| `report_*.json` | Exported JSON reports |
| `report_*.html` | Exported HTML reports |

---

## Alerts and Notifications

Alerts are classified into five severity levels: INFO, LOW, MEDIUM, HIGH, and CRITICAL. Alerts are subject to a 10-minute cooldown per unique key (module + message + path) to avoid flooding. CRITICAL alerts trigger a Windows balloon notification via PowerShell (rate-limited to once every 5 minutes).

---

## Limitations

- This tool is a heuristic scanner. It does not replace a full antivirus engine and does not perform behavioral analysis, sandboxing, or signature-based detection against a malware database.
- PE analysis is limited to header inspection and string matching; it does not perform disassembly or emulation.
- Network analysis relies on point-in-time snapshots from `netstat` rather than continuous packet capture.
- Some detection patterns may produce false positives in security research, penetration testing, or software development environments. The `whitelist` command and development project detection help mitigate this.
- The honeypot files are created with hidden and system attributes but are not monitored via filesystem change notifications; polling is used instead.

---

## License

See the LICENSE file for details.
