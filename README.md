# SysHealth

A system care toolkit for Windows and Linux: disk space, cleanup, malware protection, security hardening, health checks, network tools, and a full command line. Flat, calm interface (design specification v3.0.0) with light, dark (blue-gray), or follow-system theme.

Credit: A.T.Grep

## Features

### Overview
| Page | What it does |
|---|---|
| Dashboard | Maintenance schedule (routine tasks, when each was last done, what is due, one-click run) and status cards for every tool, backed by a shared state file. Results persist between sessions. |
| Recent Changes | Timeline of apps installed, updated or removed; Windows/Linux updates; new services and drivers; startup changes; restarts; and every action taken by SysHealth, with the files it affected (double-click an entry; Export history includes them). |

### Clean Up
| Page | What it does |
|---|---|
| Large Files | Folder size drill-down with share bars, plus the largest files. Move files to the Recycle Bin. |
| Duplicate Files | Match by name or by size within the same type, with optional SHA-256 confirmation. Keeps at least one copy per group. Skips program and project folders (virtual environments, node_modules, .git) and library files by default. Export to Excel for review before deleting. |
| Cleanup | Junk files (temp, Windows Update cache, thumbnails, crash dumps, browser caches, Recycle Bin), old downloads, empty folders, and drive optimization (TRIM / defragment). |
| Long Paths | Finds paths too long for Office (218), Windows (259) or OneDrive (400). Proposes the fewest renames; supervised or automatic; undo supported. |

### Protect
| Page | What it does |
|---|---|
| Malware Scan | ClamAV (auto-installed for your OS) and Microsoft Defender, plus a check for unknown, unsigned or disguised programs. Shows each engine's signature version, publication date and source, and reminds you when signatures are more than 3 days old (remind in 6 or 12 hours, or dismiss for 24 hours). |
| Quarantine | AES-encrypted vault for detected files. Restore or delete permanently. |
| Security | Score out of 100: antivirus, tamper protection, firewall, UAC, BitLocker, Secure Boot, TPM, SMBv1, Remote Desktop, auto sign-in, Guest account, SmartScreen (Linux: firewall, LUKS, Secure Boot, auto-updates, SSH). One-click hardening. |
| Startup Apps | Programs that start at sign-in, with publisher. Enable or disable without deleting anything. |
| Autoruns Audit | Everything that starts automatically: run keys, startup folders, services, scheduled tasks, browser extensions, Winlogon, IFEO debuggers, WMI consumers (Linux: systemd, cron, autostart, shell startup files). Signature checks, risk flags, "new since last scan". |
| Connections | Programs with network connections, open ports, host names. End process, block in firewall, check on VirusTotal. |

### Health
| Page | What it does |
|---|---|
| System Health | Resources, free space, uptime, pending restart, Defender, Windows Update, startup count; DISM + SFC repair. |
| Disk Health | Drive health, temperature, wear and errors; volume scan, spot fix, full repair, SMART reports. |
| Network | Adapters, gateway, internet (tested like a browser), DNS speed, VPNs, company-managed computers, proxy, firewall, hosts file; DNS flush, IP renew, network reset (with a warning on company computers). |
| DNS & Speed | Benchmarks Cloudflare, Google, Quad9, OpenDNS and your current DNS; switch with one click. Internet speed test. |
| Event Log | Groups recent errors and explains common ones (crashes, unexpected shutdowns, disk errors) with advice. |
| Live Monitor | Real-time CPU, memory, disk and network graphs; top programs; end process. |

### Tools
| Page | What it does |
|---|---|
| App Updates | winget (Windows), apt / dnf / flatpak (Linux). Update selected or all. |
| File Shredder | Overwrites files before deletion (1, 3 or 7 passes). |
| VirusTotal | Checks a file's SHA-256 against 70+ engines (free API key). Only the hash is sent. |
| Command Line | Cheat sheet with copy buttons; the same features from a terminal. |

## SysHealth updates

This covers SysHealth itself only; other installed apps are handled on the App Updates page. SysHealth checks its GitHub releases page for a newer version once a day when it starts (this can be turned off in the **SysHealth updates** window in the header). The user always decides:

- The prompt shows the new version, the release date, the download size and a short summary of what changed (taken from the release notes).
- **Update now** downloads the new version, verifies its checksum, then closes, replaces and reopens SysHealth. Settings, quarantine and history are kept.
- **Remind me later** asks again at the next daily check. **Skip this version** stays quiet until a newer version is published.
- The **SysHealth updates** button in the header checks at any time, including skipped versions. When a version was postponed or skipped, the button reads **Update to x.y.z**.
- From source (`python main.py`), the prompt offers **Open download page** instead, because only the built program can replace itself.

### Publishing a new version

1. The repository is set in `core/self_update.py`: `DEFAULT_REPO = "swaidi/SysHealth"`. It must stay public so the app can read its releases.
2. Raise `VERSION` in `core/version.py` (for example `2.4.0`).
3. Build: `.\build_windows.bat` on Windows and `./build_linux.sh` on Linux.
4. On GitHub, create a release with the tag `v2.4.0`. Write the release notes as short bullet points; the first ten lines appear in the update prompt.
5. Attach the files from `dist`: `SysHealth.exe`, `SysHealthCLI.exe`, `SHA256SUMS-windows.txt` and, for Linux, `SysHealth`, `SysHealthCLI`, `SHA256SUMS-linux.txt`. Keep these names unchanged.

## Feedback and problem reports

The report window shows the address to send to, with **Copy report** and **Copy address** buttons. **Send by email** appears only when an email program is set up. On Linux, copying uses the system clipboard tool when available (`xclip`, `xsel` or `wl-copy`), so the text stays available after SysHealth closes.

The **Feedback** button in the header opens a report form. When any task fails, the error message also offers to report the problem, and the form is filled in with the error, system details and recent activity. You can review and edit the report, then send it by email (to dev.oasis006@passmail.net), copy it, or save it as a file. To change the address, edit `FEEDBACK_EMAIL` in `ui/feedback.py`.

## Safety design

- Application data is never deleted, moved, renamed or shredded: browser profiles (sign-ins, passwords, extensions such as VPNs), password stores and keyrings, app settings (Windows `AppData`; Linux hidden folders such as `~/.config`, `~/.local`, `~/.mozilla`) and browsers installed in Downloads or on the Desktop (for example Tor Browser). Scans skip these folders, and every delete or rename checks each path again just before acting.
- Browser caches are cleaned only while all browsers are closed.
- Long Paths never pre-selects renames.
- System folders are excluded from deletion features; drive roots and the home folder cannot be shredded.
- Deletions go to the Recycle Bin; threats go to an encrypted quarantine; long-path renames can be undone.
- Every repair shows its exact commands and asks for confirmation.
- Actions taken by SysHealth are recorded and shown in Recent Changes.

## Changing colors and fonts

All colors, fonts and control styles live in `ui/theme.py` (`TOKENS` for light and dark). Edit the hex values there to restyle the whole app; no page code needs to change.

## Architecture (for dashboards)

```
core/        feature logic (no user interface)   → publishes results to state.json
ui/, main.py desktop interface                   → reads and writes through core
cli.py       command line                        → same core, same state.json
```

Every feature publishes its latest result to `state.json`, and SysHealth's own actions are appended to `history.jsonl`. A dashboard (the built-in one or a future external one) only needs to read these files, so its content and design can change without touching the core.

| File | Windows | Linux |
|---|---|---|
| App data folder | `%LOCALAPPDATA%\SysHealth` | `~/.local/share/SysHealth` |
| Latest results (including the maintenance schedule) | `state.json` | `state.json` |
| Action history | `history.jsonl` | `history.jsonl` |
| Settings | `settings.json` | `settings.json` |
| Quarantine, ClamAV signatures | `quarantine\`, `clamav-db\` | `quarantine/`, `clamav-db/` |

## Run and build in VS Code

1. Open the `SysHealth` folder in VS Code and select your `.venv` interpreter.
2. Install dependencies in the activated terminal:
   ```powershell
   pip install -r requirements.txt
   ```
3. Run the desktop app: `F5` ("Run SysHealth"), or `python main.py`.
4. Run the command line: `python cli.py --help` or `python cli.py cheatsheet`.
5. Build both executables: `Ctrl+Shift+B`, or in the activated terminal:
   ```powershell
   python -m PyInstaller --noconfirm --clean --onefile --windowed --icon assets/syshealth.ico --add-data assets:assets --name SysHealth main.py
   python -m PyInstaller --noconfirm --clean --onefile --console --icon assets/syshealth.ico --name SysHealthCLI cli.py
   ```
   Output: `dist\SysHealth.exe` and `dist\SysHealthCLI.exe`.

Linux: `sudo apt install python3-tk python3-venv smartmontools`, then `./build_linux.sh`.

On first start on Linux, SysHealth offers to install small helper tools it needs (xclip or wl-clipboard for reliable copying, smartmontools for disk health) with one password prompt. Later: `SysHealthCLI linux-tools install`.

## Command line

See `CHEATSHEET.md`, the Command Line page, or run `SysHealthCLI cheatsheet`. Every command supports `--json`. `self-update` checks for a newer SysHealth and prints the summary of changes. Exit codes: 0 = OK, 1 = problems found or error, 2 = administrator rights needed.

## Administrator rights

- Windows: scans run as a normal user. Repairs, security hardening, service changes and firewall rules need administrator rights; use **Restart as Administrator** in the header, or open the terminal as administrator for the command line.
- Linux: privileged actions use `pkexec` (password prompt).

## Known limitations

- SysHealth complements, and does not replace, real-time antivirus protection.
- "Unknown programs" and autorun flags are heuristics; unsigned does not mean malicious.
- Shredding cannot guarantee destruction on SSDs, flash drives or cloud-synced folders; use full-disk encryption.
- The speed test uses Cloudflare's public speed endpoints; results vary with server load and Wi-Fi conditions.
- VirusTotal free keys allow 4 lookups per minute and 500 per day.
