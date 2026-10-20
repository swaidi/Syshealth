# SysHealth Command-Line Cheat Sheet

Run from a terminal. From source, replace `SysHealthCLI` with `python cli.py`.

## Getting help

| Command | What it does |
|---|---|
| `SysHealthCLI --help` | List all commands. |
| `SysHealthCLI <command> --help` | Show the options of one command. |
| `SysHealthCLI cheatsheet` | Print this cheat sheet. |
| `SysHealthCLI <command> --json` | Any command: output machine-readable JSON (for scripts). |

## Health checks

| Command | What it does |
|---|---|
| `SysHealthCLI check all` | Run network, system, disk and security checks. |
| `SysHealthCLI check security` | Security score and findings (also: network, system, disk). |
| `SysHealthCLI events --days 7` | Summarize serious event-log errors from the last 7 days. |
| `SysHealthCLI changes --days 14` | Timeline of app installs, updates, new services, drivers and restarts. |
| `SysHealthCLI report` | Save a snapshot of all latest results (state.json) for dashboards. |

## Disk space

| Command | What it does |
|---|---|
| `SysHealthCLI large D:\ --top 30` | Largest files and folders on drive D:. |
| `SysHealthCLI duplicates C:\Users\Me\Documents` | Find duplicates (same size and type, identical content). |
| `SysHealthCLI duplicates PATH --by name` | Find files with the same name. |
| `SysHealthCLI duplicates PATH --export dups.xlsx` | Save duplicates to an Excel file to review before deleting. |
| `SysHealthCLI longpaths PATH --limit 218` | List paths too long for Office (218) and proposed renames. |
| `SysHealthCLI longpaths PATH --fix --yes` | Apply the proposed renames automatically (undo: longpaths --undo). |

## Cleanup

| Command | What it does |
|---|---|
| `SysHealthCLI cleanup analyze` | Show how much space each cleanup category would free. |
| `SysHealthCLI cleanup run user_temp browser --yes` | Clean the listed categories. |
| `SysHealthCLI cleanup old-downloads --days 90` | List downloads not used for 90 days. |
| `SysHealthCLI cleanup empty PATH` | List empty folders (add --delete --yes to remove them). |
| `SysHealthCLI optimize C` | Optimize a drive: TRIM for SSD, defragment for HDD (admin). |

## Protection

| Command | What it does |
|---|---|
| `SysHealthCLI malware --quick` | Quick scan of Downloads, Desktop, Temp and Startup. |
| `SysHealthCLI malware D:\Projects` | Scan a folder with ClamAV, Defender and the unknown-programs check. |
| `SysHealthCLI signatures update` | Update ClamAV and Defender signatures. |
| `SysHealthCLI clamav install` | Install ClamAV for this operating system (admin on Windows). |
| `SysHealthCLI linux-tools install` | Linux: install helper tools for copying and disk health (xclip, smartmontools). |
| `SysHealthCLI startup` | List startup apps and whether they are enabled. |
| `SysHealthCLI autoruns --hide-microsoft` | Full autorun audit with signature status and risk flags. |
| `SysHealthCLI connections --internet` | Programs currently connected to the internet. |
| `SysHealthCLI vt C:\path\file.exe` | Check a file's hash on VirusTotal (needs a free API key). |
| `SysHealthCLI config set vt-key YOUR_KEY` | Save your VirusTotal API key. |
| `SysHealthCLI quarantine list` | List quarantined files (also: restore ID, purge ID). |

## Network

| Command | What it does |
|---|---|
| `SysHealthCLI dns test` | Benchmark DNS providers against your current DNS. |
| `SysHealthCLI dns set cloudflare --yes` | Switch DNS (cloudflare, google, quad9, opendns, family, auto). |
| `SysHealthCLI speedtest` | Measure latency, download and upload speed. |

## Apps and files

| Command | What it does |
|---|---|
| `SysHealthCLI updates list` | Apps with available updates (winget / apt / dnf / flatpak). |
| `SysHealthCLI updates install --all --yes` | Update everything (or pass package IDs instead of --all). |
| `SysHealthCLI shred FILE --passes 3 --yes` | Securely overwrite and delete files or folders. |

## SysHealth updates

| Command | What it does |
|---|---|
| `SysHealthCLI self-update` | Check for a newer SysHealth and show a summary of what changed. |
| `SysHealthCLI config set update-startup off` | Stop the check when the app starts (on to turn it back on). |
| `SysHealthCLI config set update-repo OWNER/REPO` | Set the GitHub repository that publishes SysHealth releases. |

## Tips

| Command | What it does |
|---|---|
| `Exit codes` | 0 = OK, 1 = problems found or an error occurred, 2 = administrator rights needed. |
| `Administrator` | Windows: open the terminal with 'Run as administrator'. Linux: you are asked for your password when needed. |
| `Scheduling` | Windows Task Scheduler or cron can run e.g. 'SysHealthCLI report --json' daily. |
| `Safety` | Commands that delete, rename or change settings ask for confirmation unless --yes is given. |
