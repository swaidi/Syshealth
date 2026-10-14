"""Command-line cheat sheet, shared by `cli.py cheatsheet`, the Command Line page and CHEATSHEET.md."""
from __future__ import annotations

import sys

# On Windows the console build is SysHealthCLI.exe; from source it is `python cli.py`.
CMD = "SysHealthCLI" if getattr(sys, "frozen", False) else "python cli.py"

# (section, [(command, description)])
SECTIONS: list[tuple[str, list[tuple[str, str]]]] = [
    ("Getting help", [
        ("{cmd} --help", "List all commands."),
        ("{cmd} <command> --help", "Show the options of one command."),
        ("{cmd} cheatsheet", "Print this cheat sheet."),
        ("{cmd} <command> --json", "Any command: output machine-readable JSON (for scripts)."),
    ]),
    ("Health checks", [
        ("{cmd} check all", "Run network, system, disk and security checks."),
        ("{cmd} check security", "Security score and findings (also: network, system, disk)."),
        ("{cmd} events --days 7", "Summarize serious event-log errors from the last 7 days."),
        ("{cmd} changes --days 14", "Timeline of app installs, updates, new services, drivers and restarts."),
        ("{cmd} report", "Save a snapshot of all latest results (state.json) for dashboards."),
    ]),
    ("Disk space", [
        ("{cmd} large D:\\ --top 30", "Largest files and folders on drive D:."),
        ("{cmd} duplicates C:\\Users\\Me\\Documents", "Find duplicates (same size and type, identical content)."),
        ("{cmd} duplicates PATH --by name", "Find files with the same name."),
        ("{cmd} longpaths PATH --limit 218", "List paths too long for Office (218) and proposed renames."),
        ("{cmd} longpaths PATH --fix --yes", "Apply the proposed renames automatically (undo: longpaths --undo)."),
    ]),
    ("Cleanup", [
        ("{cmd} cleanup analyze", "Show how much space each cleanup category would free."),
        ("{cmd} cleanup run user_temp browser --yes", "Clean the listed categories."),
        ("{cmd} cleanup old-downloads --days 90", "List downloads not used for 90 days."),
        ("{cmd} cleanup empty PATH", "List empty folders (add --delete --yes to remove them)."),
        ("{cmd} optimize C", "Optimize a drive: TRIM for SSD, defragment for HDD (admin)."),
    ]),
    ("Protection", [
        ("{cmd} malware --quick", "Quick scan of Downloads, Desktop, Temp and Startup."),
        ("{cmd} malware D:\\Projects", "Scan a folder with ClamAV, Defender and the unknown-programs check."),
        ("{cmd} signatures update", "Update ClamAV and Defender signatures."),
        ("{cmd} clamav install", "Install ClamAV for this operating system (admin on Windows)."),
        ("{cmd} startup", "List startup apps and whether they are enabled."),
        ("{cmd} autoruns --hide-microsoft", "Full autorun audit with signature status and risk flags."),
        ("{cmd} connections --internet", "Programs currently connected to the internet."),
        ("{cmd} vt C:\\path\\file.exe", "Check a file's hash on VirusTotal (needs a free API key)."),
        ("{cmd} config set vt-key YOUR_KEY", "Save your VirusTotal API key."),
        ("{cmd} quarantine list", "List quarantined files (also: restore ID, purge ID)."),
    ]),
    ("Network", [
        ("{cmd} dns test", "Benchmark DNS providers against your current DNS."),
        ("{cmd} dns set cloudflare --yes", "Switch DNS (cloudflare, google, quad9, opendns, family, auto)."),
        ("{cmd} speedtest", "Measure latency, download and upload speed."),
    ]),
    ("Apps and files", [
        ("{cmd} updates list", "Apps with available updates (winget / apt / dnf / flatpak)."),
        ("{cmd} updates install --all --yes", "Update everything (or pass package IDs instead of --all)."),
        ("{cmd} shred FILE --passes 3 --yes", "Securely overwrite and delete files or folders."),
    ]),
    ("SysHealth updates", [
        ("{cmd} self-update", "Check for a newer SysHealth and show a summary of what changed."),
        ("{cmd} config set update-startup off", "Stop the check when the app starts (on to turn it back on)."),
        ("{cmd} config set update-repo OWNER/REPO", "Set the GitHub repository that publishes SysHealth releases."),
    ]),
    ("Tips", [
        ("Exit codes", "0 = OK, 1 = problems found or an error occurred, 2 = administrator rights needed."),
        ("Administrator", "Windows: open the terminal with 'Run as administrator'. Linux: you are asked for "
                          "your password when needed."),
        ("Scheduling", "Windows Task Scheduler or cron can run e.g. '{cmd} report --json' daily."),
        ("Safety", "Commands that delete, rename or change settings ask for confirmation unless --yes is given."),
    ]),
]


def rows(cmd: str = CMD) -> list[tuple[str, str, str]]:
    return [(section, c.format(cmd=cmd), d.format(cmd=cmd)) for section, items in SECTIONS for c, d in items]


def as_text(cmd: str = CMD) -> str:
    out = ["SysHealth command-line cheat sheet", "=" * 38, ""]
    for section, items in SECTIONS:
        out.append(section.upper())
        width = max(len(c.format(cmd=cmd)) for c, _ in items)
        for c, d in items:
            out.append(f"  {c.format(cmd=cmd):<{width}}  {d.format(cmd=cmd)}")
        out.append("")
    return "\n".join(out)


def as_markdown(cmd: str = "SysHealthCLI") -> str:
    out = ["# SysHealth Command-Line Cheat Sheet", "",
           "Run from a terminal. From source, replace `SysHealthCLI` with `python cli.py`.", ""]
    for section, items in SECTIONS:
        out += [f"## {section}", "", "| Command | What it does |", "|---|---|"]
        for c, d in items:
            out.append(f"| `{c.format(cmd=cmd)}` | {d.format(cmd=cmd)} |")
        out.append("")
    return "\n".join(out)
