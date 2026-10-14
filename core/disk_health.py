"""Physical disk and volume health checks with repair actions."""
from __future__ import annotations

import json
import os
import shutil

from .checks import FAIL, INFO, OK, WARN, Check, Fix
from .platform_utils import (IS_WINDOWS, human_size, is_admin, ps_json, run_cmd, win_system_exe,
                             windows_drive_letters)


def _smartctl() -> str | None:
    found = shutil.which("smartctl")
    if found:
        return found
    if IS_WINDOWS:
        cand = os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"), "smartmontools", "bin", "smartctl.exe")
        if os.path.isfile(cand):
            return cand
    return None


def _linux_disks() -> list[dict]:
    rc, out = run_cmd(["lsblk", "-J", "-d", "-o", "NAME,TYPE,SIZE,MODEL,ROTA,TRAN"])
    try:
        return [d for d in json.loads(out).get("blockdevices", []) if d.get("type") == "disk"
                and not d.get("name", "").startswith(("loop", "zram", "ram"))]
    except (json.JSONDecodeError, AttributeError):
        return []


_STATUS = {"Healthy": OK, "Warning": WARN, "Unhealthy": FAIL}


# --------------------------------------------------------------------------- checks
def run_checks(log=None) -> list[Check]:
    checks: list[Check] = []
    if IS_WINDOWS:
        script = (
            "Get-PhysicalDisk | ForEach-Object { $r = $null; "
            "try { $r = $_ | Get-StorageReliabilityCounter -ErrorAction Stop } catch {}; "
            "[pscustomobject]@{ Name=$_.FriendlyName; Media=\"$($_.MediaType)\"; Bus=\"$($_.BusType)\"; "
            "Health=\"$($_.HealthStatus)\"; Status=\"$($_.OperationalStatus)\"; Size=$_.Size; "
            "Temp=$r.Temperature; Wear=$r.Wear; ReadErr=$r.ReadErrorsUncorrected; "
            "WriteErr=$r.WriteErrorsUncorrected; Hours=$r.PowerOnHours } }")
        for d in ps_json(script):
            status = _STATUS.get(d.get("Health", ""), WARN)
            parts = [f"{d.get('Media')} {d.get('Bus')}", human_size(d.get("Size") or 0),
                     f"health {d.get('Health')}", f"status {d.get('Status')}"]
            if d.get("Temp"):
                parts.append(f"{d['Temp']}°C")
                if d["Temp"] >= 60:
                    status = WARN if status == OK else status
            if d.get("Wear") is not None:
                parts.append(f"wear {d['Wear']}%")
                if d["Wear"] >= 80:
                    status = WARN if status == OK else status
            errs = (d.get("ReadErr") or 0) + (d.get("WriteErr") or 0)
            if errs:
                parts.append(f"{errs} uncorrected errors")
                status = FAIL
            if d.get("Hours"):
                parts.append(f"{d['Hours']:,} power-on hours")
            checks.append(Check(f"Disk: {d.get('Name')}", status, ", ".join(parts),
                                "smart_check" if status != OK and _smartctl() else None))
        if not is_admin():
            checks.append(Check("Detailed disk counters", INFO,
                                "Run as administrator to read temperature, wear and error counters."))
        vols = ps_json("Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter, FileSystemLabel, "
                       "FileSystem, @{n='Health';e={\"$($_.HealthStatus)\"}}, Size, SizeRemaining")
        for v in vols:
            letter = str(v.get("DriveLetter"))
            status = _STATUS.get(v.get("Health", ""), WARN)
            checks.append(Check(f"Volume {letter}:", status,
                                f"{v.get('FileSystem')} '{v.get('FileSystemLabel') or ''}', "
                                f"health {v.get('Health')}, {human_size(v.get('SizeRemaining') or 0)} free",
                                f"scan:{letter}" if status == OK else f"spotfix:{letter}"))
    else:
        for d in _linux_disks():
            kind = "HDD" if str(d.get("rota")) in ("1", "True", "true") else "SSD"
            checks.append(Check(f"Disk: /dev/{d['name']}", INFO,
                                f"{(d.get('model') or '').strip()} {kind} {d.get('tran') or ''} {d.get('size')}",
                                "smart_check" if _smartctl() else None))
        if not _smartctl():
            checks.append(Check("SMART monitoring", WARN, "smartmontools is not installed; install it to read "
                                "drive health (sudo apt install smartmontools)."))
        else:
            checks.append(Check("SMART health", INFO, "Run 'SMART health report' to read drive self-assessment."))
    return checks


# --------------------------------------------------------------------------- fixes
def get_fixes() -> dict[str, Fix]:
    fixes: list[Fix] = []
    smart = _smartctl()
    if IS_WINDOWS:
        chkdsk = win_system_exe("chkdsk.exe")
        system_letter = os.environ.get("SystemDrive", "C:")[0].upper()
        for L in windows_drive_letters():
            fixes += [
                Fix(f"scan:{L}", f"Check drive {L}: (online scan)",
                    "Scans the file system for errors without taking the drive offline.",
                    [[chkdsk, f"{L}:", "/scan"]], admin=True),
                Fix(f"spotfix:{L}", f"Quick repair drive {L}: (spot fix)",
                    "Fixes errors found by the online scan. The system drive is repaired at the next restart.",
                    [["powershell", "-NoProfile", "-Command", f"Repair-Volume -DriveLetter {L} -SpotFix -Verbose"]],
                    admin=True, reboot=(L == system_letter)),
                Fix(f"optimize:{L}", f"Optimize drive {L}: (TRIM / defragment)",
                    "Runs TRIM on SSDs or defragmentation on hard drives.",
                    [["powershell", "-NoProfile", "-Command", f"Optimize-Volume -DriveLetter {L} -Verbose"]],
                    admin=True),
                Fix(f"fullfix:{L}", f"Full repair drive {L}: (chkdsk /f)",
                    ("Schedules a full repair at the next restart." if L == system_letter else
                     "Locks the drive and repairs it now. Close all files on this drive first."),
                    [[chkdsk, f"{L}:", "/f", "/x"] if L != system_letter else [chkdsk, f"{L}:", "/f"]],
                    admin=True, reboot=(L == system_letter), stdin="Y\nY\n"),
            ]
        if smart:
            fixes.append(Fix("smart_check", "SMART health report", "Reads each drive's self-assessment (smartctl).",
                             [["powershell", "-NoProfile", "-Command",
                               f"& '{smart}' --scan | ForEach-Object {{ $d = ($_ -split ' ')[0]; "
                               f"Write-Output \"### $d\"; & '{smart}' -H -A $d }}"]], admin=True))
    else:
        devs = [f"/dev/{d['name']}" for d in _linux_disks()]
        if smart and devs:
            loop = "; ".join(f"echo '### {d}'; {smart} -H {d}" for d in devs)
            fixes += [
                Fix("smart_check", "SMART health report", "Reads each drive's self-assessment.",
                    [["sh", "-c", loop]], admin=True),
                Fix("smart_test", "Start SMART short self-test", "Runs a 2-minute self-test inside each drive. "
                    "Run the health report afterwards to see the result.",
                    [["sh", "-c", "; ".join(f"{smart} -t short {d}" for d in devs)]], admin=True),
            ]
        if shutil.which("fstrim"):
            fixes.append(Fix("trim", "TRIM all SSDs", "Tells SSDs which blocks are free (improves speed and "
                             "lifespan).", [["fstrim", "-av"]], admin=True))

        def _fsck_info(log, cancel):
            if log:
                log("A mounted Linux file system cannot be repaired while in use. To repair it:")
                log("  1) Boot from a live USB, then run: sudo fsck -f /dev/<partition>")
                log("  2) Or add 'fsck.mode=force' to the kernel line in GRUB for one boot.")
        fixes.append(Fix("fsck_info", "How to repair a Linux file system", "Shows safe repair steps.",
                         python_fn=_fsck_info))
    return {f.id: f for f in fixes}
