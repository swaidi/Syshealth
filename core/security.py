"""Security posture checks with a 0-100 score and hardening actions."""
from __future__ import annotations

import re
import shutil

from .checks import FAIL, INFO, OK, WARN, Check, Fix
from .platform_utils import IS_WINDOWS, is_admin, open_url_or_file, ps_json, run_cmd, win_system_exe

WEIGHTS = {OK: 1.0, WARN: 0.5, FAIL: 0.0}


def score(checks: list[Check]) -> int:
    rated = [c for c in checks if c.status in WEIGHTS]
    if not rated:
        return 0
    return round(100 * sum(WEIGHTS[c.status] for c in rated) / len(rated))


def _reg(hive_name: str, path: str, value: str):
    import winreg
    hive = winreg.HKEY_LOCAL_MACHINE if hive_name == "HKLM" else winreg.HKEY_CURRENT_USER
    try:
        with winreg.OpenKey(hive, path) as k:
            return winreg.QueryValueEx(k, value)[0]
    except OSError:
        return None


ADMIN_NOTE = "Run as administrator to check this."


def _windows_checks() -> list[Check]:
    checks: list[Check] = []
    script = r"""
$r = [ordered]@{}
try { $r.SecureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $r.SecureBoot = $null }
try { $t = Get-CimInstance -Namespace root\cimv2\Security\MicrosoftTpm -ClassName Win32_Tpm -ErrorAction Stop
      $r.Tpm = [bool]$t; $r.TpmOn = [bool]$t.IsEnabled_InitialValue; $r.TpmVer = "$($t.SpecVersion)".Split(',')[0] }
catch { $r.Tpm = $null }
try { $v = Get-CimInstance -Namespace root\cimv2\Security\MicrosoftVolumeEncryption -ClassName Win32_EncryptableVolume `
      -Filter "DriveLetter='$env:SystemDrive'" -ErrorAction Stop; $r.BitLocker = [int]$v.ProtectionStatus }
catch { $r.BitLocker = $null }
$mp = Get-MpComputerStatus -ErrorAction SilentlyContinue
if ($mp) { $r.RealTime = $mp.RealTimeProtectionEnabled; $r.Tamper = $mp.IsTamperProtected; $r.SigAge = $mp.AntivirusSignatureAge }
$r.FirewallOff = @(Get-NetFirewallProfile -ErrorAction SilentlyContinue | Where-Object { -not $_.Enabled } | ForEach-Object { "$($_.Name)" })
try { $r.SMB1 = [bool](Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { $r.SMB1 = $null }
$g = Get-LocalUser -ErrorAction SilentlyContinue | Where-Object { "$($_.SID)" -like '*-501' }
$r.Guest = if ($g) { [bool]$g.Enabled } else { $null }
[pscustomobject]$r
"""
    rows = ps_json(script)
    r = rows[0] if rows else {}

    # Antivirus
    if r.get("RealTime") is None:
        checks.append(Check("Antivirus", WARN, "Microsoft Defender status unavailable (another antivirus may be "
                            "active).", "open_defender"))
    elif r.get("RealTime"):
        age = r.get("SigAge") or 0
        checks.append(Check("Antivirus", OK if age <= 3 else WARN, f"Real-time protection on; signatures {age} "
                            "day(s) old."))
    else:
        checks.append(Check("Antivirus", FAIL, "Defender real-time protection is off.", "open_defender"))
    if r.get("Tamper") is not None:
        checks.append(Check("Tamper protection", OK if r["Tamper"] else WARN,
                            "On." if r["Tamper"] else "Off: malware could switch off Defender.", "open_defender"))

    off = r.get("FirewallOff") or []
    if isinstance(off, str):
        off = [off]
    checks.append(Check("Firewall", FAIL if off else OK, f"Off for: {', '.join(off)}" if off else
                        "On for all profiles.", "enable_firewall" if off else None))

    lua = _reg("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    prompt = _reg("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "ConsentPromptBehaviorAdmin")
    if lua == 0:
        checks.append(Check("User Account Control", FAIL, "UAC is disabled.", "enable_uac"))
    elif prompt == 0:
        checks.append(Check("User Account Control", WARN, "UAC elevates without asking.", "enable_uac"))
    else:
        checks.append(Check("User Account Control", OK, "Enabled."))

    bl = r.get("BitLocker")
    if bl is None:
        checks.append(Check("Drive encryption (BitLocker)", INFO, ADMIN_NOTE if not is_admin() else
                            "BitLocker is not available on this edition of Windows.", "open_bitlocker"))
    else:
        checks.append(Check("Drive encryption (BitLocker)", OK if bl == 1 else WARN,
                            "System drive is encrypted." if bl == 1 else
                            "System drive is not encrypted; a lost laptop exposes your files.", "open_bitlocker"))

    sb = r.get("SecureBoot")
    checks.append(Check("Secure Boot", INFO if sb is None else (OK if sb else WARN),
                        ADMIN_NOTE if sb is None and not is_admin() else
                        ("Not supported (legacy BIOS)." if sb is None else ("On." if sb else "Off."))))
    tpm = r.get("Tpm")
    checks.append(Check("TPM security chip", INFO if tpm is None else (OK if r.get("TpmOn") else WARN),
                        ADMIN_NOTE if tpm is None else (f"Present, version {r.get('TpmVer') or '?'}." if r.get("TpmOn")
                                                        else "Present but disabled.")))

    smb = r.get("SMB1")
    if smb is not None:
        checks.append(Check("SMBv1 file sharing", FAIL if smb else OK,
                            "Enabled: an outdated protocol used by ransomware such as WannaCry." if smb else "Disabled.",
                            "disable_smb1" if smb else None))
    rdp = _reg("HKLM", r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    checks.append(Check("Remote Desktop", WARN if rdp == 0 else OK,
                        "Enabled: the computer accepts remote logins." if rdp == 0 else "Disabled.",
                        "disable_rdp" if rdp == 0 else None))
    ra = _reg("HKLM", r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp")
    checks.append(Check("Remote Assistance", WARN if ra == 1 else OK, "Enabled." if ra == 1 else "Disabled.",
                        "disable_ra" if ra == 1 else None))
    auto = _reg("HKLM", r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon")
    checks.append(Check("Automatic sign-in", FAIL if str(auto) == "1" else OK,
                        "Windows signs in without a password." if str(auto) == "1" else "Disabled.",
                        "disable_autologon" if str(auto) == "1" else None))
    guest = r.get("Guest")
    if guest is not None:
        checks.append(Check("Guest account", WARN if guest else OK, "Enabled." if guest else "Disabled.",
                            "disable_guest" if guest else None))
    ss = _reg("HKLM", r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen")
    ss2 = _reg("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled")
    off_ss = ss == 0 or (isinstance(ss2, str) and ss2.lower() == "off")
    checks.append(Check("SmartScreen", WARN if off_ss else OK, "Off: downloaded apps are not checked." if off_ss
                        else "On.", "open_defender" if off_ss else None))
    return checks


def _linux_checks() -> list[Check]:
    checks: list[Check] = []
    fw = [s for s in ("ufw", "firewalld") if shutil.which("systemctl")
          and run_cmd(["systemctl", "is-active", s])[1].strip() == "active"]
    checks.append(Check("Firewall", OK if fw else FAIL, f"Active: {', '.join(fw)}" if fw else "No active firewall.",
                        None if fw or not shutil.which("ufw") else "enable_ufw"))
    rc, out = run_cmd(["lsblk", "-o", "TYPE", "-n"])
    enc = "crypt" in out
    checks.append(Check("Disk encryption", OK if enc else WARN,
                        "Encrypted volumes found (LUKS)." if enc else "No encrypted volumes; a lost laptop exposes "
                        "your files."))
    if shutil.which("mokutil"):
        rc, out = run_cmd(["mokutil", "--sb-state"])
        on = "enabled" in out.lower()
        checks.append(Check("Secure Boot", OK if on else WARN, out.strip() or "Unknown."))
    if shutil.which("apt-get"):
        auto = False
        try:
            with open("/etc/apt/apt.conf.d/20auto-upgrades", encoding="utf-8") as fh:
                auto = 'Unattended-Upgrade "1"' in fh.read()
        except OSError:
            pass
        checks.append(Check("Automatic security updates", OK if auto else WARN,
                            "Enabled (unattended-upgrades)." if auto else "Not enabled.",
                            None if auto else "enable_auto_updates"))
    ssh_active = any(run_cmd(["systemctl", "is-active", s])[1].strip() == "active" for s in ("ssh", "sshd")) \
        if shutil.which("systemctl") else False
    if ssh_active:
        cfg = ""
        try:
            with open("/etc/ssh/sshd_config", encoding="utf-8") as fh:
                cfg = fh.read()
        except OSError:
            pass
        root = re.search(r"^\s*PermitRootLogin\s+yes", cfg, re.M)
        pw = not re.search(r"^\s*PasswordAuthentication\s+no", cfg, re.M)
        detail = "SSH server is running" + ("; root login allowed" if root else "") + \
                 ("; password login allowed" if pw else "") + "."
        checks.append(Check("SSH server", FAIL if root else WARN, detail, "disable_ssh"))
    else:
        checks.append(Check("SSH server", OK, "Not running."))
    rc, out = run_cmd(["sh", "-c", "getent group sudo wheel"])
    users = sorted({u for line in out.splitlines() for u in line.split(":")[-1].split(",") if u})
    checks.append(Check("Administrator accounts", INFO, ", ".join(users) or "None found."))
    return checks


def _open_bitlocker(log, cancel) -> None:
    import subprocess
    subprocess.Popen(["control.exe", "/name", "Microsoft.BitLockerDriveEncryption"])


def run_checks(log=None) -> list[Check]:
    checks = _windows_checks() if IS_WINDOWS else _linux_checks()
    checks.insert(0, Check("Security score", INFO, f"{score(checks)} / 100"))
    return checks


def get_fixes() -> dict[str, Fix]:
    fixes: list[Fix] = []
    if IS_WINDOWS:
        reg, netsh = win_system_exe("reg.exe"), win_system_exe("netsh.exe")
        sysp = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        fixes += [
            Fix("enable_firewall", "Turn on Windows Firewall", "Enables the firewall for all profiles.",
                [[netsh, "advfirewall", "set", "allprofiles", "state", "on"]], admin=True),
            Fix("enable_uac", "Turn on User Account Control", "Restores the standard UAC prompt.",
                [[reg, "add", sysp, "/v", "EnableLUA", "/t", "REG_DWORD", "/d", "1", "/f"],
                 [reg, "add", sysp, "/v", "ConsentPromptBehaviorAdmin", "/t", "REG_DWORD", "/d", "5", "/f"]],
                admin=True, reboot=True),
            Fix("disable_smb1", "Turn off SMBv1", "Disables the outdated SMBv1 file-sharing protocol.",
                [["powershell", "-NoProfile", "-Command", "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force"]],
                admin=True),
            Fix("disable_rdp", "Turn off Remote Desktop", "Stops the computer from accepting remote logins.",
                [[reg, "add", r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server", "/v", "fDenyTSConnections",
                  "/t", "REG_DWORD", "/d", "1", "/f"]], admin=True),
            Fix("disable_ra", "Turn off Remote Assistance", "Disables unsolicited remote help invitations.",
                [[reg, "add", r"HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance", "/v", "fAllowToGetHelp",
                  "/t", "REG_DWORD", "/d", "0", "/f"]], admin=True),
            Fix("disable_autologon", "Turn off automatic sign-in", "Requires a password at sign-in.",
                [[reg, "add", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "/v", "AutoAdminLogon",
                  "/t", "REG_SZ", "/d", "0", "/f"]], admin=True),
            Fix("disable_guest", "Disable the Guest account", "Turns off the built-in Guest account.",
                [["powershell", "-NoProfile", "-Command",
                  "Get-LocalUser | Where-Object { \"$($_.SID)\" -like '*-501' } | Disable-LocalUser"]], admin=True),
            Fix("open_bitlocker", "Open BitLocker settings", "Opens BitLocker Drive Encryption in Control Panel.",
                python_fn=_open_bitlocker),
            Fix("open_defender", "Open Windows Security", "Opens Windows Security to review protection settings.",
                python_fn=lambda log, c: open_url_or_file("windowsdefender:")),
        ]
    else:
        fixes += [
            Fix("enable_ufw", "Turn on the firewall (UFW)", "Enables UFW with default deny-incoming.",
                [["ufw", "enable"]], admin=True),
            Fix("enable_auto_updates", "Enable automatic security updates", "Installs and enables unattended-upgrades.",
                [["apt-get", "install", "-y", "unattended-upgrades"],
                 ["dpkg-reconfigure", "-f", "noninteractive", "unattended-upgrades"]], admin=True),
            Fix("disable_ssh", "Stop and disable the SSH server", "Stops remote SSH logins to this computer.",
                [["sh", "-c", "systemctl disable --now ssh 2>/dev/null || systemctl disable --now sshd"]],
                admin=True),
        ]
    return {f.id: f for f in fixes}
