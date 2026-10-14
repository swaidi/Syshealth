"""Network diagnostics and repair actions."""
from __future__ import annotations

import os
import re
import shutil
import socket
import threading
import urllib.request

import psutil

from .checks import FAIL, INFO, OK, WARN, Check, Fix
from .platform_utils import IS_WINDOWS, open_url_or_file, ps_json, run_cmd, win_system_exe

PROBE_URL = "http://www.msftconnecttest.com/connecttest.txt"
PROBE_TEXT = b"Microsoft Connect Test"


def _hosts_path() -> str:
    if IS_WINDOWS:
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


def _tcp_ok(host: str, port: int, timeout: float = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _dns_ok(name: str, timeout: float = 5) -> bool:
    result = {"ok": False}

    def worker():
        try:
            socket.getaddrinfo(name, 443)
            result["ok"] = True
        except OSError:
            pass

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    t.join(timeout)
    return result["ok"]


def _http_probe() -> str:
    try:
        with urllib.request.urlopen(PROBE_URL, timeout=6) as resp:
            body = resp.read(200)
        return "ok" if PROBE_TEXT in body else "captive"
    except Exception:
        return "fail"


def default_gateway() -> str:
    if IS_WINDOWS:
        rows = ps_json("Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
                       "Sort-Object RouteMetric | Select-Object -First 1 NextHop")
        return rows[0].get("NextHop", "") if rows else ""
    rc, out = run_cmd(["ip", "route", "show", "default"])
    m = re.search(r"default via (\S+)", out)
    return m.group(1) if m else ""


def _ping(host: str) -> bool:
    cmd = ["ping", "-n", "1", "-w", "1500", host] if IS_WINDOWS else ["ping", "-c", "1", "-W", "2", host]
    rc, _ = run_cmd(cmd, timeout=10)
    return rc == 0


def _hosts_entries() -> list[str]:
    entries = []
    try:
        with open(_hosts_path(), "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                parts = line.split()
                names = [n.lower() for n in parts[1:]]
                if parts[0] in ("127.0.0.1", "::1", "127.0.1.1", "fe00::0", "ff00::0", "ff02::1", "ff02::2") and \
                        all(n.startswith(("localhost", "ip6-")) or "." not in n for n in names):
                    continue
                entries.append(line)
    except OSError:
        pass
    return entries


# --------------------------------------------------------------------------- checks
def run_checks(log=None) -> list[Check]:
    checks: list[Check] = []

    # Adapters and addresses
    stats, addrs = psutil.net_if_stats(), psutil.net_if_addrs()
    active, apipa = [], []
    for name, st in stats.items():
        if not st.isup or name.lower() == "lo" or name.lower().startswith("loopback"):
            continue
        for a in addrs.get(name, []):
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                (apipa if a.address.startswith("169.254.") else active).append(f"{name} ({a.address})")
    if active:
        checks.append(Check("Network adapters", OK, ", ".join(active)))
    elif apipa:
        checks.append(Check("Network adapters", FAIL,
                            "No address from the router (169.254.x.x): " + ", ".join(apipa), "renew_ip"))
    else:
        checks.append(Check("Network adapters", FAIL, "No connected adapter with an IPv4 address.", "renew_ip"))

    # Gateway
    gw = default_gateway()
    if not gw:
        checks.append(Check("Default gateway", FAIL, "No default gateway configured.", "renew_ip"))
    elif _ping(gw):
        checks.append(Check("Default gateway", OK, f"{gw} is reachable."))
    else:
        checks.append(Check("Default gateway", WARN, f"{gw} does not answer ping (some routers block ping).",
                            "renew_ip"))

    # Internet
    ip_ok = _tcp_ok("1.1.1.1", 443) or _tcp_ok("8.8.8.8", 53)
    checks.append(Check("Internet (IP)", OK if ip_ok else FAIL,
                        "Public internet reachable." if ip_ok else "Cannot reach public IP addresses.",
                        None if ip_ok else "reset_stack"))

    dns_ok = _dns_ok("www.microsoft.com") and _dns_ok("www.google.com")
    if dns_ok:
        checks.append(Check("DNS resolution", OK, "Domain names resolve correctly."))
    else:
        checks.append(Check("DNS resolution", FAIL, "Domain names do not resolve.", "flush_dns"))

    if ip_ok and dns_ok:
        probe = _http_probe()
        if probe == "ok":
            checks.append(Check("Web access", OK, "HTTP connectivity test passed."))
        elif probe == "captive":
            checks.append(Check("Web access", WARN, "A login page (captive portal) or proxy intercepts traffic."))
        else:
            checks.append(Check("Web access", WARN, "HTTP test failed; a proxy or firewall may block web traffic.",
                                "reset_proxy" if IS_WINDOWS else None))

    # DNS servers
    if IS_WINDOWS:
        rows = ps_json("Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | "
                       "Select-Object InterfaceAlias, ServerAddresses")
        servers = "; ".join(f"{r.get('InterfaceAlias')}: {', '.join(r.get('ServerAddresses') or [])}" for r in rows)
    else:
        servers = ""
        try:
            with open("/etc/resolv.conf", encoding="utf-8") as fh:
                servers = ", ".join(l.split()[1] for l in fh if l.startswith("nameserver"))
        except OSError:
            pass
    checks.append(Check("DNS servers", INFO, servers or "Not detected."))

    # Proxy
    if IS_WINDOWS:
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as k:
                enabled = winreg.QueryValueEx(k, "ProxyEnable")[0]
                server = winreg.QueryValueEx(k, "ProxyServer")[0] if enabled else ""
            if enabled:
                checks.append(Check("Proxy (user)", WARN, f"Proxy enabled: {server}. Disable it unless your "
                                    "network requires it.", "disable_user_proxy"))
            else:
                checks.append(Check("Proxy (user)", OK, "No proxy configured."))
        except OSError:
            pass
    else:
        proxy = os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY")
        checks.append(Check("Proxy", INFO if proxy else OK, f"Proxy variable set: {proxy}" if proxy else
                            "No proxy environment variable."))

    # Firewall
    if IS_WINDOWS:
        rows = ps_json("Get-NetFirewallProfile | Select-Object Name, Enabled")
        off = [r.get("Name") for r in rows if not r.get("Enabled")]
        if rows:
            checks.append(Check("Firewall", WARN if off else OK,
                                f"Disabled for: {', '.join(off)}" if off else "Enabled for all profiles.",
                                "enable_firewall" if off else None))
    else:
        active_fw = [svc for svc in ("ufw", "firewalld")
                     if shutil.which("systemctl") and run_cmd(["systemctl", "is-active", svc])[1].strip() == "active"]
        has_ufw = bool(shutil.which("ufw"))
        checks.append(Check("Firewall", OK if active_fw else WARN,
                            f"Active: {', '.join(active_fw)}" if active_fw else "No active firewall service detected.",
                            None if active_fw or not has_ufw else "enable_firewall"))

    # Hosts file
    entries = _hosts_entries()
    if entries:
        checks.append(Check("Hosts file", WARN, f"{len(entries)} custom entr{'y' if len(entries) == 1 else 'ies'} "
                            f"(review for unwanted redirects): {entries[0]}" + (" …" if len(entries) > 1 else ""),
                            "open_hosts"))
    else:
        checks.append(Check("Hosts file", OK, "No custom redirects."))
    return checks


# --------------------------------------------------------------------------- fixes
def _open_hosts(log, cancel):
    path = _hosts_path()
    if IS_WINDOWS:
        import subprocess
        subprocess.Popen(["notepad.exe", path])
        if log:
            log("Opened the hosts file in Notepad. Run SysHealth as administrator to save changes.")
    else:
        open_url_or_file(path)
        if log:
            log(f"Opened {path}. Editing requires: sudo nano {path}")


def _disable_user_proxy(log, cancel):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 0)
    if log:
        log("User proxy disabled. Restart your browser to apply.")


def get_fixes() -> dict[str, Fix]:
    fixes: list[Fix] = []
    if IS_WINDOWS:
        ipconfig, netsh = win_system_exe("ipconfig.exe"), win_system_exe("netsh.exe")
        fixes += [
            Fix("flush_dns", "Flush DNS cache", "Clears cached domain lookups.", [[ipconfig, "/flushdns"]]),
            Fix("renew_ip", "Renew IP address", "Releases and requests a new address from the router.",
                [[ipconfig, "/release"], [ipconfig, "/renew"]], admin=True),
            Fix("reset_proxy", "Reset system (WinHTTP) proxy", "Removes the system-wide proxy setting.",
                [[netsh, "winhttp", "reset", "proxy"]], admin=True),
            Fix("disable_user_proxy", "Disable user proxy", "Turns off the proxy in Windows Internet Settings.",
                python_fn=_disable_user_proxy),
            Fix("enable_firewall", "Enable Windows Firewall", "Turns the firewall on for all profiles.",
                [[netsh, "advfirewall", "set", "allprofiles", "state", "on"]], admin=True),
            Fix("reset_stack", "Full network reset", "Flushes DNS and resets Winsock and TCP/IP. "
                "Restart the computer afterwards.",
                [[ipconfig, "/flushdns"], [netsh, "winsock", "reset"], [netsh, "int", "ip", "reset"]],
                admin=True, reboot=True),
            Fix("open_hosts", "Open hosts file", "Opens the hosts file for review.", python_fn=_open_hosts),
        ]
    else:
        flush = [["resolvectl", "flush-caches"]] if shutil.which("resolvectl") else []
        fixes += [
            Fix("flush_dns", "Flush DNS cache", "Clears cached domain lookups (systemd-resolved).",
                flush, admin=True),
            Fix("renew_ip", "Restart networking", "Turns NetworkManager networking off and on.",
                [["nmcli", "networking", "off"], ["nmcli", "networking", "on"]]),
            Fix("reset_stack", "Restart network service", "Restarts NetworkManager.",
                [["systemctl", "restart", "NetworkManager"]], admin=True),
            Fix("enable_firewall", "Enable UFW firewall", "Enables the Uncomplicated Firewall.",
                [["ufw", "enable"]], admin=True),
            Fix("open_hosts", "Open hosts file", "Opens /etc/hosts for review.", python_fn=_open_hosts),
        ]
    return {f.id: f for f in fixes if f.commands or f.python_fn}
