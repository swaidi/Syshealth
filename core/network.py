"""Network diagnostics and repair actions."""
from __future__ import annotations

import os
import re
import shutil
import socket
import time
import threading
import urllib.request

import psutil
from typing import Optional

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


VPN_NAME_PARTS = ("vpn", "proton", "wireguard", "openvpn", "tap-windows", "nordlynx", "fortinet", "anyconnect",
                  "globalprotect", "pangp", "zscaler", "tailscale", "zerotier", "wg0", "tun0", "tun1", "ppp0")
# Security and management agents that show a computer is managed by an organization (service or process names)
MANAGEMENT_AGENTS = {"csfalconservice": "CrowdStrike Falcon", "falcon-sensor": "CrowdStrike Falcon",
                     "sentinelagent": "SentinelOne", "sentinelone": "SentinelOne", "stagentsvc": "Netskope",
                     "zsatunnel": "Zscaler", "cylancesvc": "Cylance", "intunemanagementextension": "Microsoft Intune",
                     "ccmexec": "Microsoft Configuration Manager", "sense": "Microsoft Defender for Endpoint"}
RISKY_ON_MANAGED = {"reset_stack", "renew_ip", "reset_proxy", "disable_user_proxy"}
_managed_cache: Optional[str] = None


def vpn_adapters() -> list[str]:
    """Names of connected network adapters that belong to a VPN."""
    try:
        stats = psutil.net_if_stats()
    except OSError:
        return []
    return sorted(n for n, st in stats.items() if st.isup and any(p in n.lower() for p in VPN_NAME_PARTS))


def managed_device() -> str:
    """A sentence describing how this computer is managed by an organization, or "" for a personal computer."""
    global _managed_cache
    if _managed_cache is not None:
        return _managed_cache
    found: list[str] = []
    if IS_WINDOWS:
        rows = ps_json("Get-CimInstance Win32_ComputerSystem | Select-Object PartOfDomain, Domain")
        if rows and rows[0].get("PartOfDomain"):
            found.append(f"joined to the domain {rows[0].get('Domain')}")
        rc, out = run_cmd([win_system_exe("dsregcmd.exe"), "/status"], timeout=20)
        if rc == 0 and re.search(r"AzureAdJoined\s*:\s*YES", out):
            found.append("joined to Microsoft Entra ID (Azure AD)")
        try:
            for svc in psutil.win_service_iter():
                name = svc.name().lower()
                if name in MANAGEMENT_AGENTS and (name != "sense" or svc.status() == "running"):
                    found.append(MANAGEMENT_AGENTS[name])
        except Exception:
            pass
    else:
        for proc in psutil.process_iter(["name"]):
            name = (proc.info.get("name") or "").lower()
            if name in MANAGEMENT_AGENTS:
                found.append(MANAGEMENT_AGENTS[name])
        if shutil.which("realm") and run_cmd(["realm", "list"], timeout=10)[1].strip():
            found.append("joined to a company directory")
    found = list(dict.fromkeys(found))
    _managed_cache = ("This computer is managed by your organization (" + "; ".join(found) + ").") if found else ""
    return _managed_cache


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

    # Context: VPNs and company management explain many "failures" on office networks
    vpns = vpn_adapters()
    managed = managed_device()
    risky_fix = None if managed else "reset_stack"

    # Internet: test like a browser first (a normal web request, honouring the system proxy),
    # then direct connections, which office firewalls often block on purpose
    probe = _http_probe()
    web_ok = probe == "ok"
    ip_ok = _tcp_ok("1.1.1.1", 443) or _tcp_ok("8.8.8.8", 53)

    gw = default_gateway()
    if not gw:
        checks.append(Check("Default gateway", INFO if web_ok else FAIL, "No default gateway configured" +
                            (" (normal while a VPN routes all traffic)." if web_ok else "."),
                            None if web_ok else "renew_ip"))
    elif _ping(gw):
        checks.append(Check("Default gateway", OK, f"{gw} is reachable."))
    else:
        checks.append(Check("Default gateway", INFO if web_ok else WARN,
                            f"{gw} does not answer ping. Many routers and office networks block ping on purpose"
                            + ("; the internet works, so this is harmless." if web_ok else "."),
                            None if web_ok else "renew_ip"))

    if web_ok:
        checks.append(Check("Internet", OK, "Web access works (tested with a normal web request)."))
        if not ip_ok:
            checks.append(Check("Direct connections", INFO, "Direct connections to public DNS servers (1.1.1.1, "
                                "8.8.8.8) are blocked by this network. This is common on company networks and "
                                "does not affect normal use."))
    elif probe == "captive":
        checks.append(Check("Internet", WARN, "A login page (captive portal) or proxy intercepts web traffic. "
                            "Open a browser and sign in to the network."))
    elif ip_ok:
        checks.append(Check("Internet", WARN, "Public addresses are reachable, but the web test failed. A proxy, "
                            "firewall or security software may be filtering web traffic.",
                            None if managed else ("reset_proxy" if IS_WINDOWS else None)))
    else:
        checks.append(Check("Internet", FAIL, "No internet access: the web test and direct connections failed." +
                            (" This computer is managed by your organization; contact IT before resetting "
                             "network settings." if managed else ""), risky_fix))

    # DNS: several names, a patient timeout, and timing so slow lookups are reported as slow, not broken
    resolved, slowest = 0, 0.0
    for name in ("www.microsoft.com", "www.google.com", "www.cloudflare.com", "github.com"):
        started = time.monotonic()
        if _dns_ok(name, timeout=8):
            resolved += 1
            slowest = max(slowest, time.monotonic() - started)
    if resolved == 0 and not web_ok:
        checks.append(Check("DNS resolution", FAIL, "Domain names do not resolve.", "flush_dns"))
    elif resolved == 0:
        checks.append(Check("DNS resolution", INFO, "Lookups from this app failed, but web access works; your "
                            "network or proxy resolves names for you."))
    elif slowest > 2:
        cause = (f" A VPN adapter ({vpns[0]}) may be listed first with a DNS server that does not answer while "
                 "the VPN is disconnected." if vpns else "")
        checks.append(Check("DNS resolution", WARN, f"Names resolve, but slowly ({slowest:.1f} s).{cause}",
                            "flush_dns"))
    elif resolved < 4:
        checks.append(Check("DNS resolution", WARN, f"Only {resolved} of 4 test names resolved; some lookups fail "
                            "or time out. A filtering DNS server, VPN or security software may be blocking them.",
                            "flush_dns"))
    else:
        checks.append(Check("DNS resolution", OK, "Domain names resolve correctly (4 of 4 tested)."))

    if vpns:
        checks.append(Check("VPN", INFO, "VPN adapters present: " + ", ".join(vpns) + ". VPNs change routes and "
                            "DNS servers, which can explain slow lookups or repeated sign-in prompts."))
    if managed:
        checks.append(Check("Managed computer", INFO, managed + " Network resets and proxy changes can break "
                            "company settings; contact IT before using them."))

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
