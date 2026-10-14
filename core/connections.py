"""Network connections with owning process, and per-program firewall blocking."""
from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass

import psutil

from .platform_utils import IS_WINDOWS, NeedsAdmin, is_admin, run_cmd, win_system_exe

SYSTEM_NAMES = {"system", "svchost.exe", "lsass.exe", "services.exe", "wininit.exe", "system idle process",
                "systemd", "systemd-resolved", "avahi-daemon", "cupsd", "networkmanager", "chronyd"}


@dataclass
class Conn:
    proto: str
    local: str
    remote: str
    status: str
    pid: int
    process: str
    exe: str
    remote_ip: str = ""
    remote_port: int = 0
    flags: tuple = ()

    @property
    def is_listening(self) -> bool:
        return self.status == "LISTEN" or (self.proto == "UDP" and not self.remote)


def _fmt(addr) -> str:
    if not addr:
        return ""
    ip, port = addr.ip, addr.port
    return f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"


def is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified)
    except ValueError:
        return False


def list_connections() -> list[Conn]:
    procs: dict[int, tuple[str, str]] = {}
    out = []
    try:
        conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        raise NeedsAdmin("List network connections")
    for c in conns:
        pid = c.pid or 0
        if pid not in procs:
            name, exe = "", ""
            if pid:
                try:
                    p = psutil.Process(pid)
                    name = p.name()
                    try:
                        exe = p.exe()
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        exe = ""
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            procs[pid] = (name or ("System" if pid in (0, 4) else "?"), exe)
        name, exe = procs[pid]
        proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
        flags = []
        if c.status == "LISTEN" and c.laddr and c.laddr.ip in ("0.0.0.0", "::") and name.lower() not in SYSTEM_NAMES:
            flags.append("Open to the network")
        rip = c.raddr.ip if c.raddr else ""
        if rip and is_public(rip) and c.status == "ESTABLISHED":
            flags.append("Internet")
        out.append(Conn(proto, _fmt(c.laddr), _fmt(c.raddr), c.status if proto == "TCP" else "", pid, name, exe,
                        rip, c.raddr.port if c.raddr else 0, tuple(flags)))
    out.sort(key=lambda x: (x.process.lower(), x.proto, x.remote))
    return out


def reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, UnicodeError):
        return ""


def end_process(pid: int) -> None:
    try:
        p = psutil.Process(pid)
        p.terminate()
        p.wait(timeout=5)
    except psutil.TimeoutExpired:
        psutil.Process(pid).kill()
    except psutil.AccessDenied:
        raise NeedsAdmin("End process")


def block_program(exe: str) -> str:
    """Windows: add inbound and outbound firewall rules blocking this program."""
    if not IS_WINDOWS:
        raise RuntimeError("Per-program blocking is only available on Windows. On Linux, use a tool such as "
                           "OpenSnitch for application firewalling.")
    if not is_admin():
        raise NeedsAdmin("Block program in firewall")
    if not exe or not os.path.isfile(exe):
        raise RuntimeError("The program's file path is unknown, so it cannot be blocked.")
    netsh = win_system_exe("netsh.exe")
    name = f"SysHealth block {os.path.basename(exe)}"
    for direction in ("out", "in"):
        rc, out = run_cmd([netsh, "advfirewall", "firewall", "add", "rule", f"name={name}", f"dir={direction}",
                           "action=block", f"program={exe}", "enable=yes"])
        if rc != 0:
            raise RuntimeError(out.strip())
    return name


def unblock_program(exe: str) -> None:
    if not IS_WINDOWS:
        return
    if not is_admin():
        raise NeedsAdmin("Remove firewall block")
    name = f"SysHealth block {os.path.basename(exe)}"
    run_cmd([win_system_exe("netsh.exe"), "advfirewall", "firewall", "delete", "rule", f"name={name}"])


def summary(conns: list[Conn]) -> dict:
    return {"total": len(conns), "listening": sum(1 for c in conns if c.status == "LISTEN"),
            "established": sum(1 for c in conns if c.status == "ESTABLISHED"),
            "exposed": sum(1 for c in conns if "Open to the network" in c.flags)}
