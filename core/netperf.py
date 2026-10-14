"""DNS benchmark and switcher, plus an internet speed test (Cloudflare speed endpoints)."""
from __future__ import annotations

import http.client
import os
import random
import re
import shutil
import socket
import statistics
import struct
import threading
import time
from typing import Callable, Optional

from .checks import Fix
from .platform_utils import IS_WINDOWS, Cancelled, ps_json, run_cmd, win_system_exe

LogFn = Optional[Callable[[str], None]]

PROVIDERS = {
    "Cloudflare": ["1.1.1.1", "1.0.0.1"],
    "Google": ["8.8.8.8", "8.8.4.4"],
    "Quad9 (blocks malware)": ["9.9.9.9", "149.112.112.112"],
    "OpenDNS": ["208.67.222.222", "208.67.220.220"],
    "Cloudflare Family (blocks malware and adult)": ["1.1.1.3", "1.0.0.3"],
}
TEST_NAMES = ["google.com", "microsoft.com", "wikipedia.org", "amazon.com", "github.com", "apple.com"]
SPEED_HOST = "speed.cloudflare.com"


# --------------------------------------------------------------------------- DNS
def _query_packet(name: str) -> tuple[bytes, int]:
    qid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + qname + struct.pack(">HH", 1, 1), qid


def dns_query_ms(server: str, name: str, timeout: float = 2.0) -> Optional[float]:
    packet, qid = _query_packet(name)
    family = socket.AF_INET6 if ":" in server else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        start = time.perf_counter()
        try:
            s.sendto(packet, (server, 53))
            while True:
                data, _ = s.recvfrom(2048)
                if len(data) >= 2 and struct.unpack(">H", data[:2])[0] == qid:
                    return (time.perf_counter() - start) * 1000
        except OSError:
            return None


def current_dns_servers() -> list[str]:
    if IS_WINDOWS:
        rows = ps_json("Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | "
                       "Select-Object -ExpandProperty ServerAddresses")
        servers = [r if isinstance(r, str) else str(r) for r in rows]
    else:
        servers = []
        if shutil.which("resolvectl"):
            rc, out = run_cmd(["resolvectl", "dns"])
            servers = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", out)
        if not servers:
            try:
                with open("/etc/resolv.conf", encoding="utf-8") as fh:
                    servers = [l.split()[1] for l in fh if l.startswith("nameserver")]
            except OSError:
                pass
    seen, out = set(), []
    for s in servers:
        if s not in seen and not s.startswith("127."):
            seen.add(s)
            out.append(s)
    return out


def benchmark(log: LogFn = None, cancel: Optional[threading.Event] = None) -> list[dict]:
    """Median response time per provider over several domains. Includes the current DNS servers."""
    targets = dict(PROVIDERS)
    current = current_dns_servers()
    if current:
        targets = {"Current (your network)": current[:2], **targets}
    results = []
    for provider, servers in targets.items():
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        times, fails = [], 0
        for name in TEST_NAMES:
            ms = dns_query_ms(servers[0], name)
            if ms is None:
                fails += 1
            else:
                times.append(ms)
        median = statistics.median(times) if times else None
        results.append({"provider": provider, "servers": servers, "median_ms": median, "failures": fails})
        if log:
            log(f"{provider}: " + (f"{median:.0f} ms" if median is not None else "no response"))
    results.sort(key=lambda r: (r["median_ms"] is None, r["median_ms"] or 0))
    return results


def active_connection() -> str:
    """Windows: interface alias. Linux: NetworkManager connection name."""
    if IS_WINDOWS:
        rows = ps_json("Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
                       "Sort-Object RouteMetric | Select-Object -First 1 InterfaceAlias")
        return rows[0].get("InterfaceAlias", "") if rows else ""
    if shutil.which("nmcli"):
        rc, out = run_cmd(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show", "--active"])
        for line in out.splitlines():
            name, _, kind = line.rpartition(":")
            if kind not in ("loopback", "bridge") and name:
                return name.replace("\\:", ":")
    return ""


def set_dns_fix(provider: Optional[str]) -> Fix:
    """Build a Fix that switches DNS to a provider, or back to automatic when provider is None."""
    conn = active_connection()
    if not conn:
        raise RuntimeError("No active network connection was found.")
    servers = PROVIDERS.get(provider, []) if provider else []
    title = f"Use {provider} DNS" if provider else "Use automatic DNS (from router)"
    if IS_WINDOWS:
        alias = conn.replace("'", "''")
        if servers:
            ps = f"Set-DnsClientServerAddress -InterfaceAlias '{alias}' -ServerAddresses ({','.join(repr(s) for s in servers)})"
        else:
            ps = f"Set-DnsClientServerAddress -InterfaceAlias '{alias}' -ResetServerAddresses"
        return Fix("set_dns", title, f"Changes DNS for '{conn}' and clears the DNS cache.",
                   [["powershell", "-NoProfile", "-Command", ps], [win_system_exe("ipconfig.exe"), "/flushdns"]],
                   admin=True)
    if not shutil.which("nmcli"):
        raise RuntimeError("DNS switching on Linux requires NetworkManager (nmcli).")
    if servers:
        mod = ["nmcli", "connection", "modify", conn, "ipv4.dns", " ".join(servers), "ipv4.ignore-auto-dns", "yes"]
    else:
        mod = ["nmcli", "connection", "modify", conn, "ipv4.dns", "", "ipv4.ignore-auto-dns", "no"]
    return Fix("set_dns", title, f"Changes DNS for '{conn}' and reconnects it.",
               [mod, ["nmcli", "connection", "up", conn]])


# --------------------------------------------------------------------------- speed test
def _conn() -> http.client.HTTPSConnection:
    return http.client.HTTPSConnection(SPEED_HOST, timeout=30)


def speed_test(log: LogFn = None, cancel: Optional[threading.Event] = None,
               down_bytes: int = 25_000_000, up_bytes: int = 10_000_000) -> dict:
    headers = {"User-Agent": "SysHealth", "Referer": f"https://{SPEED_HOST}/"}
    conn = _conn()
    pings = []
    for _ in range(6):
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        start = time.perf_counter()
        conn.request("GET", "/__down?bytes=0", headers=headers)
        resp = conn.getresponse()
        resp.read()
        if resp.status != 200:
            raise RuntimeError(f"The speed test server returned HTTP {resp.status}.")
        pings.append((time.perf_counter() - start) * 1000)
    ping = statistics.median(pings[1:])  # first request includes connection setup
    if log:
        log(f"Latency: {ping:.0f} ms")

    start = time.perf_counter()
    conn.request("GET", f"/__down?bytes={down_bytes}", headers=headers)
    resp = conn.getresponse()
    received = 0
    while True:
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        chunk = resp.read(256 * 1024)
        if not chunk:
            break
        received += len(chunk)
    down = received * 8 / (time.perf_counter() - start) / 1e6
    if log:
        log(f"Download: {down:.1f} Mbps")

    body = os.urandom(up_bytes)
    start = time.perf_counter()
    conn.request("POST", "/__up", body=body, headers={**headers, "Content-Type": "application/octet-stream"})
    resp = conn.getresponse()
    resp.read()
    up = up_bytes * 8 / (time.perf_counter() - start) / 1e6
    if log:
        log(f"Upload: {up:.1f} Mbps")
    conn.close()
    jitter = statistics.pstdev(pings[1:]) if len(pings) > 2 else 0
    return {"ping_ms": round(ping, 1), "jitter_ms": round(jitter, 1), "download_mbps": round(down, 1),
            "upload_mbps": round(up, 1), "server": SPEED_HOST, "time": time.strftime("%Y-%m-%d %H:%M")}
