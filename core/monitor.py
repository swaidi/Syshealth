"""Live resource sampling: CPU, memory, disk and network rates, and top processes."""
from __future__ import annotations

import time
from dataclasses import dataclass

import psutil


@dataclass
class Sample:
    time: float
    cpu: float
    mem: float
    disk_read: float   # bytes per second
    disk_write: float
    net_recv: float
    net_sent: float


class Sampler:
    def __init__(self) -> None:
        self._last_disk = psutil.disk_io_counters()
        self._last_net = psutil.net_io_counters()
        self._last_t = time.time()
        self._procs: dict[int, psutil.Process] = {}
        psutil.cpu_percent(None)

    def sample(self) -> Sample:
        now = time.time()
        dt = max(now - self._last_t, 0.001)
        disk, net = psutil.disk_io_counters(), psutil.net_io_counters()
        dr = (disk.read_bytes - self._last_disk.read_bytes) / dt if disk and self._last_disk else 0
        dw = (disk.write_bytes - self._last_disk.write_bytes) / dt if disk and self._last_disk else 0
        nr = (net.bytes_recv - self._last_net.bytes_recv) / dt
        ns = (net.bytes_sent - self._last_net.bytes_sent) / dt
        self._last_disk, self._last_net, self._last_t = disk, net, now
        return Sample(now, psutil.cpu_percent(None), psutil.virtual_memory().percent, max(dr, 0), max(dw, 0),
                      max(nr, 0), max(ns, 0))

    def top_processes(self, n: int = 25, sort: str = "cpu") -> list[dict]:
        seen = set()
        rows = []
        cores = psutil.cpu_count() or 1
        for p in psutil.process_iter(["pid", "name", "username"]):
            pid = p.info["pid"]
            seen.add(pid)
            proc = self._procs.get(pid)
            if proc is None:
                self._procs[pid] = p
                try:
                    p.cpu_percent(None)  # prime; the value is available on the next sample
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                continue
            try:
                with proc.oneshot():
                    cpu = proc.cpu_percent(None) / cores
                    mem = proc.memory_info().rss
                rows.append({"pid": pid, "name": p.info["name"] or "?", "cpu": cpu, "mem": mem,
                             "user": (p.info.get("username") or "").split("\\")[-1]})
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        for pid in list(self._procs):
            if pid not in seen:
                del self._procs[pid]
        key = "cpu" if sort == "cpu" else "mem"
        return sorted(rows, key=lambda r: r[key], reverse=True)[:n]
