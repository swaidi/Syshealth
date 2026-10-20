"""Health pages: Recent Changes, Event Log, DNS & Speed, and Live Monitor."""
from __future__ import annotations

import collections
import csv
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from core import changes, events, netperf, state
from core.checks import INFO, WARN
from core.connections import end_process
from core.monitor import Sampler
from core.platform_utils import APP_NAME, NeedsAdmin, human_size, open_location
from ui.common import MutedLabel, Table, card


# =============================================================================== recent changes
class ChangesPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        self.items: list[changes.Change] = []
        app.page_header(self, "Recent Changes", "What changed on this computer: apps installed, updated or removed, "
                        "system updates, new services and drivers, startup changes, restarts, and SysHealth actions.")
        bar = card(self, 12)
        bar.pack(fill=tk.X)
        ttk.Label(bar, text="Period").pack(side=tk.LEFT, padx=(0, 6))
        self.days = tk.StringVar(value="7 days")
        ttk.Combobox(bar, textvariable=self.days, values=["1 day", "7 days", "14 days", "30 days", "90 days"],
                     state="readonly", width=9).pack(side=tk.LEFT)
        ttk.Label(bar, text="Category").pack(side=tk.LEFT, padx=(16, 6))
        self.cat = tk.StringVar(value="All")
        combo = ttk.Combobox(bar, textvariable=self.cat, state="readonly", width=16,
                             values=["All", "Apps", "System updates", "Services", "Drivers", "Startup", "Restarts",
                                     "SysHealth"])
        combo.pack(side=tk.LEFT)
        combo.bind("<<ComboboxSelected>>", lambda e: self.render())
        ttk.Button(bar, text="Show changes", style="Accent.TButton", command=self.scan).pack(side=tk.RIGHT)
        ttk.Button(bar, text="Export history", command=self.export).pack(side=tk.RIGHT, padx=6)
        self.summary = tk.StringVar(value="Click 'Show changes'. The first run records a baseline for app and "
                                    "startup tracking; later runs show what changed since then.")
        ttk.Label(self, textvariable=self.summary, style="Section.TLabel", wraplength=1000,
                  justify=tk.LEFT).pack(fill=tk.X, pady=(12, 6))
        self.table = Table(self, [("when", "When", 150), ("category", "Category", 120), ("change", "Change", 420),
                                  ("detail", "Detail", 420)])
        self.table.pack(fill=tk.BOTH, expand=True)
        self.table.tree.bind("<Double-1>", self.show_details)
        MutedLabel(self, text="Double-click a SysHealth entry to see every file or item it affected.").pack(
            anchor=tk.W, pady=(4, 0), before=self.table)

    def scan(self) -> None:
        days = int(self.days.get().split()[0])

        def done(items):
            self.items = items
            self.render()
            counts = collections.Counter(c.category for c in items)
            new_services = counts.get("Services", 0)
            self.app.dashboard.set_card("changes", WARN if new_services else INFO, f"{len(items)} change(s)",
                                        ", ".join(f"{n} {k.lower()}" for k, n in counts.most_common(3)) or
                                        f"Last {days} days")
        self.app.run_task("Reading recent changes", lambda c: changes.collect(days, self.app.log, c), done)

    def export(self) -> None:
        if not self.items:
            messagebox.showinfo(APP_NAME, "Run 'Show changes' first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", initialfile="SysHealth_changes.csv",
                                            filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline="", encoding="utf-8-sig") as fh:
            w = csv.writer(fh)
            w.writerow(["When", "Category", "Change", "Detail", "Affected items"])
            for c in self.items:
                if self.cat.get() in ("All", c.category):
                    w.writerow([c.when, c.category, c.title, c.detail, " | ".join(c.items)])
        self.app.log(f"Change history exported to {path}")

    def render(self) -> None:
        self.table.clear()
        shown = [c for c in self.items if self.cat.get() in ("All", c.category)]
        for c in shown:
            detail = c.detail
            if c.item_count:
                detail = (detail + "  ·  " if detail else "") + f"{c.item_count:,} item(s), double-click for the list"
            self.table.add((c.when, c.category, c.title, detail), c)
        counts = collections.Counter(c.category for c in self.items)
        self.summary.set(f"{len(shown)} change(s) shown · " +
                         " · ".join(f"{k}: {n}" for k, n in sorted(counts.items())))


    def show_details(self, _event=None) -> None:
        sel = self.table.selected()
        if sel and sel[0].items:
            ChangeDetails(self.app, sel[0])


class ChangeDetails(tk.Toplevel):
    """Every file or item affected by one SysHealth action."""

    def __init__(self, app, change):
        super().__init__(app)
        self.app = app
        self.change = change
        self.title("Action details")
        self.configure(background=app.palette["app"])
        from ui.update_dialog import _center
        _center(self, app, 900, 520)
        self.transient(app)
        btns = ttk.Frame(self, padding=(16, 8, 16, 16))
        btns.pack(side=tk.BOTTOM, fill=tk.X)
        body = ttk.Frame(self, padding=16)
        body.pack(fill=tk.BOTH, expand=True)
        ttk.Label(body, text=change.title, style="PageTitle.TLabel", wraplength=860, justify=tk.LEFT).pack(anchor=tk.W)
        info = change.when + (f"  ·  {change.detail}" if change.detail else "")
        if change.item_count > len(change.items):
            info += f"  ·  showing the first {len(change.items):,} of {change.item_count:,}"
        ttk.Label(body, text=info, style="Muted.TLabel", wraplength=860).pack(anchor=tk.W, pady=(2, 10))
        self.list = Table(body, [("item", "File or item", 840)])
        self.list.pack(fill=tk.BOTH, expand=True)
        for item in change.items:
            self.list.add((item,), item)
        ttk.Button(btns, text="Close", command=self.destroy).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Copy list", command=self.copy).pack(side=tk.RIGHT, padx=6)
        ttk.Button(btns, text="Open location", command=self.open_location).pack(side=tk.LEFT)

    @staticmethod
    def _path(item: str) -> str:
        return item.split("  ->  ")[0].split("  (")[0]

    def open_location(self) -> None:
        sel = self.list.selected()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select an item first.", parent=self)
            return
        path = self._path(sel[0])
        folder = path if os.path.isdir(path) else os.path.dirname(path)
        if os.path.isdir(folder):
            open_location(path if os.path.exists(path) else folder)
        else:
            messagebox.showinfo(APP_NAME, f"This location no longer exists:\n{folder}", parent=self)

    def copy(self) -> None:
        self.app.clipboard_clear()
        self.app.clipboard_append("\n".join(self.change.items))
        self.app.set_status(f"Copied {len(self.change.items):,} item(s) to the clipboard.")


# =============================================================================== event log
class EventsPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        app.page_header(self, "Event Log", "Recent errors from the system logs, grouped and explained in plain "
                        "language.")
        bar = card(self, 12)
        bar.pack(fill=tk.X)
        ttk.Label(bar, text="Period").pack(side=tk.LEFT, padx=(0, 6))
        self.days = tk.StringVar(value="7 days")
        ttk.Combobox(bar, textvariable=self.days, values=["1 day", "7 days", "14 days", "30 days"], state="readonly",
                     width=9).pack(side=tk.LEFT)
        self.known_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Only explained events", variable=self.known_only, style="Switch.TCheckbutton",
                        command=lambda: self.show(self.groups)).pack(side=tk.LEFT, padx=16)
        ttk.Button(bar, text="Summarize", style="Accent.TButton", command=self.scan).pack(side=tk.RIGHT)
        self.groups: list[events.EventGroup] = []
        self.summary = tk.StringVar(value="Click 'Summarize'.")
        ttk.Label(self, textvariable=self.summary, style="Section.TLabel").pack(fill=tk.X, pady=(12, 6))
        self.table = Table(self, [("severity", "Severity", 80), ("count", "Count", 60), ("last", "Last seen", 130),
                                  ("source", "Source", 200), ("id", "ID", 60), ("meaning", "Meaning", 520)],
                           selectmode="browse")
        self.table.pack(fill=tk.BOTH, expand=True)
        app.on_theme(lambda p: (self.table.tree.tag_configure("High", foreground=p["fail"]),
                                self.table.tree.tag_configure("Medium", foreground=p["warn"]),
                                self.table.tree.tag_configure("Info", foreground=p["muted"])))
        info = card(self, 12)
        info.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 4), before=self.table)
        self.detail = tk.StringVar(value="Select a row to see the advice and sample messages.")
        ttk.Label(info, textvariable=self.detail, wraplength=1000, justify=tk.LEFT).pack(fill=tk.X)
        self.table.tree.bind("<<TreeviewSelect>>", self._on_select)

    def scan(self) -> None:
        days = int(self.days.get().split()[0])
        self.app.run_task("Reading event logs", lambda c: events.summarize(days), self.show)

    def show(self, groups) -> None:
        self.groups = groups
        self.table.clear()
        shown = [g for g in groups if g.explanation] if self.known_only.get() else groups
        for g in shown:
            self.table.add((g.severity, g.count, g.last, g.source, g.event_id, g.explanation or g.message[:160]), g,
                           tags=(g.severity,))
        level, value, detail = events.headline(groups)
        self.summary.set(f"{value} · {len(groups)} distinct error type(s), {sum(g.count for g in groups)} entries")
        self.app.dashboard.set_card("events", level, value, detail)

    def _on_select(self, _e=None) -> None:
        sel = self.table.selected()
        if not sel:
            return
        g = sel[0]
        lines = []
        if g.explanation:
            lines.append(f"What it means: {g.explanation}")
        if g.advice:
            lines.append(f"What to do: {g.advice}")
        lines.append(f"First seen {g.first}, last seen {g.last}, {g.count} time(s).")
        samples = g.samples or [g.message]
        lines.append("Message: " + " | ".join(s[:300] for s in samples if s))
        self.detail.set("\n".join(lines))


# =============================================================================== DNS and speed
class DnsSpeedPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        app.page_header(self, "DNS & Speed", "Find the fastest DNS service for your connection, switch to it, and "
                        "measure your internet speed.")
        speed = card(self, 16)
        speed.pack(fill=tk.X)
        ttk.Label(speed, text="Internet speed", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.speed_vals = {}
        for i, (key, label) in enumerate((("ping_ms", "Latency (ms)"), ("download_mbps", "Download (Mbps)"),
                                          ("upload_mbps", "Upload (Mbps)"))):
            box = ttk.Frame(speed)
            box.grid(row=1, column=i, sticky="w", padx=(0, 48), pady=(8, 0))
            v = ttk.Label(box, text="–", style="Big.TLabel")
            v.pack(anchor=tk.W)
            MutedLabel(box, text=label, style="Muted.TLabel").pack(anchor=tk.W)
            self.speed_vals[key] = v
        self.speed_note = tk.StringVar(value="")
        MutedLabel(speed, textvariable=self.speed_note, style="Muted.TLabel").grid(row=2, column=0, columnspan=3,
                                                                                  sticky="w", pady=(8, 0))
        ttk.Button(speed, text="Run speed test", style="Accent.TButton", command=self.speed_test).grid(
            row=0, column=3, rowspan=2, sticky="e")
        speed.columnconfigure(3, weight=1)
        last = state.get("speedtest")
        if last and last.get("data"):
            self._show_speed(last["data"])

        dns = card(self, 16)
        dns.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        head = ttk.Frame(dns)
        head.pack(fill=tk.X)
        ttk.Label(head, text="DNS benchmark", style="Section.TLabel").pack(side=tk.LEFT)
        ttk.Button(head, text="Test DNS providers", style="Accent.TButton", command=self.benchmark).pack(side=tk.RIGHT)
        self.dns_current = tk.StringVar(value="Current DNS: checking…")
        self._dns_loaded = False
        MutedLabel(dns, textvariable=self.dns_current, style="Muted.TLabel").pack(anchor=tk.W, pady=(4, 8))
        self.table = Table(dns, [("provider", "Provider", 320), ("servers", "Servers", 230),
                                 ("median", "Response time", 120), ("fail", "Failures", 80)], height=6,
                           selectmode="browse")
        self.table.pack(fill=tk.BOTH, expand=True)
        b = ttk.Frame(dns)
        b.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 0), before=self.table)
        MutedLabel(b, text="Lower response time = faster browsing. Quad9 and Cloudflare Family also block known "
                  "malicious sites.", style="Muted.TLabel").pack(side=tk.LEFT)
        ttk.Button(b, text="Use automatic DNS", command=lambda: self.set_dns(None)).pack(side=tk.RIGHT)
        ttk.Button(b, text="Use selected provider", style="Accent.TButton", command=self.use_selected).pack(
            side=tk.RIGHT, padx=6)

    def on_show(self) -> None:
        if self._dns_loaded:
            return
        self._dns_loaded = True
        import threading

        def worker():
            text = "Current DNS: " + (", ".join(netperf.current_dns_servers()) or "unknown")
            self.app.ui(lambda: self.dns_current.set(text))
        threading.Thread(target=worker, daemon=True).start()

    def _show_speed(self, r: dict) -> None:
        for k, lbl in self.speed_vals.items():
            lbl.configure(text=f"{r.get(k, '–')}")
        self.speed_note.set(f"Measured {r.get('time', '')} against {r.get('server', '')}, jitter {r.get('jitter_ms')} ms.")

    def speed_test(self) -> None:
        def done(r):
            self._show_speed(r)
            self.app.dashboard.set_card("speedtest", INFO, f"{r['download_mbps']} / {r['upload_mbps']} Mbps",
                                        f"Latency {r['ping_ms']} ms", r)
        self.app.run_task("Speed test", lambda c: netperf.speed_test(self.app.log, c), done)

    def benchmark(self) -> None:
        def done(results):
            self.table.clear()
            for r in results:
                self.table.add((r["provider"], ", ".join(r["servers"]),
                                f"{r['median_ms']:.0f} ms" if r["median_ms"] is not None else "No response",
                                r["failures"]), r)
            self.dns_current.set("Current DNS: " + (", ".join(netperf.current_dns_servers()) or "unknown"))
        self.app.run_task("DNS benchmark", lambda c: netperf.benchmark(self.app.log, c), done)

    def use_selected(self) -> None:
        sel = self.table.selected()
        if not sel or sel[0]["provider"] not in netperf.PROVIDERS:
            messagebox.showinfo(APP_NAME, "Run the test, then select a provider from the list (not 'Current').")
            return
        self.set_dns(sel[0]["provider"])

    def set_dns(self, provider) -> None:
        try:
            fix = netperf.set_dns_fix(provider)
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        self.app.run_fix(fix, on_done=lambda: self.dns_current.set(
            "Current DNS: " + (", ".join(netperf.current_dns_servers()) or "unknown")))


# =============================================================================== live monitor
class Graph(ttk.Frame):
    """Simple line chart of the last N values drawn on a canvas."""

    def __init__(self, parent, app, title: str, unit: str, maximum: float | None = 100, points: int = 60):
        super().__init__(parent, style="Card.TFrame", padding=10)
        self.app, self.unit, self.maximum, self.points = app, unit, maximum, points
        self.values: collections.deque = collections.deque([0.0] * points, maxlen=points)
        head = ttk.Frame(self)
        head.pack(fill=tk.X)
        ttk.Label(head, text=title, style="CardTitle.TLabel").pack(side=tk.LEFT)
        self.value = ttk.Label(head, text="", style="CardTitle.TLabel")
        self.value.pack(side=tk.RIGHT)
        self.canvas = tk.Canvas(self, height=110, highlightthickness=0, borderwidth=0)
        self.canvas.pack(fill=tk.BOTH, expand=True, pady=(6, 0))
        self.canvas.bind("<Configure>", lambda e: self.draw())
        app.on_theme(lambda p: (self.canvas.configure(background=p["card"]), self.draw()))

    def push(self, v: float, label: str) -> None:
        self.values.append(v)
        self.value.configure(text=label)
        self.draw()

    def draw(self) -> None:
        c, p = self.canvas, self.app.palette
        c.delete("all")
        w, h = max(c.winfo_width(), 10), max(c.winfo_height(), 10)
        top = self.maximum or max(max(self.values) * 1.2, 1e-6)
        for i in range(1, 4):
            y = h * i / 4
            c.create_line(0, y, w, y, fill=p["grid"])
        step = w / (self.points - 1)
        coords = []
        for i, v in enumerate(self.values):
            coords += [i * step, h - (min(v, top) / top) * (h - 4) - 2]
        c.create_line(*coords, fill=p["accent"], width=2, smooth=True)


class MonitorPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        self.running = False
        self.sampler: Sampler | None = None
        self.tick = 0
        app.page_header(self, "Live Monitor", "Real-time CPU, memory, disk and network activity, and the programs "
                        "using the most resources. Updates every second while this page is open.")
        grid = ttk.Frame(self)
        grid.pack(fill=tk.X)
        for i in range(4):
            grid.columnconfigure(i, weight=1, uniform="g")
        self.g_cpu = Graph(grid, app, "CPU", "%")
        self.g_mem = Graph(grid, app, "Memory", "%")
        self.g_disk = Graph(grid, app, "Disk", "MB/s", maximum=None)
        self.g_net = Graph(grid, app, "Network", "Mbps", maximum=None)
        for i, g in enumerate((self.g_cpu, self.g_mem, self.g_disk, self.g_net)):
            g.grid(row=0, column=i, sticky="nsew", padx=4)

        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(12, 6))
        ttk.Label(bar, text="Top programs", style="Section.TLabel").pack(side=tk.LEFT)
        self.sort = tk.StringVar(value="CPU")
        ttk.Combobox(bar, textvariable=self.sort, values=["CPU", "Memory"], state="readonly", width=8).pack(
            side=tk.RIGHT)
        ttk.Label(bar, text="Sort by").pack(side=tk.RIGHT, padx=6)
        self.table = Table(self, [("name", "Program", 260), ("pid", "PID", 70), ("cpu", "CPU %", 80),
                                  ("mem", "Memory", 100), ("user", "User", 160)], selectmode="browse")
        self.table.pack(fill=tk.BOTH, expand=True)
        b = ttk.Frame(self)
        b.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 4), before=self.table)
        ttk.Button(b, text="End process", style="Danger.TButton", command=self.kill).pack(side=tk.RIGHT)

    def on_show(self) -> None:
        if self.sampler is None:
            self.sampler = Sampler()
            self.sampler.top_processes()  # prime per-process CPU counters
        self.running = True
        self._loop()

    def on_hide(self) -> None:
        self.running = False

    def _loop(self) -> None:
        if not self.running:
            return
        s = self.sampler.sample()
        self.g_cpu.push(s.cpu, f"{s.cpu:.0f}%")
        self.g_mem.push(s.mem, f"{s.mem:.0f}%")
        disk = (s.disk_read + s.disk_write) / 1e6
        self.g_disk.push(disk, f"{disk:.1f} MB/s")
        net = (s.net_recv + s.net_sent) * 8 / 1e6
        self.g_net.push(net, f"{net:.1f} Mbps")
        self.tick += 1
        if self.tick % 2 == 0:
            rows = self.sampler.top_processes(30, "cpu" if self.sort.get() == "CPU" else "mem")
            sel = [o["pid"] for o in self.table.selected()]
            self.table.clear()
            for r in rows:
                iid = self.table.add((r["name"], r["pid"], f"{r['cpu']:.1f}", human_size(r["mem"]), r["user"]), r)
                if r["pid"] in sel:
                    self.table.tree.selection_set(iid)
        self.after(1000, self._loop)

    def kill(self) -> None:
        sel = self.table.selected()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a program first.")
            return
        r = sel[0]
        if not messagebox.askyesno(APP_NAME, f"End '{r['name']}' (PID {r['pid']})? Unsaved work will be lost."):
            return
        try:
            end_process(r["pid"])
            state.record_action("Monitor", f"Ended process {r['name']}", f"PID {r['pid']}")
        except NeedsAdmin:
            messagebox.showwarning(APP_NAME, "Administrator rights are needed to end this program.")
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))
