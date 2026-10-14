"""Protect pages: Startup Apps, Autoruns Audit and Connections."""
from __future__ import annotations

import os
import tkinter as tk
from tkinter import messagebox, ttk

from core import connections, persistence, state
from core.checks import FAIL, INFO, OK, WARN
from core.platform_utils import APP_NAME, IS_WINDOWS, NeedsAdmin, is_protected, open_location
from ui.common import MutedLabel, Table, card


class _AutorunsBase(ttk.Frame):
    """Shared table and actions for the Startup and Autoruns pages."""
    startup_only = False
    card_key = "autoruns"

    def __init__(self, parent, app, title: str, subtitle: str, columns):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        self.entries: list[persistence.AutoEntry] = []
        self.new_keys: set[str] = set()
        self.loaded = False
        app.page_header(self, title, subtitle)

        bar = card(self, 12)
        bar.pack(fill=tk.X)
        ttk.Button(bar, text="Scan" if not self.startup_only else "Refresh", style="Accent.TButton",
                   command=self.scan).pack(side=tk.RIGHT)
        self.hide_ms = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Hide Microsoft entries", variable=self.hide_ms, style="Switch.TCheckbutton",
                        command=self.render).pack(side=tk.LEFT)
        self.build_filters(bar)

        self.summary = tk.StringVar(value="Not scanned yet.")
        ttk.Label(self, textvariable=self.summary, style="Section.TLabel").pack(fill=tk.X, pady=(12, 6))
        self.table = Table(self, columns, height=8)
        self.table.pack(fill=tk.BOTH, expand=True)
        app.on_theme(lambda p: (self.table.tree.tag_configure("High", foreground=p["fail"]),
                                self.table.tree.tag_configure("Review", foreground=p["warn"]),
                                self.table.tree.tag_configure("off", foreground=p["muted"]),
                                self.table.tree.tag_configure("new", font=(app.font_family, 9, "bold"))))
        self.detail = tk.StringVar(value="")
        MutedLabel(self, textvariable=self.detail, style="Muted.TLabel", wraplength=1000, justify=tk.LEFT).pack(
            side=tk.BOTTOM, fill=tk.X, pady=(4, 0), before=self.table)
        btns = ttk.Frame(self)
        btns.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 4), before=self.table)
        ttk.Button(btns, text="Enable", command=lambda: self.toggle(True)).pack(side=tk.LEFT)
        ttk.Button(btns, text="Disable", style="Accent.TButton", command=lambda: self.toggle(False)).pack(
            side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Open location", command=self.open_selected).pack(side=tk.LEFT)
        ttk.Button(btns, text="Check on VirusTotal", command=self.vt_selected).pack(side=tk.LEFT, padx=6)
        self.extra_buttons(btns)
        self.table.tree.bind("<<TreeviewSelect>>", self._on_select)

    def build_filters(self, bar) -> None:
        pass

    def extra_buttons(self, btns) -> None:
        pass

    def on_show(self) -> None:
        if not self.loaded:
            self.scan()

    def scan(self) -> None:
        self.loaded = True
        cats = persistence.STARTUP_CATEGORIES if self.startup_only else None

        def work(cancel):
            entries = persistence.collect(cats, True, self.app.log, cancel)
            added = []
            if not self.startup_only:
                added, removed, prev = persistence.diff_with_snapshot(entries)
                for r in removed:
                    self.app.log(f"Autorun removed since last scan: {r['name']} ({r['category']})")
            return entries, {a["name"] + a["command"] for a in added}

        def done(result):
            self.entries, new = result
            self.new_keys = {e.key for e in self.entries if e.name + e.command in new}
            self.render()
        self.app.run_task("Reading autostart entries", work, done)

    def visible(self) -> list[persistence.AutoEntry]:
        es = self.entries
        if self.hide_ms.get():
            es = [e for e in es if not persistence.is_microsoft(e)]
        return es

    def row(self, e: persistence.AutoEntry) -> tuple:
        raise NotImplementedError

    def render(self) -> None:
        self.table.clear()
        shown = self.visible()
        for e in sorted(shown, key=lambda e: ({"High": 0, "Review": 1, "Low": 2}[e.risk], e.category, e.name.lower())):
            tags = [e.risk] if e.risk != "Low" else []
            if not e.enabled:
                tags.append("off")
            if e.key in self.new_keys:
                tags.append("new")
            self.table.add(self.row(e), e, tags=tuple(tags))
        self.update_summary(shown)

    def update_summary(self, shown) -> None:
        enabled = sum(1 for e in shown if e.enabled)
        flagged = [e for e in shown if e.flags]
        high = [e for e in shown if e.risk == "High"]
        text = f"{len(shown)} entries · {enabled} enabled · {len(flagged)} to review"
        if self.new_keys:
            text += f" · {len(self.new_keys)} new since last scan (bold)"
        self.summary.set(text)
        level = FAIL if high else (WARN if flagged else OK)
        value = f"{len(high)} high-risk" if high else (f"{len(flagged)} to review" if flagged else "No issues")
        if self.startup_only:
            level, value = INFO, f"{enabled} startup app(s)"
        self.app.dashboard.set_card(self.card_key, level, value, f"{len(shown)} entries checked")

    def _on_select(self, _e=None) -> None:
        sel = self.table.selected()
        if not sel:
            self.detail.set("")
            return
        e = sel[0]
        parts = [f"Command: {e.command}", f"Registered in: {e.location}"]
        if e.signer or e.sig_status:
            parts.append(f"Signature: {e.sig_status or '-'} {('(' + e.signer + ')') if e.signer else ''}")
        if e.flags:
            parts.append("Why flagged: " + ", ".join(e.flags))
        if e.meta.get("permissions"):
            parts.append("Permissions: " + ", ".join(e.meta["permissions"][:10]))
        self.detail.set("   ·   ".join(parts))

    def toggle(self, enabled: bool) -> None:
        sel = self.table.selected()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select an entry first.")
            return
        e = sel[0]
        if not e.can_toggle:
            messagebox.showinfo(APP_NAME, f"'{e.name}' ({e.category}) cannot be switched on or off here. Use "
                                "'Open location' to review it." + (" Browser extensions are managed in the "
                                                                    "browser." if e.category == "Browser extension"
                                                                    else ""))
            return
        if not enabled and e.category == "Service" and not messagebox.askyesno(
                APP_NAME, f"Disable the service '{e.name}'?\n\nDisabling services that Windows or your hardware "
                "needs can break features. Disable only services you recognize."):
            return
        try:
            persistence.set_enabled(e, enabled)
        except NeedsAdmin as exc:
            if messagebox.askyesno(APP_NAME, f"'{exc}' requires administrator rights. Restart as Administrator?"):
                self.app.restart_admin()
            return
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        state.record_action("Startup", f"{'Enabled' if enabled else 'Disabled'}: {e.name}", e.category)
        self.app.log(f"{'Enabled' if enabled else 'Disabled'} {e.category.lower()}: {e.name}")
        self.render()

    def open_selected(self) -> None:
        sel = self.table.selected()
        if sel and (sel[0].path or sel[0].location):
            target = sel[0].path if sel[0].path and os.path.exists(sel[0].path) else sel[0].location
            if os.path.exists(target):
                open_location(target)
            else:
                messagebox.showinfo(APP_NAME, f"Location: {sel[0].location}")

    def vt_selected(self) -> None:
        sel = self.table.selected()
        if not sel or not sel[0].path or not os.path.isfile(sel[0].path):
            messagebox.showinfo(APP_NAME, "Select an entry whose file exists.")
            return
        self.app.vt_lookup(sel[0].path)


class StartupPage(_AutorunsBase):
    startup_only = True
    card_key = "startup"

    def __init__(self, parent, app):
        super().__init__(parent, app, "Startup Apps", "Programs that start when you sign in. Disabling them "
                         "speeds up startup; nothing is deleted.",
                         [("name", "Name", 220), ("state", "Status", 80), ("publisher", "Publisher", 200),
                          ("scope", "For", 80), ("command", "Command", 500)])

    def row(self, e):
        return (e.name, "✔ Enabled" if e.enabled else "✖ Disabled", e.signer or ("Unsigned" if e.sig_status ==
                                                                            "NotSigned" else e.sig_status),
                "This user" if e.scope == "user" else "All users", e.command)


class AutorunsPage(_AutorunsBase):
    startup_only = False
    card_key = "autoruns"

    def __init__(self, parent, app):
        super().__init__(parent, app, "Autoruns Audit", "Everything that starts automatically: startup apps, "
                         "services, scheduled tasks, browser extensions and hidden hooks. Rows in red need "
                         "attention.",
                         [("category", "Type", 120), ("name", "Name", 200), ("state", "Status", 70),
                          ("risk", "Risk", 70), ("publisher", "Publisher", 170), ("flags", "Flags", 220),
                          ("command", "Command", 420)])

    def build_filters(self, bar) -> None:
        self.flagged_only = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="Only entries to review", variable=self.flagged_only, style="Switch.TCheckbutton",
                        command=self.render).pack(side=tk.LEFT, padx=16)
        ttk.Label(bar, text="Type").pack(side=tk.LEFT, padx=(8, 6))
        self.cat = tk.StringVar(value="All")
        cats = ["All", "Run key", "Startup folder", "Service", "Scheduled task", "Browser extension"]
        cats += ["Winlogon", "IFEO debugger", "WMI consumer"] if IS_WINDOWS else ["Autostart", "Shell startup"]
        combo = ttk.Combobox(bar, textvariable=self.cat, values=cats, state="readonly", width=18)
        combo.pack(side=tk.LEFT)
        combo.bind("<<ComboboxSelected>>", lambda e: self.render())

    def extra_buttons(self, btns) -> None:
        ttk.Button(btns, text="Quarantine file", style="Danger.TButton", command=self.quarantine).pack(side=tk.RIGHT)

    def visible(self):
        es = super().visible()
        if self.flagged_only.get():
            es = [e for e in es if e.flags]
        if self.cat.get() != "All":
            es = [e for e in es if e.category == self.cat.get()]
        return es

    def row(self, e):
        return (e.category, e.name, "On" if e.enabled else "Off", e.risk,
                e.signer or ("Unsigned" if e.sig_status == "NotSigned" else e.sig_status), ", ".join(e.flags),
                e.command)

    def quarantine(self) -> None:
        sel = self.table.selected()
        if not sel or not sel[0].path or not os.path.isfile(sel[0].path):
            messagebox.showinfo(APP_NAME, "Select an entry whose file exists.")
            return
        e = sel[0]
        if is_protected(e.path):
            messagebox.showwarning(APP_NAME, "This file is inside a system folder and cannot be quarantined here.")
            return
        if not messagebox.askyesno(APP_NAME, f"Move this file to the encrypted quarantine?\n\n{e.path}\n\n"
                                   "The program will stop working until restored."):
            return
        try:
            self.app.quarantine.add(e.path, f"Autoruns: {e.category} {e.name}")
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))
            return
        state.record_action("Quarantine", f"Quarantined autorun file: {e.name}", e.path)
        self.app.q_tab.refresh()
        self.app.log(f"Quarantined {e.path}")


# =============================================================================== connections
class ConnectionsPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        self.visible_now = False
        self.hosts: dict[str, str] = {}
        app.page_header(self, "Connections", "Which programs are talking to the network right now.")
        bar = card(self, 12)
        bar.pack(fill=tk.X)
        ttk.Label(bar, text="Show").pack(side=tk.LEFT, padx=(0, 6))
        self.mode = tk.StringVar(value="Internet connections")
        combo = ttk.Combobox(bar, textvariable=self.mode, state="readonly", width=24,
                             values=["Internet connections", "Listening (open ports)", "All connections"])
        combo.pack(side=tk.LEFT)
        combo.bind("<<ComboboxSelected>>", lambda e: self.refresh())
        self.auto = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Auto-refresh every 5 seconds", variable=self.auto,
                        style="Switch.TCheckbutton").pack(side=tk.LEFT, padx=16)
        ttk.Button(bar, text="Refresh", style="Accent.TButton", command=self.refresh).pack(side=tk.RIGHT)
        ttk.Button(bar, text="Look up host names", command=self.lookup_hosts).pack(side=tk.RIGHT, padx=6)

        self.summary = tk.StringVar(value="")
        ttk.Label(self, textvariable=self.summary, style="Section.TLabel").pack(fill=tk.X, pady=(12, 6))
        self.table = Table(self, [("process", "Program", 170), ("pid", "PID", 60), ("proto", "Proto", 55),
                                  ("local", "Local address", 170), ("remote", "Remote address", 190),
                                  ("host", "Host name", 220), ("state", "State", 100), ("flags", "Notes", 160)])
        self.table.pack(fill=tk.BOTH, expand=True)
        app.on_theme(lambda p: self.table.tree.tag_configure("exposed", foreground=p["warn"]))
        btns = ttk.Frame(self)
        btns.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 4), before=self.table)
        ttk.Button(btns, text="Open file location", command=self.open_selected).pack(side=tk.LEFT)
        ttk.Button(btns, text="Check on VirusTotal", command=self.vt_selected).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="End process", style="Danger.TButton", command=self.end_process).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Block in firewall", style="Accent.TButton", command=self.block).pack(
            side=tk.RIGHT, padx=6)

    def on_show(self) -> None:
        self.visible_now = True
        self.refresh()
        self._tick()

    def on_hide(self) -> None:
        self.visible_now = False

    def _tick(self) -> None:
        if not self.visible_now:
            return
        if self.auto.get() and not self.app.busy:
            self.refresh(quiet=True)
        self.after(5000, self._tick)

    def refresh(self, quiet: bool = False) -> None:
        try:
            conns = connections.list_connections()
        except NeedsAdmin:
            self.summary.set("Administrator rights are needed to list connections on this system.")
            return
        mode = self.mode.get()
        if mode.startswith("Internet"):
            shown = [c for c in conns if "Internet" in c.flags]
        elif mode.startswith("Listening"):
            shown = [c for c in conns if c.is_listening]
        else:
            shown = conns
        selected = {(c.pid, c.local, c.remote) for c in self.table.selected()}
        self.table.clear()
        for c in shown:
            tags = ("exposed",) if "Open to the network" in c.flags else ()
            iid = self.table.add((c.process, c.pid, c.proto, c.local, c.remote, self.hosts.get(c.remote_ip, ""),
                                  c.status, ", ".join(f for f in c.flags if f != "Internet")), c, tags=tags)
            if (c.pid, c.local, c.remote) in selected:
                self.table.tree.selection_add(iid)
        s = connections.summary(conns)
        internet = sum(1 for c in conns if "Internet" in c.flags)
        self.summary.set(f"{internet} internet connection(s) · {s['listening']} listening port(s) · "
                         f"{s['exposed']} open to the network")
        if not quiet:
            self.app.dashboard.set_card("connections", WARN if s["exposed"] else INFO,
                                        f"{internet} internet connection(s)",
                                        f"{s['exposed']} program(s) accept connections from the network.")

    def lookup_hosts(self) -> None:
        ips = sorted({c.remote_ip for c in self.table.data.values() if c.remote_ip and c.remote_ip not in self.hosts})

        def work(cancel):
            out = {}
            for ip in ips[:60]:
                if cancel.is_set():
                    break
                out[ip] = connections.reverse_dns(ip) or "-"
            return out

        def done(res):
            self.hosts.update(res)
            self.refresh(quiet=True)
        self.app.run_task("Looking up host names", work, done)

    def _sel(self):
        sel = self.table.selected()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a connection first.")
        return sel[0] if sel else None

    def open_selected(self) -> None:
        c = self._sel()
        if c and c.exe:
            open_location(c.exe)

    def vt_selected(self) -> None:
        c = self._sel()
        if c and c.exe and os.path.isfile(c.exe):
            self.app.vt_lookup(c.exe)
        elif c:
            messagebox.showinfo(APP_NAME, "The program's file is not accessible. Try running as Administrator.")

    def end_process(self) -> None:
        c = self._sel()
        if not c or not messagebox.askyesno(APP_NAME, f"End '{c.process}' (PID {c.pid})? Unsaved work in that "
                                            "program will be lost."):
            return
        try:
            connections.end_process(c.pid)
            state.record_action("Connections", f"Ended process {c.process}", f"PID {c.pid}")
            self.refresh(quiet=True)
        except NeedsAdmin:
            messagebox.showwarning(APP_NAME, "Administrator rights are needed to end this process.")
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))

    def block(self) -> None:
        c = self._sel()
        if not c:
            return
        if not messagebox.askyesno(APP_NAME, f"Block '{c.process}' from all network access with a firewall rule?"
                                   f"\n\n{c.exe}\n\nRemove the rule later in Windows Defender Firewall "
                                   "(rules named 'SysHealth block …')."):
            return
        try:
            name = connections.block_program(c.exe)
            state.record_action("Connections", f"Blocked {c.process} in the firewall", c.exe)
            self.app.log(f"Firewall rule added: {name}")
        except NeedsAdmin:
            if messagebox.askyesno(APP_NAME, "Blocking requires administrator rights. Restart as Administrator?"):
                self.app.restart_admin()
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))
