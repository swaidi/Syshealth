"""Tools pages: App Updates, File Shredder, VirusTotal and Command Line."""
from __future__ import annotations

import datetime as dt
import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from core import app_updates, cheatsheet, settings, shredder, state, virustotal
from core.checks import OK, WARN
from core.platform_utils import APP_NAME, IS_WINDOWS, human_size, open_url_or_file
from ui.common import MutedLabel, CheckTree, Table, card


# =============================================================================== app updates
class UpdatesPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        self.items: dict[str, app_updates.UpdateItem] = {}
        mgr = app_updates.manager_name() or "no package manager found"
        app.page_header(self, "App Updates", f"Keep installed apps up to date (using {mgr}). Outdated apps are a "
                        "common way in for malware.")
        bar = card(self, 12)
        bar.pack(fill=tk.X)
        ttk.Button(bar, text="Check installed apps", style="Accent.TButton", command=self.refresh).pack(side=tk.LEFT)
        ttk.Button(bar, text="Refresh sources", command=self.refresh_sources).pack(side=tk.LEFT, padx=6)
        MutedLabel(bar, text="Some installers show their own prompts or ask for administrator approval.",
                  style="Muted.TLabel").pack(side=tk.RIGHT)
        self.summary = tk.StringVar(value="Click 'Check installed apps'. (Updates for SysHealth itself are "
                                         "in the header: 'SysHealth updates'.)")
        ttk.Label(self, textvariable=self.summary, style="Section.TLabel").pack(fill=tk.X, pady=(12, 6))
        self.tree = CheckTree(self, app, [("id", "ID", 260), ("current", "Installed", 120),
                                          ("available", "Available", 120), ("source", "Source", 90)],
                              "App (click to select)", 300)
        self.tree.pack(fill=tk.BOTH, expand=True)
        b = ttk.Frame(self)
        b.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 4), before=self.tree)
        ttk.Button(b, text="Select all", command=lambda: [self.tree.set_checked(i, True) for i in self.tree.items()]
                   ).pack(side=tk.LEFT)
        ttk.Button(b, text="Clear", command=lambda: [self.tree.set_checked(i, False) for i in self.tree.items()]
                   ).pack(side=tk.LEFT, padx=6)
        ttk.Button(b, text="Update all", command=self.update_all).pack(side=tk.RIGHT)
        ttk.Button(b, text="Update selected", style="Accent.TButton", command=self.update_selected).pack(
            side=tk.RIGHT, padx=6)

    def refresh(self) -> None:
        def done(items):
            self.tree.clear()
            self.items.clear()
            for it in items:
                iid = self.tree.add_item("", it.name, (it.id, it.current, it.available, it.source))
                self.items[iid] = it
            self.summary.set(f"{len(items)} update(s) available." if items else "All apps are up to date.")
            self.app.dashboard.set_card("updates", WARN if items else OK,
                                        f"{len(items)} update(s)" if items else "Up to date",
                                        ", ".join(i.name for i in items[:3]))
        self.app.run_task("Checking for app updates", lambda c: app_updates.list_updates(self.app.log), done)

    def refresh_sources(self) -> None:
        self.app.run_task("Refreshing package sources", lambda c: app_updates.refresh_sources(self.app.log, c),
                          lambda _r: self.refresh())

    def update_selected(self) -> None:
        chosen = [self.items[i] for i in self.tree.checked if i in self.items]
        if not chosen:
            messagebox.showinfo(APP_NAME, "Select apps first (click the box next to each name).")
            return
        if not messagebox.askyesno(APP_NAME, f"Update {len(chosen)} app(s)? Close them first to avoid errors."):
            return

        def done(r):
            ok, failed = r
            for f in failed:
                self.app.log(f"Update failed: {f}")
            state.record_action("Updates", f"Updated {ok} app(s)", ", ".join(i.name for i in chosen))
            self.refresh()
        self.app.run_task("Updating apps", lambda c: app_updates.install(chosen, self.app.log, c), done)

    def update_all(self) -> None:
        if not messagebox.askyesno(APP_NAME, "Update all apps? Close open programs first to avoid errors."):
            return

        def done(_rc):
            state.record_action("Updates", "Updated all apps")
            self.refresh()
        self.app.run_task("Updating all apps", lambda c: app_updates.install_all(self.app.log, c), done)


# =============================================================================== shredder
class ShredderPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        app.page_header(self, "File Shredder", "Overwrite files before deleting them so they cannot be recovered "
                        "with undelete tools.")
        note = card(self, 12)
        note.pack(fill=tk.X)
        ttk.Label(note, text="Important: on SSDs, USB flash drives and cloud-synced folders (OneDrive, Google Drive), "
                  "copies may survive inside the drive or in the cloud history. Full-disk encryption (BitLocker / "
                  "LUKS) is the reliable protection there. Shredded files do not go to the Recycle Bin.",
                  style="Muted.TLabel", wraplength=1000, justify=tk.LEFT).pack(fill=tk.X)
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(10, 6))
        ttk.Button(bar, text="Add files…", command=self.add_files).pack(side=tk.LEFT)
        ttk.Button(bar, text="Add folder…", command=self.add_folder).pack(side=tk.LEFT, padx=6)
        ttk.Button(bar, text="Remove from list", command=self.remove).pack(side=tk.LEFT)
        ttk.Label(bar, text="Overwrite passes").pack(side=tk.LEFT, padx=(20, 6))
        self.passes = tk.StringVar(value="1 pass")
        ttk.Combobox(bar, textvariable=self.passes, values=["1 pass", "3 passes", "7 passes"], state="readonly",
                     width=10).pack(side=tk.LEFT)
        MutedLabel(bar, text="(1 pass is enough for modern drives)", style="Muted.TLabel").pack(side=tk.LEFT, padx=6)
        self.table = Table(self, [("type", "Type", 80), ("size", "Size", 100), ("path", "Path", 700)])
        self.table.pack(fill=tk.BOTH, expand=True)
        b = ttk.Frame(self)
        b.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 4), before=self.table)
        ttk.Button(b, text="Shred permanently", style="Danger.TButton", command=self.shred).pack(side=tk.RIGHT)

    def _add(self, path: str) -> None:
        if path in self.table.data.values():
            return
        reason = shredder.check_allowed(path)
        if reason:
            messagebox.showwarning(APP_NAME, f"Not added: {path} {reason}.")
            return
        if os.path.isdir(path):
            size = sum(os.path.getsize(os.path.join(dp, f)) for dp, _, fs in os.walk(path) for f in fs
                       if os.path.isfile(os.path.join(dp, f)))
            self.table.add(("Folder", human_size(size), path), path)
        else:
            self.table.add(("File", human_size(os.path.getsize(path)), path), path)

    def add_files(self) -> None:
        for p in filedialog.askopenfilenames():
            self._add(os.path.normpath(p))

    def add_folder(self) -> None:
        p = filedialog.askdirectory()
        if p:
            self._add(os.path.normpath(p))

    def remove(self) -> None:
        for iid in self.table.tree.selection():
            self.table.tree.delete(iid)
            self.table.data.pop(iid, None)

    def shred(self) -> None:
        paths = list(self.table.data.values())
        if not paths:
            messagebox.showinfo(APP_NAME, "Add files or folders first.")
            return
        answer = simpledialog.askstring("Confirm shredding", f"{len(paths)} item(s) will be destroyed permanently. "
                                        "This cannot be undone.\n\nType SHRED to continue:", parent=self)
        if (answer or "").strip().upper() != "SHRED":
            return
        passes = int(self.passes.get().split()[0])

        def done(r):
            n, size, errors = r
            for e in errors:
                self.app.log(f"Could not shred {e}")
            state.record_action("Shredder", f"Shredded {n} file(s)", human_size(size))
            self.table.clear()
            messagebox.showinfo(APP_NAME, f"Shredded {n} file(s), {human_size(size)}." +
                                (f"\n{len(errors)} item(s) failed (see log)." if errors else ""))
        self.app.run_task("Shredding", lambda c: shredder.shred(paths, passes, self.app.log, c), done)


# =============================================================================== VirusTotal
class VirusTotalPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        app.page_header(self, "VirusTotal", "Check a file against 70+ antivirus engines. Only the file's SHA-256 "
                        "fingerprint is sent, never the file itself.")
        keybox = card(self, 14)
        keybox.pack(fill=tk.X)
        ttk.Label(keybox, text="API key", style="Section.TLabel").pack(side=tk.LEFT)
        self.key = tk.StringVar(value=settings.get("vt_api_key", ""))
        self.key_entry = ttk.Entry(keybox, textvariable=self.key, show="•", width=50)
        self.key_entry.pack(side=tk.LEFT, padx=10)
        self.show_key = tk.BooleanVar(value=False)
        ttk.Checkbutton(keybox, text="Show", variable=self.show_key,
                        command=lambda: self.key_entry.configure(show="" if self.show_key.get() else "•")).pack(
            side=tk.LEFT, padx=(0, 10))
        ttk.Button(keybox, text="Save key", command=self.save_key).pack(side=tk.LEFT)
        ttk.Button(keybox, text="Get a free key", command=lambda: open_url_or_file(virustotal.SIGNUP_URL)).pack(
            side=tk.LEFT, padx=6)
        MutedLabel(keybox, text="Free keys allow 4 lookups per minute.", style="Muted.TLabel").pack(side=tk.RIGHT)

        look = ttk.Frame(self)
        look.pack(fill=tk.X, pady=(12, 6))
        ttk.Button(look, text="Check a file…", style="Accent.TButton", command=self.pick_file).pack(side=tk.LEFT)
        ttk.Label(look, text="or SHA-256").pack(side=tk.LEFT, padx=(16, 6))
        self.hash = tk.StringVar()
        ttk.Entry(look, textvariable=self.hash, width=70).pack(side=tk.LEFT)
        ttk.Button(look, text="Look up", command=lambda: self.lookup_hash(self.hash.get().strip(), "")).pack(
            side=tk.LEFT, padx=6)
        self.table = Table(self, [("time", "Checked", 130), ("verdict", "Verdict", 140), ("score", "Detections", 90),
                                  ("labels", "Detected as", 260), ("file", "File", 380)], selectmode="browse")
        self.table.pack(fill=tk.BOTH, expand=True)
        app.on_theme(lambda p: (self.table.tree.tag_configure("Malicious", foreground=p["fail"]),
                                self.table.tree.tag_configure("Suspicious", foreground=p["warn"]),
                                self.table.tree.tag_configure("Clean", foreground=p["ok"])))
        b = ttk.Frame(self)
        b.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 4), before=self.table)
        MutedLabel(b, text="'Unknown' means no one has uploaded this file to VirusTotal yet; it is not proof of safety.",
                  style="Muted.TLabel").pack(side=tk.LEFT)
        ttk.Button(b, text="Open full report", command=self.open_report).pack(side=tk.RIGHT)

    def save_key(self) -> None:
        settings.set_value("vt_api_key", self.key.get().strip())
        self.app.log("VirusTotal API key saved.")

    def pick_file(self) -> None:
        p = filedialog.askopenfilename()
        if p:
            self.lookup_path(os.path.normpath(p))

    def lookup_path(self, path: str) -> None:
        self.app.show_page("virustotal")
        if not self.key.get().strip():
            messagebox.showinfo(APP_NAME, "Add your free VirusTotal API key first (click 'Get a free key').")
            return
        key = self.key.get().strip()

        def work(cancel):
            sha = virustotal.sha256_file(path)
            return virustotal.lookup(sha, key)
        self.app.run_task("VirusTotal lookup", work, lambda r: self._add(r, path))

    def lookup_hash(self, sha: str, label: str) -> None:
        if len(sha) != 64:
            messagebox.showerror(APP_NAME, "Enter a 64-character SHA-256 hash.")
            return
        key = self.key.get().strip()
        self.app.run_task("VirusTotal lookup", lambda c: virustotal.lookup(sha, key), lambda r: self._add(r, label))

    def _add(self, r: virustotal.VTResult, path: str) -> None:
        iid = self.table.add((dt.datetime.now().strftime("%Y-%m-%d %H:%M"), r.verdict,
                              f"{r.malicious}/{r.total}" if r.found else "–", ", ".join(r.top_labels or []),
                              path or r.name or r.sha256), r, tags=(r.verdict,))
        self.table.tree.move(iid, "", 0)
        self.table.tree.selection_set(iid)
        self.app.log(f"VirusTotal: {os.path.basename(path) or r.sha256[:12]} → {r.verdict}"
                     + (f" ({r.malicious}/{r.total})" if r.found else ""))
        if r.verdict in ("Malicious", "Suspicious"):
            messagebox.showwarning(APP_NAME, f"{r.verdict}: {r.malicious} of {r.total} engines flag this file.\n\n"
                                   "Consider quarantining it.")

    def open_report(self) -> None:
        sel = self.table.selected()
        if sel:
            open_url_or_file(sel[0].link)


# =============================================================================== command line
class CommandLinePage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        app.page_header(self, "Command Line", "Every feature is also available from a terminal, for scripting and "
                        "scheduled tasks.")
        how = card(self, 14)
        how.pack(fill=tk.X)
        if getattr(sys, "frozen", False):
            exe = os.path.join(os.path.dirname(sys.executable), "SysHealthCLI.exe" if IS_WINDOWS else "SysHealthCLI")
            text = (f"Use {exe}. Open a terminal in that folder and run 'SysHealthCLI --help'.")
        else:
            text = ("From source: open a terminal in the SysHealth folder, activate the virtual environment, then run "
                    "'python cli.py --help'. The built version is SysHealthCLI.exe next to SysHealth.exe.")
        ttk.Label(how, text=text, wraplength=1000, justify=tk.LEFT).pack(fill=tk.X)
        MutedLabel(how, text="Add --json to any command for machine-readable output. Exit code 0 = OK, 1 = problems "
                  "found, 2 = administrator rights needed.", style="Muted.TLabel").pack(fill=tk.X, pady=(6, 0))
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(12, 6))
        ttk.Label(bar, text="Cheat sheet", style="Section.TLabel").pack(side=tk.LEFT)
        ttk.Button(bar, text="Save cheat sheet…", command=self.save).pack(side=tk.RIGHT)
        ttk.Button(bar, text="Copy command", style="Accent.TButton", command=self.copy).pack(side=tk.RIGHT, padx=6)
        self.table = Table(self, [("section", "Topic", 140), ("command", "Command", 420),
                                  ("desc", "What it does", 520)], selectmode="browse")
        self.table.pack(fill=tk.BOTH, expand=True)
        for section, cmd, desc in cheatsheet.rows():
            self.table.add((section, cmd, desc), cmd)
        self.table.tree.bind("<Double-1>", lambda e: self.copy())

    def copy(self) -> None:
        sel = self.table.selected()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a command first.")
            return
        self.app.clipboard_clear()
        self.app.clipboard_append(sel[0])
        self.app.set_status(f"Copied: {sel[0]}")

    def save(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".md", initialfile="SysHealth_CLI_cheatsheet.md",
                                            filetypes=[("Markdown", "*.md"), ("Text", "*.txt")])
        if path:
            content = cheatsheet.as_text() if path.endswith(".txt") else cheatsheet.as_markdown()
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
            self.app.log(f"Cheat sheet saved to {path}")
