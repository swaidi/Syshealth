"""Prompt shown when a newer SysHealth is available. The user decides: update now, later, or skip the version."""
from __future__ import annotations

import threading
import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk

from core import self_update, settings, state
from core.version import VERSION


def _center(win: tk.Toplevel, app, width: int, height: int) -> None:
    """Place a dialog in the middle of the main window."""
    app.update_idletasks()
    x = app.winfo_rootx() + max(0, (app.winfo_width() - width) // 2)
    y = app.winfo_rooty() + max(0, (app.winfo_height() - height) // 3)
    win.geometry(f"{width}x{height}+{x}+{y}")


class UpdateDialog(tk.Toplevel):
    def __init__(self, app, release: self_update.Release):
        super().__init__(app)
        self.app = app
        self.release = release
        self.self_install = self_update.can_self_install()
        p = app.palette
        self.title("SysHealth update")
        self.configure(background=p["app"])
        _center(self, app, 620, min(520, self.winfo_screenheight() - 120))
        self.minsize(520, 440)
        self.transient(app)

        btns = ttk.Frame(self, padding=(18, 8, 18, 18))
        btns.pack(side=tk.BOTTOM, fill=tk.X)  # first, so the buttons never get pushed off screen
        body = ttk.Frame(self, padding=18)
        body.pack(fill=tk.BOTH, expand=True)
        ttk.Label(body, text="A new version of SysHealth is available", style="PageTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(body, text=f"Version {release.version} is ready. You have version {VERSION}.",
                  style="Section.TLabel").pack(anchor=tk.W, pady=(6, 0))
        facts = [f"Released {release.published}" if release.published else ""]
        size = self_update.download_size(release)
        if size:
            facts.append(f"Download {size / 1_048_576:.1f} MB")
        ttk.Label(body, text="  ·  ".join(f for f in facts if f), style="Muted.TLabel").pack(anchor=tk.W, pady=(2, 12))

        ttk.Label(body, text="What's new", style="Section.TLabel").pack(anchor=tk.W, pady=(0, 4))
        wrap = ttk.Frame(body, style="Card.TFrame", padding=1)
        wrap.pack(fill=tk.BOTH, expand=True)
        notes = tk.Text(wrap, height=8, wrap=tk.WORD, relief=tk.FLAT, bd=0, padx=10, pady=8, highlightthickness=0,
                        background=p["card"], foreground=p["fg"], font=(app.font_family, 10), cursor="arrow")
        sb = ttk.Scrollbar(wrap, orient=tk.VERTICAL, command=notes.yview)
        notes.configure(yscrollcommand=sb.set)
        notes.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        notes.tag_configure("head", font=(app.font_family, 10, "bold"), spacing1=4)
        for i, line in enumerate(release.summary):
            heading = line.endswith(":") and not line.startswith("•")
            notes.insert(tk.END, ("\n" if i else "") + line, ("head",) if heading else ())
        notes.configure(state=tk.DISABLED)

        ttk.Button(body, text="View full release notes", command=lambda: webbrowser.open(release.page)).pack(
            anchor=tk.W, pady=(8, 0))
        note = ("Updating downloads the new version, checks it, then closes and reopens SysHealth. "
                "Your settings, quarantine and history are kept." if self.self_install else
                "You are running SysHealth from source. 'Open download page' opens the release on GitHub.")
        ttk.Label(body, text=note, style="Muted.TLabel", wraplength=560, justify=tk.LEFT).pack(anchor=tk.W, pady=(10, 0))
        self.auto = tk.BooleanVar(value=self_update.check_at_startup())
        ttk.Checkbutton(body, text="Check for SysHealth updates when it starts", variable=self.auto,
                        command=lambda: settings.set_value("update_check_startup", self.auto.get())).pack(
            anchor=tk.W, pady=(8, 0))

        ttk.Button(btns, text="Skip this version", command=self.skip).pack(side=tk.LEFT)
        ttk.Button(btns, text="Update now" if self.self_install else "Open download page", style="Accent.TButton",
                   command=self.update).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Remind me later", command=self.later).pack(side=tk.RIGHT, padx=6)
        self.protocol("WM_DELETE_WINDOW", self.later)
        self.grab_set()

    # ------------------------------------------------------------------ choices
    def later(self) -> None:
        self.app.log(f"SysHealth {self.release.version} is available; you chose to be reminded later.")
        self.destroy()

    def skip(self) -> None:
        settings.set_value("update_skip_version", self.release.version)
        self.app.log(f"SysHealth {self.release.version} skipped. You will be told about the next version. "
                     "The 'SysHealth updates' button in the header still shows it.")
        self.destroy()

    def update(self) -> None:
        if not self.self_install:
            webbrowser.open(self.release.page)
            self.destroy()
            return
        if self.app.busy:
            messagebox.showinfo("SysHealth update", "Another task is running. Wait for it to finish or cancel it, "
                                "then choose Update now.", parent=self)
            return
        self.destroy()
        release, app = self.release, self.app

        def work(cancel):
            try:
                return self_update.download(release, app.log, cancel)
            except self_update.UpdateError as exc:
                return exc

        def done(result):
            if isinstance(result, self_update.UpdateError):
                app.log(f"Update not installed: {result}")
                if messagebox.askyesno("SysHealth update", f"The update could not be installed.\n\n{result}\n\n"
                                       "Open the release page to download it manually?", icon="warning"):
                    webbrowser.open(release.page)
                return
            if not messagebox.askokcancel("SysHealth update", f"Version {release.version} is downloaded and ready.\n\n"
                                          "SysHealth will now close, install it and reopen. This takes a few seconds."):
                app.log("Update postponed. It will be offered again.")
                return
            try:
                method = self_update.apply(result, VERSION, release.version)
            except (self_update.UpdateError, OSError) as exc:
                app.log(f"Update not installed: {exc}")
                if messagebox.askyesno("SysHealth update", f"SysHealth could not install the update.\n\n{exc}\n\n"
                                       "Nothing was changed. Open the release page to download it manually?",
                                       icon="warning"):
                    webbrowser.open(release.page)
                return
            state.record_action("SysHealth update", f"Installing version {release.version}",
                                f"from {VERSION}; files {method}")
            app.destroy()

        app.run_task(f"Downloading SysHealth {release.version}", work, done)


class SelfUpdateStatus(tk.Toplevel):
    """Opened from the header. Checks GitHub for a newer SysHealth only (not other installed apps)."""

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        p = app.palette
        self.title("SysHealth updates")
        self.configure(background=p["app"])
        _center(self, app, 520, 300)
        self.resizable(False, False)
        self.transient(app)

        body = ttk.Frame(self, padding=18)
        body.pack(fill=tk.BOTH, expand=True)
        ttk.Label(body, text="SysHealth updates", style="PageTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(body, text=f"Installed version: {VERSION}", style="Section.TLabel").pack(anchor=tk.W, pady=(8, 0))
        self.last = tk.StringVar()
        ttk.Label(body, textvariable=self.last, style="Muted.TLabel").pack(anchor=tk.W, pady=(2, 0))
        self.status = tk.StringVar()
        ttk.Label(body, textvariable=self.status, wraplength=480, justify=tk.LEFT).pack(anchor=tk.W, pady=(14, 0))
        self.auto = tk.BooleanVar(value=self_update.check_at_startup())
        ttk.Checkbutton(body, text="Check for SysHealth updates when it starts (once a day)", variable=self.auto,
                        command=lambda: settings.set_value("update_check_startup", self.auto.get())).pack(
            anchor=tk.SW, side=tk.BOTTOM)

        btns = ttk.Frame(self, padding=(18, 0, 18, 18))
        btns.pack(fill=tk.X)
        ttk.Button(btns, text="Close", command=self.destroy).pack(side=tk.RIGHT)
        self.check_btn = ttk.Button(btns, text="Check now", style="Accent.TButton", command=self.check)
        self.check_btn.pack(side=tk.RIGHT, padx=6)
        self._show_last()
        self.grab_set()
        self.check()

    def _show_last(self) -> None:
        last = (settings.get("update_last_check") or "").replace("T", " ")[:16]
        self.last.set(f"Last checked: {last}" if last else "Not checked yet")

    def check(self) -> None:
        if not self_update.repo():
            self.status.set("The update source is not set yet, so SysHealth cannot check for new versions. "
                            "It is set once by the developer (see 'SysHealth updates' in README.md).")
            self.check_btn.state(["disabled"])
            return
        self.status.set("Checking for a newer version of SysHealth…")
        self.check_btn.state(["disabled"])

        def worker():
            try:
                result = self_update.check(VERSION)
            except Exception as exc:
                result = exc
            self.app.ui(lambda: self._done(result))
        threading.Thread(target=worker, daemon=True).start()

    def _done(self, result) -> None:
        if not self.winfo_exists():
            return
        self._show_last()
        self.check_btn.state(["!disabled"])
        if isinstance(result, Exception):
            self.status.set(f"Could not check for updates. {result}")
            self.app.log(f"SysHealth update check: {result}")
        elif result is None:
            self.status.set("You have the latest version of SysHealth.")
            self.app.log(f"SysHealth {VERSION} is the latest version.")
            self.app.update_btn.configure(text="SysHealth updates", style="TButton")
        else:
            self.destroy()
            self.app.show_update(result)
