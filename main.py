"""SysHealth - duplicate finder, malware scanner and system health toolkit for Windows and Linux."""
from __future__ import annotations

import ctypes
import datetime as dt
import os
import queue
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from send2trash import send2trash

from core import disk_health, network, system_health
from core.checks import FAIL, INFO, OK, WARN, Fix, execute_fix
from core import long_paths
from core.duplicates import export_xlsx as export_duplicates_xlsx, find_duplicates, in_program_folder, index_files
from core.malware import Allowlist, ClamAV, Defender, quick_scan_locations, scan_unknown_files
from core.platform_utils import (APP_NAME, IS_LINUX, IS_WINDOWS, Cancelled, NeedsAdmin, app_data_dir, human_size,
                                 is_admin, is_protected, open_location, open_url_or_file,
                                 relaunch_as_admin)
from core import security, self_update, state, settings as settings_store
from core.version import VERSION
from core.quarantine import Quarantine
from ui import theme
from ui.activity import ActivityIndicator
from ui.sidebar import Sidebar
from ui.common import (PALETTES, STATUS_BADGE, MutedLabel, ThemedLabel, retheme, STATUS_TEXT, CheckTree,
                       DriveSelector, ScrollFrame, card, register_tree, summarize_checks)

try:
    import darkdetect  # reads the operating system light/dark setting
except ImportError:
    darkdetect = None


# Sidebar navigation: (section, [(page key, label)])
NAV_SECTIONS = [
    ("Overview", [("dashboard", "Dashboard"), ("changes", "Recent Changes")]),
    ("Clean Up", [("largefiles", "Large Files"), ("duplicates", "Duplicate Files"), ("cleanup", "Cleanup"),
                  ("longpaths", "Long Paths")]),
    ("Protect", [("malware", "Malware Scan"), ("quarantine", "Quarantine"), ("security", "Security"),
                 ("startup", "Startup Apps"), ("autoruns", "Autoruns Audit"), ("connections", "Connections")]),
    ("Health", [("system", "System Health"), ("disk", "Disk Health"), ("network", "Network"),
                ("dnsspeed", "DNS & Speed"), ("events", "Event Log"), ("monitor", "Live Monitor")]),
    ("Tools", [("updates", "App Updates"), ("shredder", "File Shredder"), ("virustotal", "VirusTotal"),
               ("cli", "Command Line")]),
]


# =============================================================================== application
class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"{APP_NAME} {VERSION}")
        self._set_window_icon()
        self.geometry("1280x820")
        self.minsize(1040, 680)
        self._queue: "queue.Queue" = queue.Queue()
        self.cancel_event = threading.Event()
        self.busy = False
        self.settings = settings_store.load()
        self.theme_mode = self.settings.get("theme", "system")
        self.dark = False
        self._theme_listeners: list = []
        self.quarantine = Quarantine()
        self.allowlist = Allowlist()
        self.version = VERSION
        self.is_admin = is_admin()
        self.last_error: dict | None = None
        self.font_family = theme.font_family()

        from ui.common import install_input_helpers
        install_input_helpers(self)
        self._build_header()
        self._build_statusbar()
        self._build_body()
        self.apply_theme(self.theme_mode, save=False)
        self.show_page("dashboard")
        self.after(100, self._drain_queue)
        self.after(5000, self._watch_system_theme)
        self.after(1500, self._offer_linux_tools if IS_LINUX else self._offer_clamav)
        self.log(f"{APP_NAME} {VERSION} started. Administrator rights: {'yes' if is_admin() else 'no'}.")
        self._report_finished_update()
        self.after(4000, self._startup_update_check)
        self.after(8000, self._check_signature_age)

    # ------------------------------------------------------------------ layout
    def _build_header(self) -> None:
        bar = ttk.Frame(self, style="Card.TFrame", padding=(16, 9))
        bar.pack(fill=tk.X)
        if self._logo_small is not None:
            ttk.Label(bar, image=self._logo_small).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Label(bar, text=APP_NAME, style="AppTitle.TLabel").pack(side=tk.LEFT)
        MutedLabel(bar, text="   System care toolkit").pack(side=tk.LEFT, pady=(3, 0))

        if IS_WINDOWS and not is_admin():
            ttk.Button(bar, text="Restart as Administrator", command=self.restart_admin).pack(side=tk.RIGHT)
        ThemedLabel(bar, "ok" if is_admin() else "info", size=10, bold=True,
                    text="✔ Admin" if is_admin() else "ℹ User").pack(side=tk.RIGHT, padx=14)
        self.theme_var = tk.StringVar(value={"system": "Follow System"}.get(self.theme_mode,
                                                                          self.theme_mode.capitalize()))
        combo = ttk.Combobox(bar, textvariable=self.theme_var, values=["Follow System", "Light", "Dark"],
                             state="readonly", width=14)
        combo.pack(side=tk.RIGHT)
        combo.bind("<<ComboboxSelected>>", lambda e: self.apply_theme(
            "system" if self.theme_var.get().startswith("Follow") else self.theme_var.get().lower()))
        MutedLabel(bar, text="Theme").pack(side=tk.RIGHT, padx=(14, 6))
        ttk.Button(bar, text="Feedback", command=lambda: self.open_feedback("suggestion")).pack(
            side=tk.RIGHT, padx=(0, 10))
        self.update_btn = ttk.Button(bar, text="SysHealth updates", command=self.check_for_app_update)
        self.update_btn.pack(side=tk.RIGHT, padx=(0, 6))

    def _set_window_icon(self) -> None:
        """Window/taskbar icon and the small header logo, from the bundled assets folder."""
        self._icons, self._logo_small = [], None
        try:
            self._icons = [tk.PhotoImage(file=resource_path("assets", f"logo_{s}.png")) for s in (256, 64, 48, 32, 16)]
            self.iconphoto(True, *self._icons)
            self._logo_small = tk.PhotoImage(file=resource_path("assets", "logo_32.png"))
        except tk.TclError:
            pass  # assets missing: keep the default icon
        if IS_WINDOWS:
            try:
                self.iconbitmap(default=resource_path("assets", "syshealth.ico"))
            except tk.TclError:
                pass

    def _build_body(self) -> None:
        body = ttk.Frame(self)
        body.pack(fill=tk.BOTH, expand=True)

        self.nav = Sidebar(body, NAV_SECTIONS, self.show_page, footer=f"v{VERSION} · A.T.Grep")
        self.nav.pack(side=tk.LEFT, fill=tk.Y)
        self.on_theme(lambda p: self.nav.apply_palette(p, self.font_family))
        self._current_page = ""

        self.split = ttk.PanedWindow(body, orient=tk.VERTICAL)
        self.split.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=16, pady=(14, 0))
        content = ttk.Frame(self.split)
        content.rowconfigure(0, weight=1)
        content.columnconfigure(0, weight=1)
        self.split.add(content, weight=5)
        self._build_log()
        self.split.add(self.log_frame, weight=1)
        self.log_visible = True

        from ui import pages_space, pages_protect, pages_health, pages_tools
        self.dashboard = DashboardPage(content, self)
        self.dup_tab = DuplicatesTab(content, self)
        self.lp_tab = LongPathsTab(content, self)
        self.mal_tab = MalwareTab(content, self)
        self.q_tab = QuarantineTab(content, self)
        self.pages: dict[str, ttk.Frame] = {
            "dashboard": self.dashboard,
            "changes": pages_health.ChangesPage(content, self),
            "largefiles": pages_space.LargeFilesPage(content, self),
            "duplicates": self.dup_tab,
            "cleanup": pages_space.CleanupPage(content, self),
            "longpaths": self.lp_tab,
            "malware": self.mal_tab,
            "quarantine": self.q_tab,
            "security": ChecksTab(content, self, security, "Security", "security",
                                  "Protection settings scored out of 100, with one-click hardening."),
            "startup": pages_protect.StartupPage(content, self),
            "autoruns": pages_protect.AutorunsPage(content, self),
            "connections": pages_protect.ConnectionsPage(content, self),
            "system": ChecksTab(content, self, system_health, "System Health", "system",
                                "Resources, updates, protection and Windows component integrity."),
            "disk": ChecksTab(content, self, disk_health, "Disk Health", "disk",
                              "Drive health, temperature, wear and file system condition."),
            "network": ChecksTab(content, self, network, "Network", "network",
                                 "Adapters, gateway, internet, DNS, proxy, firewall and hosts file."),
            "dnsspeed": pages_health.DnsSpeedPage(content, self),
            "events": pages_health.EventsPage(content, self),
            "monitor": pages_health.MonitorPage(content, self),
            "updates": pages_tools.UpdatesPage(content, self),
            "shredder": pages_tools.ShredderPage(content, self),
            "virustotal": pages_tools.VirusTotalPage(content, self),
            "cli": pages_tools.CommandLinePage(content, self),
        }
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")

    def _build_log(self) -> None:
        self.log_frame = ttk.Frame(self.split, padding=(0, 8, 0, 8))
        ttk.Label(self.log_frame, text="Activity log", style="Section.TLabel").pack(anchor=tk.W, pady=(0, 4))
        inner = ttk.Frame(self.log_frame, style="Card.TFrame", padding=1)
        inner.pack(fill=tk.BOTH, expand=True)
        self.log_box = tk.Text(inner, height=6, state=tk.DISABLED, wrap=tk.WORD, relief=tk.FLAT,
                               borderwidth=0, padx=10, pady=8, highlightthickness=0,
                               font=(theme.mono_family(), 9))
        sb = ttk.Scrollbar(inner, orient=tk.VERTICAL, command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=sb.set)
        self.log_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.on_theme(lambda p: self.log_box.configure(background=p["log_bg"], foreground=p["log_fg"],
                                                       insertbackground=p["log_fg"],
                                                       selectbackground=p["selected"]))

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self, style="Card.TFrame", padding=(16, 5))
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var = tk.StringVar(value="Ready.")
        self.activity = ActivityIndicator(bar)
        self.activity.pack(side=tk.LEFT, padx=(0, 10))
        self.status_lbl = ThemedLabel(bar, "fg", size=10, textvariable=self.status_var)
        self.status_lbl.pack(side=tk.LEFT)
        self.elapsed_var = tk.StringVar(value="")
        self.elapsed_lbl = ThemedLabel(bar, "accent", size=10, bold=True, textvariable=self.elapsed_var)
        self.elapsed_lbl.pack(side=tk.LEFT, padx=(12, 0))
        ttk.Button(bar, text="Save log", command=self.save_log).pack(side=tk.RIGHT, padx=(6, 0))
        self.log_btn = ttk.Button(bar, text="▼ Hide log", command=self.toggle_log)
        self.log_btn.pack(side=tk.RIGHT, padx=6)
        self.cancel_btn = ttk.Button(bar, text="Cancel", command=self.cancel_task, state=tk.DISABLED)
        self.cancel_btn.pack(side=tk.RIGHT, padx=6)
        self.on_theme(lambda p: self.activity.apply_palette(p, p["card"]))

    def _tick_elapsed(self) -> None:
        if self.busy:
            self.elapsed_var.set(f"running {self.activity.elapsed()}")
            self.after(500, self._tick_elapsed)

    def page_header(self, parent, title: str, subtitle: str) -> ttk.Frame:
        head = ttk.Frame(parent)
        head.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(head, text=title, style="PageTitle.TLabel").pack(anchor=tk.W)
        MutedLabel(head, text=subtitle, style="Muted.TLabel").pack(anchor=tk.W, pady=(2, 0))
        return head

    def show_page(self, key: str) -> None:
        if key not in self.pages:
            return
        previous = self.pages.get(self._current_page)
        if previous is not None and hasattr(previous, "on_hide"):
            previous.on_hide()
        self._current_page = key
        self.pages[key].tkraise()
        if hasattr(self.pages[key], "on_show"):
            self.pages[key].on_show()
        self.nav.select(key)

    def vt_lookup(self, path: str) -> None:
        self.pages["virustotal"].lookup_path(path)

    def toggle_log(self) -> None:
        if self.log_visible:
            self.split.forget(self.log_frame)
            self.log_btn.configure(text="▲ Show log")
        else:
            self.split.add(self.log_frame, weight=1)
            self.log_btn.configure(text="▼ Hide log")
        self.log_visible = not self.log_visible

    # ------------------------------------------------------------------ theming
    @property
    def palette(self) -> dict:
        return PALETTES["dark" if self.dark else "light"]

    def on_theme(self, callback) -> None:
        self._theme_listeners.append(callback)

    def _system_is_dark(self) -> bool:
        if darkdetect is not None:
            try:
                return bool(darkdetect.isDark())
            except Exception:
                return False
        return False

    def apply_theme(self, mode: str, save: bool = True) -> None:
        self.theme_mode = mode
        self.dark = mode == "dark" or (mode == "system" and self._system_is_dark())
        p = theme.apply(self, self.dark, self.font_family)
        if hasattr(self, "pages"):
            theme.adapt_surfaces(self, ttk.Style(self), p)
        self._reapply_colors()
        self._set_titlebar(self.dark)
        if save:
            self.settings["theme"] = mode
            settings_store.set_value("theme", mode)

    def _reapply_colors(self) -> None:
        retheme(self.palette, self.font_family)
        for cb in self._theme_listeners:
            cb(self.palette)

    def _watch_system_theme(self) -> None:
        if self.theme_mode == "system" and self._system_is_dark() != self.dark:
            self.apply_theme("system", save=False)
        self.after(5000, self._watch_system_theme)

    def _set_titlebar(self, dark: bool) -> None:
        """Windows 10/11: match the title bar to the theme."""
        if not IS_WINDOWS:
            return
        try:
            self.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            value = ctypes.c_int(1 if dark else 0)
            for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (new / older builds)
                if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(value),
                                                              ctypes.sizeof(value)) == 0:
                    break
            w, h = self.winfo_width(), self.winfo_height()
            if w > 1:  # nudge the window so the title bar repaints
                self.geometry(f"{w + 1}x{h}")
                self.geometry(f"{w}x{h}")
        except Exception:
            pass

    # ------------------------------------------------------------------ threading helpers
    def ui(self, fn) -> None:
        """Schedule fn on the UI thread (safe to call from worker threads)."""
        self._queue.put(fn)

    def _drain_queue(self) -> None:
        try:
            while True:
                self._queue.get_nowait()()
        except queue.Empty:
            pass
        self.after(100, self._drain_queue)

    def log(self, msg: str) -> None:
        def append():
            self.log_box.configure(state=tk.NORMAL)
            self.log_box.insert(tk.END, f"[{dt.datetime.now():%H:%M:%S}] {msg}\n")
            if int(self.log_box.index("end-1c").split(".")[0]) > 5000:
                self.log_box.delete("1.0", "1000.0")
            self.log_box.see(tk.END)
            self.log_box.configure(state=tk.DISABLED)
        self.ui(append)

    def set_status(self, msg: str) -> None:
        self.ui(lambda: self.status_var.set(msg))

    def run_task(self, title: str, work, on_done=None) -> None:
        if self.busy:
            messagebox.showinfo(APP_NAME, "Another task is running. Wait for it to finish or click Cancel.")
            return
        self.busy = True
        self.cancel_event = threading.Event()
        self.status_var.set(f"{title}…")
        self.activity.start()
        self.status_lbl.bold = True
        self.status_lbl._apply()
        self._tick_elapsed()
        self.cancel_btn.configure(state=tk.NORMAL, style="Danger.TButton")
        self.log(f"--- {title} ---")
        cancel = self.cancel_event

        def runner():
            result, error = None, None
            try:
                result = work(cancel)
            except Exception as exc:  # reported on the UI thread
                error = exc

            def finish():
                self.busy = False
                took = self.activity.elapsed()
                self.activity.stop("cancel" if isinstance(error, Cancelled) else
                                   "ok" if error is None else "fail")
                self.status_lbl.bold = False
                self.status_lbl._apply()
                self.elapsed_var.set(f"took {took}")
                self.cancel_btn.configure(state=tk.DISABLED, style="TButton")
                if isinstance(error, Cancelled):
                    self.status_var.set(f"{title}: cancelled.")
                    self.log(f"{title} cancelled.")
                elif isinstance(error, NeedsAdmin):
                    self.status_var.set("Administrator rights required.")
                    resume = ["--install-clamav"] if str(error) == "Install ClamAV" else None
                    if messagebox.askyesno(APP_NAME, f"'{error}' requires administrator rights.\n\n"
                                           "Restart SysHealth as Administrator now?" +
                                           ("\nThe installation will continue automatically." if resume else "")):
                        self.restart_admin(resume)
                elif error is not None:
                    self.status_var.set(f"{title}: failed.")
                    self.report_error(title, error)
                else:
                    self.status_var.set(f"{title}: done")
                    if on_done:
                        on_done(result)
            self.ui(finish)

        threading.Thread(target=runner, daemon=True).start()

    def report_error(self, title: str, error: BaseException, tb=None) -> None:
        """Log an error, remember it for feedback reports, and offer to report it."""
        import traceback
        detail = f"{type(error).__name__}: {error}" if str(error) else type(error).__name__
        trace = "".join(traceback.format_exception(type(error), error, tb or error.__traceback__))
        self.last_error = {"time": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "title": title,
                           "detail": detail, "traceback": trace}
        self.log(f"ERROR in {title}: {detail}")
        for line in trace.strip().splitlines()[-4:]:
            self.log("  " + line.strip())
        if messagebox.askyesno(APP_NAME, f"{title} failed:\n\n{detail}\n\nDetails are in the activity log.\n\n"
                               "Report this problem to the developer?", icon="error"):
            self.open_feedback("problem")

    def report_callback_exception(self, exc, val, tb) -> None:  # unexpected errors in buttons and events
        self.report_error("Unexpected error", val, tb)

    def guard_paths(self, paths: list[str], action: str) -> list[str]:
        """Final safety check before deleting, moving or renaming: drop anything in app data, and say so."""
        from core.safety import split_allowed
        allowed, blocked = split_allowed(paths)
        if blocked:
            for p, reason in blocked[:30]:
                self.log(f"Protected, left unchanged: {p} ({reason})")
            messagebox.showwarning(APP_NAME, f"{len(blocked):,} item(s) were left out and will not be {action}, "
                                   "because they are application data: browser profiles, sign-ins, passwords, "
                                   "extensions or app settings. Changing them can sign you out or break apps.\n\n"
                                   "The activity log lists them.")
        return allowed

    def open_feedback(self, kind: str = "suggestion") -> None:
        from ui.feedback import FeedbackDialog
        FeedbackDialog(self, kind)

    def cancel_task(self) -> None:
        self.cancel_event.set()
        self.status_var.set("Cancelling…")

    # ------------------------------------------------------------------ actions
    def restart_admin(self, extra_args=None) -> None:
        if relaunch_as_admin(extra_args):
            self.destroy()
        else:
            messagebox.showwarning(APP_NAME, "The administrator prompt was declined or could not be shown.")

    def save_log(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=f"{APP_NAME}_log_"
                                            f"{dt.datetime.now():%Y%m%d_%H%M}.txt",
                                            filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.log_box.get("1.0", tk.END))
            self.log(f"Log saved to {path}")

    def confirm_fix(self, fix: Fix) -> bool:
        notes = []
        if fix.admin:
            notes.append("Requires administrator rights.")
        if fix.reboot:
            notes.append("A restart is required to complete this action.")
        msg = f"{fix.title}\n\n{fix.description}\n\nCommands:\n{fix.preview()}"
        from core import network as net
        if fix.id in net.RISKY_ON_MANAGED:
            managed = net.managed_device()
            if managed:
                if not messagebox.askyesno(
                        "Company-managed computer", f"{managed}\n\n'{fix.title}' can remove VPN adapters, "
                        "company proxy or network settings, and may need IT to restore them.\n\n"
                        "Contact your IT department first. Continue anyway?", icon="warning", default="no"):
                    return False
        if notes:
            msg += "\n\n" + "\n".join(notes)
        return messagebox.askyesno("Confirm action", msg + "\n\nProceed?")

    def run_fix(self, fix: Fix, on_done=None) -> None:
        if not self.confirm_fix(fix):
            return

        def done(_r):
            self.log(f"{fix.title} finished." + (" Restart the computer to complete it." if fix.reboot else ""))
            state.record_action("Repair", fix.title)
            if on_done:
                on_done()
        self.run_task(fix.title, lambda c: execute_fix(fix, self.log, c), done)

    def _offer_linux_tools(self) -> None:
        """First start on Linux: offer the small helper tools once (one password prompt), then ClamAV."""
        from core import linux_tools
        needed = linux_tools.missing()
        if not needed or self.settings.get("linux_tools_prompted"):
            self._offer_clamav()
            return
        settings_store.set_value("linux_tools_prompted", True)
        lines = "\n".join(f"•  {t.package}: {t.purpose}" for t in needed)
        if not messagebox.askyesno(APP_NAME, "SysHealth works best with these small system tools, which are not "
                                   f"installed yet:\n\n{lines}\n\nInstall them now? You will be asked for your "
                                   "password once.\n\nYou can also install them later from a terminal:\n"
                                   "SysHealthCLI linux-tools install"):
            self._offer_clamav()
            return

        def done(_r):
            state.record_action("System", "Installed helper tools", ", ".join(t.package for t in needed))
            self.log("Helper tools installed.")
            self._offer_clamav()
        self.run_task("Installing helper tools", lambda c: linux_tools.install(needed, self.log, c), done)

    def _offer_clamav(self) -> None:
        """First launch: offer to install ClamAV once. Skipped when it is already installed."""
        if "--install-clamav" in sys.argv and not self.mal_tab.clam.installed():
            self.show_page("malware")
            self.mal_tab.install_clamav()
            return
        if self.mal_tab.clam.installed() or self.settings.get("clamav_prompted"):
            return
        self.settings["clamav_prompted"] = True
        settings_store.set_value("clamav_prompted", True)
        edition = "Windows" if IS_WINDOWS else "Linux"
        note = ("\n\nThis requires administrator rights; SysHealth will offer to restart as "
                "Administrator if needed." if IS_WINDOWS and not is_admin() else "")
        if messagebox.askyesno(APP_NAME, "The ClamAV antivirus engine is not installed.\n\n"
                               f"Install the {edition} edition now? SysHealth will download it from the "
                               f"official source and fetch its virus signatures.{note}\n\n"
                               "You can also install it later from the Malware Scan page."):
            self.show_page("malware")
            self.mal_tab.install_clamav()

    # ------------------------------------------------------------------ malware signature freshness
    def _check_signature_age(self) -> None:
        """Every hour: if signatures are over 3 days old and no reminder is postponed, show the reminder."""
        from core.malware import stale_engines
        from ui import reminders
        self.after(3600 * 1000, self._check_signature_age)
        if not reminders.reminder_due() or any(isinstance(w, reminders.SignatureReminder)
                                               for w in self.winfo_children()):
            return

        def worker():
            try:
                stale = stale_engines(self.mal_tab.clam, self.mal_tab.defender if IS_WINDOWS else None)
            except Exception as exc:
                self.log(f"Signature age check skipped: {exc}")
                return
            if stale:
                self.ui(lambda: reminders.SignatureReminder(self, stale, self._update_signatures_now))
        threading.Thread(target=worker, daemon=True).start()

    def _update_signatures_now(self) -> None:
        self.show_page("malware")
        self.mal_tab.update_signatures()

    # ------------------------------------------------------------------ SysHealth updates
    def _report_finished_update(self) -> None:
        try:
            msg = self_update.finish_pending(VERSION)
        except OSError:
            msg = None
        if msg:
            self.log(msg)
            self.status_var.set(msg)
            if "updated" in msg:
                state.record_action("SysHealth update", msg)

    def _startup_update_check(self) -> None:
        """Quiet daily check. Only a newer, not-skipped version produces a prompt; problems go to the log."""
        if not (self_update.check_at_startup() and self_update.repo() and self_update.due_for_check()):
            return

        def worker():
            try:
                release = self_update.check(VERSION)
            except Exception as exc:  # never interrupt startup for an update check
                self.log(f"SysHealth update check skipped: {exc}")
                return
            if release and release.version != self_update.skipped_version():
                self.ui(lambda: self.show_update(release))
            elif release:
                self.ui(lambda: self.mark_update_available(release))
        threading.Thread(target=worker, daemon=True).start()

    def check_for_app_update(self) -> None:
        """Header button: SysHealth's own version, a fresh check, and the start-up check setting."""
        from ui.update_dialog import SelfUpdateStatus
        SelfUpdateStatus(self)

    def show_update(self, release) -> None:
        from ui.update_dialog import UpdateDialog
        self.mark_update_available(release)
        if any(isinstance(w, UpdateDialog) and w.winfo_exists() for w in self.winfo_children()):
            return  # one prompt at a time (start-up and manual checks can finish together)
        self.log(f"SysHealth {release.version} is available (you have {VERSION}).")
        UpdateDialog(self, release)

    def mark_update_available(self, release) -> None:
        """Keep a quiet reminder in the header after 'Remind me later' or 'Skip this version'."""
        self.update_btn.configure(text=f"Update to {release.version}", style="Accent.TButton")

    def run_all_checks(self) -> None:
        from core import events as events_mod
        modules = [("network", network), ("system", system_health), ("disk", disk_health), ("security", security)]

        def work(cancel):
            results = {}
            for key, module in modules:
                if cancel.is_set():
                    raise Cancelled()
                self.set_status(f"Checking {key}…")
                results[key] = module.run_checks(self.log)
            self.set_status("Reading event log…")
            results["events"] = events_mod.summarize(7)
            return results

        def done(results):
            for key, data in results.items():
                self.pages[key].show(data)
        self.run_task("Health check", work, done)


# =============================================================================== reusable widgets
# =============================================================================== dashboard
class DashboardPage(ttk.Frame):
    """Status cards. Each card shows the latest entry for its section in the shared state store
    (core/state.py), so results persist between sessions and other dashboards can read the same data."""

    CARDS = [("security", "Security"), ("malware", "Threats"), ("system", "System Health"),
             ("disk", "Disk Health"), ("network", "Network"), ("events", "Event Log"),
             ("updates", "App Updates"), ("cleanup", "Cleanup"), ("largefiles", "Disk Space"),
             ("duplicates", "Duplicate Files"), ("longpaths", "Long Paths"), ("startup", "Startup Apps"),
             ("autoruns", "Autoruns"), ("connections", "Connections"), ("speedtest", "Internet Speed"),
             ("changes", "Recent Changes"), ("quarantine", "Quarantine")]
    COLUMNS = 4

    def __init__(self, parent, app: App):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        app.page_header(self, "Dashboard", "Latest results from every tool. Results are kept between sessions.")

        actions = ttk.Frame(self)
        actions.pack(fill=tk.X, pady=(0, 10))
        ttk.Button(actions, text="Run all health checks", style="Accent.TButton",
                   command=app.run_all_checks).pack(side=tk.LEFT)
        ttk.Button(actions, text="Quick malware scan", command=self.quick_scan).pack(side=tk.LEFT, padx=8)
        ttk.Button(actions, text="Check app updates",
                   command=lambda: (app.show_page("updates"), app.pages["updates"].refresh())).pack(side=tk.LEFT)
        ttk.Button(actions, text="Analyze cleanup",
                   command=lambda: (app.show_page("cleanup"), app.pages["cleanup"].analyze())).pack(
            side=tk.LEFT, padx=8)

        scroll = ScrollFrame(self, app)
        scroll.pack(fill=tk.BOTH, expand=True)
        grid = scroll.inner
        for c in range(self.COLUMNS):
            grid.columnconfigure(c, weight=1, uniform="cards")
        self._build_schedule(grid)
        self.cards: dict[str, tuple] = {}
        for i, (key, title) in enumerate(self.CARDS):
            box = card(grid, 16)
            box.grid(row=1 + i // self.COLUMNS, column=i % self.COLUMNS, sticky="nsew", padx=5, pady=5)
            ttk.Label(box, text=title, style="CardTitle.TLabel").pack(anchor=tk.W)
            badge = ThemedLabel(box, "muted", size=10, bold=True, text="ℹ Not checked")
            badge.pack(anchor=tk.W, pady=(8, 0))
            value = ThemedLabel(box, "muted", size=15, bold=True, text="–", wraplength=230, justify=tk.LEFT)
            value.pack(anchor=tk.W, pady=(2, 2))
            detail = MutedLabel(box, text="", style="Muted.TLabel", wraplength=210, justify=tk.LEFT)
            detail.pack(anchor=tk.W, fill=tk.X)
            foot = ttk.Frame(box)
            foot.pack(fill=tk.X, side=tk.BOTTOM, pady=(10, 0))
            updated = MutedLabel(foot, text="", style="Muted.TLabel")
            updated.pack(side=tk.LEFT)
            ttk.Button(foot, text="Open", command=lambda k=key: app.show_page(k)).pack(side=tk.RIGHT)
            self.cards[key] = (badge, value, detail, updated)
        self.load_from_state()

    # ------------------------------------------------------------------ maintenance schedule
    SCHEDULE_ROLES = {"overdue": "fail", "never": "warn", "soon": "warn", "ok": "ok"}

    def _build_schedule(self, grid) -> None:
        """A compact list (not cards): each routine task, when it was last done, and what is due."""
        box = card(grid, 14)
        box.grid(row=0, column=0, columnspan=self.COLUMNS, sticky="nsew", padx=5, pady=(0, 10))
        head = ttk.Frame(box)
        head.pack(fill=tk.X)
        ttk.Label(head, text="Maintenance schedule", style="CardTitle.TLabel").pack(side=tk.LEFT)
        self.sched_summary = ThemedLabel(head, "muted", size=10, bold=True, text="")
        self.sched_summary.pack(side=tk.LEFT, padx=12)
        MutedLabel(head, text="Routine tasks and when each was last done.").pack(side=tk.RIGHT)
        self.sched_rows = ttk.Frame(box)
        self.sched_rows.pack(fill=tk.X, pady=(8, 0))
        for col, weight in enumerate((3, 2, 1, 2, 0)):
            self.sched_rows.columnconfigure(col, weight=weight)
        self._sched_widgets: list = []
        self.after(1500, self.refresh_schedule)

    def _schedule_actions(self) -> dict:
        app = self.app
        return {
            "signatures": ("Update", app._update_signatures_now),
            "malware_scan": ("Scan", self.quick_scan),
            "health": ("Run", app.run_all_checks),
            "app_updates": ("Check", lambda: (app.show_page("updates"), app.pages["updates"].refresh())),
            "events": ("Review", lambda: (app.show_page("events"), app.pages["events"].scan())),
            "security": ("Run", lambda: (app.show_page("security"), app.pages["security"].run_checks())),
            "startup": ("Review", lambda: (app.show_page("startup"), app.pages["startup"].scan())),
            "cleanup": ("Analyze", lambda: (app.show_page("cleanup"), app.pages["cleanup"].analyze())),
            "space": ("Open", lambda: app.show_page("largefiles")),
            "duplicates": ("Open", lambda: app.show_page("duplicates")),
        }

    def refresh_schedule(self) -> None:
        """Recalculate in the background (reading signature dates can take a moment), then redraw."""
        from core import maintenance

        def worker():
            mal = self.app.mal_tab
            extra = {"signatures": mal.clam.published}
            if IS_WINDOWS:
                defender_time = mal.defender.published
                extra = {"signatures": lambda: max([t for t in (mal.clam.published(), defender_time()) if t],
                                                   default=None)}
            try:
                tasks = maintenance.schedule(extra_last=extra)
            except Exception as exc:
                self.app.log(f"Maintenance schedule unavailable: {exc}")
                return
            maintenance.publish(tasks)
            self.app.ui(lambda: self._draw_schedule(tasks))
        threading.Thread(target=worker, daemon=True).start()

    def _draw_schedule(self, tasks) -> None:
        for w in self._sched_widgets:
            w.destroy()
        self._sched_widgets = []
        actions = self._schedule_actions()
        for c, text in enumerate(("Task", "Last done", "Every", "Status", "")):
            lbl = MutedLabel(self.sched_rows, text=text)
            lbl.grid(row=0, column=c, sticky="w", padx=(0, 12), pady=(0, 4))
            self._sched_widgets.append(lbl)
        for r, t in enumerate(tasks, 1):
            cells = [ThemedLabel(self.sched_rows, "fg", size=10, bold=t.status != "ok", text=t.title),
                     ThemedLabel(self.sched_rows, "fg", size=10,
                                 text=t.last.strftime("%Y-%m-%d") if t.last else "Never"),
                     MutedLabel(self.sched_rows, text=f"{t.every_days} days"),
                     ThemedLabel(self.sched_rows, self.SCHEDULE_ROLES[t.status], size=10, bold=True, text=t.note)]
            for c, w in enumerate(cells):
                w.grid(row=r, column=c, sticky="w", padx=(0, 12), pady=1)
            label, cmd = actions.get(t.id, ("Open", lambda p=t.page: self.app.show_page(p)))
            btn = ttk.Button(self.sched_rows, text=label, command=cmd, width=9)
            btn.grid(row=r, column=4, sticky="e", pady=1)
            self._sched_widgets += cells + [btn]
        due = sum(t.status in ("overdue", "never") for t in tasks)
        soon = sum(t.status == "soon" for t in tasks)
        self.sched_summary.configure(text=(f"{due} due" if due else "All up to date") +
                                     (f" · {soon} due soon" if soon else ""))
        self.sched_summary.set_role("warn" if due else "ok")

    def on_show(self) -> None:
        self.refresh_schedule()

    def load_from_state(self) -> None:
        for key, entry in state.load().items():
            if key in self.cards and isinstance(entry, dict):
                self._show(key, entry.get("level", INFO), entry.get("value", ""), entry.get("detail", ""),
                           entry.get("updated", ""))

    def _show(self, key: str, level: str, value: str, detail: str, updated: str) -> None:
        badge, val_lbl, det_lbl, upd_lbl = self.cards[key]
        level = level if level in (OK, WARN, FAIL, INFO) else INFO
        badge.configure(text=STATUS_BADGE[level])
        badge.set_role(level.lower())
        val_lbl.configure(text=value)
        val_lbl.set_role("fg")
        det_lbl.configure(text=detail)
        upd_lbl.configure(text=updated[5:16] if updated else "")

    def set_card(self, key: str, level: str, value: str, detail: str = "", data=None) -> None:
        """Publish a result to the shared state store and refresh the card."""
        try:
            state.publish(key, level, value, detail, data)
        except OSError as exc:
            self.app.log(f"Could not save dashboard state: {exc}")
        if key in self.cards:
            self._show(key, level, value, detail, dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        if key != "maintenance" and hasattr(self, "_sched_widgets"):
            self.after(500, self.refresh_schedule)

    def quick_scan(self) -> None:
        self.app.show_page("malware")
        self.app.mal_tab.scope.set("quick")
        self.app.mal_tab.scan()


# =============================================================================== duplicates
class DuplicatesTab(ttk.Frame):
    MAX_GROUPS = 5000

    def __init__(self, parent, app: App):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        self.files: dict[str, object] = {}
        self.group_of: dict[str, str] = {}
        app.page_header(self, "Duplicate Files", "Find copies by name or by size within the same file type. "
                        "System folders and app data (browser profiles, passwords, settings) are always excluded.")

        opts = card(self, 14)
        opts.pack(fill=tk.X)
        ttk.Label(opts, text="Locations", style="Section.TLabel").grid(row=0, column=0, sticky="nw", padx=(0, 16))
        self.drives = DriveSelector(opts)
        self.drives.grid(row=0, column=1, columnspan=4, sticky="w")

        ttk.Label(opts, text="Match by", style="Section.TLabel").grid(row=1, column=0, sticky="w", pady=(12, 0))
        self.mode = tk.StringVar(value="size_ext")
        ttk.Radiobutton(opts, text="Size within the same file type", variable=self.mode,
                        value="size_ext").grid(row=1, column=1, sticky="w", pady=(12, 0), padx=(0, 20))
        ttk.Radiobutton(opts, text="File name", variable=self.mode, value="name").grid(
            row=1, column=2, sticky="w", pady=(12, 0))

        ttk.Label(opts, text="Options", style="Section.TLabel").grid(row=2, column=0, sticky="w", pady=(12, 0))
        self.verify = tk.BooleanVar(value=True)
        self.hidden = tk.BooleanVar(value=False)
        self.appdata = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Confirm identical content", variable=self.verify,
                        style="Switch.TCheckbutton").grid(row=2, column=1, sticky="w", pady=(12, 0), padx=(0, 20))
        ttk.Checkbutton(opts, text="Include hidden files", variable=self.hidden,
                        style="Switch.TCheckbutton").grid(row=2, column=2, sticky="w", pady=(12, 0), padx=(0, 20))
        self.program = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Include program folders (advanced)", variable=self.program,
                        style="Switch.TCheckbutton", command=self._warn_program).grid(
            row=2, column=3, sticky="w", pady=(12, 0))

        size_row = ttk.Frame(opts)
        size_row.grid(row=3, column=1, columnspan=2, sticky="w", pady=(12, 0))
        ttk.Label(size_row, text="Minimum size (KB)").pack(side=tk.LEFT)
        self.min_kb = tk.StringVar(value="100")
        ttk.Entry(size_row, textvariable=self.min_kb, width=8).pack(side=tk.LEFT, padx=8)
        ttk.Button(opts, text="Scan for duplicates", style="Accent.TButton",
                   command=self.scan).grid(row=3, column=4, sticky="e", pady=(12, 0))
        opts.columnconfigure(4, weight=1)

        self.summary = tk.StringVar(value="Select locations and click 'Scan for duplicates'.")
        head = ttk.Frame(self)
        head.pack(fill=tk.X, pady=(12, 6))
        ttk.Label(head, textvariable=self.summary, style="Section.TLabel").pack(side=tk.LEFT)
        self.sel_var = tk.StringVar(value="")
        ttk.Label(head, textvariable=self.sel_var, style="Section.TLabel").pack(side=tk.RIGHT)

        self.tree = CheckTree(self, app, [("size", "Size", 100), ("modified", "Modified", 140),
                                          ("folder", "Folder", 520)], "Group / File (click to select)")
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.tree.bind("<Double-1>", self._open_selected)

        btns = ttk.Frame(self)
        btns.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 4), before=self.tree)
        ttk.Button(btns, text="Select all but newest", command=lambda: self.auto_select(True)).pack(side=tk.LEFT)
        ttk.Button(btns, text="Select all but oldest", command=lambda: self.auto_select(False)).pack(
            side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Clear selection", command=self.clear_selection).pack(side=tk.LEFT)
        ttk.Button(btns, text="Open file location", command=self._open_selected).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Export to Excel…", command=self.export_excel).pack(side=tk.LEFT)
        ttk.Button(btns, text="Move selected to Recycle Bin", style="Danger.TButton",
                   command=self.delete_selected).pack(side=tk.RIGHT)
        self.tree.tree.bind("<ButtonRelease-1>", lambda e: self.update_selection_label(), add=True)

    def scan(self) -> None:
        roots = self.drives.selected()
        if not roots:
            messagebox.showinfo(APP_NAME, "Select at least one drive or folder.")
            return
        try:
            min_size = max(0, int(float(self.min_kb.get()) * 1024))
        except ValueError:
            messagebox.showerror(APP_NAME, "Minimum size must be a number.")
            return
        mode, verify = self.mode.get(), self.verify.get()
        hidden, appdata, program = self.hidden.get(), self.appdata.get(), self.program.get()
        self.last_scan = {"roots": roots, "mode": mode, "verify": verify}

        def progress(msg: str) -> None:
            self.app.set_status(msg)
            if "files." in msg or "groups" in msg:
                self.app.log(msg)

        def work(cancel):
            files = index_files(roots, max(min_size, 1), hidden, appdata, cancel, progress, program)
            return find_duplicates(files, mode, verify, cancel, progress)

        self.tree.clear()
        self.app.run_task("Duplicate scan", work, self.show_results)

    def show_results(self, groups) -> None:
        self.tree.clear()
        self.files.clear()
        self.group_of.clear()
        self.groups = groups
        for i, g in enumerate(groups[:self.MAX_GROUPS], 1):
            gid = self.tree.add_group(f"Group {i}: {g.label} — {len(g.files)} files",
                                      (human_size(g.total), "", f"Reclaimable: {human_size(g.wasted)}"))
            for f in g.files:
                iid = self.tree.add_item(gid, f.name, (human_size(f.size),
                                                      dt.datetime.fromtimestamp(f.mtime).strftime("%Y-%m-%d %H:%M"),
                                                      os.path.dirname(f.path)))
                self.files[iid] = f
                self.group_of[iid] = gid
        wasted = sum(g.wasted for g in groups)
        self.total_wasted = wasted
        note = f" Showing the largest {self.MAX_GROUPS:,}." if len(groups) > self.MAX_GROUPS else ""
        self.summary.set(f"{len(groups):,} duplicate groups · {sum(len(g.files) for g in groups):,} files · "
                         f"{human_size(wasted)} reclaimable.{note}")
        if groups:
            self.app.dashboard.set_card("duplicates", WARN if wasted > 1024 ** 3 else INFO,
                                        f"{human_size(wasted)} reclaimable", f"{len(groups):,} duplicate groups")
        else:
            self.app.dashboard.set_card("duplicates", OK, "No duplicates", "Nothing to clean up.")
        self.update_selection_label()

    def auto_select(self, keep_newest: bool) -> None:
        for gid in self.tree.tree.get_children():
            kids = list(self.tree.tree.get_children(gid))
            if len(kids) < 2:
                continue
            keep = max(kids, key=lambda k: self.files[k].mtime) if keep_newest else \
                min(kids, key=lambda k: self.files[k].mtime)
            for k in kids:
                self.tree.set_checked(k, k != keep and not is_protected(self.files[k].path))
        self.update_selection_label()

    def clear_selection(self) -> None:
        for iid in list(self.tree.checked):
            self.tree.set_checked(iid, False)
        self.update_selection_label()

    def update_selection_label(self) -> None:
        sel = [self.files[i] for i in self.tree.checked if i in self.files]
        # the total reclaimable space is in the summary line above the list
        self.sel_var.set(f"Selected: {len(sel):,} files, {human_size(sum(f.size for f in sel))}" if sel else "")

    def _warn_program(self) -> None:
        if self.program.get():
            messagebox.showwarning(APP_NAME, "Program folders include Python environments, Node.js modules, Git "
                                   "data, Wine, Steam and Flatpak, plus program library files (.dll, .so).\n\n"
                                   "Their files often look like duplicates, but each program needs its own copy. "
                                   "Deleting them can stop programs or projects from working.\n\n"
                                   "Use this only to review space, for example with 'Export to Excel'.")

    def export_excel(self) -> None:
        groups = getattr(self, "groups", None)
        if not groups:
            messagebox.showinfo(APP_NAME, "Run a duplicate scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel workbook", "*.xlsx")],
                                            initialfile=f"SysHealth_duplicates_{dt.datetime.now():%Y%m%d_%H%M}.xlsx")
        if not path:
            return
        scan = getattr(self, "last_scan", {"roots": [], "mode": self.mode.get(), "verify": self.verify.get()})
        selected = {self.files[i].path for i in self.tree.checked if i in self.files}

        def done(rows):
            self.app.log(f"Duplicate report saved: {path} ({rows:,} files).")
            if messagebox.askyesno(APP_NAME, f"Saved {rows:,} files in {len(groups):,} groups to:\n{path}\n\n"
                                   "Open it now?"):
                open_url_or_file(path)
        self.app.run_task("Exporting duplicates to Excel", lambda c: export_duplicates_xlsx(
            groups, path, scan["roots"], scan["mode"], scan["verify"], selected), done)

    def _open_selected(self, _e=None) -> None:
        for iid in self.tree.tree.selection():
            if iid in self.files:
                open_location(self.files[iid].path)
                break

    def delete_selected(self) -> None:
        targets = [i for i in self.tree.checked if i in self.files]
        if not targets:
            messagebox.showinfo(APP_NAME, "Select files first (click the box next to each file).")
            return
        for gid in {self.group_of[i] for i in targets}:
            kids = set(self.tree.tree.get_children(gid))
            if kids and kids <= set(targets):
                messagebox.showwarning(APP_NAME, "Every copy in at least one group is selected. Keep at least one "
                                       "copy in each group.")
                return
        blocked = [i for i in targets if is_protected(self.files[i].path)]
        if blocked:
            messagebox.showwarning(APP_NAME, f"{len(blocked)} selected files are in protected system folders "
                                   "and were deselected.")
            for i in blocked:
                self.tree.set_checked(i, False)
            targets = [i for i in targets if i not in blocked]
        keep_paths = set(self.app.guard_paths([self.files[i].path for i in targets], "moved"))
        for i in [i for i in targets if self.files[i].path not in keep_paths]:
            self.tree.set_checked(i, False)
        targets = [i for i in targets if self.files[i].path in keep_paths]
        if not targets:
            return
        program = [i for i in targets if in_program_folder(self.files[i].path)]
        if program and not messagebox.askyesno(
                APP_NAME, f"{len(program):,} of the selected files belong to a program or project folder "
                "(for example a Python environment) or are program libraries.\n\n"
                "Deleting them can stop that program or project from working.\n\n"
                "Move them to the Recycle Bin anyway?", icon="warning", default="no"):
            return
        size = sum(self.files[i].size for i in targets)
        if not messagebox.askyesno(APP_NAME, f"Move {len(targets):,} files ({human_size(size)}) to the Recycle "
                                   "Bin?\n\nYou can restore them from the Recycle Bin if needed."):
            return
        paths = {i: self.files[i].path for i in targets}
        sizes = {i: self.files[i].size for i in targets}

        def work(cancel):
            done, failed = [], []
            for iid, path in paths.items():
                if cancel.is_set():
                    raise Cancelled()
                try:
                    send2trash(os.path.normpath(path))
                    done.append(iid)
                except Exception as exc:
                    failed.append(f"{path}: {exc}")
            return done, failed

        def finish(result):
            done, failed = result
            for iid in done:
                gid = self.group_of.pop(iid, None)
                self.files.pop(iid, None)
                self.tree.remove(iid)
                if gid and self.tree.tree.exists(gid) and len(self.tree.tree.get_children(gid)) < 2:
                    for k in self.tree.tree.get_children(gid):
                        self.files.pop(k, None)
                        self.tree.remove(k)
                    self.tree.tree.delete(gid)
            self.app.log(f"Moved {len(done):,} files to the Recycle Bin.")
            if done:
                state.record_action("Duplicates", f"Moved {len(done):,} duplicate file(s) to the Recycle Bin",
                                    human_size(sum(sizes[i] for i in done)), [paths[i] for i in done])
            for f in failed[:50]:
                self.app.log(f"Could not move: {f}")
            self.update_selection_label()
            if failed:
                messagebox.showwarning(APP_NAME, f"{len(failed)} files could not be moved. See the activity log.")

        self.app.run_task("Moving duplicates to Recycle Bin", work, finish)


# =============================================================================== long paths
class LongPathsTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        self.proposals: dict[str, long_paths.Proposal] = {}
        app.page_header(self, "Long Paths", "Find files whose full path is too long to open reliably, and "
                        "shorten folder or file names to fix them. App data and program folders are never renamed."
                        + ("" if IS_WINDOWS else " On Linux this matters only for files you open on Windows, "
                           "Office or OneDrive."))

        opts = card(self, 14)
        opts.pack(fill=tk.X)
        ttk.Label(opts, text="Locations", style="Section.TLabel").grid(row=0, column=0, sticky="nw", padx=(0, 16))
        self.drives = DriveSelector(opts, default_first=False)
        self.drives.grid(row=0, column=1, columnspan=4, sticky="w")

        ttk.Label(opts, text="Path limit", style="Section.TLabel").grid(row=1, column=0, sticky="w", pady=(12, 0))
        self.limit = tk.StringVar(value=long_paths.DEFAULT_LIMIT)
        ttk.Combobox(opts, textvariable=self.limit, values=list(long_paths.LIMITS), width=26).grid(
            row=1, column=1, sticky="w", pady=(12, 0))
        ttk.Label(opts, text="Shorten names to (characters)").grid(row=1, column=2, sticky="e", padx=(16, 6),
                                                                  pady=(12, 0))
        self.max_name = tk.StringVar(value="24")
        ttk.Entry(opts, textvariable=self.max_name, width=6).grid(row=1, column=3, sticky="w", pady=(12, 0))
        ttk.Button(opts, text="Scan for long paths", style="Accent.TButton", command=self.scan).grid(
            row=1, column=4, sticky="e", pady=(12, 0))
        opts.columnconfigure(4, weight=1)

        if IS_WINDOWS:
            self.win_var = tk.StringVar(value="")
            row = ttk.Frame(opts)
            row.grid(row=2, column=0, columnspan=5, sticky="ew", pady=(12, 0))
            MutedLabel(row, textvariable=self.win_var, style="Muted.TLabel").pack(side=tk.LEFT)
            self.win_btn = ttk.Button(row, text="Enable in Windows", command=self.enable_windows_support)
            self.win_btn.pack(side=tk.RIGHT)
            self.refresh_windows_status()

        self.summary = tk.StringVar(value="Select a drive or folder and click 'Scan for long paths'.")
        ttk.Label(self, textvariable=self.summary, style="Section.TLabel").pack(fill=tk.X, pady=(12, 6))

        self.tree = CheckTree(self, app, [("proposed", "Proposed name", 240), ("saves", "Saves", 70),
                                          ("files", "Files fixed", 90), ("folder", "Location", 420)],
                              "Current name (click to select)", 320)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.tree.bind("<Double-1>", lambda e: self.edit_selected())

        btns = ttk.Frame(self)
        btns.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 4), before=self.tree)
        ttk.Button(btns, text="Select all", command=lambda: [self.tree.set_checked(i, True)
                                                             for i in self.tree.items()]).pack(side=tk.LEFT)
        ttk.Button(btns, text="Clear", command=lambda: [self.tree.set_checked(i, False)
                                                        for i in self.tree.items()]).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Edit proposed name", command=self.edit_selected).pack(side=tk.LEFT)
        ttk.Button(btns, text="Open location", command=self.open_selected).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Undo last rename", command=self.undo).pack(side=tk.LEFT)
        ttk.Button(btns, text="Fix all automatically", command=self.fix_all).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Rename selected", style="Accent.TButton",
                   command=self.rename_selected).pack(side=tk.RIGHT, padx=6)

    # ------------------------------------------------------------------ Windows setting
    def refresh_windows_status(self) -> None:
        enabled = long_paths.windows_long_paths_enabled()
        if enabled:
            self.win_var.set("Windows long path support: enabled. Some apps (File Explorer, Office) may still "
                             "fail on long paths, so shortening names remains recommended.")
            self.win_btn.pack_forget()
        else:
            self.win_var.set("Windows long path support: disabled. Enabling it helps programs that support "
                             "long paths; it does not fix File Explorer or Office.")

    def enable_windows_support(self) -> None:
        fix = Fix("enable_long_paths", "Enable Windows long path support",
                   "Sets LongPathsEnabled=1 in the registry. Takes effect for newly started programs.",
                   [long_paths.ENABLE_LONG_PATHS_CMD], admin=True)
        if not self.app.confirm_fix(fix):
            return
        self.app.run_task(fix.title, lambda c: execute_fix(fix, self.app.log, c),
                          lambda _r: self.refresh_windows_status())

    # ------------------------------------------------------------------ scanning
    def _limit_value(self) -> int:
        text = self.limit.get()
        if text in long_paths.LIMITS:
            return long_paths.LIMITS[text]
        digits = "".join(ch for ch in text if ch.isdigit())
        if not digits:
            raise ValueError("Path limit must be a number, for example 218.")
        return int(digits)

    def scan(self) -> None:
        roots = self.drives.selected()
        if not roots:
            messagebox.showinfo(APP_NAME, "Select at least one drive or folder.")
            return
        try:
            limit = self._limit_value()
            max_name = max(8, int(self.max_name.get()))
        except ValueError as exc:
            messagebox.showerror(APP_NAME, str(exc) if "Path limit" in str(exc) else
                                 "Name length must be a whole number.")
            return

        def work(cancel):
            items, checked = long_paths.scan(roots, limit, cancel, self.app.set_status)
            proposals, unresolved = long_paths.plan(items, limit, max_name)
            return items, checked, proposals, unresolved, limit

        self.tree.clear()
        self.app.run_task("Long path scan", work, self.show_results)

    def show_results(self, result) -> None:
        items, checked, proposals, unresolved, limit = result
        self.tree.clear()
        self.proposals.clear()
        for p in proposals:
            iid = self.tree.add_item("", p.old_name, (p.new_name, f"-{p.saves}", p.affected,
                                                     os.path.dirname(p.path)))
            # nothing is selected automatically: renaming is always a deliberate choice
            self.proposals[iid] = p
        files = sum(1 for i in items if not i.is_dir)
        if not items:
            self.summary.set(f"Checked {checked:,} items. No paths longer than {limit} characters.")
            self.app.dashboard.set_card("longpaths", OK, "No long paths", f"Limit: {limit} characters.")
            return
        text = (f"{files:,} files exceed {limit} characters · {len(proposals)} rename(s) proposed. "
                "Double-click a row to edit its proposed name.")
        if unresolved:
            text += f" {len(unresolved)} item(s) need manual attention (see log)."
            for u in unresolved[:20]:
                self.app.log(f"Still too long after proposed renames ({u.length} chars): {u.path}")
        self.summary.set(text)
        self.app.dashboard.set_card("longpaths", WARN, f"{files:,} long path(s)",
                                    f"{len(proposals)} rename(s) proposed.")

    # ------------------------------------------------------------------ editing and applying
    def edit_selected(self) -> None:
        sel = [i for i in self.tree.tree.selection() if i in self.proposals]
        if not sel:
            messagebox.showinfo(APP_NAME, "Select a row first.")
            return
        p = self.proposals[sel[0]]
        new = simpledialog.askstring("Edit proposed name", f"Current name:\n{p.old_name}\n\nNew name:",
                                     initialvalue=p.new_name, parent=self)
        if new is None:
            return
        new = new.strip()
        error = long_paths.validate_name(new)
        if error is None and new != p.old_name and os.path.exists(
                long_paths.to_ext(os.path.join(os.path.dirname(p.path), new))):
            error = "An item with this name already exists in the same folder."
        if error:
            messagebox.showerror(APP_NAME, error)
            return
        p.new_name = new
        self.tree.tree.set(sel[0], "proposed", new)
        self.tree.tree.set(sel[0], "saves", f"-{p.saves}")

    def open_selected(self) -> None:
        sel = [i for i in self.tree.tree.selection() if i in self.proposals]
        if sel:
            open_location(self.proposals[sel[0]].path)

    def rename_selected(self) -> None:
        self._apply([i for i in self.tree.checked if i in self.proposals])

    def fix_all(self) -> None:
        self._apply(list(self.proposals.keys()), automatic=True)

    def _apply(self, iids: list[str], automatic: bool = False) -> None:
        if not iids:
            messagebox.showinfo(APP_NAME, "Select items first (click the box next to each name)." if not automatic
                                else "Nothing to fix. Run a scan first.")
            return
        mode = "Rename all proposed items automatically" if automatic else f"Rename {len(iids)} selected item(s)"
        if not messagebox.askyesno(APP_NAME, f"{mode}?\n\nRenaming folders can break shortcuts, recent-file "
                                   "lists and links inside other documents. Close any files open from these "
                                   "folders first.\n\nYou can reverse this with 'Undo last rename'."):
            return
        allowed = set(self.app.guard_paths([self.proposals[i].path for i in iids], "renamed"))
        chosen = {i: self.proposals[i] for i in iids if self.proposals[i].path in allowed}
        if not chosen:
            return

        def work(cancel):
            return long_paths.apply(list(chosen.values()), self.app.log, cancel)

        def finish(result):
            done, errors = result
            done_ids = {id(p) for p in done}
            for iid, p in chosen.items():
                if id(p) in done_ids:
                    self.tree.remove(iid)
                    self.proposals.pop(iid, None)
            for e in errors:
                self.app.log(f"Rename failed: {e}")
            if done:
                state.record_action("Long paths", f"Renamed {len(done)} item(s)", "Undo is available on the "
                                    "Long Paths page.", [f"{p.path}  ->  {p.new_name}" for p in done])
            self.summary.set(f"Renamed {len(done)} item(s)." + (f" {len(errors)} failed (see log)." if errors else
                                                                 " Scan again to confirm everything is fixed."))
            if errors:
                messagebox.showwarning(APP_NAME, f"{len(errors)} item(s) could not be renamed. They may be open in "
                                       "another program or require administrator rights.")

        self.app.run_task("Renaming long paths", work, finish)

    def undo(self) -> None:
        if not long_paths.has_undo():
            messagebox.showinfo(APP_NAME, "There is nothing to undo.")
            return
        if not messagebox.askyesno(APP_NAME, "Restore the original names from the last rename batch?"):
            return

        def finish(result):
            restored, errors = result
            for e in errors:
                self.app.log(f"Undo failed: {e}")
            if restored:
                state.record_action("Long paths", f"Undid the last rename batch ({restored} name(s) restored)")
            self.tree.clear()
            self.proposals.clear()
            self.summary.set(f"Restored {restored} name(s)." + (f" {len(errors)} failed (see log)." if errors else
                                                               " Scan again to review."))

        self.app.run_task("Undo rename", lambda c: long_paths.undo_last(self.app.log), finish)


# =============================================================================== malware
class MalwareTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        self.clam = ClamAV()
        self.defender = Defender()
        self.detections: dict[str, object] = {}
        app.page_header(self, "Malware Scan", "Antivirus signatures from ClamAV (Cisco Talos) and Microsoft "
                        "Defender, plus a check for unknown programs.")

        sig = card(self, 14)
        sig.pack(fill=tk.X)
        ttk.Label(sig, text="Signatures", style="Section.TLabel").grid(row=0, column=0, sticky="w")
        self.clam_var = tk.StringVar(value="ClamAV: checking…")
        self.def_var = tk.StringVar(value="Microsoft Defender: checking…" if IS_WINDOWS else
                                    "Microsoft Defender: Windows only")
        ttk.Label(sig, textvariable=self.clam_var, wraplength=760, justify=tk.LEFT).grid(
            row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Label(sig, textvariable=self.def_var, wraplength=760, justify=tk.LEFT).grid(
            row=2, column=0, sticky="w", pady=(2, 0))
        bf = ttk.Frame(sig)
        bf.grid(row=0, column=1, rowspan=3, sticky="e")
        sig.columnconfigure(0, weight=1)
        ttk.Button(bf, text="Update signatures", style="Accent.TButton",
                   command=self.update_signatures).pack(side=tk.LEFT)
        ttk.Button(bf, text="Refresh", command=self.refresh_status).pack(side=tk.LEFT, padx=6)
        self.install_btn = ttk.Button(bf, text="Install ClamAV", command=self.install_clamav)
        self.install_btn.pack(side=tk.LEFT)

        scan = card(self, 14)
        scan.pack(fill=tk.X, pady=(10, 0))
        ttk.Label(scan, text="Scope", style="Section.TLabel").grid(row=0, column=0, sticky="nw", padx=(0, 16))
        self.scope = tk.StringVar(value="quick")
        ttk.Radiobutton(scan, text="Quick scan (Downloads, Desktop, Temp, Startup)", variable=self.scope,
                        value="quick").grid(row=0, column=1, sticky="w")
        ttk.Radiobutton(scan, text="Selected drives / folders", variable=self.scope, value="custom").grid(
            row=1, column=1, sticky="w", pady=(6, 0))
        self.drives = DriveSelector(scan, default_first=False)
        self.drives.grid(row=2, column=1, columnspan=3, sticky="w", padx=(24, 0), pady=(4, 0))

        ttk.Label(scan, text="Engines", style="Section.TLabel").grid(row=3, column=0, sticky="w", pady=(12, 0))
        self.use_clam = tk.BooleanVar(value=True)
        self.use_def = tk.BooleanVar(value=IS_WINDOWS)
        self.use_heur = tk.BooleanVar(value=True)
        ef = ttk.Frame(scan)
        ef.grid(row=3, column=1, sticky="w", pady=(12, 0))
        ttk.Checkbutton(ef, text="ClamAV", variable=self.use_clam, style="Switch.TCheckbutton").pack(side=tk.LEFT)
        cb = ttk.Checkbutton(ef, text="Microsoft Defender", variable=self.use_def, style="Switch.TCheckbutton")
        cb.pack(side=tk.LEFT, padx=16)
        if not IS_WINDOWS:
            cb.state(["disabled"])
        ttk.Checkbutton(ef, text="Unknown programs", variable=self.use_heur,
                        style="Switch.TCheckbutton").pack(side=tk.LEFT)
        ttk.Button(scan, text="Start scan", style="Accent.TButton", command=self.scan).grid(
            row=3, column=3, sticky="e", pady=(12, 0))
        scan.columnconfigure(2, weight=1)

        self.summary = tk.StringVar(value="Update signatures before your first scan. Full-drive scans can take "
                                    "a long time.")
        ttk.Label(self, textvariable=self.summary, style="Section.TLabel").pack(fill=tk.X, pady=(12, 6))
        self.tree = CheckTree(self, app, [("source", "Engine", 100), ("threat", "Detection / reason", 280),
                                          ("size", "Size", 90), ("folder", "Folder", 420)], "File", 260)
        self.tree.pack(fill=tk.BOTH, expand=True)

        btns = ttk.Frame(self)
        btns.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 4), before=self.tree)
        ttk.Button(btns, text="Select all", command=lambda: [self.tree.set_checked(i, True)
                                                             for i in self.tree.items()]).pack(side=tk.LEFT)
        ttk.Button(btns, text="Clear", command=lambda: [self.tree.set_checked(i, False)
                                                        for i in self.tree.items()]).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Open file location", command=self.open_selected).pack(side=tk.LEFT)
        ttk.Button(btns, text="Mark as safe", command=self.ignore_selected).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Quarantine selected", style="Accent.TButton",
                   command=self.quarantine_selected).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Move to Recycle Bin", command=self.recycle_selected).pack(side=tk.RIGHT, padx=6)
        self.after(500, self.refresh_status)

    # ------------------------------------------------------------------ signatures
    def refresh_status(self) -> None:
        """Read engine status in the background so the window stays responsive."""
        def worker():
            installed = self.clam.installed()
            clam = (f"ClamAV: {self.clam.db_status()}" if installed
                    else "ClamAV: not installed. Click 'Install ClamAV' to add it automatically.")
            try:
                from core.malware import stale_engines
                old = dict(stale_engines(self.clam, self.defender if IS_WINDOWS else None))
            except Exception:
                old = {}
            if "ClamAV" in old:
                clam += "  ·  OUT OF DATE"
            defs = f"Microsoft Defender: {self.defender.status()}" if IS_WINDOWS else None
            if defs and "Microsoft Defender" in old:
                defs += "  ·  OUT OF DATE"

            def apply():
                self.clam_var.set(clam)
                if installed:
                    self.install_btn.pack_forget()
                elif not self.install_btn.winfo_ismapped():
                    self.install_btn.pack(side=tk.LEFT)
                if defs:
                    self.def_var.set(defs)
            self.app.ui(apply)

        threading.Thread(target=worker, daemon=True).start()

    def install_clamav(self) -> None:
        """Install the ClamAV edition that matches this OS, then download its signatures."""
        def done(_r):
            self.refresh_status()
            if self.clam.installed():
                state.record_action("Malware", "Installed ClamAV")
                self.app.log("Downloading ClamAV signatures for the first time (about 300 MB)…")
                self.update_signatures()
        self.app.run_task("Install ClamAV", lambda c: self.clam.install(self.app.log, c), done)

    def update_signatures(self) -> None:
        def work(cancel):
            failed = []
            if self.clam.installed():
                self.app.log("Updating ClamAV signatures from database.clamav.net…")
                rc = self.clam.update(self.app.log, cancel)
                if rc not in (0, 1):  # freshclam: 0 = updated, 1 = already up to date
                    failed.append(f"ClamAV (freshclam exit code {rc})")
                elif not self.clam.has_db():  # success means signatures actually exist
                    failed.append("ClamAV (no signatures were downloaded)")
            else:
                self.app.log("ClamAV is not installed; skipping.")
            if IS_WINDOWS and self.defender.installed():
                self.app.log("Updating Microsoft Defender signatures…")
                rc = self.defender.update(self.app.log, cancel)
                if rc not in (0, None):
                    failed.append(f"Microsoft Defender (exit code {rc})")
            return (failed, self.clam.db_status() if self.clam.installed() else "ClamAV not installed",
                    self.defender.status() if IS_WINDOWS and self.defender.installed() else "")

        def done(result):
            from ui import reminders
            failed, clam, defender = result
            summary = f"ClamAV: {clam}" + (f"; Defender: {defender}" if defender else "")
            self.refresh_status()
            if failed:
                state.record_action("Malware", "Signature update failed", "; ".join(failed) + ". " + summary)
                self.app.set_status("Signature update: failed")
                messagebox.showwarning(APP_NAME, "The signature update did not complete for:\n\n" +
                                       "\n".join(failed) + "\n\nThe activity log shows the reason. Check the "
                                       "internet connection and try again.")
                return
            state.record_action("Malware", "Updated malware signatures", summary)
            reminders.clear()
        self.app.run_task("Signature update", work, done)

    # ------------------------------------------------------------------ scanning
    def scan(self) -> None:
        targets = quick_scan_locations() if self.scope.get() == "quick" else self.drives.selected()
        if not targets:
            messagebox.showinfo(APP_NAME, "Select at least one drive or folder.")
            return
        engines = {"clam": self.use_clam.get() and self.clam.installed(),
                   "def": self.use_def.get() and IS_WINDOWS and self.defender.installed(),
                   "heur": self.use_heur.get()}
        if self.use_clam.get() and not self.clam.installed():
            self.app.log("ClamAV is not installed; the ClamAV engine is skipped.")
        if not any(engines.values()):
            messagebox.showinfo(APP_NAME, "No scanning engine is available. Install ClamAV or enable the "
                                "unknown-programs check.")
            return
        quick = self.scope.get() == "quick"

        def work(cancel):
            results = []
            self.app.log("Targets: " + "; ".join(targets))
            if engines["clam"]:
                self.app.set_status("ClamAV scanning…")
                results += self.clam.scan(targets, self.app.log, cancel)
            if engines["def"]:
                self.app.set_status("Microsoft Defender scanning…")
                results += self.defender.scan(targets, self.app.log, cancel)
            if engines["heur"]:
                self.app.set_status("Checking for unknown programs…")
                results += scan_unknown_files(self.app.log, cancel, self.app.allowlist,
                                              None if quick else targets)
            return [r for r in results if not self.app.allowlist.contains(r.path) or r.source != "Heuristic"]

        self.tree.clear()
        self.app.run_task("Malware scan", work, self.show_results)

    def show_results(self, detections) -> None:
        self.tree.clear()
        self.detections.clear()
        threats = 0
        for d in detections:
            iid = self.tree.add_item("", os.path.basename(d.path),
                                     (d.source, d.name, human_size(d.size), os.path.dirname(d.path)))
            if d.source != "Heuristic":
                self.tree.tree.item(iid, tags=("threat",))
                threats += 1
            self.detections[iid] = d
        unknown = len(detections) - threats
        self.summary.set(f"{threats} threat(s) detected · {unknown} unknown program(s) to review."
                         if detections else "No threats or unknown programs found.")
        self.app.log(self.summary.get())
        if threats:
            self.app.dashboard.set_card("malware", FAIL, f"{threats} threat(s)", "Quarantine them from the "
                                        "Malware Scan page.")
        elif unknown:
            self.app.dashboard.set_card("malware", WARN, f"{unknown} to review", "Unknown or unsigned programs.")
        else:
            self.app.dashboard.set_card("malware", OK, "No threats", "Last scan was clean.")

    # ------------------------------------------------------------------ actions
    def _selected(self):
        return [(i, self.detections[i]) for i in self.tree.checked if i in self.detections]

    def open_selected(self) -> None:
        for iid in self.tree.tree.selection():
            if iid in self.detections:
                open_location(self.detections[iid].path)
                return

    def ignore_selected(self) -> None:
        sel = self._selected()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select items first.")
            return
        if any(d.source != "Heuristic" for _, d in sel):
            if not messagebox.askyesno(APP_NAME, "Some selected items were detected by an antivirus engine. "
                                       "Marking them as safe only hides unknown-program warnings. Continue?"):
                return
        self.app.allowlist.add([d.path for _, d in sel])
        for iid, _ in sel:
            self.tree.remove(iid)
            self.detections.pop(iid, None)
        self.app.log(f"Marked {len(sel)} item(s) as safe.")
        state.record_action("Malware", f"Marked {len(sel)} item(s) as safe", "They will not be flagged again.",
                            [f"{d.path}  ({d.name})" for _, d in sel])

    def _process(self, title: str, action, verb: str) -> None:
        sel = self._selected()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select items first (click the box next to each file).")
            return
        system = [d for _, d in sel if is_protected(d.path)]
        warn = (f"\n\nWarning: {len(system)} item(s) are inside system folders. Removing them may affect "
                "installed software.") if system else ""
        if not messagebox.askyesno(APP_NAME, f"{verb} {len(sel)} item(s)?{warn}"):
            return

        by_id = {iid: d for iid, d in sel}

        def work(cancel):
            done, failed = [], []
            for iid, d in sel:
                if cancel.is_set():
                    raise Cancelled()
                try:
                    action(d)
                    done.append(iid)
                except Exception as exc:
                    failed.append(f"{d.path}: {exc}")
            return done, failed

        def finish(r):
            done, failed = r
            for iid in done:
                self.tree.remove(iid)
                self.detections.pop(iid, None)
            self.app.log(f"{title}: {len(done)} item(s) processed.")
            if done:
                state.record_action("Malware", f"{verb}: {len(done)} item(s)", "",
                                    [f"{by_id[i].path}  ({by_id[i].name})" for i in done])
            for f in failed:
                self.app.log(f"Failed: {f}")
            if failed:
                messagebox.showwarning(APP_NAME, f"{len(failed)} item(s) failed. Files in use may require "
                                       "administrator rights or a restart.")
            self.app.q_tab.refresh()

        self.app.run_task(title, work, finish)

    def quarantine_selected(self) -> None:
        self._process("Quarantine", lambda d: self.app.quarantine.add(d.path, f"{d.source}: {d.name}"),
                      "Move to the encrypted quarantine")

    def recycle_selected(self) -> None:
        self._process("Recycle", lambda d: send2trash(os.path.normpath(d.path)), "Move to the Recycle Bin")


# =============================================================================== quarantine
class QuarantineTab(ttk.Frame):
    def __init__(self, parent, app: App):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        app.page_header(self, "Quarantine", "Quarantined files are encrypted and cannot run. Restore a file "
                        "only if you are sure it is safe.")
        cols = ("date", "reason", "size", "path")
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(bar, text="Search").pack(side=tk.LEFT)
        self.search = tk.StringVar()
        ttk.Entry(bar, textvariable=self.search, width=40).pack(side=tk.LEFT, padx=8)
        self.search.trace_add("write", lambda *a: self.refresh(publish=False))
        wrap = ttk.Frame(self)
        wrap.pack(fill=tk.BOTH, expand=True)
        self.tree = ttk.Treeview(wrap, columns=cols, show="headings", selectmode="extended", height=5)
        for cid, text, width in (("date", "Date", 140), ("reason", "Reason", 300), ("size", "Size", 90),
                                 ("path", "Original location", 560)):
            self.tree.heading(cid, text=text, anchor=tk.W)
            self.tree.column(cid, width=width, stretch=cid == "path")
        sb = ttk.Scrollbar(wrap, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        register_tree(self.tree)
        btns = ttk.Frame(self)
        btns.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 4), before=wrap)
        ttk.Button(btns, text="Refresh", command=self.refresh).pack(side=tk.LEFT)
        ttk.Button(btns, text="Open quarantine folder",
                   command=lambda: open_location(app.quarantine.dir)).pack(side=tk.LEFT, padx=6)
        ttk.Button(btns, text="Delete permanently", style="Danger.TButton", command=self.purge).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Restore", command=self.restore).pack(side=tk.RIGHT, padx=6)
        self.refresh()

    def refresh(self, publish: bool = True) -> None:
        self.tree.delete(*self.tree.get_children())
        items = self.app.quarantine.items()
        q = self.search.get().strip().lower()
        shown = [i for i in items if not q or q in i.reason.lower() or q in i.original_path.lower()]
        for n, item in enumerate(shown):
            self.tree.insert("", tk.END, iid=item.id, values=(item.date, item.reason, human_size(item.size),
                                                              item.original_path), tags=("odd",) if n % 2 else ())
        if not publish:
            return
        if items:
            self.app.dashboard.set_card("quarantine", INFO, f"{len(items)} item(s)",
                                        f"{human_size(sum(i.size for i in items))} isolated.")
        else:
            self.app.dashboard.set_card("quarantine", OK, "Empty", "No files in quarantine.")

    def restore(self) -> None:
        ids = self.tree.selection()
        if not ids or not messagebox.askyesno(APP_NAME, f"Restore {len(ids)} item(s) to their original location?"):
            return
        restored = []
        for i in ids:
            try:
                dest = self.app.quarantine.restore(i)
                restored.append(str(dest))
                self.app.log(f"Restored to {dest}")
            except Exception as exc:
                self.app.log(f"Restore failed: {exc}")
        if restored:
            state.record_action("Quarantine", f"Restored {len(restored)} item(s) from quarantine", "", restored)
        self.refresh()

    def purge(self) -> None:
        ids = self.tree.selection()
        if not ids or not messagebox.askyesno(APP_NAME, f"Permanently delete {len(ids)} item(s)? "
                                              "This cannot be undone."):
            return
        names = {q.id: q.original_path for q in self.app.quarantine.items()}
        for i in ids:
            self.app.quarantine.purge(i)
        self.app.log(f"Permanently deleted {len(ids)} quarantined item(s).")
        state.record_action("Quarantine", f"Permanently deleted {len(ids)} quarantined item(s)", "",
                            [names.get(i, i) for i in ids])
        self.refresh()


# =============================================================================== checks (network/system/disk)
class ChecksTab(ttk.Frame):
    def __init__(self, parent, app: App, module, title: str, key: str, subtitle: str):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app, self.module, self.title, self.key = app, module, title, key
        self.fix_by_row: dict[str, str] = {}
        self.fixes: dict[str, Fix] = {}
        head = app.page_header(self, title, subtitle)
        ttk.Button(head, text=f"Run {title.lower()} check", style="Accent.TButton",
                   command=self.run_checks).place(relx=1.0, rely=0.5, anchor="e")

        self.summary = tk.StringVar(value="Not checked yet.")
        ttk.Label(self, textvariable=self.summary, style="Section.TLabel").pack(fill=tk.X, pady=(0, 6))

        self.score_lbl = self.rating_lbl = None
        if key == "security":
            score = card(self, 14)
            score.pack(fill=tk.X, pady=(0, 10))
            self.score_lbl = ThemedLabel(score, "muted", size=26, bold=True, text="–")
            self.score_lbl.pack(side=tk.LEFT)
            box = ttk.Frame(score)
            box.pack(side=tk.LEFT, padx=16)
            self.rating_lbl = ThemedLabel(box, "muted", size=12, bold=True, text="Not checked yet")
            self.rating_lbl.pack(anchor=tk.W)
            MutedLabel(box, text="Score out of 100. Each OK check counts fully, each review item half.").pack(
                anchor=tk.W)

        body = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        body.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(body)
        self.tree = ttk.Treeview(left, columns=("status", "detail"), selectmode="browse", height=5)
        register_tree(self.tree)
        self.tree.heading("#0", text="Check", anchor=tk.W)
        self.tree.column("#0", width=200)
        self.tree.heading("status", text="Status", anchor=tk.W)
        self.tree.column("status", width=120, stretch=False)
        self.tree.heading("detail", text="Details", anchor=tk.W)
        self.tree.column("detail", width=440)
        self.tree.pack(fill=tk.BOTH, expand=True)
        rf = ttk.Frame(left)
        rf.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 4), before=self.tree)
        self.rec_btn = ttk.Button(rf, text="Apply recommended fix", style="Accent.TButton",
                                  command=self.apply_recommended, state=tk.DISABLED)
        self.rec_btn.pack(side=tk.LEFT)
        self.rec_var = tk.StringVar(value="Select a row with a warning to see its recommended fix.")
        MutedLabel(rf, textvariable=self.rec_var, wraplength=620, justify=tk.LEFT).pack(side=tk.LEFT, padx=10)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        body.add(left, weight=3)

        right = card(body, 12)
        ttk.Label(right, text="Repair tools", style="Section.TLabel").pack(anchor=tk.W, pady=(0, 6))
        self.actions = ttk.Treeview(right, show="tree", selectmode="browse", height=10)
        self.actions.column("#0", width=280)
        self.actions.pack(fill=tk.BOTH, expand=True)
        self.actions.bind("<<TreeviewSelect>>", self._on_action_select)
        self.action_desc = tk.StringVar(value="Select a tool to see what it does.")
        MutedLabel(right, textvariable=self.action_desc, style="Muted.TLabel", wraplength=280,
                  justify=tk.LEFT).pack(fill=tk.X, pady=8)
        ttk.Button(right, text="Run selected tool", command=self.run_action).pack(anchor=tk.E)
        body.add(right, weight=1)
        app.on_theme(self._apply_palette)
        self._load_fixes()

    def _apply_palette(self, p: dict) -> None:
        for status in (OK, WARN, FAIL, INFO):
            self.tree.tag_configure(status, foreground=p[status.lower()])

    def _load_fixes(self) -> None:
        try:
            self.fixes = self.module.get_fixes()
        except Exception as exc:
            self.app.log(f"{self.title}: could not load repair tools: {exc}")
            self.fixes = {}
        self.actions.delete(*self.actions.get_children())
        for fid, f in self.fixes.items():
            self.actions.insert("", tk.END, iid=fid, text=f.title + ("   [admin]" if f.admin else ""))

    def run_checks(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.app.run_task(f"{self.title} check", lambda c: self.module.run_checks(self.app.log), self.show)

    def show(self, checks) -> None:
        self._load_fixes()
        self.tree.delete(*self.tree.get_children())
        self.fix_by_row.clear()
        counts = {OK: 0, WARN: 0, FAIL: 0, INFO: 0}
        for n, c in enumerate(checks):
            iid = self.tree.insert("", tk.END, text=c.name, values=(STATUS_TEXT.get(c.status, c.status), c.detail),
                                   tags=(c.status,) + (("odd",) if n % 2 else ()))
            counts[c.status] = counts.get(c.status, 0) + 1
            if c.fix_id and c.fix_id in self.fixes:
                self.fix_by_row[iid] = c.fix_id
            self.app.log(f"[{c.status}] {c.name}: {c.detail}")
        self.summary.set(f"{counts[OK]} OK · {counts[WARN]} warning(s) · {counts[FAIL]} problem(s)")
        level, value, detail = summarize_checks(checks)
        if self.key == "security":
            sc = security.score(checks)
            value = f"Score {sc}/100"
            rating, role = (("Good", "ok") if sc >= 80 else ("Fair", "warn") if sc >= 50 else ("At risk", "fail"))
            self.score_lbl.configure(text=f"{sc} / 100")
            self.score_lbl.set_role(role)
            self.rating_lbl.configure(text=f"{STATUS_BADGE[{'ok': OK, 'warn': WARN, 'fail': FAIL}[role]]} · {rating}")
            self.rating_lbl.set_role(role)
        self.app.dashboard.set_card(self.key, level, value, detail)

    def _on_select(self, _e=None) -> None:
        sel = self.tree.selection()
        fid = self.fix_by_row.get(sel[0]) if sel else None
        if fid:
            self.rec_btn.configure(state=tk.NORMAL)
            self.rec_var.set(f"Recommended: {self.fixes[fid].title}. {self.fixes[fid].description}")
        else:
            self.rec_btn.configure(state=tk.DISABLED)
            self.rec_var.set("No fix needed for this item." if sel else "")

    def apply_recommended(self) -> None:
        sel = self.tree.selection()
        fid = self.fix_by_row.get(sel[0]) if sel else None
        if fid:
            self.app.run_fix(self.fixes[fid])

    def _on_action_select(self, _e=None) -> None:
        sel = self.actions.selection()
        if sel and sel[0] in self.fixes:
            f = self.fixes[sel[0]]
            self.action_desc.set(f.description + ("\nRequires administrator rights." if f.admin else "") +
                                 ("\nRestart required afterwards." if f.reboot else ""))

    def run_action(self) -> None:
        sel = self.actions.selection()
        if not sel or sel[0] not in self.fixes:
            messagebox.showinfo(APP_NAME, "Select a tool from the list first.")
            return
        self.app.run_fix(self.fixes[sel[0]])


# =============================================================================== entry point
def resource_path(*parts: str) -> str:
    """Path to a bundled file, both from source and inside the PyInstaller executable."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def main() -> None:
    if IS_WINDOWS:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
        try:  # show the SysHealth icon on the taskbar instead of the Python icon
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("ATGrep.SysHealth")
        except Exception:
            pass
    app_data_dir()
    App().mainloop()


if __name__ == "__main__":
    main()
