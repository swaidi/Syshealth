"""Feedback and problem-report dialog.

Builds a plain-text report (message, optional last error, system details, recent activity) that the user
can review and edit, then send by email, copy, or save as a file.
"""
from __future__ import annotations

import datetime as dt
import os
import platform
import sys
import tkinter as tk
import urllib.parse
import webbrowser
from tkinter import filedialog, messagebox, ttk

FEEDBACK_EMAIL = "dev.oasis006@passmail.net"
MAILTO_LIMIT = 1800  # Windows limits the length of mailto links; longer reports go via the clipboard


class FeedbackDialog(tk.Toplevel):
    def __init__(self, app, kind: str = "problem", error: dict | None = None):
        super().__init__(app)
        self.app = app
        self.error = error if error is not None else getattr(app, "last_error", None)
        p = app.palette
        self.title("Send feedback")
        self.configure(background=p["app"])
        self.geometry("760x640")
        self.minsize(640, 520)
        self.transient(app)

        body = ttk.Frame(self, padding=16)
        body.pack(fill=tk.BOTH, expand=True)
        ttk.Label(body, text="Send feedback", style="PageTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(body, text="Report a problem or suggest an improvement. You can review and edit everything "
                  "before it is sent.", style="Muted.TLabel").pack(anchor=tk.W, pady=(2, 12))

        row = ttk.Frame(body)
        row.pack(fill=tk.X)
        self.kind = tk.StringVar(value=kind)
        ttk.Radiobutton(row, text="Report a problem", variable=self.kind, value="problem",
                        command=self.refresh).pack(side=tk.LEFT, padx=(0, 20))
        ttk.Radiobutton(row, text="Suggest an improvement", variable=self.kind, value="suggestion",
                        command=self.refresh).pack(side=tk.LEFT)

        ttk.Label(body, text="Your message", style="Section.TLabel").pack(anchor=tk.W, pady=(14, 4))
        self.message = self._text(body, height=5)
        self.message.bind("<KeyRelease>", lambda e: self.refresh())

        opts = ttk.Frame(body)
        opts.pack(fill=tk.X, pady=(10, 0))
        self.inc_error = tk.BooleanVar(value=self.error is not None and kind == "problem")
        self.inc_system = tk.BooleanVar(value=True)
        self.inc_log = tk.BooleanVar(value=kind == "problem")
        err_text = (f"Include the last error ({self.error['title']}, {self.error['time']})" if self.error
                    else "Include the last error (no errors this session)")
        cb = ttk.Checkbutton(opts, text=err_text, variable=self.inc_error, command=self.refresh)
        cb.pack(anchor=tk.W)
        if self.error is None:
            cb.state(["disabled"])
        ttk.Checkbutton(opts, text="Include system details (app version, operating system, Python)",
                        variable=self.inc_system, command=self.refresh).pack(anchor=tk.W, pady=2)
        ttk.Checkbutton(opts, text="Include recent activity log (last 40 lines)", variable=self.inc_log,
                        command=self.refresh).pack(anchor=tk.W)

        ttk.Label(body, text="Report preview (editable)", style="Section.TLabel").pack(anchor=tk.W, pady=(14, 4))
        ttk.Label(body, text="The log can contain file and folder names. Remove anything you prefer not to share.",
                  style="Muted.TLabel").pack(anchor=tk.W, pady=(0, 4))
        self.preview = self._text(body, height=10, mono=True)

        btns = ttk.Frame(self, padding=(16, 0, 16, 16))
        btns.pack(fill=tk.X)
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side=tk.LEFT)
        ttk.Button(btns, text="Send by email", style="Accent.TButton", command=self.send_email).pack(side=tk.RIGHT)
        ttk.Button(btns, text="Save as file…", command=self.save).pack(side=tk.RIGHT, padx=6)
        ttk.Button(btns, text="Copy report", command=self.copy).pack(side=tk.RIGHT)

        self._user_edited = False
        self.preview.bind("<Key>", lambda e: setattr(self, "_user_edited", True))
        self.refresh(force=True)
        self.message.focus_set()
        self.grab_set()

    # ------------------------------------------------------------------ widgets
    def _text(self, parent, height: int, mono: bool = False) -> tk.Text:
        p = self.app.palette
        wrap = ttk.Frame(parent, style="Card.TFrame", padding=1)
        wrap.pack(fill=tk.BOTH, expand=True)
        font = (self.app.font_family, 10) if not mono else ("Consolas" if sys.platform.startswith("win")
                                                             else "Monospace", 9)
        t = tk.Text(wrap, height=height, wrap=tk.WORD, relief=tk.FLAT, bd=0, padx=8, pady=6, highlightthickness=0,
                    background=p["input"] if self.app.dark else "#FFFFFF", foreground=p["fg"],
                    insertbackground=p["fg"], selectbackground=p["selected"], font=font)
        sb = ttk.Scrollbar(wrap, orient=tk.VERTICAL, command=t.yview)
        t.configure(yscrollcommand=sb.set)
        t.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        return t

    # ------------------------------------------------------------------ report
    def subject(self) -> str:
        kind = "Problem report" if self.kind.get() == "problem" else "Suggestion"
        extra = f": {self.error['title']}" if self.inc_error.get() and self.error else ""
        return f"SysHealth {self.app.version} - {kind}{extra}"

    def build(self) -> str:
        lines = [self.subject(), "=" * 60, "", "Message:", self.message.get("1.0", tk.END).strip() or "(none)", ""]
        if self.inc_error.get() and self.error:
            lines += ["Error:", f"  When: {self.error['time']}", f"  Task: {self.error['title']}",
                      f"  Detail: {self.error['detail']}", "  Traceback:"]
            lines += ["    " + l for l in self.error.get("traceback", "").strip().splitlines()]
            lines.append("")
        if self.inc_system.get():
            lines += ["System:", f"  App: SysHealth {self.app.version}" + (" (built)" if getattr(sys, "frozen", False)
                                                                          else " (source)"),
                      f"  OS: {platform.platform()}", f"  Python: {platform.python_version()}",
                      f"  Administrator: {'yes' if self.app.is_admin else 'no'}",
                      f"  Theme: {self.app.theme_mode}", ""]
        if self.inc_log.get():
            log = self.app.log_box.get("1.0", tk.END).strip().splitlines()[-40:]
            lines += ["Recent activity:"] + ["  " + l for l in log] + [""]
        lines.append(f"Generated {dt.datetime.now():%Y-%m-%d %H:%M}")
        return "\n".join(lines)

    def refresh(self, force: bool = False) -> None:
        if self._user_edited and not force:
            return
        self.preview.delete("1.0", tk.END)
        self.preview.insert("1.0", self.build())

    def report(self) -> str:
        return self.preview.get("1.0", tk.END).strip()

    # ------------------------------------------------------------------ actions
    def _check_message(self) -> bool:
        if not self.message.get("1.0", tk.END).strip() and not (self.inc_error.get() and self.error):
            messagebox.showinfo("Send feedback", "Write a short message first.", parent=self)
            self.message.focus_set()
            return False
        return True

    def copy(self) -> None:
        self.app.clipboard_clear()
        self.app.clipboard_append(self.report())
        self.app.set_status("Feedback report copied to the clipboard.")

    def save(self) -> None:
        if not self._check_message():
            return
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".txt",
                                            initialfile=f"SysHealth_feedback_{dt.datetime.now():%Y%m%d_%H%M}.txt",
                                            filetypes=[("Text files", "*.txt")])
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(self.report())
            self.app.log(f"Feedback report saved to {path}")

    def send_email(self) -> None:
        if not self._check_message():
            return
        report = self.report()
        body = report
        if len(urllib.parse.quote(report)) > MAILTO_LIMIT:
            self.copy()
            body = ("The full report has been copied to the clipboard. Paste it here (Ctrl+V) before sending.\n\n"
                    + self.message.get("1.0", tk.END).strip()[:600])
        url = (f"mailto:{FEEDBACK_EMAIL}?subject={urllib.parse.quote(self.subject())}"
               f"&body={urllib.parse.quote(body)}")
        try:
            if sys.platform.startswith("win"):
                os.startfile(url)  # type: ignore[attr-defined]
            else:
                webbrowser.open(url)
        except OSError:
            self.copy()
            messagebox.showinfo("Send feedback", f"No email program is set up. The report has been copied to the "
                                f"clipboard; paste it into an email to {FEEDBACK_EMAIL}.", parent=self)
            return
        if body is not report:
            messagebox.showinfo("Send feedback", "Your email program is opening. The full report is on the "
                                "clipboard: paste it into the email body before sending.", parent=self)
        self.app.log("Feedback email prepared.")
        self.destroy()
