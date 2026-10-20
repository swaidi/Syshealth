"""Reminder shown when malware signatures are out of date. The user can update now or postpone."""
from __future__ import annotations

import datetime as dt
import tkinter as tk
from tkinter import ttk

from core import settings, state
from ui.update_dialog import _center

SNOOZE_KEY = "signature_reminder_after"
CHOICES = (("Remind me in 6 hours", 6), ("Remind me in 12 hours", 12), ("Dismiss", 24))  # dismiss = 24 hours


def reminder_due() -> bool:
    try:
        return dt.datetime.now() >= dt.datetime.fromisoformat(settings.get(SNOOZE_KEY) or "")
    except ValueError:
        return True


def snooze(hours: int) -> None:
    until = dt.datetime.now() + dt.timedelta(hours=hours)
    settings.set_value(SNOOZE_KEY, until.isoformat(timespec="minutes"))


def clear() -> None:
    settings.set_value(SNOOZE_KEY, "")


class SignatureReminder(tk.Toplevel):
    def __init__(self, app, stale: list[tuple[str, str]], on_update):
        super().__init__(app)
        self.app = app
        self.on_update = on_update
        p = app.palette
        self.title("Malware signatures out of date")
        self.configure(background=p["app"])
        _center(self, app, 680, 270)
        self.transient(app)

        btns = ttk.Frame(self, padding=(18, 8, 18, 18))
        btns.pack(side=tk.BOTTOM, fill=tk.X)
        body = ttk.Frame(self, padding=18)
        body.pack(fill=tk.BOTH, expand=True)
        ttk.Label(body, text="Malware signatures are out of date", style="PageTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(body, text="Signatures older than 3 days miss recently discovered threats.", style="Muted.TLabel",
                  wraplength=640, justify=tk.LEFT).pack(anchor=tk.W, pady=(4, 10))
        for engine, detail in stale:
            ttk.Label(body, text=f"•  {engine}: {detail}", wraplength=640, justify=tk.LEFT).pack(anchor=tk.W, pady=1)
        self.stale = stale

        ttk.Button(btns, text="Update now", style="Accent.TButton", command=self.update_now).pack(side=tk.RIGHT)
        for label, hours in reversed(CHOICES):
            ttk.Button(btns, text=label, command=lambda h=hours, t=label: self.later(h, t)).pack(
                side=tk.RIGHT if label != "Dismiss" else tk.LEFT, padx=(0, 6))
        self.protocol("WM_DELETE_WINDOW", lambda: self.later(6, "Closed the reminder"))

    def _record(self, action: str) -> None:
        state.record_action("Malware", f"Signature reminder: {action}",
                            "; ".join(f"{e}: {d}" for e, d in self.stale))

    def later(self, hours: int, label: str) -> None:
        snooze(hours)
        when = dt.datetime.now() + dt.timedelta(hours=hours)
        self.app.log(f"Signature reminder postponed until {when:%Y-%m-%d %H:%M}.")
        self._record(f"{label.lower()} (next reminder {when:%Y-%m-%d %H:%M})")
        self.destroy()

    def update_now(self) -> None:
        self._record("update now")
        self.destroy()
        self.on_update()
