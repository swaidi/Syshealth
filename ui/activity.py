"""Status-bar activity indicator: a spinning ring while a task runs, then a colored result mark."""
from __future__ import annotations

import time
import tkinter as tk

IDLE, BUSY, OK, FAIL, CANCEL = "idle", "busy", "ok", "fail", "cancel"


class ActivityIndicator(tk.Canvas):
    SIZE = 20

    def __init__(self, parent):
        super().__init__(parent, width=self.SIZE, height=self.SIZE, bd=0, highlightthickness=0)
        self.state = IDLE
        self.angle = 0
        self.started = 0.0
        self.p: dict = {}
        self._job = None

    # ------------------------------------------------------------------ public
    def start(self) -> None:
        self.state, self.started = BUSY, time.monotonic()
        if self._job is None:
            self._spin()

    def stop(self, result: str) -> None:
        self.state = result
        if self._job is not None:
            self.after_cancel(self._job)
            self._job = None
        self.draw()

    def elapsed(self) -> str:
        secs = int(time.monotonic() - self.started) if self.started else 0
        return f"{secs // 3600}:{secs // 60 % 60:02d}:{secs % 60:02d}" if secs >= 3600 else f"{secs // 60}:{secs % 60:02d}"

    def apply_palette(self, p: dict, background: str) -> None:
        self.p = p
        self.configure(background=background)
        self.draw()

    # ------------------------------------------------------------------ drawing
    def _spin(self) -> None:
        if self.state != BUSY:
            self._job = None
            return
        self.angle = (self.angle - 14) % 360
        self.draw()
        self._job = self.after(40, self._spin)

    def draw(self) -> None:
        if not self.p:
            return
        p, s, w = self.p, self.SIZE, 3
        self.delete("all")
        if self.state == BUSY:
            self.create_oval(w, w, s - w, s - w, outline=p["border"], width=w)
            self.create_arc(w, w, s - w, s - w, start=self.angle, extent=110, style="arc", outline=p["accent"],
                            width=w)
            return
        if self.state == IDLE:
            self.create_oval(6, 6, s - 6, s - 6, outline=p["muted"], width=2)
            return
        color = {OK: p["ok"], FAIL: p["fail"], CANCEL: p["warn"]}[self.state]
        mark = p.get("on_accent", "#ffffff") if self.state != CANCEL else p["app"]
        self.create_oval(1, 1, s - 1, s - 1, fill=color, outline=color)
        if self.state == OK:
            self.create_line(5.5, 10.5, 8.5, 13.5, 14.5, 6.5, fill=mark, width=2.2, capstyle="round",
                             joinstyle="round")
        elif self.state == FAIL:
            self.create_line(6.5, 6.5, 13.5, 13.5, fill=mark, width=2.2, capstyle="round")
            self.create_line(13.5, 6.5, 6.5, 13.5, fill=mark, width=2.2, capstyle="round")
        else:
            self.create_line(6, 10, 14, 10, fill=mark, width=2.2, capstyle="round")
