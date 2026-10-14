"""Sidebar navigation: full-width highlighted section bars with page items underneath.

Colors come from ui/theme.py tokens: sidebar, nav_header, nav_hover, nav_selected, accent, fg, fg2.
"""
from __future__ import annotations

import tkinter as tk
from typing import Callable


class Sidebar(tk.Frame):
    WIDTH = 220

    def __init__(self, parent, sections: list[tuple[str, list[tuple[str, str]]]],
                 on_select: Callable[[str], None], footer: str = ""):
        super().__init__(parent, width=self.WIDTH, bd=0, highlightthickness=0)
        self.pack_propagate(False)
        self.on_select = on_select
        self.keys: list[str] = []
        self.rows: dict[str, tuple[tk.Frame, tk.Frame, tk.Label]] = {}
        self.headers: list[tuple[tk.Frame, tk.Label]] = []
        self.current = ""
        self.hover = ""
        self.p: dict = {}
        self.family = "TkDefaultFont"

        self.footer = tk.Label(self, text=footer, bd=0, pady=8)
        self.footer.pack(side=tk.BOTTOM, fill=tk.X)
        self.canvas = tk.Canvas(self, bd=0, highlightthickness=0, takefocus=1)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.inner = tk.Frame(self.canvas, bd=0)
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._win, width=e.width))
        for w in (self.canvas, self.inner):
            w.bind("<Enter>", lambda e: self.canvas.bind_all("<MouseWheel>", self._wheel))
            w.bind("<Leave>", lambda e: self.canvas.unbind_all("<MouseWheel>"))
        self.canvas.bind("<Button-4>", lambda e: self.canvas.yview_scroll(-2, "units"))
        self.canvas.bind("<Button-5>", lambda e: self.canvas.yview_scroll(2, "units"))
        self.canvas.bind("<Up>", lambda e: self._step(-1))
        self.canvas.bind("<Down>", lambda e: self._step(1))

        for i, (section, items) in enumerate(sections):
            bar = tk.Frame(self.inner, bd=0)
            bar.pack(fill=tk.X, pady=(0 if i == 0 else 8, 2))
            lbl = tk.Label(bar, text=section.upper(), anchor="w", bd=0, padx=14, pady=8)
            lbl.pack(fill=tk.X)
            self.headers.append((bar, lbl))
            for key, label in items:
                row = tk.Frame(self.inner, bd=0, cursor="hand2")
                row.pack(fill=tk.X)
                marker = tk.Frame(row, width=3, bd=0)
                marker.pack(side=tk.LEFT, fill=tk.Y)
                text = tk.Label(row, text=label, anchor="w", bd=0, padx=27, pady=5, cursor="hand2")
                text.pack(side=tk.LEFT, fill=tk.X, expand=True)
                for w in (row, text, marker):
                    w.bind("<Button-1>", lambda e, k=key: self._click(k))
                    w.bind("<Enter>", lambda e, k=key: self._set_hover(k))
                    w.bind("<Leave>", lambda e, k=key: self._set_hover("") if self.hover == k else None)
                    w.bind("<MouseWheel>", self._wheel)
                    w.bind("<Button-4>", lambda e: self.canvas.yview_scroll(-2, "units"))
                    w.bind("<Button-5>", lambda e: self.canvas.yview_scroll(2, "units"))
                self.rows[key] = (row, marker, text)
                self.keys.append(key)

    # ------------------------------------------------------------------ behaviour
    def _wheel(self, event) -> None:
        if self.inner.winfo_height() > self.canvas.winfo_height():
            self.canvas.yview_scroll(int(-event.delta / 120) or (-1 if event.delta > 0 else 1), "units")

    def _click(self, key: str) -> None:
        self.canvas.focus_set()
        if key != self.current:
            self.on_select(key)

    def _step(self, delta: int) -> str:
        if self.current in self.keys:
            idx = max(0, min(len(self.keys) - 1, self.keys.index(self.current) + delta))
            self.on_select(self.keys[idx])
        return "break"

    def _set_hover(self, key: str) -> None:
        old, self.hover = self.hover, key
        for k in (old, key):
            if k:
                self._paint(k)

    def select(self, key: str) -> None:
        """Mark a page as current (called by the app when a page is shown)."""
        old, self.current = self.current, key
        for k in (old, key):
            if k in self.rows:
                self._paint(k)
        self.see(key)

    def see(self, key: str) -> None:
        if key not in self.rows:
            return
        self.update_idletasks()
        row = self.rows[key][0]
        total = max(self.inner.winfo_height(), 1)
        top, bottom = row.winfo_y(), row.winfo_y() + row.winfo_height()
        view_top = self.canvas.yview()[0] * total
        view_bottom = view_top + self.canvas.winfo_height()
        if top < view_top:
            self.canvas.yview_moveto(top / total)
        elif bottom > view_bottom:
            self.canvas.yview_moveto((bottom - self.canvas.winfo_height()) / total)

    # ------------------------------------------------------------------ theming
    def apply_palette(self, p: dict, family: str) -> None:
        self.p, self.family = p, family
        for w in (self, self.canvas, self.inner):
            w.configure(background=p["sidebar"])
        self.footer.configure(background=p["sidebar"], foreground=p["muted"], font=(family, 9))
        for bar, lbl in self.headers:
            bar.configure(background=p["nav_header"])
            lbl.configure(background=p["nav_header"], foreground=p["fg"], font=(family, 9, "bold"))
        for key in self.rows:
            self._paint(key)

    def _paint(self, key: str) -> None:
        if not self.p:
            return
        p = self.p
        row, marker, text = self.rows[key]
        if key == self.current:
            bg, fg, mark, weight = p["nav_selected"], p["accent"], p["accent"], "bold"
        elif key == self.hover:
            bg, fg, mark, weight = p["nav_hover"], p["fg"], p["nav_hover"], "normal"
        else:
            bg, fg, mark, weight = p["sidebar"], p["fg2"], p["sidebar"], "normal"
        row.configure(background=bg)
        marker.configure(background=mark)
        text.configure(background=bg, foreground=fg, font=(self.family, 10, weight))
