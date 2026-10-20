"""Shared widgets and constants for SysHealth pages."""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, ttk

from core.checks import FAIL, INFO, OK, WARN
from core.platform_utils import list_drives, system_env
from ui import theme

UNCHECKED, CHECKED = "☐", "☑"
# Spec 1.2 status pairing: symbol + text + color
STATUS_TEXT = {OK: "✔  OK", WARN: "⚠  Review", FAIL: "✖  Problem", INFO: "ℹ  Info"}
STATUS_BADGE = {OK: "✔ OK", WARN: "⚠ Review", FAIL: "✖ Problem", INFO: "ℹ Info"}

PALETTES = {"light": theme.palette(False), "dark": theme.palette(True)}


def summarize_checks(checks) -> tuple[str, str, str]:
    fails = [c for c in checks if c.status == FAIL]
    warns = [c for c in checks if c.status == WARN]
    issues = ", ".join(c.name for c in (fails + warns)[:3])
    if fails:
        text = f"{len(fails)} problem(s)" + (f", {len(warns)} warning(s)" if warns else "")
        return FAIL, text, issues
    if warns:
        return WARN, f"{len(warns)} warning(s)", issues
    return OK, "Healthy", "All checks passed."




class CheckTree(ttk.Frame):
    """Treeview with a checkbox in the first column and optional group (parent) rows."""

    def __init__(self, parent, app, columns: list[tuple[str, str, int]], first_heading: str,
                 first_width: int = 360):
        super().__init__(parent)
        ids = [c[0] for c in columns]
        self.tree = ttk.Treeview(self, columns=ids, selectmode="extended", height=5)
        self.tree.heading("#0", text=first_heading, anchor=tk.W)
        self.tree.column("#0", width=first_width, stretch=True)
        for cid, text, width in columns:
            self.tree.heading(cid, text=text, anchor=tk.W)
            self.tree.column(cid, width=width, stretch=cid == ids[-1])
        ysb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        xsb = ttk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.checked: set[str] = set()
        self.labels: dict[str, str] = {}
        self.tree.bind("<Button-1>", self._on_click)
        self.tree.bind("<space>", self._on_space)
        register_tree(self.tree)
        app.on_theme(self._apply_palette)

    def _apply_palette(self, p: dict) -> None:
        self.tree.tag_configure("group", background=p.get("border", p["group"]),
                                font=(_CURRENT["family"], 10, "bold"))
        self.tree.tag_configure("threat", foreground=p["fail"])

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.checked.clear()
        self.labels.clear()

    def add_group(self, text: str, values=()) -> str:
        return self.tree.insert("", tk.END, text=text, values=values, open=True, tags=("group",))

    def add_item(self, parent: str, label: str, values) -> str:
        odd = ("odd",) if len(self.tree.get_children(parent)) % 2 else ()
        iid = self.tree.insert(parent, tk.END, text=f"{UNCHECKED} {label}", values=values, tags=odd)
        self.labels[iid] = label
        return iid

    def set_checked(self, iid: str, state: bool) -> None:
        if iid not in self.labels:
            return
        (self.checked.add if state else self.checked.discard)(iid)
        self.tree.item(iid, text=f"{CHECKED if state else UNCHECKED} {self.labels[iid]}")

    def toggle(self, iid: str) -> None:
        self.set_checked(iid, iid not in self.checked)

    def _on_click(self, event) -> None:
        if self.tree.identify_region(event.x, event.y) != "tree":
            return
        iid = self.tree.identify_row(event.y)
        if iid in self.labels:
            self.toggle(iid)

    def _on_space(self, _event) -> None:
        for iid in self.tree.selection():
            self.toggle(iid)

    def items(self) -> list[str]:
        return list(self.labels.keys())

    def remove(self, iid: str) -> None:
        self.checked.discard(iid)
        self.labels.pop(iid, None)
        if self.tree.exists(iid):
            self.tree.delete(iid)


class DriveSelector(ttk.Frame):
    """Checkbuttons for each drive plus custom folders."""

    def __init__(self, parent, default_first: bool = True):
        super().__init__(parent)
        self.vars: dict[str, tk.BooleanVar] = {}
        self.folders: list[str] = []
        row = ttk.Frame(self)
        row.pack(fill=tk.X)
        for i, d in enumerate(list_drives()):
            v = tk.BooleanVar(value=default_first and i == 0)
            self.vars[d] = v
            ttk.Checkbutton(row, text=d, variable=v).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Button(row, text="Add folder…", command=self.add_folder).pack(side=tk.LEFT, padx=6)
        ttk.Button(row, text="Clear folders", command=self.clear_folders).pack(side=tk.LEFT)
        self.folder_var = tk.StringVar(value="")
        MutedLabel(self, textvariable=self.folder_var, style="Muted.TLabel").pack(fill=tk.X, pady=(4, 0))

    def add_folder(self) -> None:
        path = filedialog.askdirectory()
        if path and path not in self.folders:
            self.folders.append(path)
            self.folder_var.set("Folders: " + "; ".join(self.folders))

    def clear_folders(self) -> None:
        self.folders.clear()
        self.folder_var.set("")

    def selected(self) -> list[str]:
        return [d for d, v in self.vars.items() if v.get()] + self.folders


def card(parent, padding=14) -> ttk.Frame:
    return ttk.Frame(parent, style="Card.TFrame", padding=padding)




class Table(ttk.Frame):
    """A themed, scrollable table (Treeview) with simple column definitions and sorting."""

    def __init__(self, parent, columns: list[tuple[str, str, int]], height: int = 8, selectmode: str = "extended",
                 tree_column: tuple[str, int] | None = None):
        super().__init__(parent)
        ids = [c[0] for c in columns]
        show = "tree headings" if tree_column else "headings"
        self.tree = ttk.Treeview(self, columns=ids, show=show, selectmode=selectmode, height=height)
        if tree_column:
            self.tree.heading("#0", text=tree_column[0], anchor=tk.W)
            self.tree.column("#0", width=tree_column[1], stretch=True)
        for cid, text, width in columns:
            self.tree.heading(cid, text=text, anchor=tk.W, command=lambda c=cid: self.sort_by(c))
            self.tree.column(cid, width=width, stretch=cid == ids[-1])
        ysb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.tree.yview)
        xsb = ttk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        ysb.grid(row=0, column=1, sticky="ns")
        xsb.grid(row=1, column=0, sticky="ew")
        self.rowconfigure(0, weight=1)
        self.columnconfigure(0, weight=1)
        self.data: dict[str, object] = {}
        self._sort_desc: dict[str, bool] = {}
        register_tree(self.tree)

    def clear(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.data.clear()

    def add(self, values, obj=None, tags=(), parent: str = "", text: str = "", open_: bool = False) -> str:
        if len(self.tree.get_children(parent)) % 2:
            tags = tuple(tags) + ("odd",)
        iid = self.tree.insert(parent, tk.END, values=values, tags=tags, text=text, open=open_)
        if obj is not None:
            self.data[iid] = obj
        return iid

    def selected(self) -> list:
        return [self.data[i] for i in self.tree.selection() if i in self.data]

    def sort_by(self, col: str) -> None:
        desc = not self._sort_desc.get(col, False)
        self._sort_desc[col] = desc
        rows = [(self.tree.set(i, col), i) for i in self.tree.get_children("")]

        def key(v):
            text = v[0].replace(",", "")
            num = text.split()[0] if text else ""
            units = {"B": 1, "KB": 1024, "MB": 1024 ** 2, "GB": 1024 ** 3, "TB": 1024 ** 4}
            parts = text.split()
            try:
                if len(parts) == 2 and parts[1] in units:
                    return (0, float(parts[0]) * units[parts[1]])
                return (0, float(num.rstrip("%")))
            except ValueError:
                return (1, text.lower())
        rows.sort(key=key, reverse=desc)
        for idx, (_, iid) in enumerate(rows):
            self.tree.move(iid, "", idx)
        restripe(self.tree)


class ScrollFrame(ttk.Frame):
    """Vertically scrollable container; put widgets in .inner."""

    def __init__(self, parent, app):
        super().__init__(parent)
        self.canvas = tk.Canvas(self, highlightthickness=0, borderwidth=0)
        self.sb = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self.canvas.yview)
        self.inner = ttk.Frame(self.canvas)
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.configure(yscrollcommand=self.sb.set)
        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._win, width=e.width))
        _SCROLL_FRAMES[str(self.canvas)] = self  # scrolled by the app-wide wheel handler (install_input_helpers)
        app.on_theme(lambda p: self.canvas.configure(background=p["window"]))

    def scroll(self, steps: int) -> None:
        if self.inner.winfo_height() > self.canvas.winfo_height():
            self.canvas.yview_scroll(steps, "units")


# ---------------------------------------------------------------------------------------------------------------
# App-wide input helpers: mouse wheel and touchpad scrolling on every platform, Ctrl+A, reliable clipboard.
_SCROLL_FRAMES: dict[str, "ScrollFrame"] = {}
_NATIVE_SCROLL = {"Text", "Treeview", "Listbox", "TCombobox", "Scrollbar", "TScrollbar"}


def _wheel_steps(event) -> int:
    if getattr(event, "num", None) == 4:
        return -2                       # Linux/X11: scroll up
    if getattr(event, "num", None) == 5:
        return 2                        # Linux/X11: scroll down
    delta = getattr(event, "delta", 0) or 0
    if not delta:
        return 0
    if abs(delta) >= 120:               # Windows: multiples of 120
        return int(-delta / 120) * 2
    return -1 if delta > 0 else 1       # macOS and Tk 9 touchpads: small deltas


def _on_wheel(event, steps=None):
    """Scroll the page under the pointer. Text boxes and lists scroll themselves, so they are left alone."""
    try:
        widget = event.widget.winfo_containing(event.x_root, event.y_root)
    except (tk.TclError, AttributeError, KeyError):
        return None
    w = widget
    while w is not None:
        try:
            cls = w.winfo_class()
        except tk.TclError:
            return None
        if cls in _NATIVE_SCROLL:
            return None
        frame = _SCROLL_FRAMES.get(str(w))
        if frame is not None:
            steps = steps if steps is not None else _wheel_steps(event)
            if steps:
                frame.scroll(steps)
            return "break"
        w = w.master
    return None


def _select_all_text(event):
    event.widget.tag_add("sel", "1.0", "end-1c")
    event.widget.mark_set("insert", "end-1c")
    return "break"


def _select_all_entry(event):
    event.widget.select_range(0, "end")
    event.widget.icursor("end")
    return "break"


def install_input_helpers(root: tk.Misc) -> None:
    """Call once on the main window."""
    root.bind_all("<MouseWheel>", _on_wheel, add="+")                        # Windows, macOS, Tk 9
    root.bind_all("<Button-4>", lambda e: _on_wheel(e, -2), add="+")        # Linux touchpad/wheel: up
    root.bind_all("<Button-5>", lambda e: _on_wheel(e, 2), add="+")         # Linux touchpad/wheel: down
    for seq in ("<Control-a>", "<Control-A>"):
        root.bind_class("Text", seq, _select_all_text)
        for cls in ("Entry", "TEntry", "TCombobox"):
            root.bind_class(cls, seq, _select_all_entry)


def copy_to_clipboard(root: tk.Misc, text: str) -> None:
    """Copy text so other programs can paste it, even after SysHealth closes. On Linux the system clipboard
    tool is used when available (Tk's own clipboard only lasts while the app runs and is unreliable on some
    desktops); Tk's clipboard is always set as well."""
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update_idletasks()
    if sys.platform.startswith("win") or sys.platform == "darwin":
        return
    tools = []
    if os.environ.get("WAYLAND_DISPLAY"):
        tools.append(["wl-copy"])
    tools += [["xclip", "-selection", "clipboard"], ["xsel", "--clipboard", "--input"]]
    for cmd in tools:
        if shutil.which(cmd[0]):
            try:
                subprocess.run(cmd, input=text.encode("utf-8"), env=system_env(), timeout=5,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
            except (OSError, subprocess.SubprocessError):
                continue


def bar(fraction: float, width: int = 20) -> str:
    """Text bar for table cells, e.g. ██████░░░░."""
    fraction = max(0.0, min(1.0, fraction))
    full = int(round(fraction * width))
    return "█" * full + "░" * (width - full)



# ---------------------------------------------------------------------------------------------------------------
# Colored text. Some ttk themes ignore per-label text colors, so colored captions use classic Tk labels whose
# colors are set directly and refreshed whenever the theme changes.
_THEMED: list = []
_CURRENT = {"palette": PALETTES["light"], "family": "TkDefaultFont"}


class ThemedLabel(tk.Label):
    def __init__(self, parent, role: str = "muted", size: int = 9, bold: bool = False, **kw):
        kw.pop("style", None)
        kw.setdefault("anchor", "w")
        super().__init__(parent, bd=0, padx=0, pady=0, highlightthickness=0, **kw)
        self.role, self.size, self.bold = role, size, bold
        _THEMED.append(self)
        self._apply()

    def set_role(self, role: str) -> None:
        self.role = role
        self._apply()

    def _apply(self) -> None:
        p, fam = _CURRENT["palette"], _CURRENT["family"]
        try:
            self.configure(background=theme.surface_color(self, p), foreground=p.get(self.role, p["muted"]),
                           font=(fam, self.size, "bold" if self.bold else "normal"))
        except tk.TclError:
            pass


def MutedLabel(parent, **kw) -> ThemedLabel:
    return ThemedLabel(parent, "muted", **kw)


_TREES: list = []


def register_tree(tree: ttk.Treeview) -> None:
    _TREES.append(tree)
    _style_tree(tree)


def _style_tree(tree: ttk.Treeview) -> None:
    p = _CURRENT["palette"]
    try:
        tree.tag_configure("odd", background=p.get("stripe", p["window"]))
    except tk.TclError:
        pass


def restripe(tree: ttk.Treeview, parent: str = "") -> None:
    for i, iid in enumerate(tree.get_children(parent)):
        tags = [t for t in tree.item(iid, "tags") if t != "odd"]
        if i % 2:
            tags.append("odd")
        tree.item(iid, tags=tuple(tags))


def retheme(palette: dict, family: str) -> None:
    _CURRENT["palette"], _CURRENT["family"] = palette, family
    for t in list(_TREES):
        try:
            if t.winfo_exists():
                _style_tree(t)
                continue
        except tk.TclError:
            pass
        _TREES.remove(t)
    for w in list(_THEMED):
        try:
            exists = w.winfo_exists()
        except tk.TclError:
            exists = False
        if exists:
            w._apply()
        else:
            _THEMED.remove(w)
