"""SysHealth flat theme.

Implements the design specification's tokens (v3.0.0) as a ttk theme built on 'clam', so every color is
controlled here for both light and dark modes. To restyle the app, edit TOKENS; no page code changes.
"""
from __future__ import annotations

import sys
import tkinter as tk
from tkinter import font as tkfont, ttk

THEME_NAME = "syssentinel"

# Design-spec tokens. Keys on the left of each comment group are the spec's token names.
TOKENS = {
    "dark": {
        "app": "#2E3440",            # color.bg.app
        "sidebar": "#272C36",        # color.bg.sidebar
        "card": "#3B4252",           # color.bg.card
        "card_hover": "#434C5E",     # color.bg.card_hover
        "input": "#434C5E",          # color.bg.input
        "border": "#4C566A",         # color.border.subtle
        "border_strong": "#D8DEE9",  # color.border.strong
        "fg": "#ECEFF4",             # color.fg.primary
        "fg2": "#D8DEE9",            # color.fg.secondary
        "muted": "#B8C0CF",          # color.fg.muted
        "accent": "#88C0D0",         # color.accent
        "accent_hover": "#81A1C1",   # color.accent.hover
        "on_accent": "#2E3440",      # text on accent (contrast fix)
        "ok": "#6CCB5F", "warn": "#F2C94C", "fail": "#FF8F99", "info": "#C5CBD6",
        "stripe": "#353C4A", "row_hover": "#434C5E", "selected": "#4C566A",
        "disabled": "#6B7385", "button": "#434C5E", "button_hover": "#4C566A", "button_border": "#5E6779",
        # Sidebar: section bars sit between the sidebar and the selected item in lightness.
        "nav_header": "#353C4A", "nav_hover": "#2F3540", "nav_selected": "#434C5E",
    },
    "light": {
        "app": "#F3F3F3", "sidebar": "#E8E8E8", "card": "#FFFFFF", "card_hover": "#F9F9F9",
        "input": "#FFFFFF", "border": "#E5E5E5", "border_strong": "#D1D1D1",
        "fg": "#1A1A1A", "fg2": "#5C5C5C", "muted": "#767676",
        "accent": "#0067C0", "accent_hover": "#1875D0", "on_accent": "#FFFFFF",
        "ok": "#0F7B0F", "warn": "#9D5D00", "fail": "#C42B1C", "info": "#005FB8",
        "stripe": "#F8F8F8", "row_hover": "#EEEEEE", "selected": "#E0EEF9",
        "disabled": "#A0A0A0", "button": "#FFFFFF", "button_hover": "#F0F0F0", "button_border": "#C8C8C8",
        "nav_header": "#F2F2F2", "nav_hover": "#EFEFEF", "nav_selected": "#FFFFFF",
    },
}


def palette(dark: bool) -> dict:
    """Token set plus the legacy keys used by pages (window, text, log_bg, grid, ...)."""
    t = dict(TOKENS["dark" if dark else "light"])
    t.update({"window": t["app"], "text": t["fg"], "group": t["stripe"], "log_bg": t["input"] if dark else "#FFFFFF",
              "log_fg": t["fg2"] if dark else t["fg"], "grid": t["border"], "accent2": t["info"],
              "select": t["selected"]})
    return t


def font_family() -> str:
    if sys.platform.startswith("win"):
        return "Segoe UI"
    families = set(tkfont.families())
    for f in ("Ubuntu", "Cantarell", "Noto Sans", "DejaVu Sans"):
        if f in families:
            return f
    return tkfont.nametofont("TkDefaultFont").actual("family")


def mono_family() -> str:
    if sys.platform.startswith("win"):
        return "Consolas"
    families = set(tkfont.families())
    for f in ("Ubuntu Mono", "DejaVu Sans Mono", "Noto Sans Mono"):
        if f in families:
            return f
    return "TkFixedFont"


# Styles that get a card-colored twin ("OnCard.<style>") for widgets placed inside cards.
_ON_CARD: set[str] = set()
_ON_SIDEBAR: set[str] = set()


def apply(root: tk.Tk, dark: bool, family: str) -> dict:
    """Create/refresh the theme for the given mode and return the palette."""
    p = palette(dark)
    style = ttk.Style(root)
    if THEME_NAME not in style.theme_names():
        style.theme_create(THEME_NAME, parent="clam")
    style.theme_use(THEME_NAME)

    for name, size, weight in (("TkDefaultFont", 10, "normal"), ("TkTextFont", 10, "normal"),
                               ("TkHeadingFont", 10, "bold"), ("TkMenuFont", 10, "normal")):
        try:
            tkfont.nametofont(name).configure(family=family, size=size, weight=weight)
        except tk.TclError:
            pass
    body = (family, 10)

    style.configure(".", background=p["app"], foreground=p["fg"], fieldbackground=p["input"],
                    bordercolor=p["border"], lightcolor=p["border"], darkcolor=p["border"],
                    troughcolor=p["app"], focuscolor=p["accent"], selectbackground=p["selected"],
                    selectforeground=p["fg"], insertcolor=p["fg"], font=body, relief="flat")
    style.map(".", foreground=[("disabled", p["disabled"])])

    # Surfaces
    style.configure("TFrame", background=p["app"])
    style.configure("Card.TFrame", background=p["card"], bordercolor=p["border"], relief="solid", borderwidth=1)
    style.configure("Sidebar.TFrame", background=p["sidebar"])
    style.configure("TLabel", background=p["app"], foreground=p["fg"])
    style.configure("TPanedwindow", background=p["app"])
    style.configure("Sash", sashthickness=6, gripcount=0, background=p["app"])

    # Typography (spec 1.3)
    style.configure("AppTitle.TLabel", font=(family, 14, "bold"))
    style.configure("PageTitle.TLabel", font=(family, 18, "bold"))
    style.configure("Section.TLabel", font=(family, 12, "bold"))
    style.configure("CardTitle.TLabel", font=(family, 10, "bold"), foreground=p["fg2"])
    style.configure("CardValue.TLabel", font=(family, 15, "bold"))
    style.configure("Big.TLabel", font=(family, 24, "bold"))
    style.configure("Muted.TLabel", foreground=p["muted"])

    # Buttons
    style.configure("TButton", background=p["button"], foreground=p["fg"], bordercolor=p["button_border"],
                    lightcolor=p["button"], darkcolor=p["button"], relief="solid", borderwidth=1,
                    padding=(12, 5), font=(family, 10, "bold"), focusthickness=1, focuscolor=p["accent"],
                    anchor="center")
    style.map("TButton", background=[("disabled", p["button"]), ("pressed", p["button_border"]),
                                     ("active", p["button_hover"])],
              lightcolor=[("active", p["button_hover"])], darkcolor=[("active", p["button_hover"])],
              bordercolor=[("focus", p["accent"])], foreground=[("disabled", p["disabled"])])
    for name, bg, hover, fg in (("Accent.TButton", p["accent"], p["accent_hover"], p["on_accent"]),
                                ("Danger.TButton", p["fail"], p["fail"], p["on_accent"])):
        style.configure(name, background=bg, foreground=fg, bordercolor=bg, lightcolor=bg, darkcolor=bg)
        style.map(name, background=[("disabled", p["border"]), ("pressed", hover), ("active", hover)],
                  bordercolor=[("active", hover)], lightcolor=[("active", hover)], darkcolor=[("active", hover)],
                  foreground=[("disabled", p["disabled"])])

    # Inputs
    for name in ("TEntry", "TCombobox", "TSpinbox"):
        style.configure(name, fieldbackground=p["input"], foreground=p["fg"], bordercolor=p["border_strong"],
                        lightcolor=p["input"], darkcolor=p["input"], arrowcolor=p["fg"], background=p["input"],
                        insertcolor=p["fg"], padding=(6, 4))
        style.map(name, bordercolor=[("focus", p["accent"])], lightcolor=[("focus", p["accent"])],
                  fieldbackground=[("readonly", p["input"]), ("disabled", p["app"])],
                  foreground=[("readonly", p["fg"]), ("disabled", p["disabled"])],
                  selectbackground=[("readonly", p["input"])], selectforeground=[("readonly", p["fg"])])
    root.option_add("*TCombobox*Listbox.background", p["input"])
    root.option_add("*TCombobox*Listbox.foreground", p["fg"])
    root.option_add("*TCombobox*Listbox.selectBackground", p["selected"])
    root.option_add("*TCombobox*Listbox.selectForeground", p["fg"])
    root.option_add("*TCombobox*Listbox.font", body)

    # Choice controls
    for name in ("TCheckbutton", "TRadiobutton"):
        style.configure(name, background=p["app"], foreground=p["fg"], indicatorbackground=p["input"],
                        indicatorforeground=p["accent"], upperbordercolor=p["border_strong"],
                        lowerbordercolor=p["border_strong"], indicatormargin=(0, 0, 6, 0), padding=(0, 2))
        style.map(name, background=[("active", p["app"])],
                  indicatorbackground=[("selected", p["input"]), ("pressed", p["card_hover"])],
                  indicatorforeground=[("selected", p["accent"])])

    # Tables
    style.configure("Treeview", background=p["card"], fieldbackground=p["card"], foreground=p["fg"],
                    bordercolor=p["border"], lightcolor=p["border"], darkcolor=p["border"], rowheight=30, font=body)
    style.map("Treeview", background=[("selected", p["selected"])], foreground=[("selected", p["fg"])])
    style.configure("Treeview.Heading", background=p["card"], foreground=p["fg"], bordercolor=p["border"],
                    lightcolor=p["card"], darkcolor=p["card"], relief="flat", font=(family, 10, "bold"),
                    padding=(6, 6))
    style.map("Treeview.Heading", background=[("active", p["card_hover"])])
    style.configure("Nav.Treeview", background=p["sidebar"], fieldbackground=p["sidebar"], foreground=p["fg2"],
                    bordercolor=p["sidebar"], lightcolor=p["sidebar"], darkcolor=p["sidebar"], rowheight=28,
                    font=body)
    style.map("Nav.Treeview", background=[("selected", p["card_hover"])], foreground=[("selected", p["accent"])])
    # Remove the expand arrow from the sidebar (sections are always open).
    style.layout("Nav.Treeview.Item", [("Treeitem.padding", {"sticky": "nswe", "children": [
        ("Treeitem.image", {"side": "left", "sticky": ""}),
        ("Treeitem.focus", {"side": "left", "sticky": "", "children": [
            ("Treeitem.text", {"side": "left", "sticky": ""})]})]})])

    # Tabs, scrollbars, progress
    style.configure("TNotebook", background=p["app"], bordercolor=p["border"], tabmargins=(0, 0, 0, 0))
    style.configure("TNotebook.Tab", background=p["app"], foreground=p["fg2"], bordercolor=p["border"],
                    lightcolor=p["app"], padding=(16, 7), font=(family, 10))
    style.map("TNotebook.Tab", background=[("selected", p["card"]), ("active", p["card_hover"])],
              foreground=[("selected", p["accent"])], lightcolor=[("selected", p["card"])],
              font=[("selected", (family, 10, "bold"))])
    style.configure("TScrollbar", background=p["border"], troughcolor=p["app"], bordercolor=p["app"],
                    lightcolor=p["border"], darkcolor=p["border"], arrowcolor=p["muted"], gripcount=0)
    style.map("TScrollbar", background=[("active", p["muted"])])
    style.configure("Horizontal.TProgressbar", background=p["accent"], troughcolor=p["border"],
                    bordercolor=p["border"], lightcolor=p["accent"], darkcolor=p["accent"], thickness=6)

    # Card/sidebar twins of label, frame and choice styles
    for name in list(_ON_CARD):
        _configure_twin(style, "OnCard.", name, p["card"])
    for name in list(_ON_SIDEBAR):
        _configure_twin(style, "OnSidebar.", name, p["sidebar"])

    root.configure(background=p["app"])
    _restyle_comboboxes(root, p)
    return p


def _configure_twin(style: ttk.Style, prefix: str, base: str, color: str) -> None:
    style.configure(prefix + base, background=color)
    if base in ("TCheckbutton", "TRadiobutton"):
        style.map(prefix + base, background=[("active", color)])


def _restyle_comboboxes(root: tk.Misc, p: dict) -> None:
    """Already-created combobox drop-down lists keep old colors unless updated directly."""
    def walk(w):
        for child in w.winfo_children():
            if isinstance(child, ttk.Combobox):
                try:
                    pop = child.tk.call("ttk::combobox::PopdownWindow", child)
                    child.tk.call(f"{pop}.f.l", "configure", "-background", p["input"], "-foreground", p["fg"],
                                  "-selectbackground", p["selected"], "-selectforeground", p["fg"])
                except tk.TclError:
                    pass
            walk(child)
    walk(root)


_TWIN_CLASSES = {"TLabel", "TFrame", "TCheckbutton", "TRadiobutton"}


def adapt_surfaces(root: tk.Misc, style: ttk.Style, p: dict) -> None:
    """Give labels, frames and choice controls inside cards (and the sidebar) the matching background."""
    def surface_of(w) -> str:
        m = w.master
        while m is not None:
            try:
                s = str(m.cget("style")) if isinstance(m, ttk.Frame) else ""
            except tk.TclError:
                s = ""
            if s in ("Card.TFrame",) or s.startswith("OnCard."):
                return "card"
            if s == "Sidebar.TFrame" or s.startswith("OnSidebar."):
                return "sidebar"
            m = m.master
        return "app"

    def walk(w):
        for child in w.winfo_children():
            cls = child.winfo_class()
            if cls in _TWIN_CLASSES:
                try:
                    current = str(child.cget("style"))
                except tk.TclError:
                    current = ""
                if current not in ("Card.TFrame", "Sidebar.TFrame") and not current.startswith(("OnCard.", "OnSidebar.")):
                    surface = surface_of(child)
                    if surface != "app":
                        base = current.replace("Switch.", "") or cls
                        prefix, registry, color = (("OnCard.", _ON_CARD, p["card"]) if surface == "card"
                                                   else ("OnSidebar.", _ON_SIDEBAR, p["sidebar"]))
                        if base not in registry:
                            registry.add(base)
                            _configure_twin(style, prefix, base, color)
                        child.configure(style=prefix + base)
            walk(child)
    walk(root)


def surface_color(widget: tk.Misc, p: dict) -> str:
    """Background color of the surface a classic Tk widget sits on."""
    m = widget.master
    while m is not None:
        if isinstance(m, ttk.Frame):
            try:
                s = str(m.cget("style"))
            except tk.TclError:
                s = ""
            if s == "Card.TFrame" or s.startswith("OnCard."):
                return p["card"]
            if s == "Sidebar.TFrame" or s.startswith("OnSidebar."):
                return p["sidebar"]
        m = m.master
    return p["app"]
