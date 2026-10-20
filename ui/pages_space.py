"""Clean Up pages: Large Files (space analyzer) and Cleanup (junk, old downloads, empty folders, optimize)."""
from __future__ import annotations

import datetime as dt
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from send2trash import send2trash

from core import cleanup, disk_health, state
from core.checks import INFO, WARN
from core.disk_usage import analyze as analyze_space
from core.platform_utils import APP_NAME, IS_WINDOWS, Cancelled, human_size, is_protected, open_location
from ui.common import MutedLabel, CheckTree, DriveSelector, Table, bar, card


def _fmt_time(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts).strftime("%Y-%m-%d") if ts else ""


# =============================================================================== Large files
class LargeFilesPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        self.report = None
        app.page_header(self, "Large Files", "See which folders and files use the most space. Expand a folder "
                        "to drill down.")
        opts = card(self, 14)
        opts.pack(fill=tk.X)
        ttk.Label(opts, text="Locations", style="Section.TLabel").grid(row=0, column=0, sticky="nw", padx=(0, 16))
        self.drives = DriveSelector(opts)
        self.drives.grid(row=0, column=1, sticky="w")
        ttk.Button(opts, text="Analyze space", style="Accent.TButton", command=self.analyze).grid(
            row=0, column=2, sticky="ne")
        opts.columnconfigure(1, weight=1)

        self.summary = tk.StringVar(value="Select a drive or folder and click 'Analyze space'.")
        ttk.Label(self, textvariable=self.summary, style="Section.TLabel").pack(fill=tk.X, pady=(12, 6))

        panes = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        left = ttk.Frame(panes)
        ttk.Label(left, text="Folders", style="Section.TLabel").pack(anchor=tk.W, pady=(0, 4))
        self.folders = Table(left, [("size", "Size", 90), ("share", "Share", 170), ("files", "Files", 80)],
                             tree_column=("Folder", 300), selectmode="browse")
        self.folders.pack(fill=tk.BOTH, expand=True)
        self.folders.tree.bind("<<TreeviewOpen>>", self._expand)
        fb = ttk.Frame(left)
        fb.pack(side=tk.BOTTOM, fill=tk.X, pady=(6, 4), before=self.folders)
        ttk.Button(fb, text="Open folder", command=self.open_folder).pack(side=tk.LEFT)
        panes.add(left, weight=1)

        right = ttk.Frame(panes)
        rhead = ttk.Frame(right)
        rhead.pack(fill=tk.X, pady=(0, 4))
        ttk.Label(rhead, text="Largest files", style="Section.TLabel").pack(side=tk.LEFT)
        self.min_size = tk.StringVar(value="All sizes")
        combo = ttk.Combobox(rhead, textvariable=self.min_size, state="readonly", width=12,
                             values=["All sizes", "> 100 MB", "> 500 MB", "> 1 GB"])
        combo.pack(side=tk.RIGHT)
        combo.bind("<<ComboboxSelected>>", lambda e: self._render_files())
        ttk.Label(rhead, text="Show").pack(side=tk.RIGHT, padx=6)
        self.files = Table(right, [("size", "Size", 90), ("modified", "Modified", 100), ("name", "Name", 220),
                                   ("folder", "Folder", 300)])
        self.files.pack(fill=tk.BOTH, expand=True)
        rb = ttk.Frame(right)
        rb.pack(side=tk.BOTTOM, fill=tk.X, pady=(6, 4), before=self.files)
        ttk.Button(rb, text="Open file location", command=self.open_file).pack(side=tk.LEFT)
        ttk.Button(rb, text="Move to Recycle Bin", style="Danger.TButton", command=self.recycle).pack(side=tk.RIGHT)
        panes.add(right, weight=1)
        panes.pack(fill=tk.BOTH, expand=True)

    def analyze(self) -> None:
        roots = self.drives.selected()
        if not roots:
            messagebox.showinfo(APP_NAME, "Select at least one drive or folder.")
            return
        self.app.run_task("Space analysis", lambda c: analyze_space(roots, 300, c, self.app.set_status), self.show)

    def show(self, rep) -> None:
        self.report = rep
        self.folders.clear()
        self.files.clear()
        for root in rep.roots:
            self._insert_folder("", root, rep.dir_size.get(root, 0), rep.dir_files.get(root, 0),
                                rep.dir_size.get(root, 0) or 1, label=root, open_=True)
        self._render_files()
        top = rep.top_folders(1, 2)
        detail = f"Largest: {top[0][0]}" if top else ""
        self.summary.set(f"{human_size(rep.total_size)} in {rep.total_files:,} files" +
                         (f" · {rep.errors:,} items could not be read" if rep.errors else ""))
        self.app.dashboard.set_card("largefiles", INFO, human_size(rep.total_size), detail)

    def _render_files(self) -> None:
        if self.report is None:
            return
        limit = {"> 100 MB": 100 * 1024 ** 2, "> 500 MB": 500 * 1024 ** 2, "> 1 GB": 1024 ** 3}.get(
            self.min_size.get(), 0)
        self.files.clear()
        for f in self.report.largest:
            if f.size > limit:
                self.files.add((human_size(f.size), _fmt_time(f.mtime), os.path.basename(f.path),
                                os.path.dirname(f.path)), f)

    def _insert_folder(self, parent: str, path: str, size: int, files: int, parent_size: int,
                       label: str = "", open_: bool = False) -> str:
        share = size / parent_size if parent_size else 0
        iid = self.folders.add((human_size(size), f"{bar(share, 12)} {share * 100:4.0f}%", f"{files:,}"), path,
                               parent=parent, text=label or os.path.basename(path) or path, open_=False)
        if self.report.children.get(path):
            self.folders.tree.insert(iid, tk.END, text="…")  # placeholder so the expand arrow shows
        if open_:
            self.folders.tree.item(iid, open=True)
            self._fill(iid)
        return iid

    def _fill(self, iid: str) -> None:
        path = self.folders.data.get(iid)
        kids = self.folders.tree.get_children(iid)
        if not path or (kids and self.folders.tree.item(kids[0], "text") != "…"):
            return
        self.folders.tree.delete(*kids)
        rep = self.report
        parent_size = rep.dir_size.get(path, 0) or 1
        for sub, size, files in rep.subfolders(path):
            self._insert_folder(iid, sub, size, files, parent_size)
        own = rep.files_only_size(path)
        if own > 0:
            self.folders.add((human_size(own), f"{bar(own / parent_size, 12)} {own / parent_size * 100:4.0f}%", ""),
                             None, parent=iid, text="(files in this folder)")

    def _expand(self, _e=None) -> None:
        iid = self.folders.tree.focus()
        if iid:
            self._fill(iid)

    def open_folder(self) -> None:
        sel = self.folders.selected()
        if sel:
            open_location(sel[0])

    def open_file(self) -> None:
        sel = self.files.selected()
        if sel:
            open_location(sel[0].path)

    def recycle(self) -> None:
        sel = self.files.selected()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select one or more files in the 'Largest files' list.")
            return
        blocked = [f for f in sel if is_protected(f.path)]
        if blocked:
            messagebox.showwarning(APP_NAME, "Files in system folders cannot be deleted here.")
            return
        allowed = set(self.app.guard_paths([f.path for f in sel], "moved"))
        sel = [f for f in sel if f.path in allowed]
        if not sel:
            return
        size = sum(f.size for f in sel)
        if not messagebox.askyesno(APP_NAME, f"Move {len(sel)} file(s) ({human_size(size)}) to the Recycle Bin?"):
            return
        removed = []
        for f in sel:
            try:
                send2trash(os.path.normpath(f.path))
                removed.append(f)
            except Exception as exc:
                self.app.log(f"Could not move {f.path}: {exc}")
        for iid in [i for i, o in self.files.data.items() if o in removed]:
            self.files.tree.delete(iid)
            self.files.data.pop(iid, None)
        state.record_action("Large files", f"Moved {len(removed)} large file(s) to the Recycle Bin",
                            human_size(sum(f.size for f in removed)), [f.path for f in removed])
        self.app.log(f"Moved {len(removed)} file(s) to the Recycle Bin.")


# =============================================================================== Cleanup
class CleanupPage(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, padding=(4, 4, 4, 0))
        self.app = app
        self.categories = {c.id: c for c in cleanup.categories()}
        app.page_header(self, "Cleanup", "Free space safely: junk files, old downloads, empty folders, and drive "
                        "optimization.")
        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True)
        nb.add(self._junk_tab(nb), text="  Junk files  ")
        nb.add(self._downloads_tab(nb), text="  Old downloads  ")
        nb.add(self._empty_tab(nb), text="  Empty folders  ")
        nb.add(self._optimize_tab(nb), text="  Optimize drives  ")

    # ------------------------------------------------------------------ junk files
    def _junk_tab(self, nb) -> ttk.Frame:
        f = ttk.Frame(nb, padding=10)
        self.junk_summary = tk.StringVar(value="Click 'Analyze' to measure each category.")
        top = ttk.Frame(f)
        top.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(top, textvariable=self.junk_summary, style="Section.TLabel").pack(side=tk.LEFT)
        ttk.Button(top, text="Analyze", style="Accent.TButton", command=self.analyze).pack(side=tk.RIGHT)
        self.junk = CheckTree(f, self.app, [("size", "Size", 90), ("files", "Files", 80), ("admin", "Admin", 60),
                                            ("desc", "Description", 420)], "Category (click to select)", 260)
        self.junk.pack(fill=tk.BOTH, expand=True)
        self.junk_ids: dict[str, str] = {}
        for c in self.categories.values():
            iid = self.junk.add_item("", c.title, ("", "", "yes" if c.admin else "", c.description))
            self.junk_ids[iid] = c.id
            if c.id not in ("recycle",):
                self.junk.set_checked(iid, True)
        b = ttk.Frame(f)
        b.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 0), before=self.junk)
        MutedLabel(b, text="Recycle Bin is not selected by default because emptying it is permanent.",
                  style="Muted.TLabel").pack(side=tk.LEFT)
        ttk.Button(b, text="Clean selected", style="Accent.TButton", command=self.clean).pack(side=tk.RIGHT)
        return f

    def analyze(self) -> None:
        def work(cancel):
            return {cid: cleanup.analyze(c, cancel) for cid, c in self.categories.items()}

        def done(sizes):
            total = 0
            for iid, cid in self.junk_ids.items():
                size, count = sizes.get(cid, (0, 0))
                total += size
                self.junk.tree.set(iid, "size", human_size(size))
                self.junk.tree.set(iid, "files", f"{count:,}" if count else "")
            self.junk_summary.set(f"{human_size(total)} can be freed.")
            self.app.dashboard.set_card("cleanup", WARN if total > 2 * 1024 ** 3 else INFO,
                                        f"{human_size(total)} reclaimable", "Junk files, caches and Recycle Bin.")
        self.app.run_task("Cleanup analysis", work, done)

    def clean(self) -> None:
        chosen = [self.categories[self.junk_ids[i]] for i in self.junk.checked if i in self.junk_ids]
        if not chosen:
            messagebox.showinfo(APP_NAME, "Select at least one category.")
            return
        names = "\n".join(f"• {c.title}" for c in chosen)
        if not messagebox.askyesno(APP_NAME, f"Clean these categories?\n\n{names}\n\nFiles in use are skipped."):
            return

        def work(cancel):
            freed, skipped = 0, []
            for c in chosen:
                if cancel.is_set():
                    raise Cancelled()
                try:
                    f, _ = cleanup.clean(c, self.app.log, cancel)
                    freed += f
                except Exception as exc:  # e.g. administrator rights needed for one category
                    skipped.append(f"{c.title}: {exc}")
            return freed, skipped

        def done(r):
            freed, skipped = r
            for s in skipped:
                self.app.log(f"Skipped {s}")
            state.record_action("Cleanup", f"Freed {human_size(freed)}", ", ".join(c.title for c in chosen))
            self.junk_summary.set(f"Freed {human_size(freed)}." + (" Some categories need administrator rights "
                                                                   "(see log)." if skipped else ""))
            self.analyze()
        self.app.run_task("Cleanup", work, done)

    # ------------------------------------------------------------------ old downloads
    def _downloads_tab(self, nb) -> ttk.Frame:
        f = ttk.Frame(nb, padding=10)
        top = ttk.Frame(f)
        top.pack(fill=tk.X, pady=(0, 8))
        self.dl_folder = tk.StringVar(value=cleanup.downloads_folder())
        ttk.Label(top, text="Folder").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.dl_folder, width=50).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Browse…", command=lambda: self.dl_folder.set(
            filedialog.askdirectory() or self.dl_folder.get())).pack(side=tk.LEFT)
        ttk.Label(top, text="Not used for (days)").pack(side=tk.LEFT, padx=(16, 6))
        self.dl_days = tk.StringVar(value="90")
        ttk.Combobox(top, textvariable=self.dl_days, values=["30", "60", "90", "180", "365"], width=6).pack(
            side=tk.LEFT)
        ttk.Button(top, text="Find", style="Accent.TButton", command=self.find_old).pack(side=tk.RIGHT)
        self.dl_summary = tk.StringVar(value="")
        ttk.Label(f, textvariable=self.dl_summary, style="Section.TLabel").pack(fill=tk.X, pady=(0, 6))
        self.dl = CheckTree(f, self.app, [("size", "Size", 90), ("modified", "Last modified", 110),
                                          ("folder", "Folder", 420)], "File (click to select)", 300)
        self.dl.pack(fill=tk.BOTH, expand=True)
        self.dl_paths: dict[str, tuple] = {}
        b = ttk.Frame(f)
        b.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 0), before=self.dl)
        ttk.Button(b, text="Select all", command=lambda: [self.dl.set_checked(i, True) for i in self.dl.items()]).pack(
            side=tk.LEFT)
        ttk.Button(b, text="Clear", command=lambda: [self.dl.set_checked(i, False) for i in self.dl.items()]).pack(
            side=tk.LEFT, padx=6)
        ttk.Button(b, text="Move selected to Recycle Bin", style="Danger.TButton",
                   command=self.recycle_old).pack(side=tk.RIGHT)
        return f

    def find_old(self) -> None:
        folder = self.dl_folder.get()
        try:
            days = int(self.dl_days.get())
        except ValueError:
            messagebox.showerror(APP_NAME, "Days must be a whole number.")
            return
        if not os.path.isdir(folder):
            messagebox.showerror(APP_NAME, "The folder does not exist.")
            return

        def done(files):
            self.dl.clear()
            self.dl_paths.clear()
            for p, size, mtime in files:
                iid = self.dl.add_item("", os.path.basename(p), (human_size(size), _fmt_time(mtime), os.path.dirname(p)))
                self.dl_paths[iid] = (p, size)
            self.dl_summary.set(f"{len(files)} file(s), {human_size(sum(s for _, s, _ in files))}, not used for "
                                f"{days}+ days.")
        self.app.run_task("Finding old downloads", lambda c: cleanup.old_files(folder, days, c), done)

    def recycle_old(self) -> None:
        chosen = [i for i in self.dl.checked if i in self.dl_paths]
        if not chosen:
            messagebox.showinfo(APP_NAME, "Select files first.")
            return
        allowed = set(self.app.guard_paths([self.dl_paths[i][0] for i in chosen], "moved"))
        chosen = [i for i in chosen if self.dl_paths[i][0] in allowed]
        if not chosen:
            return
        size = sum(self.dl_paths[i][1] for i in chosen)
        if not messagebox.askyesno(APP_NAME, f"Move {len(chosen)} file(s) ({human_size(size)}) to the Recycle Bin?"):
            return
        moved, moved_paths = 0, []
        for iid in chosen:
            try:
                send2trash(os.path.normpath(self.dl_paths[iid][0]))
                moved_paths.append(self.dl_paths[iid][0])
                self.dl.remove(iid)
                moved += 1
            except Exception as exc:
                self.app.log(f"Could not move {self.dl_paths[iid][0]}: {exc}")
        state.record_action("Cleanup", f"Moved {moved} old download(s) to the Recycle Bin", human_size(size),
                            moved_paths)
        self.dl_summary.set(f"Moved {moved} file(s) to the Recycle Bin.")

    # ------------------------------------------------------------------ empty folders
    def _empty_tab(self, nb) -> ttk.Frame:
        f = ttk.Frame(nb, padding=10)
        top = ttk.Frame(f)
        top.pack(fill=tk.X, pady=(0, 8))
        self.empty_root = tk.StringVar(value=os.path.expanduser("~"))
        ttk.Label(top, text="Folder").pack(side=tk.LEFT)
        ttk.Entry(top, textvariable=self.empty_root, width=50).pack(side=tk.LEFT, padx=6)
        ttk.Button(top, text="Browse…", command=lambda: self.empty_root.set(
            filedialog.askdirectory() or self.empty_root.get())).pack(side=tk.LEFT)
        ttk.Button(top, text="Find empty folders", style="Accent.TButton", command=self.find_empty).pack(side=tk.RIGHT)
        self.empty_summary = tk.StringVar(value="Folders that contain nothing (or only desktop.ini / Thumbs.db).")
        ttk.Label(f, textvariable=self.empty_summary, style="Section.TLabel").pack(fill=tk.X, pady=(0, 6))
        self.empty = CheckTree(f, self.app, [("parent", "Location", 520)], "Folder (click to select)", 300)
        self.empty.pack(fill=tk.BOTH, expand=True)
        self.empty_paths: dict[str, str] = {}
        b = ttk.Frame(f)
        b.pack(side=tk.BOTTOM, fill=tk.X, pady=(8, 0), before=self.empty)
        ttk.Button(b, text="Select all", command=lambda: [self.empty.set_checked(i, True)
                                                          for i in self.empty.items()]).pack(side=tk.LEFT)
        ttk.Button(b, text="Delete selected", style="Danger.TButton", command=self.delete_empty).pack(side=tk.RIGHT)
        return f

    def find_empty(self) -> None:
        root = self.empty_root.get()
        if not os.path.isdir(root):
            messagebox.showerror(APP_NAME, "The folder does not exist.")
            return

        def done(dirs):
            self.empty.clear()
            self.empty_paths.clear()
            for d in dirs:
                iid = self.empty.add_item("", os.path.basename(d), (os.path.dirname(d),))
                self.empty_paths[iid] = d
            self.empty_summary.set(f"{len(dirs)} empty folder(s) found.")
        self.app.run_task("Finding empty folders", lambda c: cleanup.empty_folders([root], c), done)

    def delete_empty(self) -> None:
        chosen = self.app.guard_paths([self.empty_paths[i] for i in self.empty.checked if i in self.empty_paths],
                                      "deleted")
        if not chosen or not messagebox.askyesno(APP_NAME, f"Delete {len(chosen)} empty folder(s)?"):
            return
        n, errors = cleanup.remove_empty_folders(chosen, self.app.log)
        for e in errors:
            self.app.log(f"Could not delete {e}")
        state.record_action("Cleanup", f"Removed {n} empty folder(s)", "", chosen)
        self.find_empty()

    # ------------------------------------------------------------------ optimize
    def _optimize_tab(self, nb) -> ttk.Frame:
        f = ttk.Frame(nb, padding=10)
        text = ("Optimizing runs TRIM on SSDs (tells the drive which blocks are free) and defragments hard drives. "
                "Windows also does this weekly on its own; run it manually after large cleanups."
                if IS_WINDOWS else "TRIM tells SSDs which blocks are free, keeping them fast. Hard drives with Linux "
                "file systems do not need defragmenting.")
        MutedLabel(f, text=text, style="Muted.TLabel", wraplength=760, justify=tk.LEFT).pack(anchor=tk.W, pady=(0, 10))
        fixes = disk_health.get_fixes()
        row = ttk.Frame(f)
        row.pack(fill=tk.X)
        found = False
        for fid, fix in fixes.items():
            if fid.startswith("optimize:") or fid == "trim":
                found = True
                ttk.Button(row, text=fix.title, command=lambda fx=fix: self.app.run_fix(fx)).pack(
                    anchor=tk.W, pady=3)
        if not found:
            ttk.Label(row, text="No drives can be optimized from here.").pack(anchor=tk.W)
        MutedLabel(f, text="Requires administrator rights.", style="Muted.TLabel").pack(anchor=tk.W, pady=(10, 0))
        return f

    def on_show(self) -> None:
        pass
