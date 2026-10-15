"""Disk space analysis: folder sizes (drill-down) and the largest files."""
from __future__ import annotations

import heapq
import os
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from .platform_utils import IS_WINDOWS, Cancelled, is_virtual_dir, list_dir

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


@dataclass
class BigFile:
    path: str
    size: int
    mtime: float


@dataclass
class SpaceReport:
    roots: list[str]
    dir_size: dict[str, int] = field(default_factory=dict)
    dir_files: dict[str, int] = field(default_factory=dict)       # file count (recursive)
    children: dict[str, list[str]] = field(default_factory=dict)  # dir -> subdirs
    largest: list[BigFile] = field(default_factory=list)
    total_size: int = 0
    total_files: int = 0
    errors: int = 0

    def subfolders(self, path: str) -> list[tuple[str, int, int]]:
        kids = self.children.get(path, [])
        return sorted(((k, self.dir_size.get(k, 0), self.dir_files.get(k, 0)) for k in kids),
                      key=lambda t: t[1], reverse=True)

    def files_only_size(self, path: str) -> int:
        return self.dir_size.get(path, 0) - sum(self.dir_size.get(k, 0) for k in self.children.get(path, []))

    def top_folders(self, n: int = 100, max_depth: int = 4) -> list[tuple[str, int]]:
        out = []
        for root in self.roots:
            base = root.rstrip(os.sep).count(os.sep)
            for path, size in self.dir_size.items():
                if path != root and path.startswith(root) and path.count(os.sep) - base <= max_depth:
                    out.append((path, size))
        return sorted(out, key=lambda t: t[1], reverse=True)[:n]


def analyze(roots: list[str], top_files: int = 200, cancel: Optional[threading.Event] = None,
            progress: Optional[Callable[[str], None]] = None) -> SpaceReport:
    roots = [os.path.abspath(r) for r in roots if os.path.isdir(r)]
    rep = SpaceReport(roots)
    heap: list[tuple[int, str, float]] = []
    for root in roots:
        rep.dir_size.setdefault(root, 0)
        rep.dir_files.setdefault(root, 0)
        stack = [root]
        while stack:
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            current = stack.pop()
            entries, complete = list_dir(current)
            if not complete:
                rep.errors += 1
            local_size, local_count, subdirs = 0, 0, []
            for e in entries:
                try:
                    if e.is_symlink():
                        continue
                    if IS_WINDOWS:
                        st = e.stat(follow_symlinks=False)
                        if getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT:
                            continue
                    if e.is_dir(follow_symlinks=False):
                        if not is_virtual_dir(e.path):  # /proc, /sys, /dev, /run and similar
                            subdirs.append(e.path)
                        continue
                    if not e.is_file(follow_symlinks=False):
                        continue
                    st = e.stat(follow_symlinks=False)
                    size = st.st_size
                    local_size += size
                    local_count += 1
                    if len(heap) < top_files:
                        heapq.heappush(heap, (size, e.path, st.st_mtime))
                    elif size > heap[0][0]:
                        heapq.heapreplace(heap, (size, e.path, st.st_mtime))
                except OSError:
                    rep.errors += 1
            rep.children[current] = subdirs
            for d in subdirs:
                rep.dir_size.setdefault(d, 0)
                rep.dir_files.setdefault(d, 0)
            stack.extend(subdirs)
            rep.total_size += local_size
            rep.total_files += local_count
            # add this folder's own files to it and every ancestor up to the root
            p = current
            while True:
                rep.dir_size[p] = rep.dir_size.get(p, 0) + local_size
                rep.dir_files[p] = rep.dir_files.get(p, 0) + local_count
                if p == root:
                    break
                parent = os.path.dirname(p)
                if parent == p:
                    break
                p = parent
            if progress and rep.total_files and rep.total_files % 20000 < local_count:
                progress(f"Measured {rep.total_files:,} files…")
    rep.largest = [BigFile(p, s, m) for s, p, m in sorted(heap, reverse=True)]
    return rep
