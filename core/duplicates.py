"""Duplicate file detection by name or by size within the same extension, with optional content verification."""
from __future__ import annotations

import hashlib
import os
import stat
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Optional

from .platform_utils import IS_WINDOWS, Cancelled, human_size, norm, protected_roots

FILE_ATTRIBUTE_HIDDEN = 0x2
FILE_ATTRIBUTE_SYSTEM = 0x4
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

SKIP_DIR_NAMES = {"$recycle.bin", "system volume information", "$winreagent", "config.msi",
                  "recovery", "lost+found", ".trash", ".trash-1000", "__pycache__"}
APPDATA_DIR_NAMES = {"appdata", ".cache", ".local", ".config", ".var"}

PARTIAL_BYTES = 64 * 1024
CHUNK = 1024 * 1024


@dataclass
class FileInfo:
    path: str
    name: str
    ext: str
    size: int
    mtime: float


@dataclass
class DupGroup:
    label: str
    files: list[FileInfo] = field(default_factory=list)
    verified: bool = False

    @property
    def total(self) -> int:
        return sum(f.size for f in self.files)

    @property
    def wasted(self) -> int:
        return self.total - max((f.size for f in self.files), default=0)


def normalize_roots(roots: list[str]) -> list[str]:
    """Drop roots nested inside other selected roots so no file is indexed twice."""
    cleaned = sorted({norm(r) for r in roots if os.path.isdir(r)}, key=len)
    result: list[str] = []
    for r in cleaned:
        if not any(r == p or r.startswith(p.rstrip(os.sep) + os.sep) for p in result):
            result.append(r)
    return result


def _skip_dir(path: str, name: str, include_hidden: bool, include_appdata: bool, protected: set[str]) -> bool:
    low = name.lower()
    if low in SKIP_DIR_NAMES:
        return True
    if not include_appdata and low in APPDATA_DIR_NAMES:
        return True
    if not include_hidden and not IS_WINDOWS and name.startswith("."):
        return True
    return norm(path) in protected


def index_files(roots: list[str], min_size: int = 1, include_hidden: bool = False,
                include_appdata: bool = False, cancel: Optional[threading.Event] = None,
                progress: Optional[Callable[[str], None]] = None) -> list[FileInfo]:
    protected = set(protected_roots())
    files: list[FileInfo] = []
    stack = normalize_roots(roots)
    count = 0
    while stack:
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        current = stack.pop()
        try:
            it = os.scandir(current)
        except OSError:
            continue
        with it:
            for entry in it:
                try:
                    if entry.is_symlink():
                        continue
                    if IS_WINDOWS:
                        st = entry.stat(follow_symlinks=False)
                        attrs = getattr(st, "st_file_attributes", 0)
                        if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                            continue
                        if not include_hidden and attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM):
                            continue
                    if entry.is_dir(follow_symlinks=False):
                        if not _skip_dir(entry.path, entry.name, include_hidden, include_appdata, protected):
                            stack.append(entry.path)
                        continue
                    if not entry.is_file(follow_symlinks=False):
                        continue
                    if not include_hidden and not IS_WINDOWS and entry.name.startswith("."):
                        continue
                    st = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(st.st_mode) or st.st_size < min_size:
                        continue
                    ext = os.path.splitext(entry.name)[1].lower()
                    files.append(FileInfo(entry.path, entry.name, ext, st.st_size, st.st_mtime))
                    count += 1
                    if progress and count % 5000 == 0:
                        progress(f"Indexed {count:,} files… {current}")
                except OSError:
                    continue
    if progress:
        progress(f"Indexed {len(files):,} files.")
    return files


def hash_file(path: str, limit: Optional[int] = None, cancel: Optional[threading.Event] = None) -> Optional[str]:
    h = hashlib.sha256()
    remaining = limit
    try:
        with open(path, "rb") as fh:
            while True:
                if cancel is not None and cancel.is_set():
                    raise Cancelled()
                size = CHUNK if remaining is None else min(CHUNK, remaining)
                if size <= 0:
                    break
                data = fh.read(size)
                if not data:
                    break
                h.update(data)
                if remaining is not None:
                    remaining -= len(data)
    except OSError:
        return None
    return h.hexdigest()


def _split_by_content(files: list[FileInfo], cancel, progress) -> list[list[FileInfo]]:
    by_size: dict[int, list[FileInfo]] = defaultdict(list)
    for f in files:
        by_size[f.size].append(f)
    out: list[list[FileInfo]] = []
    for size, same_size in by_size.items():
        if len(same_size) < 2:
            continue
        by_partial: dict[str, list[FileInfo]] = defaultdict(list)
        for f in same_size:
            digest = hash_file(f.path, PARTIAL_BYTES, cancel)
            if digest:
                by_partial[digest].append(f)
        for candidates in by_partial.values():
            if len(candidates) < 2:
                continue
            if size <= PARTIAL_BYTES:  # partial hash already covers the whole file
                out.append(candidates)
                continue
            by_full: dict[str, list[FileInfo]] = defaultdict(list)
            for f in candidates:
                digest = hash_file(f.path, None, cancel)
                if digest:
                    by_full[digest].append(f)
            out.extend(g for g in by_full.values() if len(g) > 1)
    return out


def find_duplicates(files: list[FileInfo], mode: str = "size_ext", verify: bool = True,
                    cancel: Optional[threading.Event] = None,
                    progress: Optional[Callable[[str], None]] = None) -> list[DupGroup]:
    """mode: 'name' (same file name) or 'size_ext' (same size and same extension)."""
    buckets: dict[tuple, list[FileInfo]] = defaultdict(list)
    for f in files:
        if mode == "name":
            buckets[(f.name.lower(),)].append(f)
        elif f.size > 0:
            buckets[(f.ext, f.size)].append(f)
    candidates = [b for b in buckets.values() if len(b) > 1]
    if progress:
        progress(f"{len(candidates):,} candidate groups found.")

    groups: list[DupGroup] = []
    total = len(candidates)
    for i, bucket in enumerate(candidates, 1):
        if cancel is not None and cancel.is_set():
            raise Cancelled()
        if verify:
            if progress and i % 200 == 0:
                progress(f"Verifying content: group {i:,} of {total:,}…")
            subgroups = _split_by_content(bucket, cancel, progress)
        else:
            subgroups = [bucket]
        for sub in subgroups:
            first = sub[0]
            if mode == "name":
                label = first.name
            else:
                label = f"{first.ext or '(no extension)'} · {human_size(first.size)}"
            if verify:
                label += " · identical content"
            groups.append(DupGroup(label, sorted(sub, key=lambda f: f.mtime, reverse=True), verify))
    groups.sort(key=lambda g: g.wasted, reverse=True)
    if progress:
        progress(f"{len(groups):,} duplicate groups; {human_size(sum(g.wasted for g in groups))} reclaimable.")
    return groups
