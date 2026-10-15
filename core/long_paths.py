"""Long path detection and repair: finds files whose full path exceeds a limit and proposes
shorter folder/file names, applies renames with undo support."""
from __future__ import annotations

import json
import os
import re
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from .platform_utils import IS_WINDOWS, Cancelled, is_virtual_dir, list_dir, app_data_dir, norm, protected_roots

LogFn = Optional[Callable[[str], None]]

LIMITS = {"Office-safe (218)": 218, "Windows standard (259)": 259, "OneDrive / SharePoint (400)": 400}
DEFAULT_LIMIT = "Office-safe (218)"
FILLER_WORDS = {"the", "and", "of", "for", "a", "an", "to", "in", "on", "with", "&"}
INVALID_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
FILE_ATTRIBUTE_REPARSE_POINT = 0x400
EXT_PREFIX = "\\\\?\\"


# --------------------------------------------------------------------------- path helpers
def to_ext(path: str) -> str:
    """Windows: extended-length path (\\\\?\\) so paths over 260 characters can be read and renamed."""
    if not IS_WINDOWS or path.startswith(EXT_PREFIX):
        return path
    full = os.path.abspath(path)
    if full.startswith("\\\\"):
        return EXT_PREFIX + "UNC\\" + full[2:]
    return EXT_PREFIX + full


def to_plain(path: str) -> str:
    if IS_WINDOWS and path.startswith(EXT_PREFIX):
        rest = path[len(EXT_PREFIX):]
        return "\\\\" + rest[4:] if rest.upper().startswith("UNC\\") else rest
    return path


@dataclass
class LongItem:
    path: str
    root: str
    is_dir: bool

    @property
    def length(self) -> int:
        return len(self.path)


@dataclass
class Proposal:
    path: str          # current full path of the folder or file to rename
    new_name: str
    is_dir: bool
    affected: int = 0  # number of long items this rename helps

    @property
    def old_name(self) -> str:
        return os.path.basename(self.path)

    @property
    def saves(self) -> int:
        return len(self.old_name) - len(self.new_name)


# --------------------------------------------------------------------------- scanning
def scan(roots: list[str], limit: int, cancel: Optional[threading.Event] = None,
         progress: Optional[Callable[[str], None]] = None) -> tuple[list[LongItem], int]:
    protected = set(protected_roots())
    found: list[LongItem] = []
    checked = 0
    for root in roots:
        root_plain = os.path.abspath(root)
        stack = [to_ext(root_plain)]
        while stack:
            if cancel is not None and cancel.is_set():
                raise Cancelled()
            current = stack.pop()
            entries, _complete = list_dir(current)
            for entry in entries:
                try:
                    if entry.is_symlink():
                        continue
                    plain = to_plain(entry.path)
                    is_dir = entry.is_dir(follow_symlinks=False)
                    if IS_WINDOWS:
                        attrs = getattr(entry.stat(follow_symlinks=False), "st_file_attributes", 0)
                        if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
                            continue
                    if is_dir:
                        if norm(plain) in protected or is_virtual_dir(plain) or entry.name.lower() in (
                                "$recycle.bin", "system volume information"):
                            continue
                        stack.append(entry.path)
                    checked += 1
                    if len(plain) > limit:
                        found.append(LongItem(plain, root_plain, is_dir))
                    if progress and checked % 5000 == 0:
                        progress(f"Checked {checked:,} items… {to_plain(current)}")
                except OSError:
                    continue
    return found, checked


# --------------------------------------------------------------------------- planning
def shorten_name(name: str, max_len: int, is_dir: bool) -> str:
    base, ext = (name, "") if is_dir else os.path.splitext(name)
    budget = max(8, max_len - len(ext))
    words = [w for w in re.split(r"[\s_]+", base) if w]
    kept = [w for w in words if w.lower() not in FILLER_WORDS] or words
    out = ""
    for w in kept:
        candidate = f"{out} {w}".strip()
        if len(candidate) > budget:
            break
        out = candidate
    if not out:
        out = (kept[0] if kept else base)[:budget]
    out = out.rstrip(" .-")
    return (out or base[:budget]) + ext


def _segments(item: LongItem) -> list[str]:
    rel = os.path.relpath(item.path, item.root)
    return [] if rel == "." else rel.split(os.sep)


def plan(items: list[LongItem], limit: int, max_name: int = 24) -> tuple[list[Proposal], list[LongItem]]:
    """Choose the fewest renames (longest names first) that bring each long path under the limit."""
    renames: dict[str, Proposal] = {}          # key: norm(original path)
    taken: dict[str, set[str]] = {}            # parent -> names in use (lowercase)

    def effective_length(item: LongItem) -> int:
        length, prefix = len(item.root), item.root
        for seg in _segments(item):
            prefix = os.path.join(prefix, seg)
            p = renames.get(norm(prefix))
            length += 1 + len(p.new_name if p else seg)
        return length

    def unique(parent: str, name: str, is_dir: bool) -> str:
        used = taken.setdefault(norm(parent), set())
        if not used:
            try:
                used.update(n.lower() for n in os.listdir(to_ext(parent)))
            except OSError:
                pass
        base, ext = (name, "") if is_dir else os.path.splitext(name)
        candidate, n = name, 2
        while candidate.lower() in used:
            candidate = f"{base} {n}{ext}"
            n += 1
        used.add(candidate.lower())
        return candidate

    unresolved: list[LongItem] = []
    deepest = {}
    for item in items:  # only leaf-most entries matter; a long folder makes its children long too
        deepest[norm(item.path)] = item
    for item in sorted(deepest.values(), key=lambda i: i.length, reverse=True):
        segs = _segments(item)
        prefixes = []
        prefix = item.root
        for seg in segs:
            prefix = os.path.join(prefix, seg)
            prefixes.append((prefix, seg))
        guard = 0
        while effective_length(item) > limit and guard < len(prefixes):
            guard += 1
            candidates = [(p, s) for i, (p, s) in enumerate(prefixes)
                          if norm(p) not in renames and len(s) > max_name]
            if not candidates:
                break
            path, seg = max(candidates, key=lambda c: len(c[1]))
            is_dir = path != item.path or item.is_dir
            new = unique(os.path.dirname(path), shorten_name(seg, max_name, is_dir), is_dir)
            if len(new) >= len(seg):
                break
            renames[norm(path)] = Proposal(path, new, is_dir)
        if effective_length(item) > limit:
            unresolved.append(item)

    proposals = list(renames.values())
    for p in proposals:
        key = norm(p.path)
        p.affected = sum(1 for i in deepest.values() if not i.is_dir and
                         (norm(i.path) == key or norm(i.path).startswith(key + os.sep)))
    proposals.sort(key=lambda p: (p.affected, p.saves), reverse=True)
    return proposals, unresolved


def validate_name(name: str) -> Optional[str]:
    name = name.strip()
    if not name:
        return "The name cannot be empty."
    if INVALID_CHARS.search(name):
        return 'The name cannot contain < > : " / \\ | ? *'
    if name.endswith((".", " ")):
        return "The name cannot end with a dot or space."
    return None


# --------------------------------------------------------------------------- applying and undo
def _undo_file() -> str:
    return os.path.join(app_data_dir(), "long_path_undo.json")


def _load_batches() -> list[list[dict]]:
    try:
        with open(_undo_file(), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return []


def _save_batches(batches: list[list[dict]]) -> None:
    with open(_undo_file(), "w", encoding="utf-8") as fh:
        json.dump(batches[-20:], fh, indent=2, ensure_ascii=False)


def has_undo() -> bool:
    return bool(_load_batches())


def apply(proposals: list[Proposal], log: LogFn, cancel: Optional[threading.Event]) -> tuple[list[Proposal], list[str]]:
    """Rename deepest items first so parent paths stay valid. Returns (done, errors)."""
    done, errors, steps = [], [], []
    for p in sorted(proposals, key=lambda x: x.path.count(os.sep), reverse=True):
        if cancel is not None and cancel.is_set():
            break
        dst = os.path.join(os.path.dirname(p.path), p.new_name)
        try:
            if os.path.exists(to_ext(dst)):
                raise OSError("an item with the new name already exists")
            os.rename(to_ext(p.path), to_ext(dst))
            steps.append({"from": dst, "to": p.path})
            done.append(p)
            if log:
                log(f"Renamed: {p.old_name}  →  {p.new_name}")
        except OSError as exc:
            errors.append(f"{p.path}: {exc}")
    if steps:
        batches = _load_batches()
        batches.append(steps)
        _save_batches(batches)
    if cancel is not None and cancel.is_set():
        raise Cancelled()
    return done, errors


def undo_last(log: LogFn) -> tuple[int, list[str]]:
    batches = _load_batches()
    if not batches:
        return 0, []
    steps = batches.pop()
    restored, errors = 0, []
    for step in reversed(steps):  # parents first, so child paths exist again
        try:
            os.rename(to_ext(step["from"]), to_ext(step["to"]))
            restored += 1
            if log:
                log(f"Restored: {os.path.basename(step['to'])}")
        except OSError as exc:
            errors.append(f"{step['from']}: {exc}")
    _save_batches(batches)
    return restored, errors


# --------------------------------------------------------------------------- Windows setting
def windows_long_paths_enabled() -> Optional[bool]:
    if not IS_WINDOWS:
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem") as k:
            return bool(winreg.QueryValueEx(k, "LongPathsEnabled")[0])
    except OSError:
        return False


ENABLE_LONG_PATHS_CMD = ["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Control\FileSystem",
                         "/v", "LongPathsEnabled", "/t", "REG_DWORD", "/d", "1", "/f"]
