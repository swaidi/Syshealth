"""Shared state store.

Every feature publishes its latest result here (state.json), and SysHealth's own actions are
appended to history.jsonl. Any dashboard - the built-in one or a future external one - reads
these files instead of calling feature code, so dashboard content and design can change without
touching the core modules.
"""
from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Optional

from .platform_utils import app_data_dir

SCHEMA_VERSION = 1
_lock = threading.Lock()


def state_path() -> str:
    return os.path.join(app_data_dir(), "state.json")


def history_path() -> str:
    return os.path.join(app_data_dir(), "history.jsonl")


def load() -> dict:
    try:
        with open(state_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def publish(section: str, level: str, value: str, detail: str = "", data: Optional[dict] = None) -> None:
    """Record the latest result of a feature. level is OK | WARN | FAIL | INFO."""
    with _lock:
        st = load()
        st["_schema"] = SCHEMA_VERSION
        st[section] = {"level": level, "value": value, "detail": detail,
                       "updated": time.strftime("%Y-%m-%d %H:%M:%S"), "data": data or {}}
        tmp = state_path() + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(st, fh, indent=2, ensure_ascii=False, default=str)
        os.replace(tmp, state_path())


def get(section: str) -> Optional[dict]:
    return load().get(section)


def record_action(category: str, action: str, detail: str = "") -> None:
    """Append an entry to SysHealth's own change history."""
    entry = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "category": category, "action": action, "detail": detail}
    with _lock:
        with open(history_path(), "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _trim_history()


def _trim_history(max_lines: int = 5000) -> None:
    try:
        if os.path.getsize(history_path()) < 1_500_000:
            return
        with open(history_path(), "r", encoding="utf-8") as fh:
            lines = fh.readlines()[-max_lines:]
        with open(history_path(), "w", encoding="utf-8") as fh:
            fh.writelines(lines)
    except OSError:
        pass


def read_history(days: int = 30) -> list[dict[str, Any]]:
    cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - days * 86400))
    out = []
    try:
        with open(history_path(), "r", encoding="utf-8") as fh:
            for line in fh:
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if e.get("time", "") >= cutoff:
                    out.append(e)
    except OSError:
        pass
    return out
