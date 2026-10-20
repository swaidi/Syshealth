"""Maintenance schedule: routine tasks, when each was last done, and whether it is due.

"Last done" comes from data SysHealth already keeps: the latest result of each tool (state.json) and
SysHealth's own action history (history.jsonl). The schedule is also published to state.json under
"maintenance", so an external dashboard can show it without calling this code.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Callable, Optional

from . import state

DUE_SOON_SHARE = 0.2  # "due soon" in the last 20% of the interval


@dataclass
class Task:
    id: str
    title: str
    every_days: int
    page: str                 # page to open
    why: str
    last: Optional[dt.datetime] = None
    status: str = ""          # never | overdue | soon | ok
    note: str = ""

    @property
    def next_due(self) -> Optional[dt.datetime]:
        return self.last + dt.timedelta(days=self.every_days) if self.last else None


# (id, title, every N days, page, how "last done" is found, why it matters)
TASKS = [
    ("signatures", "Update malware signatures", 3, "malware", ("history", "Malware", "Updated malware signatures"),
     "New threats appear daily; old signatures miss them."),
    ("malware_scan", "Quick malware scan", 7, "malware", ("state", "malware"),
     "Checks Downloads, Desktop and startup locations for threats."),
    ("health", "Health checks (system, disk, network)", 7, "system", ("state", "system", "disk", "network"),
     "Finds failing disks, low space and network problems early."),
    ("app_updates", "Check app updates", 7, "updates", ("state", "updates"),
     "Outdated apps are a common way in for malware."),
    ("events", "Review the event log", 14, "events", ("state", "events"),
     "Repeated crashes or disk errors warn of bigger problems."),
    ("security", "Security review", 30, "security", ("state", "security"),
     "Confirms the firewall, encryption and other protections are still on."),
    ("startup", "Review startup apps", 30, "startup", ("state", "startup"),
     "New startup entries slow sign-in and can hide unwanted programs."),
    ("cleanup", "Clean junk files", 30, "cleanup", ("history", "Cleanup", "Freed"),
     "Temporary files and caches grow over time."),
    ("space", "Check disk space", 30, "largefiles", ("state", "largefiles"),
     "Shows what fills the drive before it runs out."),
    ("duplicates", "Review duplicate files", 90, "duplicates", ("state", "duplicates"),
     "Recovers space taken by second copies of your own files."),
]


def _parse(text: str) -> Optional[dt.datetime]:
    try:
        return dt.datetime.strptime(text[:19], "%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return None


def _last_from_state(st: dict, keys: list[str]) -> Optional[dt.datetime]:
    """Oldest of the given sections (a combined task is only as fresh as its oldest part)."""
    times = [_parse((st.get(k) or {}).get("updated", "")) for k in keys]
    return None if not times or any(t is None for t in times) else min(times)


def _last_from_history(history: list[dict], category: str, prefix: str) -> Optional[dt.datetime]:
    found = [_parse(h.get("time", "")) for h in history
             if h.get("category") == category and h.get("action", "").startswith(prefix)]
    found = [t for t in found if t]
    return max(found) if found else None


def schedule(now: Optional[dt.datetime] = None,
             extra_last: Optional[dict[str, Callable[[], Optional[dt.datetime]]]] = None) -> list[Task]:
    """All tasks with status, most urgent first. extra_last can supply other evidence of a task being done
    (for example the publication date of the installed malware signatures)."""
    now = now or dt.datetime.now()
    st = state.load()
    history = state.read_history(days=400)
    tasks = []
    for tid, title, every, page, source, why in TASKS:
        t = Task(tid, title, every, page, why)
        if source[0] == "state":
            t.last = _last_from_state(st, list(source[1:]))
        else:
            t.last = _last_from_history(history, source[1], source[2])
        if extra_last and tid in extra_last:
            try:
                other = extra_last[tid]()
            except Exception:
                other = None
            if other and (t.last is None or other > t.last):
                t.last = other
        if t.last is None:
            t.status, t.note = "never", "Not done yet"
        else:
            left = t.next_due - now
            if left.total_seconds() < 0:
                days = max(1, -left.days)
                t.status, t.note = "overdue", f"Overdue by {days} day{'s' if days != 1 else ''}"
            elif left <= dt.timedelta(days=every * DUE_SOON_SHARE) or left < dt.timedelta(days=1):
                t.status, t.note = "soon", "Due today" if left < dt.timedelta(days=1) else f"Due in {left.days} days"
            else:
                t.status, t.note = "ok", f"Next in {left.days} days"
        tasks.append(t)
    order = {"overdue": 0, "never": 1, "soon": 2, "ok": 3}
    tasks.sort(key=lambda t: (order[t.status], t.next_due or dt.datetime.min))
    return tasks


def publish(tasks: list[Task]) -> None:
    due = [t for t in tasks if t.status in ("overdue", "never")]
    try:
        state.publish("maintenance", "WARN" if due else "OK",
                      f"{len(due)} task(s) due" if due else "All up to date",
                      ", ".join(t.title for t in due[:3]),
                      {"tasks": [{"id": t.id, "title": t.title, "every_days": t.every_days, "status": t.status,
                                  "note": t.note, "last": t.last.strftime("%Y-%m-%d %H:%M") if t.last else None}
                                 for t in tasks]})
    except OSError:
        pass
