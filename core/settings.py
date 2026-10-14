"""User settings shared by the desktop app and the command line (settings.json in the app data folder)."""
from __future__ import annotations

import json
import os

from .platform_utils import app_data_dir


def _path() -> str:
    return os.path.join(app_data_dir(), "settings.json")


def load() -> dict:
    try:
        with open(_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
            return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save(data: dict) -> None:
    try:
        with open(_path(), "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
    except OSError:
        pass


def get(key: str, default=None):
    return load().get(key, default)


def set_value(key: str, value) -> None:
    data = load()
    data[key] = value
    save(data)
