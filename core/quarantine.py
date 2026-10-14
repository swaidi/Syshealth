"""Quarantine: moves files into an AES-encrypted vault so they cannot run, with restore and purge."""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import asdict, dataclass

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .platform_utils import app_data_dir

CHUNK = 1024 * 1024


@dataclass
class QuarantineItem:
    id: str
    original_path: str
    reason: str
    size: int
    sha256: str
    date: str
    nonce: str


class Quarantine:
    def __init__(self) -> None:
        self.dir = app_data_dir("quarantine")
        self.manifest_path = os.path.join(self.dir, "manifest.json")
        self._lock = threading.Lock()
        self._key = self._load_key()

    # ---------------------------------------------------------------- storage
    def _load_key(self) -> bytes:
        path = os.path.join(self.dir, "vault.key")
        if not os.path.exists(path):
            with open(path, "wb") as fh:
                fh.write(os.urandom(32))
        with open(path, "rb") as fh:
            return fh.read()

    def _read_manifest(self) -> list[dict]:
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return []

    def _write_manifest(self, items: list[dict]) -> None:
        tmp = self.manifest_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(items, fh, indent=2, ensure_ascii=False)
        os.replace(tmp, self.manifest_path)

    def _vault_file(self, item_id: str) -> str:
        return os.path.join(self.dir, f"{item_id}.qbin")

    def _crypt(self, src: str, dst: str, nonce: bytes, hasher=None) -> None:
        cipher = Cipher(algorithms.AES(self._key), modes.CTR(nonce))
        ctx = cipher.encryptor()  # CTR mode: encryption and decryption are the same operation
        with open(src, "rb") as fin, open(dst, "wb") as fout:
            while True:
                data = fin.read(CHUNK)
                if not data:
                    break
                if hasher is not None:
                    hasher.update(data)
                fout.write(ctx.update(data))
            fout.write(ctx.finalize())

    # ---------------------------------------------------------------- public API
    def items(self) -> list[QuarantineItem]:
        with self._lock:
            return [QuarantineItem(**d) for d in self._read_manifest()]

    def add(self, path: str, reason: str) -> QuarantineItem:
        item_id = uuid.uuid4().hex
        nonce = os.urandom(16)
        vault = self._vault_file(item_id)
        hasher = hashlib.sha256()
        size = os.path.getsize(path)
        self._crypt(path, vault, nonce, hasher)
        try:
            os.remove(path)
        except OSError as exc:
            os.remove(vault)
            raise OSError(f"Could not remove the original file (it may be in use): {exc}") from exc
        item = QuarantineItem(item_id, os.path.abspath(path), reason, size, hasher.hexdigest(),
                              time.strftime("%Y-%m-%d %H:%M"), nonce.hex())
        with self._lock:
            items = self._read_manifest()
            items.append(asdict(item))
            self._write_manifest(items)
        return item

    def restore(self, item_id: str) -> str:
        with self._lock:
            items = self._read_manifest()
            match = next((d for d in items if d["id"] == item_id), None)
            if match is None:
                raise KeyError(item_id)
            target = match["original_path"]
            base, ext = os.path.splitext(target)
            n = 1
            while os.path.exists(target):
                target = f"{base} (restored {n}){ext}"
                n += 1
            os.makedirs(os.path.dirname(target), exist_ok=True)
            self._crypt(self._vault_file(item_id), target, bytes.fromhex(match["nonce"]))
            os.remove(self._vault_file(item_id))
            self._write_manifest([d for d in items if d["id"] != item_id])
        return target

    def purge(self, item_id: str) -> None:
        with self._lock:
            items = self._read_manifest()
            try:
                os.remove(self._vault_file(item_id))
            except FileNotFoundError:
                pass
            self._write_manifest([d for d in items if d["id"] != item_id])
