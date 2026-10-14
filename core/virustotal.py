"""VirusTotal hash lookup (API v3). Only the SHA-256 hash is sent, never the file."""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

API = "https://www.virustotal.com/api/v3/files/"
GUI = "https://www.virustotal.com/gui/file/"
SIGNUP_URL = "https://www.virustotal.com/gui/join-us"


@dataclass
class VTResult:
    sha256: str
    found: bool
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    name: str = ""
    top_labels: Optional[list[str]] = None

    @property
    def total(self) -> int:
        return self.malicious + self.suspicious + self.harmless + self.undetected

    @property
    def link(self) -> str:
        return GUI + self.sha256

    @property
    def verdict(self) -> str:
        if not self.found:
            return "Unknown to VirusTotal"
        if self.malicious >= 3:
            return "Malicious"
        if self.malicious or self.suspicious:
            return "Suspicious"
        return "Clean"


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def lookup(sha256: str, api_key: str) -> VTResult:
    if not api_key:
        raise RuntimeError("No VirusTotal API key configured. Add a free key on the VirusTotal page.")
    sha256 = sha256.strip().lower()
    req = urllib.request.Request(API + sha256, headers={"x-apikey": api_key, "User-Agent": "SysHealth"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return VTResult(sha256, False)
        if exc.code == 401:
            raise RuntimeError("The VirusTotal API key is invalid.") from exc
        if exc.code == 429:
            raise RuntimeError("VirusTotal rate limit reached (free keys allow 4 lookups per minute). "
                               "Wait a minute and try again.") from exc
        raise RuntimeError(f"VirusTotal returned HTTP {exc.code}.") from exc
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    labels = sorted({r.get("result") for r in attrs.get("last_analysis_results", {}).values()
                     if r.get("category") == "malicious" and r.get("result")})[:5]
    return VTResult(sha256, True, stats.get("malicious", 0), stats.get("suspicious", 0), stats.get("harmless", 0),
                    stats.get("undetected", 0), attrs.get("meaningful_name", ""), labels)
