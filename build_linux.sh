#!/usr/bin/env bash
# Builds SysHealth (desktop app) and SysHealthCLI (command line) into ./dist.
set -euo pipefail
cd "$(dirname "$0")"
if ! python3 -c "import tkinter" 2>/dev/null; then
    echo "Tkinter is missing. Install it first: sudo apt install python3-tk python3-venv"
    exit 1
fi
if [ -z "${VIRTUAL_ENV:-}" ]; then
    [ -d .venv ] || python3 -m venv .venv
    source .venv/bin/activate
fi
python -m pip install -r requirements.txt
python -m PyInstaller --noconfirm --clean --onefile --windowed --icon assets/syshealth.ico --add-data assets:assets --name SysHealth main.py
python -m PyInstaller --noconfirm --clean --onefile --console --icon assets/syshealth.ico --name SysHealthCLI cli.py
cp CHEATSHEET.md dist/
# Checksums for the GitHub release; SysHealth uses them to verify downloaded updates.
(cd dist && sha256sum SysHealth SysHealthCLI > SHA256SUMS-linux.txt)
echo
echo "Build complete: dist/SysHealth, dist/SysHealthCLI and dist/SHA256SUMS-linux.txt"
