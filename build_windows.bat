@echo off
REM Builds SysHealth.exe (desktop app) and SysHealthCLI.exe (command line) into the dist folder.
REM Run from the project folder with your virtual environment activated, or let this script create one.
cd /d "%~dp0"
if not defined VIRTUAL_ENV (
    if not exist .venv ( python -m venv .venv || goto :error )
    call .venv\Scripts\activate.bat
)
python -m pip install -r requirements.txt || goto :error
python -m PyInstaller --noconfirm --clean --onefile --windowed --icon assets\syshealth.ico --add-data assets:assets --name SysHealth main.py || goto :error
python -m PyInstaller --noconfirm --clean --onefile --console --icon assets\syshealth.ico --name SysHealthCLI cli.py || goto :error
copy /y CHEATSHEET.md dist\ >nul
REM Checksums for the GitHub release; SysHealth uses them to verify downloaded updates.
powershell -NoProfile -Command "Get-FileHash dist\SysHealth.exe, dist\SysHealthCLI.exe -Algorithm SHA256 | ForEach-Object { $_.Hash.ToLower() + '  ' + (Split-Path $_.Path -Leaf) } | Set-Content -Encoding ascii dist\SHA256SUMS-windows.txt" || goto :error
echo.
echo Build complete: dist\SysHealth.exe, dist\SysHealthCLI.exe and dist\SHA256SUMS-windows.txt
goto :eof
:error
echo Build failed.
exit /b 1
