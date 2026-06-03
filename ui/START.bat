@echo off
title PROMET Web UI
cd /d "%~dp0"

echo.
echo  ╔══════════════════════════════════════╗
echo  ║     PROMET  Android RE  Web UI       ║
echo  ╚══════════════════════════════════════╝
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ and try again.
    pause & exit /b 1
)

:: Install deps if needed
if not exist venv (
    echo [*] Creating virtual environment...
    python -m venv venv
)

call venv\Scripts\activate.bat

echo [*] Installing / checking dependencies...
pip install -q -r requirements.txt

echo.
echo [*] Starting PROMET Web UI on http://localhost:8765
echo [*] Press Ctrl+C to stop.
echo.

:: Open browser after 2 seconds
start /min "" cmd /c "timeout /t 2 /nobreak >nul && start http://localhost:8765"

python app.py

pause
