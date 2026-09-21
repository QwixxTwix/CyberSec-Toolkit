@echo off
chcp 65001 >nul
cd /d "%~dp0"
title CyberSec Toolkit

echo ============================================================
echo   CyberSec Toolkit
echo ============================================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found in PATH.
    echo Install Python 3.10+ from python.org
    echo Check "Add Python to PATH" during install.
    pause
    exit /b 1
)

if not exist "main.py" (
    echo [ERROR] main.py not found in this folder.
    echo Put start.bat next to main.py.
    pause
    exit /b 1
)

python -c "import rich, requests, dns, yaml, cryptography" >nul 2>nul
if errorlevel 1 (
    echo Dependencies missing. Installing...
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] pip install failed.
        pause
        exit /b 1
    )
) else (
    echo All dependencies OK.
)

echo Starting CyberSec Toolkit...
echo.
python main.py

echo.
echo ============================================================
echo   Finished.
echo ============================================================
pause