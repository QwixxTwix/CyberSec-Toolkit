@echo off
cd /d "%~dp0"
title CyberSec Toolkit TUI

echo Opening maximized window for TUI...
echo.

REM Opens a NEW maximized cmd window and runs the app there.
REM Artifacts from mode con are avoided because start /max
REM opens cmd already at full screen size.
start "CyberSec Toolkit TUI" /max cmd /k "chcp 65001 >nul && python main.py --tui & pause"

exit