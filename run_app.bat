@echo off
REM Windows launcher for Digital Footprint Analyzer.
REM The virtual environment lives in .venv (see .gitignore).
setlocal
cd /d "%~dp0"
set "VENV=%~dp0.venv"
if not exist "%VENV%\Scripts\python.exe" (
    echo Virtual environment not found at "%VENV%".
    echo Create it with:  python -m venv .venv
    echo Then install requirements:  .venv\Scripts\pip install -r requirements.txt
    pause
    exit /b 1
)
REM pythonw.exe keeps the console window hidden; python.exe shows errors.
start "Digital Footprint Analyzer" "%VENV%\Scripts\pythonw.exe" "%~dp0app\main.py"
endlocal
