@echo off
REM Windows launcher for Digital Footprint Analyzer.
REM The virtual environment lives in backend\venv (see .gitignore), not in a
REM repository-root .venv, so both paths below are anchored there.
setlocal
cd /d "%~dp0"
set "VENV=%~dp0backend\venv"
if not exist "%VENV%\Scripts\python.exe" (
    echo Virtual environment not found at "%VENV%".
    echo Create it with:  python -m venv backend\venv
    echo Then install requirements:  backend\venv\Scripts\pip install -r backend\requirements.txt
    pause
    exit /b 1
)
REM pythonw.exe keeps the console window hidden; python.exe shows errors.
start "Digital Footprint Analyzer" "%VENV%\Scripts\pythonw.exe" "%~dp0app\main.py"
endlocal
