@echo off
cd /d "%~dp0"
call "%~dp0.venv\Scripts\activate.bat"
start "Digital Footprint Analyzer" "%~dp0.venv\Scripts\python.exe" "%~dp0app\main.py"
