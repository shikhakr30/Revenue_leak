@echo off
title RevenueLeak AI
cd /d "%~dp0"

echo ========================================
echo        Starting RevenueLeak AI
echo ========================================
echo.

if not exist ".env" (
    copy ".env.example" ".env" >nul
    echo Created .env from .env.example.
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating the Python environment...
    py -m venv .venv
    if errorlevel 1 goto :failed
)

echo Installing or checking requirements...
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto :failed

echo.
echo Open http://127.0.0.1:5000 in Chrome.
echo Keep this window open while using the website.
echo.
".venv\Scripts\python.exe" app.py
goto :end

:failed
echo.
echo Setup could not be completed. Check the message above.

:end
pause
