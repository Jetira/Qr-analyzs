@echo off
echo [INFO] Starting QR Threat Analyzer...
echo.

REM Activate virtual environment
if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
) else (
    echo [ERROR] Virtual environment not found! Please run 'python -m venv .venv' first.
    pause
    exit /b 1
)

REM Run the application
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

pause
