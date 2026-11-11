@echo off
setlocal enabledelayedexpansion

title Digital Footprint Intelligence - Launcher

echo ====================================================================
echo      DIGITAL FOOTPRINT INTELLIGENCE PLATFORM (DFI)
echo      "Discover Your Digital Presence. Understand Your Risks."
echo ====================================================================
echo.

REM 1. Check Python Installation
echo [*] Checking Python installation...
where python >nul 2>&1
if %ERRORLEVEL% equ 0 (
    set "PY_CMD=python"
) else (
    where py >nul 2>&1
    if %ERRORLEVEL% equ 0 (
        set "PY_CMD=py"
    ) else (
        echo [ERROR] Python is not found in your system PATH.
        echo Please install Python 3.10+ from https://www.python.org/
        pause
        exit /b 1
    )
)

%PY_CMD% --version
echo [OK] Python is detected.
echo.

REM 2. Check / Create Virtual Environment
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

if not exist ".venv" (
    echo [*] Creating virtual environment (.venv)...
    "%PY_CMD%" -m venv .venv
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [OK] Virtual environment created.
) else (
    echo [OK] Virtual environment (.venv) already exists.
)
echo.

REM 3. Activate Virtual Environment
echo [*] Activating virtual environment...
if exist ".venv\Scripts\activate.bat" (
    call ".venv\Scripts\activate.bat"
) else (
    echo [ERROR] .venv\Scripts\activate.bat not found.
    pause
    exit /b 1
)
echo [OK] Virtual environment active.
echo.

REM 4. Install / Verify Requirements
echo [*] Installing and verifying dependencies...
python -m pip install -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Encountered notice during pip install. Continuing...
)

REM Ensure cython pyd files are disabled on Windows Python 3.14 if present
if exist ".venv\Lib\site-packages\sqlalchemy\sql\_util_cy.cp314-win_amd64.pyd" (
    powershell -NoProfile -Command "Get-ChildItem -Path '.\.venv\Lib\site-packages\sqlalchemy' -Recurse -Filter '*.pyd' -ErrorAction SilentlyContinue | ForEach-Object { Rename-Item $_.FullName ($_.Name + '.bak') -Force }" >nul 2>&1
)

echo.

REM 5. Check Environment Configuration
if not exist ".env" (
    if exist ".env.example" (
        echo [*] .env not found. Copying from .env.example...
        copy ".env.example" ".env" >nul
        echo [OK] Default .env created.
    )
) else (
    echo [OK] Environment file (.env) exists.
)
echo.

REM 6. Initialize Database and Recommendations
echo [*] Initializing database models and security catalogs...
python -c "from app import create_app; app = create_app(); print('Database initialized successfully.')"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Failed to initialize database.
    pause
    exit /b 1
)
echo.

REM 7. Launch Platform Server
echo ====================================================================
echo  DIGITAL FOOTPRINT INTELLIGENCE IS RUNNING LOCALLY!
echo.
echo  Access the dashboard in your web browser at:
echo  >>>  http://127.0.0.1:5000  <<<
echo.
echo  Press CTRL+C in this terminal window to stop the server.
echo ====================================================================
echo.

python app.py

pause

