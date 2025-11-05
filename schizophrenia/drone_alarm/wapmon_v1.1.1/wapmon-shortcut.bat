@echo off
setlocal

:: --- Configuration ---
set VENV_PATH=.venv\Scripts\activate
set VENV_PATH_FALLBACK=venv\Scripts\activate
set SCRIPT_NAME=wapmon.py

echo.
echo --- WAP Monitor Setup ---
echo.

:: 1. Check for and activate the virtual environment
if not exist "%VENV_PATH%" (
echo [WARNING] Primary virtual environment path not found: "%VENV_PATH%".
echo Attempting fallback path: "%VENV_PATH_FALLBACK%".

if exist "%VENV_PATH_FALLBACK%" (
    set VENV_PATH=%VENV_PATH_FALLBACK%
    echo Using fallback environment: "%VENV_PATH%".
) else (
    echo [ERROR] Neither primary nor fallback virtual environment found.
    echo Please ensure you have run "python -m venv .venv" or "python -m venv venv".
    goto :end
)

)

echo Activating virtual environment...
call "%VENV_PATH%"

if errorlevel 1 (
echo [ERROR] Failed to activate the virtual environment. Exiting.
goto :end
)

:: 2. Collect arguments
set PARAMS=
set /p LOG_CHOICE="Enable persistent logging to 'wap_monitor.log'? (y/N): "
if /i "%LOG_CHOICE%"=="Y" (
set PARAMS=%PARAMS% --log
echo Logging enabled.
)

set /p ALARM_CHOICE="Enable sound alarms for WAP changes? (y/N): "
if /i "%ALARM_CHOICE%"=="Y" (
set PARAMS=%PARAMS% --alarm
echo Alarms enabled.
)

echo.
echo Launching script with arguments: python %SCRIPT_NAME% %PARAMS%
echo ----------------------------------------------------
echo.

:: 3. Run the script
python %SCRIPT_NAME% %PARAMS%

:end
echo.
echo Press any key to exit the launcher...
pause > nul
endlocal