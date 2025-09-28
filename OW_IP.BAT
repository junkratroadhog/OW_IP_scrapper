@echo off
:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit
)

:: Run the PowerShell script in the same folder
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0OW_IP_Scrapper.ps1"

pause
