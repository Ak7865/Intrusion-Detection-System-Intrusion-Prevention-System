@echo off
title IPS Central API Server (ML + Suricata)
color 0A
echo =====================================================
echo   IPS Central API Server
echo   Port : 8765
echo   URL  : http://192.168.56.1:8765/api/health
echo =====================================================
echo.
cd /d "d:\IPS-Lab\Shared\IPS-Project"
echo [*] Starting server...
echo [*] Press Ctrl+C to stop.
echo.
.venv\Scripts\python.exe integration\windows_ml_service\server.py
pause

