@echo off
title IPS Lab — Start All Windows Services
color 0E
echo =====================================================
echo   IPS Lab — Starting ALL Windows Services
echo =====================================================
echo.
echo [1/2] Starting IPS Central API Server (port 8765)...
start "IPS API Server" cmd /k "cd /d d:\IPS-Lab\Shared\IPS-Project && .venv\Scripts\python.exe integration\windows_ml_service\server.py"

echo [*] Waiting 12 seconds for ML models to load...
timeout /t 12 /nobreak > nul

echo [2/2] Starting Admin Panel (port 3000)...
start "IPS Admin Panel" cmd /k "cd /d d:\IPS-Lab\Shared\IPS-Project\k-ra3p-ui\k-ra3p-ui && npm run dev"

echo.
echo [*] Waiting 10 seconds for Admin Panel to compile...
timeout /t 10 /nobreak > nul

echo.
echo =====================================================
echo   Both services started!
echo   API Server : http://192.168.56.1:8765/api/health
echo   Admin Panel: http://localhost:3000
echo =====================================================
echo.
echo [*] Opening Admin Panel in browser...
start "" "http://localhost:3000"
echo.
pause

