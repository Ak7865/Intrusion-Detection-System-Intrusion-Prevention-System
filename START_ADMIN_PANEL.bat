@echo off
title IPS Admin Panel (Next.js)
color 0B
echo =====================================================
echo   IPS Admin Panel
echo   Port : 3000
echo   URL  : http://localhost:3000
echo =====================================================
echo.
cd /d "d:\IPS-Lab\Shared\IPS-Project\k-ra3p-ui\k-ra3p-ui"
echo [*] Starting Admin Panel...
echo [*] Open browser at http://localhost:3000
echo [*] Press Ctrl+C to stop.
echo.
npm run dev
pause

