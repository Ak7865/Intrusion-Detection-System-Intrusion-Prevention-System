@echo off
REM Build script for IPS Attack Simulator Windows EXE
REM Run from the attack_simulator\ directory

echo ============================================================
echo  IPS Attack Simulator - Windows EXE Build
echo ============================================================
echo.

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Install Python 3.10+ and add to PATH.
    exit /b 1
)

REM Install dependencies
echo Installing dependencies...
pip install customtkinter requests pillow pyinstaller --quiet
if %errorlevel% neq 0 (
    echo WARNING: Some packages may not have installed. Check output above.
)

echo.
echo Building EXE with PyInstaller...
pyinstaller simulator.spec --clean --noconfirm

if %errorlevel% equ 0 (
    echo.
    echo ============================================================
    echo  Build SUCCESS!
    echo  Output: dist\IPS_Attack_Simulator.exe
    echo ============================================================
) else (
    echo.
    echo ============================================================
    echo  Build FAILED. Check output above for errors.
    echo ============================================================
    exit /b 1
)

