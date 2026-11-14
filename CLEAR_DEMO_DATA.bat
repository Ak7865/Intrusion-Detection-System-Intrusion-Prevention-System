@echo off
echo ===================================================
echo   IPS Lab - Clear Test Events and ML Rules for Demo
echo ===================================================

echo [1/3] Clearing Hyperledger events and alert caches on Central API...
curl -s -X POST http://127.0.0.1:8765/api/events/clear
echo.

echo [2/3] Clearing ML-generated rules endpoint...
curl -s -X POST http://127.0.0.1:8765/api/rules/clear
echo.

echo [3/3] Truncating local runtime event file...
if exist "runtime\events\hyperledger_events.jsonl" (
    type nul > "runtime\events\hyperledger_events.jsonl"
    echo Truncated runtime\events\hyperledger_events.jsonl
)

echo.
echo ===================================================
echo   CLEAN STATE READY FOR DEMONSTRATION!
echo   Note: On Kali Node A/B, run: bash /mnt/hgfs/IPS-Project/clear_ml_rules.sh
echo ===================================================
pause

