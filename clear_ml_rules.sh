#!/usr/bin/env bash
# =============================================================================
# clear_ml_rules.sh — Reset Suricata ML-generated rules for testing/demo
# Run on Node A and Node B before presenting to teacher.
# =============================================================================

echo "[reset] Clearing ML-generated Suricata rules on $(hostname)..."
if [ -f /etc/suricata/rules/ips-ml-generated.rules ]; then
    echo "# Cleared for demo $(date -u)" | sudo tee /etc/suricata/rules/ips-ml-generated.rules > /dev/null
    echo "[reset] /etc/suricata/rules/ips-ml-generated.rules cleared."
fi

# Reload Suricata if running
if command -v suricatasc >/dev/null 2>&1; then
    sudo suricatasc -c reload-rules 2>/dev/null && echo "[reset] Suricata rules reloaded." || true
elif systemctl is-active --quiet suricata; then
    sudo systemctl reload suricata 2>/dev/null || sudo systemctl restart suricata 2>/dev/null
    echo "[reset] Suricata reloaded."
fi

echo "[reset] Done! ML model will now detect attacks fresh without Suricata rule interception."

