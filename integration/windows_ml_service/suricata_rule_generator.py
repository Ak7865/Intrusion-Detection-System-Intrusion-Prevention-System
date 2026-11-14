"""
suricata_rule_generator.py
==========================
Generates Suricata rules from ML-detected attack events.

TEAMMATE INTEGRATION POINT:
  - Call generate_rule() after ML detection
  - Call push_rule_to_suricata() to write rule to Suricata rules file
  - Call reload_suricata() to apply the rule
  - Then submit updated Hyperledger event via blockchain_sync()

This module is a STUB — implement the blockchain_sync function.
"""

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

# Path to the custom IPS-generated Suricata rules file (on each Kali node)
SURICATA_CUSTOM_RULES = Path("/etc/suricata/rules/ips-ml-generated.rules")
SURICATA_RELOAD_SIGNAL = "sudo suricatasc -c reload-rules"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def generate_rule(event: dict) -> str | None:
    """
    Generate a Suricata rule string from an ML detection event.
    Returns None if the event doesn't have enough info to generate a rule.

    Example output:
      alert tcp 192.168.56.129 any -> any 80
        (msg:"IPS ML-Generated: DoS/DDoS from 192.168.56.129";
         flow:to_server; threshold:type threshold,track by_src,count 500,seconds 1;
         classtype:denial-of-service; sid:9000001; rev:1;)
    """
    det = event.get("detection", {})
    net = event.get("network", {})
    attack_type = det.get("attack_type", "Unknown").lower()
    src_ip = net.get("source_ip", "any")
    dst_port = net.get("destination_port", "any")
    proto = (net.get("protocol") or "tcp").lower()
    event_id = event.get("event_id", str(uuid.uuid4()))

    # Assign a stable SID based on event_id hash
    sid = 9000000 + (hash(event_id) % 999999)

    if "dos" in attack_type or "ddos" in attack_type:
        rule = (
            f'alert {proto} {src_ip} any -> any {dst_port} '
            f'(msg:"IPS ML-Generated: DoS/DDoS from {src_ip}"; '
            f'flow:to_server; '
            f'threshold:type threshold,track by_src,count 500,seconds 1; '
            f'classtype:denial-of-service; '
            f'sid:{sid}; rev:1;)'
        )
    elif "brute" in attack_type:
        rule = (
            f'alert {proto} {src_ip} any -> any {dst_port} '
            f'(msg:"IPS ML-Generated: Brute Force from {src_ip}"; '
            f'flow:to_server,established; '
            f'threshold:type threshold,track by_src,count 20,seconds 60; '
            f'classtype:attempted-admin; '
            f'sid:{sid}; rev:1;)'
        )
    elif "botnet" in attack_type:
        rule = (
            f'alert {proto} {src_ip} any -> any any '
            f'(msg:"IPS ML-Generated: Botnet traffic from {src_ip}"; '
            f'classtype:trojan-activity; '
            f'sid:{sid}; rev:1;)'
        )
    elif "web" in attack_type:
        rule = (
            f'alert http {src_ip} any -> any any '
            f'(msg:"IPS ML-Generated: Web Attack from {src_ip}"; '
            f'flow:to_server,established; '
            f'classtype:web-application-attack; '
            f'sid:{sid}; rev:1;)'
        )
    else:
        rule = (
            f'alert {proto} {src_ip} any -> any any '
            f'(msg:"IPS ML-Generated: Attack from {src_ip} ({det.get(\"attack_type\",\"Unknown\")})"; '
            f'classtype:misc-attack; '
            f'sid:{sid}; rev:1;)'
        )

    return rule


def push_rule_to_suricata(rule: str) -> bool:
    """
    Append the generated rule to the custom IPS rules file.
    Returns True on success.

    Call this on the NODE where the ML attack was detected.
    Then call reload_suricata() to apply it.
    """
    try:
        SURICATA_CUSTOM_RULES.parent.mkdir(parents=True, exist_ok=True)
        with SURICATA_CUSTOM_RULES.open("a", encoding="utf-8") as f:
            f.write(f"# Generated at {utcnow()}\n")
            f.write(rule + "\n\n")
        return True
    except Exception as e:
        print(f"[rule_gen] Failed to write rule: {e}")
        return False


def reload_suricata() -> bool:
    """
    Signal Suricata to reload its rules (requires suricatasc installed).
    Call after push_rule_to_suricata().
    """
    import subprocess
    try:
        result = subprocess.run(
            SURICATA_RELOAD_SIGNAL.split(),
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            print("[rule_gen] Suricata rules reloaded successfully")
            return True
        else:
            print(f"[rule_gen] Suricata reload failed: {result.stderr}")
            return False
    except Exception as e:
        print(f"[rule_gen] Could not reload Suricata: {e}")
        return False


# =============================================================================
# BLOCKCHAIN SYNC — TEAMMATE IMPLEMENTS THIS
# =============================================================================

def blockchain_sync(event: dict, suricata_rule: str | None, trigger: str) -> None:
    """
    TEAMMATE INTEGRATION POINT
    ==========================
    Called after every detection event. Implement the Hyperledger Fabric
    synchronization here.

    Parameters:
        event       : The full event dict (already written to hyperledger_events.jsonl)
        suricata_rule: The generated Suricata rule string (only for ML_DETECTED)
        trigger     : "SURICATA_DETECTED" or "ML_DETECTED_NEW_RULE"

    ## SURICATA_DETECTED flow:
        1. Event is already in local hyperledger_events.jsonl  ✅ (done by server.py)
        2. Submit event to Hyperledger Fabric channel
        3. All connected nodes auto-sync their ledger from Fabric
        → No Suricata rule update needed (Suricata already detected it)

    ## ML_DETECTED_NEW_RULE flow:
        1. Event is already in local hyperledger_events.jsonl  ✅ (done by server.py)
        2. suricata_rule is already written to /etc/suricata/rules/ips-ml-generated.rules ✅
        3. Suricata reloaded on THIS node ✅
        4. Submit (event + rule) to Hyperledger Fabric channel
        5. All connected nodes receive the new rule from Fabric
        6. Each node:
            a. Writes rule to their /etc/suricata/rules/ips-ml-generated.rules
            b. Reloads their Suricata
            c. Appends synced event to their hyperledger_events.jsonl
        → Now all nodes can detect this attack via Suricata (not just ML)

    ## Hyperledger Fabric SDK (Python):
        pip install fabric-sdk-py
        from hfc.fabric import Client
        # ... implement channel submission here

    ## Example structure:
    ```python
    from hfc.fabric import Client
    
    async def submit_to_fabric(event, rule=None):
        cli = Client(net_profile="network.json")
        channel = cli.new_channel("ipschannel")
        # Submit chaincode transaction
        response = await cli.chaincode_invoke(
            requestor=cli.get_user("Admin", "Org1"),
            channel_name="ipschannel",
            peers=["peer0.org1.example.com"],
            args=[json.dumps(event), rule or ""],
            cc_name="ips_chaincode",
            cc_version="1.0"
        )
        return response
    ```
    """
    # STUB — replace with real implementation
    print(f"[blockchain] STUB: {trigger} — event {event.get('event_id')} "
          f"(rule={'yes' if suricata_rule else 'no'}) — NOT submitted to Fabric")


# =============================================================================
# MAIN: called from server.py _blockchain_sync_placeholder
# =============================================================================

def handle_ml_detection(event: dict) -> None:
    """
    Full ML detection pipeline:
    1. Generate Suricata rule
    2. Push to local Suricata
    3. Reload Suricata
    4. Sync to blockchain (TEAMMATE implements blockchain_sync)
    """
    rule = generate_rule(event)
    if rule:
        success = push_rule_to_suricata(rule)
        if success:
            reload_suricata()
        blockchain_sync(event, rule, "ML_DETECTED_NEW_RULE")
    else:
        blockchain_sync(event, None, "ML_DETECTED_NEW_RULE")


def handle_suricata_detection(event: dict) -> None:
    """
    Suricata detection pipeline:
    1. No rule update needed (Suricata already has the rule)
    2. Sync event to blockchain (TEAMMATE implements blockchain_sync)
    """
    blockchain_sync(event, None, "SURICATA_DETECTED")

