"""
eve_forwarder.py — Suricata EVE JSON → Central IPS API forwarder.

Environment variables (all optional):
  SURICATA_EVE        Path to Suricata eve.json  (default: /var/log/suricata/eve.json)
  IPS_API_URL         POST endpoint              (default: http://192.168.56.1:8765/suricata)
  IPS_NODE_TOKEN      Raw bearer token (takes priority over file lookup)
  IPS_NODE_TOKEN_FILE Path to plaintext token file
                      (default search order: ~/node-a.token, /etc/ips/node-a.token)
"""
import json, os, time, urllib.request
from pathlib import Path

EVE      = Path(os.environ.get("SURICATA_EVE", "/var/log/suricata/eve.json"))
ENDPOINT = os.environ.get("IPS_API_URL", "http://192.168.56.1:8765/suricata")
RETRY_SECONDS = 2

# --- Token resolution (3 methods, in priority order) ---
def resolve_token() -> str:
    # 1. Direct env-var (most convenient, no file needed)
    direct = os.environ.get("IPS_NODE_TOKEN", "").strip()
    if direct:
        print("[auth] Token loaded from IPS_NODE_TOKEN env var")
        return direct

    # 2. Explicit file path from env-var
    env_file = os.environ.get("IPS_NODE_TOKEN_FILE", "").strip()
    if env_file:
        p = Path(env_file).expanduser()
        if p.is_file():
            tok = p.read_text(encoding="utf-8").strip()
            if tok:
                print(f"[auth] Token loaded from {p}")
                return tok
        raise RuntimeError(f"Token file specified but not readable: {p}")

    # 3. Auto-discover from common locations
    candidates = [
        Path.home() / "node-a.token",          # ~/node-a.token  (no sudo needed)
        Path("/etc/ips/node-a.token"),           # system path (needs chmod 644)
        Path("/mnt/hgfs/IPS-Project/integration/node_a_suricata/.node-a.token"),  # shared folder
    ]
    for p in candidates:
        if p.is_file():
            try:
                tok = p.read_text(encoding="utf-8").strip()
                if tok:
                    print(f"[auth] Token auto-loaded from {p}")
                    return tok
            except PermissionError:
                print(f"[auth] Permission denied reading {p}, trying next…")
                continue

    raise RuntimeError(
        "No node token found. Use one of:\n"
        "  export IPS_NODE_TOKEN=<token>              # pass token directly\n"
        "  export IPS_NODE_TOKEN_FILE=~/node-a.token  # explicit file path\n"
        "  echo <token> > ~/node-a.token              # auto-discovered home file"
    )


def is_api_traffic(event):
    """Filter out events that are just the forwarder talking to the IPS API itself."""
    http = event.get("http") or {}
    if (http.get("hostname") == "192.168.56.1"
            and http.get("http_port") == 8765):
        return True
    return (
        (event.get("dest_ip") == "192.168.56.1" and event.get("dest_port") == 8765)
        or
        (event.get("src_ip") == "192.168.56.1" and event.get("src_port") == 8765)
    )


def is_generic_protocol_decode(event):
    """Filter out generic protocol decode notices that are not security attack signatures."""
    alert = event.get("alert") or {}
    sig = str(alert.get("signature") or "").lower()
    cat = str(alert.get("category") or "").lower()
    return (
        "generic protocol command decode" in sig
        or "generic protocol command decode" in cat
        or "generic protocol" in cat
        or "potential corporate privacy violation" in cat
        or "potential corporate privacy violation" in sig
        or "applayer detect protocol" in sig
        or sig.startswith("et info")
        or sig.startswith("suricata stream")
    )


def post(event, token):
    payload = json.dumps(event).encode()
    req = urllib.request.Request(
        ENDPOINT, data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as response:
        response.read()


def main():
    token = resolve_token()

    print(f"[forwarder] Watching {EVE}")
    print(f"[forwarder] Forwarding alerts → {ENDPOINT}")

    while not EVE.exists():
        print(f"[forwarder] Waiting for {EVE} to appear…")
        time.sleep(RETRY_SECONDS)

    with EVE.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)          # skip existing history; only forward new events
        print("[forwarder] Ready — forwarding new Suricata alert events…")
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            try:
                event = json.loads(line)
                if event.get("event_type") != "alert":
                    continue
                if is_api_traffic(event) or is_generic_protocol_decode(event):
                    continue
                while True:
                    try:
                        post(event, token)
                        sig = event.get("alert", {}).get("signature", "unknown")
                        src = event.get("src_ip", "?")
                        dst = event.get("dest_ip", "?")
                        print(f"[forwarded] {sig}  {src} → {dst}")
                        break
                    except Exception as exc:
                        print(f"[retry] Forward failed: {exc}")
                        time.sleep(RETRY_SECONDS)
            except json.JSONDecodeError:
                continue


if __name__ == "__main__":
    main()
