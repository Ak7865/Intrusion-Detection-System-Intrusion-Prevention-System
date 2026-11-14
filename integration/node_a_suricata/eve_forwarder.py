import json, os, time, urllib.request
from pathlib import Path

EVE = Path(os.environ.get("SURICATA_EVE", "/var/log/suricata/eve.json"))
ENDPOINT = os.environ.get("IPS_API_URL", "http://192.168.56.1:8765/suricata")
TOKEN_FILE = Path(os.environ.get("IPS_NODE_TOKEN_FILE", "/etc/ips/node-a.token"))
RETRY_SECONDS = 2

def is_api_traffic(event):
    http = event.get("http") or {}

    # Suricata can report the API response in the reverse
    # direction, where dest_port is an ephemeral client port.
    if (http.get("hostname") == "192.168.56.1"
            and http.get("http_port") == 8765):
        return True

    # Also exclude events matching the API connection tuple.
    return (
        (event.get("dest_ip") == "192.168.56.1"
         and event.get("dest_port") == 8765)
        or
        (event.get("src_ip") == "192.168.56.1"
         and event.get("src_port") == 8765)
    )


def post(event, token):
    payload = json.dumps(event).encode()
    req = urllib.request.Request(ENDPOINT, data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}"
        }, method="POST")
    with urllib.request.urlopen(req, timeout=5) as response:
        response.read()

def main():
    if not TOKEN_FILE.is_file():
        raise RuntimeError(f"Node credential file not found: {TOKEN_FILE}")
    token = TOKEN_FILE.read_text(encoding="utf-8").strip()
    if not token:
        raise RuntimeError("Node credential file is empty")

    print(f"Following {EVE}; forwarding alert events to {ENDPOINT}")
    while not EVE.exists():
        print(f"Waiting for {EVE}")
        time.sleep(RETRY_SECONDS)
    with EVE.open("r", encoding="utf-8", errors="replace") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2)
                continue
            try:
                event = json.loads(line)
                if event.get("event_type") != "alert":
                    continue
                if is_api_traffic(event):
                    continue
                while True:
                    try:
                        post(event, token)
                        print("Forwarded alert:", event.get("alert", {}).get("signature"))
                        break
                    except Exception as exc:
                        print("Forward failed; retrying:", exc)
                        time.sleep(RETRY_SECONDS)
            except json.JSONDecodeError:
                continue

if __name__ == "__main__":
    main()
