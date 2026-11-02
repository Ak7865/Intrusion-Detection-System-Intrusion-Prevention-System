#!/usr/bin/env python3
"""Low-rate, controlled HTTP detection demo for the isolated IPS lab."""

from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.request import urlopen
from pathlib import Path
import ipaddress
import json
import subprocess
import uuid

NODES = {
    "A": {"name": "Node A - Kali", "ip": "192.168.56.128"},
    "B": {"name": "Node B - Kali", "ip": "192.168.56.129"},
    "C": {"name": "Node C - Ubuntu", "ip": "192.168.56.130"},
}

TEST_PATHS = {
    "A": "/ips-lab-demo",
    "B": "/ips-lab-demo",
    "C": "/ips-lab-detection-test",
}

LOG_FILE = Path("/mnt/hgfs/IPS-Project/logs/demo-traffic.jsonl")
PORT = 8080


def detect_local_node():
    """Identify this VM using its configured host-only IPv4 address."""
    result = subprocess.run(
        ["ip", "-j", "-4", "addr", "show"],
        capture_output=True,
        text=True,
        check=True,
    )
    interfaces = json.loads(result.stdout)
    local_ips = {
        addr["local"]
        for interface in interfaces
        for addr in interface.get("addr_info", [])
        if addr.get("scope") == "global"
    }

    matches = [
        node_id for node_id, node in NODES.items()
        if node["ip"] in local_ips
    ]

    if len(matches) != 1:
        raise RuntimeError(
            "Could not uniquely identify this VM by its host-only IP. "
            f"Detected IPv4 addresses: {sorted(local_ips)}"
        )

    return matches[0]


def send_test(sender_id, receiver_id):
    sender = NODES[sender_id]
    receiver = NODES[receiver_id]
    url = f"http://{receiver['ip']}:{PORT}{TEST_PATHS[receiver_id]}"
    timestamp = datetime.now().astimezone().isoformat(timespec="microseconds")
    run_id = str(uuid.uuid4())

    result = {
        "run_id": run_id,
        "timestamp": timestamp,
        "sender_id": sender_id,
        "sender": sender["name"],
        "sender_ip": sender["ip"],
        "receiver_id": receiver_id,
        "receiver": receiver["name"],
        "receiver_ip": receiver["ip"],
        "url": url,
        "purpose": "benign HTTP signature detection test",
    }

    try:
        with urlopen(url, timeout=5) as response:
            result["http_status"] = response.status
            result["status"] = "request_sent"
    except HTTPError as exc:
        # HTTP 404 still means the HTTP request reached the server.
        result["http_status"] = exc.code
        result["status"] = "request_sent"
    except (URLError, TimeoutError, OSError) as exc:
        result["status"] = "connection_failed"
        result["error"] = str(exc)

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as log:
        log.write(json.dumps(result) + "\n")

    print(f"\n[{timestamp}] {sender['name']} -> {receiver['name']}")
    print(f"Source IP: {sender['ip']}")
    print(f"Destination: {url}")
    print(f"Result: {result['status']}")
    if "http_status" in result:
        print(f"HTTP status: {result['http_status']}")
    if "error" in result:
        print(f"Error: {result['error']}")
    print(f"Traffic log: {LOG_FILE}")


def main():
    try:
        sender_id = detect_local_node()
    except (RuntimeError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Cannot safely identify this sender VM: {exc}")

    sender = NODES[sender_id]
    receivers = [node_id for node_id in NODES if node_id != sender_id]

    print("=" * 58)
    print(" IPS LAB - CONTROLLED HTTP DETECTION DEMO")
    print("=" * 58)
    print(f"Running on: {sender['name']} ({sender['ip']})")
    print("Sender identity is detected from this VM's host-only IP.")
    print("Each selection sends exactly one HTTP request.")
    print("Only the two other configured lab VMs are allowed.\n")

    for number, receiver_id in enumerate(receivers, start=1):
        print(f"{number}. Send test to {NODES[receiver_id]['name']} "
              f"({NODES[receiver_id]['ip']})")
    print("Q. Quit")

    while True:
        choice = input("\nSelect destination (1-2, Q to quit): ").strip().upper()
        if choice == "Q":
            print("Demo stopped.")
            break
        if choice not in ("1", "2"):
            print("Invalid selection. Choose 1, 2, or Q.")
            continue

        receiver_id = receivers[int(choice) - 1]
        send_test(sender_id, receiver_id)


if __name__ == "__main__":
    main()
