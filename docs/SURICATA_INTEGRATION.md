# Suricata Integration

## Overview

Suricata provides signature-based intrusion detection on Linux Node A.
Detection events are forwarded to the Central IPS API via the EVE forwarder.

## Configuration

### Suricata EVE Output

Ensure `suricata.yaml` includes EVE JSON output:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - http
        - dns
        - flow
```

### Network Interface

Configure Suricata to listen on the VirtualBox host-only adapter:

```yaml
af-packet:
  - interface: eth1
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

### API Traffic Exclusion

The EVE forwarder automatically filters out events that match the IPS API
connection tuple (192.168.56.1:8765) to avoid forwarding self-generated traffic.

## EVE Forwarder

**File:** `integration/node_a_suricata/eve_forwarder.py`

The forwarder:

1. Waits for `/var/log/suricata/eve.json` to exist
2. Seeks to end of file (skips historical events)
3. Tails the file, reading new lines
4. Filters: only `event_type: "alert"` events
5. Filters: excludes API traffic (192.168.56.1:8765)
6. POSTs each alert to `IPS_API_URL` with Bearer token auth
7. Retries on failure (2s delay, indefinite retry)

### Environment Variables

| Variable              | Default                             | Description          |
| --------------------- | ----------------------------------- | -------------------- |
| `SURICATA_EVE`        | `/var/log/suricata/eve.json`        | EVE log path         |
| `IPS_API_URL`         | `http://192.168.56.1:8765/suricata` | Central API endpoint |
| `IPS_NODE_TOKEN_FILE` | `/etc/ips/node-a.token`             | Node token file path |

### Node Token Setup

```bash
# On Linux Node A:
sudo mkdir -p /etc/ips
# Token must match the hash in IPS_NODE_TOKEN_HASHES (see .env)
echo "your-node-a-token-here" | sudo tee /etc/ips/node-a.token
sudo chmod 600 /etc/ips/node-a.token
```

## Suricata Rules

Suricata uses the Emerging Threats (ET) ruleset.
Rule updates can be managed with `suricata-update`:

```bash
sudo suricata-update
sudo systemctl restart suricata
```

## Common Suricata Alert Categories

| Category                               | Description              |
| -------------------------------------- | ------------------------ |
| A Network Trojan was detected          | Malware/botnet traffic   |
| Attempted Information Leak             | Recon/scanning           |
| Potential Corporate Privacy Violation  | ET INFO alerts           |
| Attempted Administrator Privilege Gain | Privilege escalation     |
| Web Application Attack                 | SQL injection, XSS, etc. |
| Attempted Denial of Service            | DoS/DDoS patterns        |

## Deduplication

The Central API deduplicates Suricata alerts using a 3-minute cache keyed on:

- `node_id`
- `flow_id`
- `signature_id`
- `src_ip`, `dest_ip`, `src_port`, `dest_port`, `protocol`

Bidirectional flow matching is supported.
