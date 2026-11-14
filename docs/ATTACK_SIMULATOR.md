# Attack Simulator Documentation

## Overview

The IPS Attack Simulator is a standalone Windows desktop application that generates
controlled network traffic against an authorised lab target.

**IMPORTANT:** This tool is for authorised lab use only. It enforces private-IP-only
targets and strict rate limits.

## Interface

| Control | Description |
|---|---|
| Target IP | Destination IP (must be a private RFC 1918 address) |
| Port | Destination TCP port |
| Mode | Traffic generation mode (see below) |
| Duration | Maximum simulation duration in seconds (1–300) |
| Rate | Requests per second (0.05–20, mode-capped) |
| Start | Start simulation |
| Pause/Resume | Pause and resume simulation |
| Stop | Stop simulation immediately |
| Total / Success / Failure | Live request counters |
| Source IP | Detected local IP (read-only, informational) |
| Log | Live timestamped log of all requests and events |
| Clear | Clear log display |

## Modes

### Mode 1: Normal Traffic
- Sends HTTP GET requests to common API endpoints
- Endpoints: `/api/Challenges`, `/`, `/api/Products`, `/api/Users`
- Purpose: verify benign traffic is NOT flagged as an attack

### Mode 2: SQL Injection
- Sends GET requests with SQL injection payloads as search query parameters
- Target endpoint: `/api/Challenges?search=<payload>`
- Payloads are harmless test strings (no destructive SQL)
- Purpose: trigger Suricata signature detection (ET rules)

### Mode 3: Brute Force
- Sends POST login attempts with a small credential list
- Target: `/rest/user/login`
- Hard limit: max 20 attempts
- Configurable delay between attempts (minimum 0.5s)
- Stops automatically at limit or on first success
- Purpose: generate authentication failure logs

### Mode 4: DoS / High-Volume
- Sends controlled high-volume HTTP GET requests using a small thread pool
- Max workers: 4
- Max rate: 10 req/s per worker (enforced)
- Purpose: test network load monitoring and ML flow-based detection

## Authorization Check

The simulator validates the target IP before every simulation start.
Only the following address ranges are permitted:
- `192.168.0.0/16` (VirtualBox host-only, typical lab range)
- `10.0.0.0/8`
- `172.16.0.0/12`
- `127.0.0.0/8` (loopback)

Attempts to target public IP addresses will be rejected with an error.

## Building the EXE

```
cd attack_simulator
pip install pyinstaller customtkinter requests pillow
pyinstaller simulator.spec --clean --noconfirm
```

Output: `attack_simulator/dist/IPS_Attack_Simulator.exe`

The EXE is standalone and does not require Python to be installed on the target machine.
The `config/simulator_config.json` is bundled into the EXE.

## Configuration

Edit `attack_simulator/config/simulator_config.json` to adjust defaults:
- `default_target_ip` — pre-filled target IP
- `default_target_port` — pre-filled target port
- `max_duration_seconds` — hard cap on duration
- `max_rate_per_second` — hard cap on rate
- `allowed_targets` — CIDR ranges allowed as targets

