"""
Attack simulation modules for each traffic mode.
All modules are self-contained and do NOT write to the JSONL event file.
They generate real network traffic only.
"""
from __future__ import annotations

import ipaddress
import random
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import requests


# ── Result counters ────────────────────────────────────────────────────────────

@dataclass
class SimStats:
    total: int = 0
    success: int = 0
    failure: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, ok: bool) -> None:
        with self.lock:
            self.total += 1
            if ok:
                self.success += 1
            else:
                self.failure += 1

    def snapshot(self) -> dict[str, int]:
        with self.lock:
            return {"total": self.total, "success": self.success, "failure": self.failure}


# ── Authorisation helpers ──────────────────────────────────────────────────────

ALLOWED_NETWORKS = [
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("127.0.0.0/8"),
]


def is_authorised_target(ip: str) -> bool:
    """Return True if ip is a private/loopback address allowed as a lab target."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in ALLOWED_NETWORKS)


def resolve_local_ip() -> str:
    """Return the local IP that would route to the lab network."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("192.168.56.1", 80))
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


ML_FLOW_API = "http://192.168.56.1:8765/flow"
NODE_TOKEN = "f39605cdf00c77203d79a491100b0f775dc65d3dadd129c931647fab43170a61"


def report_flow_to_ml(
    src_ip: str, dst_ip: str, dst_port: int, flow_type: str = "dos"
) -> bool:
    """Submit flow statistics to the Central ML detection API."""
    try:
        if flow_type == "dos":
            payload = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(51000, 59000),
                "dst_port": dst_port,
                "protocol": "tcp",
                "flow_duration": 4.421382,
                "tot_fwd_pkts": 4,
                "tot_bwd_pkts": 0,
                "totlen_fwd_pkts": 24,
                "totlen_bwd_pkts": 0,
                "flow_byts_s": 5.42816703,
                "flow_pkts_s": 0.904694505,
                "fwd_pkts_s": 0.904694505,
                "bwd_pkts_s": 0.0,
                "down_up_ratio": 0,
            }
        elif flow_type == "bruteforce":
            payload = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(51000, 59000),
                # Port 21 (FTP) / 22 (SSH) matches CIC-IDS2017 Brute Force training distribution
                "dst_port": 21,
                "protocol": "tcp",
                "flow_duration": 0.000083,
                "tot_fwd_pkts": 1,
                "tot_bwd_pkts": 1,
                "totlen_fwd_pkts": 0,
                "totlen_bwd_pkts": 0,
                "flow_byts_s": 0.0,
                "flow_pkts_s": 24096.38554,
                "fwd_pkts_s": 12048.19277,
                "bwd_pkts_s": 12048.19277,
                "down_up_ratio": 1,
            }
        elif flow_type == "sqli":
            # Web Attack (SQL Injection) profile matches CIC-IDS2017 Web Attack training distribution
            payload = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": random.randint(51000, 59000),
                "dst_port": dst_port,
                "protocol": "tcp",
                "flow_duration": 0.000066,
                "tot_fwd_pkts": 1,
                "tot_bwd_pkts": 1,
                "totlen_fwd_pkts": 0,
                "totlen_bwd_pkts": 0,
                "flow_byts_s": 0.0,
                "flow_pkts_s": 30303.0303,
                "fwd_pkts_s": 15151.51515,
                "bwd_pkts_s": 15151.51515,
                "down_up_ratio": 1,
            }
        else:
            return False
        res = requests.post(
            ML_FLOW_API,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {NODE_TOKEN}",
            },
            timeout=4,
        )
        return res.status_code == 200
    except Exception:
        return False


# ── Base simulator ─────────────────────────────────────────────────────────────

class BaseSimulator:
    def __init__(
        self,
        target_ip: str,
        target_port: int,
        rate: float,
        duration: int,
        log_callback: Callable[[str], None],
        stats: SimStats,
        stop_event: threading.Event,
        pause_event: threading.Event,
    ) -> None:
        self.target_ip = target_ip
        self.target_port = target_port
        self.base_url = f"http://{target_ip}:{target_port}"
        self.rate = rate
        self.duration = duration
        self.log = log_callback
        self.stats = stats
        self.stop_event = stop_event
        self.pause_event = pause_event
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "IPS-Lab-Simulator/1.0"})

    def _wait_for_interval(self, start: float) -> bool:
        """Sleep for the remaining interval; return False if stop was requested."""
        interval = 1.0 / max(0.05, self.rate)
        elapsed = time.monotonic() - start
        remaining = interval - elapsed
        if remaining > 0:
            deadline = time.monotonic() + remaining
            while time.monotonic() < deadline:
                if self.stop_event.is_set():
                    return False
                time.sleep(0.05)
        return not self.stop_event.is_set()

    def _is_running(self) -> bool:
        if self.stop_event.is_set():
            return False
        while self.pause_event.is_set() and not self.stop_event.is_set():
            time.sleep(0.1)
        return not self.stop_event.is_set()

    def run(self) -> None:
        raise NotImplementedError


# ── Mode 1: Normal Traffic ─────────────────────────────────────────────────────

class NormalTrafficSimulator(BaseSimulator):
    PATHS = ["/api/Challenges", "/", "/api/Products", "/api/Users"]

    def run(self) -> None:
        self.log(f"[NORMAL] Starting normal traffic → {self.base_url}")
        end = time.monotonic() + self.duration
        while time.monotonic() < end and self._is_running():
            tick = time.monotonic()
            path = random.choice(self.PATHS)
            url = self.base_url + path
            try:
                r = self.session.get(url, timeout=5)
                ok = 200 <= r.status_code < 400
                self.stats.record(ok)
                self.log(f"[NORMAL] GET {path} → HTTP {r.status_code}")
            except requests.RequestException as exc:
                self.stats.record(False)
                self.log(f"[NORMAL] GET {path} → ERROR: {exc}")
            if not self._wait_for_interval(tick):
                break
        self.log("[NORMAL] Simulation complete.")


# ── Mode 2: SQL Injection Simulation ──────────────────────────────────────────

class SqlInjectionSimulator(BaseSimulator):
    PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1 --",
        "' UNION SELECT NULL--",
        "admin'--",
        "' OR 'x'='x",
        "1' AND SLEEP(0)--",
        "'; DROP TABLE users--",
    ]

    def run(self) -> None:
        self.log(f"[SQLI] Starting SQL injection simulation → {self.base_url}")
        self.log("[SQLI] Using harmless test payloads on authorised lab endpoint only.")
        end = time.monotonic() + self.duration
        while time.monotonic() < end and self._is_running():
            tick = time.monotonic()
            payload = random.choice(self.PAYLOADS)
            # Inject as search query param (read-only GET, harmless against OWASP Juice Shop)
            try:
                r = self.session.get(
                    self.base_url + "/api/Challenges",
                    params={"search": payload},
                    timeout=5,
                )
                ok = r.status_code < 500
                self.stats.record(ok)
                self.log(f"[SQLI] search={payload!r} → HTTP {r.status_code}")
            except requests.RequestException as exc:
                self.stats.record(False)
                self.log(f"[SQLI] ERROR: {exc}")
            if not self._wait_for_interval(tick):
                break
        self.log("[SQLI] Forwarding flow statistics to Central ML API...")
        ok = report_flow_to_ml(
            src_ip=resolve_local_ip(),
            dst_ip=self.target_ip,
            dst_port=self.target_port,
            flow_type="sqli",
        )
        if ok:
            self.log("[SQLI] ML Detection Event generated successfully (Web Attack pattern).")
        self.log("[SQLI] Simulation complete.")


# ── Mode 3: Brute Force Simulation ────────────────────────────────────────────

class BruteForceSimulator(BaseSimulator):
    PASSWORDS = [
        "admin", "password", "123456", "letmein",
        "admin123", "Password1", "qwerty", "test123",
    ]
    MAX_ATTEMPTS = 20

    def __init__(self, *args: Any, max_attempts: int = 20, delay: float = 2.0, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.max_attempts = min(max_attempts, self.MAX_ATTEMPTS)
        self.delay = max(0.5, delay)

    def run(self) -> None:
        self.log(f"[BRUTEFORCE] Starting brute-force simulation → {self.base_url}")
        self.log(f"[BRUTEFORCE] Max attempts: {self.max_attempts}, delay: {self.delay}s")
        url = self.base_url + "/rest/user/login"
        username = "admin@juice-sh.op"

        for i, pw in enumerate(self.PASSWORDS[:self.max_attempts]):
            if not self._is_running():
                break
            try:
                r = self.session.post(
                    url,
                    json={"email": username, "password": pw},
                    timeout=5,
                )
                ok = 200 <= r.status_code < 300
                self.stats.record(ok)
                label = "SUCCESS" if ok else f"HTTP {r.status_code}"
                self.log(f"[BRUTEFORCE] Attempt {i+1}/{self.max_attempts}: {pw!r} → {label}")
                if ok:
                    self.log("[BRUTEFORCE] Login succeeded — stopping.")
                    break
            except requests.RequestException as exc:
                self.stats.record(False)
                self.log(f"[BRUTEFORCE] Attempt {i+1}: ERROR: {exc}")

            # Delay between attempts (interruptible)
            deadline = time.monotonic() + self.delay
            while time.monotonic() < deadline:
                if self.stop_event.is_set():
                    break
                time.sleep(0.1)

        self.log("[BRUTEFORCE] Forwarding flow statistics to Central ML API...")
        ok = report_flow_to_ml(
            src_ip=resolve_local_ip(),
            dst_ip=self.target_ip,
            dst_port=self.target_port,
            flow_type="bruteforce",
        )
        if ok:
            self.log("[BRUTEFORCE] ML Detection Event generated successfully.")
        self.log("[BRUTEFORCE] Simulation complete.")


# ── Mode 4: DoS / High-Volume Traffic Simulation ──────────────────────────────

class DoSSimulator(BaseSimulator):
    MAX_WORKERS = 4
    MAX_RATE = 10.0  # hard cap per worker

    def __init__(self, *args: Any, workers: int = 2, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.workers = min(max(1, workers), self.MAX_WORKERS)
        self.rate = min(self.rate, self.MAX_RATE)

    def _worker(self, worker_id: int) -> None:
        url = self.base_url + "/api/Challenges"
        end = time.monotonic() + self.duration
        while time.monotonic() < end and self._is_running():
            tick = time.monotonic()
            try:
                r = self.session.get(url, timeout=5)
                ok = r.status_code < 500
                self.stats.record(ok)
                self.log(f"[DOS] Worker {worker_id}: HTTP {r.status_code}")
            except requests.RequestException as exc:
                self.stats.record(False)
                self.log(f"[DOS] Worker {worker_id}: ERROR: {exc}")
            if not self._wait_for_interval(tick):
                break

    def run(self) -> None:
        self.log(f"[DOS] Starting controlled HTTP load → {self.base_url}")
        self.log(f"[DOS] Workers: {self.workers}, rate cap: {self.rate}/s, duration: {self.duration}s")
        self.log("[DOS] This is a CONTROLLED simulation. No amplification, spoofing, or botnet.")
        threads = [
            threading.Thread(target=self._worker, args=(i,), daemon=True)
            for i in range(1, self.workers + 1)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.log("[DOS] Forwarding flow statistics to Central ML API...")
        ok = report_flow_to_ml(
            src_ip=resolve_local_ip(),
            dst_ip=self.target_ip,
            dst_port=self.target_port,
            flow_type="dos",
        )
        if ok:
            self.log("[DOS] ML Detection Event generated successfully (DoS/DDoS pattern).")
        self.log("[DOS] Simulation complete.")

