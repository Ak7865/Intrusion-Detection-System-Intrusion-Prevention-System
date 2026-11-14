"""
IPS Attack Simulator — Main Application Entry Point
====================================================
Wires together the gui/ widgets and the modules/ simulators.

Three-layer architecture:
  gui/          — reusable widget components (config_panel, control_bar, log_panel, counter_bar)
  modules/      — simulation logic (NormalTrafficSimulator, SqlInjectionSimulator, …)
  app.py        — application shell (layout + wiring only)

Builds as a Windows .exe via PyInstaller (simulator.spec).
"""
from __future__ import annotations

import json
import sys
import threading
from pathlib import Path
from typing import Any

# ── Path setup ─────────────────────────────────────────────────────────────────
if getattr(sys, "frozen", False):
    _BASE = Path(sys.executable).parent
else:
    _BASE = Path(__file__).resolve().parent

sys.path.insert(0, str(_BASE))

# ── GUI toolkit detection ───────────────────────────────────────────────────────
try:
    import customtkinter as ctk
    _HAS_CTK = True
except ImportError:
    _HAS_CTK = False

# ── Load config ─────────────────────────────────────────────────────────────────
_CFG_PATH = _BASE / "config" / "simulator_config.json"
try:
    with _CFG_PATH.open(encoding="utf-8") as _f:
        CONFIG: dict[str, Any] = json.load(_f)
except (FileNotFoundError, json.JSONDecodeError):
    CONFIG = {
        "version": "1.0.0",
        "app_name": "IPS Attack Simulator",
        "default_target_ip": "192.168.56.129",
        "default_target_port": 3000,
        "max_duration_seconds": 300,
        "max_rate_per_second": 20,
    }

VERSION  = CONFIG.get("version", "1.0.0")
APP_NAME = CONFIG.get("app_name", "IPS Attack Simulator")

# ── GUI widgets (from gui/ package) ────────────────────────────────────────────
from gui.config_panel import ConfigPanel      # noqa: E402
from gui.control_bar  import ControlBar       # noqa: E402
from gui.counter_bar  import CounterBar       # noqa: E402
from gui.log_panel    import LogPanel         # noqa: E402

# ── Simulation modules ─────────────────────────────────────────────────────────
from modules.simulators import (              # noqa: E402
    BruteForceSimulator,
    DoSSimulator,
    NormalTrafficSimulator,
    SimStats,
    SqlInjectionSimulator,
    is_authorised_target,
    resolve_local_ip,
)


# ── Application shell ──────────────────────────────────────────────────────────

class SimulatorApp:
    """
    Top-level application window.
    Owns the root Tk/CTk window, creates the three GUI sections,
    and coordinates simulation lifecycle.
    """

    def __init__(self) -> None:
        self._stop_event  = threading.Event()
        self._pause_event = threading.Event()
        self._sim_thread: threading.Thread | None = None
        self._stats  = SimStats()
        self._state  = "idle"      # idle | running | paused | stopping | finished

        # ── Root window ────────────────────────────────────────────────────────
        if _HAS_CTK:
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("blue")
            self._root = ctk.CTk()
        else:
            import tkinter as tk
            self._root = tk.Tk()

        self._root.title(f"{APP_NAME} v{VERSION}")
        self._root.geometry("1100x780")
        self._root.minsize(900, 650)

        self._build_layout()
        self._start_background_tasks()

    def run(self) -> None:
        self._root.mainloop()

    # ── Layout ─────────────────────────────────────────────────────────────────

    def _build_layout(self) -> None:
        root = self._root

        if _HAS_CTK:
            root.grid_columnconfigure(0, weight=1)
            root.grid_rowconfigure(3, weight=1)   # log panel expands

            # Header bar
            hdr = ctk.CTkFrame(root, fg_color="#1a1a2e", corner_radius=0)
            hdr.grid(row=0, column=0, sticky="ew")
            ctk.CTkLabel(
                hdr, text=f"⚡  {APP_NAME}",
                font=ctk.CTkFont(size=20, weight="bold"),
                text_color="#00bfff",
            ).pack(side="left", padx=20, pady=12)
            ctk.CTkLabel(
                hdr,
                text=f"v{VERSION}  —  Authorised Lab Use Only",
                font=ctk.CTkFont(size=12), text_color="#888888",
            ).pack(side="left", padx=4)

            # Config panel
            self._config_panel = ConfigPanel(
                root, config=CONFIG, on_mode_change=self._on_mode_change
            )
            self._config_panel.grid(row=1, column=0, sticky="ew", padx=12, pady=(8, 2))

            # Control bar + counter bar in one sub-frame
            mid = ctk.CTkFrame(root, fg_color="transparent")
            mid.grid(row=2, column=0, sticky="ew", padx=12, pady=2)
            self._control_bar = ControlBar(
                mid,
                on_start=self._on_start,
                on_pause=self._on_pause,
                on_stop=self._on_stop,
            )
            self._control_bar.pack(side="left")
            self._counter_bar = CounterBar(mid)
            self._counter_bar.pack(side="left", padx=24)

            # Log panel
            self._log_panel = LogPanel(root)
            self._log_panel.grid(row=3, column=0, sticky="nsew", padx=12, pady=(2, 8))

        else:
            import tkinter as tk

            # Header
            tk.Label(
                root,
                text=f"⚡  {APP_NAME}  v{VERSION}  —  Authorised Lab Use Only",
                bg="#1a1a2e", fg="#00bfff",
                font=("Segoe UI", 13, "bold"), anchor="w", padx=16, pady=8,
            ).pack(fill="x")

            self._config_panel = ConfigPanel(
                root, config=CONFIG, on_mode_change=self._on_mode_change
            )
            self._config_panel.pack(fill="x", padx=8, pady=4)

            mid = tk.Frame(root)
            mid.pack(fill="x", padx=8, pady=2)
            self._control_bar = ControlBar(
                mid,
                on_start=self._on_start,
                on_pause=self._on_pause,
                on_stop=self._on_stop,
            )
            self._control_bar.pack(side="left")
            self._counter_bar = CounterBar(mid)
            self._counter_bar.pack(side="left", padx=20)

            self._log_panel = LogPanel(root)
            self._log_panel.pack(fill="both", expand=True, padx=8, pady=(2, 8))

    def _start_background_tasks(self) -> None:
        """Start periodic counter refresh and log drain, and async IP detection."""
        self._log_panel.start_drain(self._root)
        self._refresh_counters()
        threading.Thread(target=self._detect_source_ip, daemon=True).start()

    # ── Callbacks ──────────────────────────────────────────────────────────────

    def _on_mode_change(self, mode_key: str) -> None:
        pass  # ConfigPanel handles its own description update; hook for future use.

    def _on_start(self) -> None:
        cfg = self._config_panel.get_config()

        # Authorisation check
        if not is_authorised_target(cfg.target_ip):
            self._log_panel.append(
                f"[AUTH] ❌ Target {cfg.target_ip!r} is not an authorised lab address.\n"
                "        Only private IPv4 addresses (192.168.x.x, 10.x.x.x, etc.) are permitted."
            )
            return

        if not (1 <= cfg.target_port <= 65535):
            self._log_panel.append("[AUTH] ❌ Invalid port number.")
            return

        rate     = max(0.05, min(cfg.rate,     float(CONFIG.get("max_rate_per_second", 20))))
        duration = max(1,    min(cfg.duration,  int(CONFIG.get("max_duration_seconds", 300))))
        src_ip   = resolve_local_ip()

        self._log_panel.append("=" * 60)
        self._log_panel.append(f"[AUTH] ✅ Target authorised: {cfg.target_ip}:{cfg.target_port}")
        self._log_panel.append(f"[INFO] Source: {src_ip}  →  Destination: {cfg.target_ip}:{cfg.target_port}")
        self._log_panel.append(f"[INFO] Mode: {cfg.mode_key.upper()}, Rate: {rate}/s, Duration: {duration}s")
        self._log_panel.append("=" * 60)

        self._stats = SimStats()
        self._stop_event.clear()
        self._pause_event.clear()
        self._set_state("running")
        self._config_panel.set_state(running=True)

        sim = self._build_simulator(cfg, rate, duration)
        self._sim_thread = threading.Thread(
            target=self._run_sim, args=(sim,), daemon=True
        )
        self._sim_thread.start()

    def _on_pause(self) -> None:
        if self._state == "running":
            self._pause_event.set()
            self._set_state("paused")
            self._log_panel.append("[CTRL] Paused — click Resume to continue.")
        elif self._state == "paused":
            self._pause_event.clear()
            self._set_state("running")
            self._log_panel.append("[CTRL] Resumed.")

    def _on_stop(self) -> None:
        self._stop_event.set()
        self._pause_event.clear()
        self._set_state("stopping")
        self._log_panel.append("[CTRL] Stop requested — waiting for current request to finish…")

    # ── Simulation lifecycle ────────────────────────────────────────────────────

    def _build_simulator(self, cfg: Any, rate: float, duration: int) -> Any:
        kwargs = dict(
            target_ip=cfg.target_ip,
            target_port=cfg.target_port,
            rate=rate,
            duration=duration,
            log_callback=self._log_panel.append,
            stats=self._stats,
            stop_event=self._stop_event,
            pause_event=self._pause_event,
        )
        if cfg.mode_key == "sqli":
            return SqlInjectionSimulator(**kwargs)
        if cfg.mode_key == "bruteforce":
            return BruteForceSimulator(
                **kwargs,
                max_attempts=min(cfg.bf_max_attempts, 20),
                delay=max(0.5, cfg.bf_delay),
            )
        if cfg.mode_key == "dos":
            return DoSSimulator(**kwargs, workers=2)
        return NormalTrafficSimulator(**kwargs)

    def _run_sim(self, sim: Any) -> None:
        try:
            sim.run()
        except Exception as exc:
            self._log_panel.append(f"[ERROR] Simulation error: {exc}")
        finally:
            self._root.after(0, self._on_sim_finished)

    def _on_sim_finished(self) -> None:
        snap = self._stats.snapshot()
        self._log_panel.append(
            f"[DONE] Finished — Total: {snap['total']}, "
            f"Success: {snap['success']}, Failure: {snap['failure']}"
        )
        self._set_state("finished")
        self._config_panel.set_state(running=False)

    # ── Helpers ─────────────────────────────────────────────────────────────────

    def _set_state(self, state: str) -> None:
        self._state = state
        self._control_bar.set_state(state)

    def _refresh_counters(self) -> None:
        snap = self._stats.snapshot()
        self._counter_bar.update(
            total=snap["total"],
            success=snap["success"],
            failure=snap["failure"],
        )
        self._root.after(500, self._refresh_counters)

    def _detect_source_ip(self) -> None:
        ip = resolve_local_ip()
        self._root.after(0, lambda: self._config_panel.set_source_ip(ip))


# ── Entry point ─────────────────────────────────────────────────────────────────

def main() -> None:
    if not _HAS_CTK:
        try:
            import tkinter as tk
            import tkinter.messagebox as mb
            _r = tk.Tk()
            _r.withdraw()
            mb.showinfo(
                "CustomTkinter not installed",
                "CustomTkinter is not installed.\n"
                "The simulator will run with the standard tkinter UI.\n\n"
                "For the premium dark-theme UI:\n"
                "  pip install customtkinter"
            )
            _r.destroy()
        except Exception:
            pass

    app = SimulatorApp()
    app.run()


if __name__ == "__main__":
    main()
