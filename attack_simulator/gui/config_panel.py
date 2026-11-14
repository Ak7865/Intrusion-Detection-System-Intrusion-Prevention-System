"""
config_panel.py — Configuration controls panel for the Attack Simulator.

Encapsulates: target IP/port, mode selector, duration, rate,
source-IP label, brute-force extras, and mode description.

Usage:
    from gui.config_panel import ConfigPanel
    panel = ConfigPanel(parent, on_mode_change=callback)
    panel.grid(row=1, column=0, sticky="ew")
    cfg = panel.get_config()   # → ConfigValues namedtuple
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

try:
    import customtkinter as ctk
    _CTK = True
except ImportError:
    _CTK = False

try:
    import tkinter as tk
    import tkinter.ttk as ttk
except ImportError:
    tk = None   # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]

# ── Default config (overridden by simulator_config.json) ───────────────────────
_DEFAULTS = {
    "default_target_ip": "192.168.56.129",
    "default_target_port": 3000,
    "max_duration_seconds": 300,
    "max_rate_per_second": 20,
}

MODES = [
    ("Normal Traffic",     "normal"),
    ("SQL Injection",      "sqli"),
    ("Brute Force",        "bruteforce"),
    ("DoS / High-Volume",  "dos"),
]

MODE_DESCRIPTIONS: dict[str, str] = {
    "normal": (
        "Generates ordinary HTTP GET requests to the lab application.\n"
        "Purpose: verify benign traffic is NOT flagged as an attack."
    ),
    "sqli": (
        "Sends controlled SQL injection test payloads to the search endpoint.\n"
        "Purpose: test Suricata signature detection and Admin Panel event display."
    ),
    "bruteforce": (
        "Sends a limited set of authentication attempts to the login endpoint.\n"
        "Max 20 attempts. Configurable delay between each attempt."
    ),
    "dos": (
        "Sends controlled high-volume HTTP requests using a small thread pool.\n"
        "Strictly rate-limited. No amplification, spoofing, or uncontrolled traffic."
    ),
}


@dataclass
class ConfigValues:
    target_ip: str
    target_port: int
    mode_key: str
    duration: int
    rate: float
    bf_max_attempts: int
    bf_delay: float


class ConfigPanel:
    """
    Configuration panel widget.  Works with customtkinter or plain tkinter.
    Call get_config() to retrieve current user-entered values.
    """

    def __init__(
        self,
        parent: Any,
        config: dict[str, Any] | None = None,
        on_mode_change: Callable[[str], None] | None = None,
    ) -> None:
        self._cfg = config or _DEFAULTS
        self._on_mode_change = on_mode_change
        self._mode_key = "normal"

        if _CTK:
            self._build_ctk(parent)
        else:
            self._build_ttk(parent)

    # ── Layout helpers ──────────────────────────────────────────────────────────

    def grid(self, **kwargs: Any) -> None:
        self._frame.grid(**kwargs)

    def pack(self, **kwargs: Any) -> None:
        self._frame.pack(**kwargs)

    # ── Public API ──────────────────────────────────────────────────────────────

    def get_config(self) -> ConfigValues:
        """Return the current values from all input fields."""
        try:
            port = int(self._port_var.get())
        except ValueError:
            port = 0
        try:
            duration = int(self._dur_var.get())
        except ValueError:
            duration = 30
        try:
            rate = float(self._rate_var.get())
        except ValueError:
            rate = 1.0
        try:
            bf_max = int(self._bf_attempts_var.get())
        except ValueError:
            bf_max = 10
        try:
            bf_delay = float(self._bf_delay_var.get())
        except ValueError:
            bf_delay = 2.0

        return ConfigValues(
            target_ip=self._ip_var.get().strip(),
            target_port=port,
            mode_key=self._mode_key,
            duration=duration,
            rate=rate,
            bf_max_attempts=bf_max,
            bf_delay=bf_delay,
        )

    def set_source_ip(self, ip: str) -> None:
        """Update the detected source IP label."""
        try:
            self._src_label.configure(text=f"Source IP: {ip}")
        except Exception:
            pass

    def set_state(self, running: bool) -> None:
        """Enable/disable editable controls based on simulation state."""
        editable_state = "disabled" if running else "normal"
        for widget in self._editable_widgets:
            try:
                widget.configure(state=editable_state)
            except Exception:
                pass

    # ── CTK build ──────────────────────────────────────────────────────────────

    def _build_ctk(self, parent: Any) -> None:
        import customtkinter as ctk

        self._frame = ctk.CTkFrame(parent)
        self._frame.grid_columnconfigure((1, 3, 5), weight=1)

        self._ip_var         = ctk.StringVar(value=self._cfg.get("default_target_ip", "192.168.56.129"))
        self._port_var       = ctk.StringVar(value=str(self._cfg.get("default_target_port", 3000)))
        self._mode_var       = ctk.StringVar(value=MODES[0][0])
        self._dur_var        = ctk.StringVar(value="30")
        self._rate_var       = ctk.StringVar(value="1.0")
        self._bf_attempts_var = ctk.StringVar(value="10")
        self._bf_delay_var   = ctk.StringVar(value="2.0")

        # Row 0 — IP / Port / Mode
        ctk.CTkLabel(self._frame, text="Target IP").grid(row=0, column=0, padx=8, pady=4, sticky="w")
        ip_entry = ctk.CTkEntry(self._frame, textvariable=self._ip_var, width=140)
        ip_entry.grid(row=0, column=1, padx=8, pady=4, sticky="ew")

        ctk.CTkLabel(self._frame, text="Port").grid(row=0, column=2, padx=8, pady=4, sticky="w")
        port_entry = ctk.CTkEntry(self._frame, textvariable=self._port_var, width=70)
        port_entry.grid(row=0, column=3, padx=8, pady=4, sticky="ew")

        ctk.CTkLabel(self._frame, text="Mode").grid(row=0, column=4, padx=8, pady=4, sticky="w")
        mode_menu = ctk.CTkOptionMenu(
            self._frame, variable=self._mode_var,
            values=[m[0] for m in MODES],
            command=self._handle_mode_change,
        )
        mode_menu.grid(row=0, column=5, padx=8, pady=4, sticky="ew")

        # Row 1 — Duration / Rate / Source IP
        ctk.CTkLabel(self._frame, text="Duration (s)").grid(row=1, column=0, padx=8, pady=4, sticky="w")
        dur_entry = ctk.CTkEntry(self._frame, textvariable=self._dur_var, width=70)
        dur_entry.grid(row=1, column=1, padx=8, pady=4, sticky="ew")

        ctk.CTkLabel(self._frame, text="Rate (req/s)").grid(row=1, column=2, padx=8, pady=4, sticky="w")
        rate_entry = ctk.CTkEntry(self._frame, textvariable=self._rate_var, width=70)
        rate_entry.grid(row=1, column=3, padx=8, pady=4, sticky="ew")

        self._src_label = ctk.CTkLabel(self._frame, text="Source IP: detecting…", text_color="#aaaaaa")
        self._src_label.grid(row=1, column=4, columnspan=2, padx=8, pady=4, sticky="w")

        # Row 2 — Brute Force extras (hidden by default)
        self._bf_frame = ctk.CTkFrame(self._frame, fg_color="transparent")
        self._bf_frame.grid(row=2, column=0, columnspan=6, sticky="ew")
        ctk.CTkLabel(self._bf_frame, text="Max attempts").pack(side="left", padx=8)
        ctk.CTkEntry(self._bf_frame, textvariable=self._bf_attempts_var, width=60).pack(side="left")
        ctk.CTkLabel(self._bf_frame, text="Delay (s)").pack(side="left", padx=8)
        ctk.CTkEntry(self._bf_frame, textvariable=self._bf_delay_var, width=60).pack(side="left")
        self._bf_frame.grid_remove()

        # Row 3 — Mode description
        self._desc_label = ctk.CTkLabel(
            self._frame, text=MODE_DESCRIPTIONS["normal"],
            font=ctk.CTkFont(size=11), text_color="#aaaaaa",
            wraplength=800, justify="left",
        )
        self._desc_label.grid(row=3, column=0, columnspan=6, padx=8, pady=4, sticky="w")

        self._editable_widgets = [ip_entry, port_entry, mode_menu, dur_entry, rate_entry]

    # ── TTK build ───────────────────────────────────────────────────────────────

    def _build_ttk(self, parent: Any) -> None:
        import tkinter as tk
        import tkinter.ttk as ttk

        self._frame = ttk.LabelFrame(parent, text="Configuration", padding=8)

        self._ip_var          = tk.StringVar(value=self._cfg.get("default_target_ip", "192.168.56.129"))
        self._port_var        = tk.StringVar(value=str(self._cfg.get("default_target_port", 3000)))
        self._mode_var        = tk.StringVar(value=MODES[0][0])
        self._dur_var         = tk.StringVar(value="30")
        self._rate_var        = tk.StringVar(value="1.0")
        self._bf_attempts_var = tk.StringVar(value="10")
        self._bf_delay_var    = tk.StringVar(value="2.0")

        r = 0
        ttk.Label(self._frame, text="Target IP:").grid(row=r, column=0, sticky="w")
        ip_entry = ttk.Entry(self._frame, textvariable=self._ip_var, width=18)
        ip_entry.grid(row=r, column=1, padx=4)
        ttk.Label(self._frame, text="Port:").grid(row=r, column=2, sticky="w", padx=(8, 0))
        port_entry = ttk.Entry(self._frame, textvariable=self._port_var, width=8)
        port_entry.grid(row=r, column=3, padx=4)
        ttk.Label(self._frame, text="Mode:").grid(row=r, column=4, sticky="w", padx=(8, 0))
        mode_menu = ttk.Combobox(
            self._frame, textvariable=self._mode_var,
            values=[m[0] for m in MODES], state="readonly", width=18,
        )
        mode_menu.grid(row=r, column=5, padx=4)
        mode_menu.bind("<<ComboboxSelected>>",
                       lambda _: self._handle_mode_change(self._mode_var.get()))

        r += 1
        ttk.Label(self._frame, text="Duration (s):").grid(row=r, column=0, sticky="w")
        dur_entry = ttk.Entry(self._frame, textvariable=self._dur_var, width=8)
        dur_entry.grid(row=r, column=1, padx=4)
        ttk.Label(self._frame, text="Rate (req/s):").grid(row=r, column=2, sticky="w", padx=(8, 0))
        rate_entry = ttk.Entry(self._frame, textvariable=self._rate_var, width=8)
        rate_entry.grid(row=r, column=3, padx=4)
        self._src_label = ttk.Label(self._frame, text="Source IP: detecting…", foreground="gray")
        self._src_label.grid(row=r, column=4, columnspan=2, padx=8, sticky="w")

        r += 1
        self._bf_frame = ttk.Frame(self._frame)
        self._bf_frame.grid(row=r, column=0, columnspan=6, sticky="ew")
        ttk.Label(self._bf_frame, text="Max attempts:").pack(side="left", padx=4)
        ttk.Entry(self._bf_frame, textvariable=self._bf_attempts_var, width=5).pack(side="left")
        ttk.Label(self._bf_frame, text="Delay (s):").pack(side="left", padx=8)
        ttk.Entry(self._bf_frame, textvariable=self._bf_delay_var, width=5).pack(side="left")
        self._bf_frame.grid_remove()

        r += 1
        self._desc_label = ttk.Label(
            self._frame, text=MODE_DESCRIPTIONS["normal"],
            foreground="gray", wraplength=700, justify="left",
        )
        self._desc_label.grid(row=r, column=0, columnspan=6, sticky="w", pady=4)

        self._editable_widgets = [ip_entry, port_entry, mode_menu, dur_entry, rate_entry]

    # ── Internal ────────────────────────────────────────────────────────────────

    def _handle_mode_change(self, label: str) -> None:
        self._mode_key = dict(MODES).get(label, "normal")
        try:
            self._desc_label.configure(text=MODE_DESCRIPTIONS.get(self._mode_key, ""))
        except Exception:
            pass
        if self._mode_key == "bruteforce":
            try:
                self._bf_frame.grid()
            except Exception:
                pass
        else:
            try:
                self._bf_frame.grid_remove()
            except Exception:
                pass
        if self._on_mode_change:
            self._on_mode_change(self._mode_key)

