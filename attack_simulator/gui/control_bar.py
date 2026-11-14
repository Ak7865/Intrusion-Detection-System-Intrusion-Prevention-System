"""
control_bar.py — Start / Pause / Stop button row with status indicator.

Usage:
    from gui.control_bar import ControlBar
    bar = ControlBar(parent, on_start=..., on_pause=..., on_stop=...)
    bar.pack(fill="x")
    bar.set_state("running")   # idle | running | paused | stopping | finished
"""
from __future__ import annotations

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

# State → (status text, colour)
_STATE_MAP = {
    "idle":      ("● IDLE",     "#aaaaaa"),
    "running":   ("● RUNNING",  "#2ecc71"),
    "paused":    ("● PAUSED",   "#f1c40f"),
    "stopping":  ("● STOPPING", "#e74c3c"),
    "finished":  ("● FINISHED", "#7f8c8d"),
}


class ControlBar:
    """
    Row of Start / Pause / Stop buttons + status label.
    Works with customtkinter or plain tkinter/ttk.
    """

    def __init__(
        self,
        parent: Any,
        on_start:  Callable[[], None] | None = None,
        on_pause:  Callable[[], None] | None = None,
        on_stop:   Callable[[], None] | None = None,
    ) -> None:
        self._on_start = on_start
        self._on_pause = on_pause
        self._on_stop  = on_stop

        if _CTK:
            self._build_ctk(parent)
        else:
            self._build_ttk(parent)

        self.set_state("idle")

    # ── Layout helpers ──────────────────────────────────────────────────────────

    def pack(self, **kwargs: Any) -> None:
        self._frame.pack(**kwargs)

    def grid(self, **kwargs: Any) -> None:
        self._frame.grid(**kwargs)

    # ── Public API ──────────────────────────────────────────────────────────────

    def set_state(self, state: str) -> None:
        """
        Update button enabled/disabled states and the status label.
        state: 'idle' | 'running' | 'paused' | 'stopping' | 'finished'
        """
        running = state in ("running", "paused")

        # Button enable/disable
        start_state = "disabled" if running or state == "stopping" else "normal"
        pause_state = "normal"  if running else "disabled"
        stop_state  = "normal"  if running or state == "stopping" else "disabled"

        for btn, s in ((self._start_btn, start_state),
                       (self._pause_btn, pause_state),
                       (self._stop_btn,  stop_state)):
            try:
                btn.configure(state=s)
            except Exception:
                pass

        # Pause button label
        pause_text = "▶ Resume" if state == "paused" else "⏸ Pause"
        try:
            self._pause_btn.configure(text=pause_text)
        except Exception:
            pass

        # Status label
        text, color = _STATE_MAP.get(state, _STATE_MAP["idle"])
        try:
            if _CTK:
                self._status_lbl.configure(text=text, text_color=color)
            else:
                self._status_lbl.configure(text=text, foreground=color)
        except Exception:
            pass

    # ── CTK build ──────────────────────────────────────────────────────────────

    def _build_ctk(self, parent: Any) -> None:
        import customtkinter as ctk

        self._frame = ctk.CTkFrame(parent, fg_color="transparent")

        self._start_btn = ctk.CTkButton(
            self._frame, text="▶ Start",
            fg_color="#1a7a3c", hover_color="#155f2f",
            command=self._on_start, width=110,
        )
        self._start_btn.pack(side="left", padx=4)

        self._pause_btn = ctk.CTkButton(
            self._frame, text="⏸ Pause",
            fg_color="#7a7a1a", hover_color="#5f5f15",
            command=self._on_pause, width=110, state="disabled",
        )
        self._pause_btn.pack(side="left", padx=4)

        self._stop_btn = ctk.CTkButton(
            self._frame, text="⏹ Stop",
            fg_color="#7a1a1a", hover_color="#5f1515",
            command=self._on_stop, width=110, state="disabled",
        )
        self._stop_btn.pack(side="left", padx=4)

        self._status_lbl = ctk.CTkLabel(
            self._frame, text="● IDLE",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#aaaaaa",
        )
        self._status_lbl.pack(side="left", padx=16)

    # ── TTK build ───────────────────────────────────────────────────────────────

    def _build_ttk(self, parent: Any) -> None:
        import tkinter as tk
        import tkinter.ttk as ttk

        self._frame = ttk.Frame(parent)

        self._start_btn = ttk.Button(self._frame, text="▶ Start", command=self._on_start)
        self._start_btn.pack(side="left", padx=4, pady=4)

        self._pause_btn = ttk.Button(self._frame, text="⏸ Pause",
                                     command=self._on_pause, state="disabled")
        self._pause_btn.pack(side="left", padx=4, pady=4)

        self._stop_btn = ttk.Button(self._frame, text="⏹ Stop",
                                    command=self._on_stop, state="disabled")
        self._stop_btn.pack(side="left", padx=4, pady=4)

        self._status_lbl = tk.Label(self._frame, text="● IDLE", fg="#aaaaaa",
                                    font=("Segoe UI", 11, "bold"))
        self._status_lbl.pack(side="left", padx=12)

