"""
counter_bar.py — Live request counter widget (Total / Success / Failure).

Usage:
    from gui.counter_bar import CounterBar
    bar = CounterBar(parent)
    bar.pack(fill="x")
    bar.update(total=10, success=8, failure=2)
"""
from __future__ import annotations

from typing import Any

try:
    import customtkinter as ctk
    _CTK = True
except ImportError:
    _CTK = False

try:
    import tkinter as tk
    import tkinter.ttk as ttk
except ImportError:
    tk = None  # type: ignore[assignment]
    ttk = None  # type: ignore[assignment]


class CounterBar:
    """Displays three counters: Total, Success, Failure."""

    def __init__(self, parent: Any, **kwargs: Any) -> None:
        self._labels: dict[str, Any] = {}

        if _CTK:
            self._frame = ctk.CTkFrame(parent, fg_color="transparent", **kwargs)
            pairs = [
                ("Total",   "fg_primary"),
                ("Success", "#2ecc71"),
                ("Failure", "#e74c3c"),
            ]
            for name, color in pairs:
                ctk.CTkLabel(
                    self._frame, text=f"{name}:",
                    font=ctk.CTkFont(size=11), text_color="#888888"
                ).pack(side="left", padx=(8, 2))
                lbl = ctk.CTkLabel(
                    self._frame, text="0",
                    font=ctk.CTkFont(size=14, weight="bold"),
                    text_color=color if color != "fg_primary" else None
                )
                lbl.pack(side="left", padx=(0, 14))
                self._labels[name.lower()] = lbl
        else:
            assert tk is not None
            self._frame = tk.Frame(parent)
            pairs_tk = [("Total", "white"), ("Success", "#2ecc71"), ("Failure", "#e74c3c")]
            for name, color in pairs_tk:
                tk.Label(self._frame, text=f"{name}:",
                         font=("Segoe UI", 10), fg="#888888",
                         bg=self._frame.cget("bg")).pack(side="left", padx=(6, 2))
                lbl = tk.Label(self._frame, text="0",
                               font=("Segoe UI", 11, "bold"), fg=color,
                               bg=self._frame.cget("bg"))
                lbl.pack(side="left", padx=(0, 12))
                self._labels[name.lower()] = lbl

    def pack(self, **kwargs: Any) -> None:
        self._frame.pack(**kwargs)

    def grid(self, **kwargs: Any) -> None:
        self._frame.grid(**kwargs)

    def update(self, total: int = 0, success: int = 0, failure: int = 0) -> None:
        """Update all three counter labels (call from main thread)."""
        mapping = {"total": total, "success": success, "failure": failure}
        for key, val in mapping.items():
            lbl = self._labels.get(key)
            if lbl is None:
                continue
            try:
                lbl.configure(text=str(val))
            except Exception:
                pass

    def reset(self) -> None:
        """Reset all counters to zero."""
        self.update(0, 0, 0)

