"""
log_panel.py — Thread-safe, scrollable log display widget.

Usage:
    from gui.log_panel import LogPanel
    panel = LogPanel(parent)
    panel.pack(fill="both", expand=True)
    panel.append("[INFO] Something happened")
    panel.clear()
"""
from __future__ import annotations

import queue
import time
from typing import Any

try:
    import customtkinter as ctk
    _CTK = True
except ImportError:
    _CTK = False

try:
    import tkinter as tk
    import tkinter.scrolledtext as scrolledtext
except ImportError:
    tk = None  # type: ignore[assignment]
    scrolledtext = None  # type: ignore[assignment]


class LogPanel:
    """
    A log display panel that works with both customtkinter and standard tkinter.

    Thread-safe: call append() from any thread.
    Draining is performed by polling; call start_drain(root) once after
    the Tk main window is available.
    """

    # Maximum number of log lines to keep in memory before rotating
    MAX_LINES = 2000

    def __init__(self, parent: Any, **kwargs: Any) -> None:
        self._queue: queue.Queue[str] = queue.Queue()
        self._root: Any = None
        self._line_count = 0

        if _CTK:
            self._frame = ctk.CTkFrame(parent, **kwargs)
            self._header = ctk.CTkFrame(self._frame, fg_color="transparent")
            self._header.pack(fill="x", padx=4, pady=(4, 0))
            ctk.CTkLabel(
                self._header, text="Simulation Log",
                font=ctk.CTkFont(size=13, weight="bold")
            ).pack(side="left", padx=8)
            ctk.CTkButton(
                self._header, text="Clear", width=70, height=24,
                command=self.clear
            ).pack(side="right", padx=8)
            self._textbox = ctk.CTkTextbox(
                self._frame,
                font=ctk.CTkFont(family="Courier New", size=11),
            )
            self._textbox.pack(fill="both", expand=True, padx=4, pady=(2, 4))
            self._textbox.configure(state="disabled")
        else:
            assert tk is not None
            self._frame = tk.Frame(parent)
            hdr = tk.Frame(self._frame)
            hdr.pack(fill="x")
            tk.Label(hdr, text="Simulation Log",
                     font=("Segoe UI", 11, "bold")).pack(side="left", padx=4, pady=2)
            tk.Button(hdr, text="Clear", command=self.clear,
                      relief="flat", padx=6).pack(side="right", padx=4)
            assert scrolledtext is not None
            self._textbox = scrolledtext.ScrolledText(
                self._frame,
                font=("Courier New", 10),
                bg="#1e1e1e", fg="#d4d4d4",
                insertbackground="white",
                state="disabled",
            )
            self._textbox.pack(fill="both", expand=True, padx=2, pady=2)

    # ── Layout helpers ──────────────────────────────────────────────────────────

    def pack(self, **kwargs: Any) -> None:
        self._frame.pack(**kwargs)

    def grid(self, **kwargs: Any) -> None:
        self._frame.grid(**kwargs)

    def place(self, **kwargs: Any) -> None:
        self._frame.place(**kwargs)

    # ── Public API ──────────────────────────────────────────────────────────────

    def append(self, message: str) -> None:
        """Thread-safe: queue a log line with a timestamp prefix."""
        ts = time.strftime("%H:%M:%S")
        self._queue.put(f"[{ts}] {message}\n")

    def clear(self) -> None:
        """Clear all log lines (call from main thread)."""
        self._line_count = 0
        try:
            self._textbox.configure(state="normal")
            self._textbox.delete("1.0", "end")
            self._textbox.configure(state="disabled")
        except Exception:
            pass

    def start_drain(self, root: Any) -> None:
        """Begin the periodic queue-drain loop. Must be called from the main thread."""
        self._root = root
        self._drain()

    # ── Private ─────────────────────────────────────────────────────────────────

    def _drain(self) -> None:
        """Drain the queue and append to the textbox, then reschedule."""
        try:
            while True:
                msg = self._queue.get_nowait()
                self._write(msg)
        except queue.Empty:
            pass
        if self._root is not None:
            self._root.after(100, self._drain)

    def _write(self, text: str) -> None:
        try:
            self._textbox.configure(state="normal")
            # Rotate if too many lines
            if self._line_count >= self.MAX_LINES:
                self._textbox.delete("1.0", "500.0")
                self._line_count = max(0, self._line_count - 500)
            self._textbox.insert("end", text)
            self._textbox.see("end")
            self._line_count += text.count("\n")
            self._textbox.configure(state="disabled")
        except Exception:
            pass

