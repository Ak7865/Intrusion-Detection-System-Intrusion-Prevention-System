"""
theme.py — Colour palette and font constants for the IPS Attack Simulator GUI.

Import from any gui module:
    from gui.theme import COLORS, FONTS, SEVERITY
"""
from __future__ import annotations

# ── Colour palette ──────────────────────────────────────────────────────────────
COLORS: dict[str, str] = {
    # Backgrounds
    "bg_primary":    "#1a1a2e",   # Header / sidebar
    "bg_secondary":  "#16213e",   # Card backgrounds
    "bg_surface":    "#0f3460",   # Elevated surfaces
    "bg_input":      "#1e1e2e",   # Text entry fields

    # Foregrounds
    "fg_primary":    "#e2e2e2",   # Main text
    "fg_muted":      "#aaaaaa",   # Secondary text
    "fg_accent":     "#00bfff",   # Brand accent (deep sky blue)

    # Status / severity
    "status_running":  "#2ecc71",  # Green
    "status_paused":   "#f1c40f",  # Amber
    "status_stopping": "#e74c3c",  # Red
    "status_idle":     "#aaaaaa",  # Grey
    "status_finished": "#7f8c8d",  # Muted grey

    # Buttons
    "btn_start":        "#1a7a3c",
    "btn_start_hover":  "#155f2f",
    "btn_pause":        "#7a7a1a",
    "btn_pause_hover":  "#5f5f15",
    "btn_stop":         "#7a1a1a",
    "btn_stop_hover":   "#5f1515",
    "btn_neutral":      "#2c2c3e",
    "btn_neutral_hover":"#3a3a50",

    # Mode badges
    "mode_normal":    "#1a7a3c",
    "mode_sqli":      "#c0392b",
    "mode_bruteforce":"#e67e22",
    "mode_dos":       "#8e44ad",
}

# ── Font definitions ────────────────────────────────────────────────────────────
# Used as (family, size, weight) tuples for standard tkinter,
# or as CTkFont kwargs for customtkinter.

FONTS: dict[str, dict[str, object]] = {
    "header":    {"family": "Segoe UI", "size": 20, "weight": "bold"},
    "subheader": {"family": "Segoe UI", "size": 14, "weight": "bold"},
    "body":      {"family": "Segoe UI", "size": 11},
    "muted":     {"family": "Segoe UI", "size": 11},
    "mono":      {"family": "Courier New", "size": 11},
    "counter":   {"family": "Segoe UI", "size": 14, "weight": "bold"},
    "status":    {"family": "Segoe UI", "size": 13, "weight": "bold"},
    "label":     {"family": "Segoe UI", "size": 11},
    "badge":     {"family": "Segoe UI", "size": 10, "weight": "bold"},
}

# ── Severity badge colours ──────────────────────────────────────────────────────
SEVERITY: dict[str, str] = {
    "critical": "#e74c3c",
    "high":     "#e67e22",
    "medium":   "#f1c40f",
    "low":      "#2ecc71",
    "info":     "#3498db",
}

# ── Window geometry ─────────────────────────────────────────────────────────────
WINDOW = {
    "width":     1100,
    "height":    780,
    "min_width": 900,
    "min_height": 650,
}

