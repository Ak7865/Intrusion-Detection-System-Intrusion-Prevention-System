# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller build spec for IPS Attack Simulator.
Run from the attack_simulator/ directory:
    pyinstaller simulator.spec
Output: dist/IPS_Attack_Simulator.exe
"""

import sys
from pathlib import Path

HERE = Path(SPECPATH)

a = Analysis(
    [str(HERE / "app.py")],
    pathex=[str(HERE)],
    binaries=[],
    datas=[
        (str(HERE / "config" / "simulator_config.json"), "config"),
        (str(HERE / "gui"),   "gui"),
    ],
    hiddenimports=[
        "customtkinter",
        "requests",
        "PIL",
        "PIL.Image",
        "PIL.ImageTk",
        "gui.theme",
        "gui.log_panel",
        "gui.counter_bar",
        "gui.config_panel",
        "gui.control_bar",
        "modules.simulators",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Exclude heavy ML/data-science packages not needed in the simulator
        "numpy", "pandas", "scipy", "sklearn", "xgboost", "joblib",
        "matplotlib", "seaborn", "notebook", "jupyter",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="IPS_Attack_Simulator",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # No console window; set to True for debug builds
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # icon=str(HERE / "build" / "icon.ico"),  # Uncomment and add icon.ico to build/
)

