"""Build a standalone Fissure.exe from the Tkinter GUI using PyInstaller.

Usage:
    pip install pyinstaller
    python build_exe.py

Produces dist/Fissure.exe — a single file that needs no Python install on the
target machine. Tkinter ships with CPython, so only httpx is bundled.
"""

from __future__ import annotations

import subprocess
import sys


def main() -> int:
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",              # no console window
        "--name", "Fissure",
        "--collect-all", "httpx",  # ensure httpx + its deps are bundled
        "--collect-all", "httpcore",
        "--collect-all", "customtkinter",  # bundle CustomTkinter themes/assets
        "--add-data", "extension;extension",  # ship the browser extension inside the exe
        "fissure/gui_entry.py",
    ]
    print("Running:", " ".join(cmd))
    return subprocess.call(cmd)


if __name__ == "__main__":
    raise SystemExit(main())
