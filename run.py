"""Launcher for process managers that run a script file rather than `python -m`
(e.g. pyker, pm2). Runs from the project folder, so config.yaml and the state
file are found wherever the manager starts it from.

    pyker start proxmox-canary /path/to/proxmox-canary/run.py --venv /path/to/proxmox-canary/.venv --auto-restart
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
os.chdir(HERE)
sys.path.insert(0, str(HERE))

from proxmox_canary.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
