#!/usr/bin/env python3
"""
========================================================================================
HOMZ-ENGINE: ROOT LAUNCHER FOR LIVE DEFENSE PANEL DEMONSTRATION
========================================================================================
Project: Hybrid Open-Set Multi-Signal Zero-Day Intrusion Detection Engine (HOMZ-Engine)
Dataset: UNSW Bot-IoT Dataset (73.3M flows)
Reference: ACM Transactions on Privacy and Security (ACM TOPS, 2025)

Enables running `py run_live_panel_demo.py` directly from the project root (c:\\Iot_bot).
Delegates execution to Live_Demonstration/run_live_panel_demo.py.
========================================================================================
"""

import os
import sys
import subprocess

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DEMO_DIR = os.path.join(ROOT_DIR, "Live_Demonstration")
DEMO_SCRIPT = os.path.join(DEMO_DIR, "run_live_panel_demo.py")

def main():
    if not os.path.exists(DEMO_SCRIPT):
        print(f"[ERROR] Demonstration script not found at: {DEMO_SCRIPT}", file=sys.stderr)
        sys.exit(1)

    cmd = [sys.executable, DEMO_SCRIPT] + sys.argv[1:]
    try:
        # Run in Live_Demonstration directory so relative output folders work seamlessly
        res = subprocess.run(cmd, cwd=DEMO_DIR)
        sys.exit(res.returncode)
    except KeyboardInterrupt:
        print("\n\nDemonstration session interrupted by user. Exiting cleanly.")
        sys.exit(0)

if __name__ == "__main__":
    main()
