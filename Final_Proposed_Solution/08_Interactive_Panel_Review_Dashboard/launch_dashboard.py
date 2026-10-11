#!/usr/bin/env python3
"""
Launcher for HOMZ-Engine Interactive Panel Review Dashboard
Opens the standalone HTML dashboard in your default web browser.
"""

import os
import sys
import webbrowser

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
HTML_PATH = os.path.join(CURRENT_DIR, "index.html")

def main():
    if not os.path.exists(HTML_PATH):
        print(f"Error: {HTML_PATH} does not exist.")
        sys.exit(1)

    print("=" * 80)
    print("LAUNCHING HOMZ-ENGINE INTERACTIVE PANEL REVIEW DASHBOARD")
    print("=" * 80)
    print(f"Dashboard File: file://{HTML_PATH}")
    print("Opening in default browser...")
    webbrowser.open(f"file://{HTML_PATH}")
    print("Dashboard launched successfully! Press Ctrl+C to exit.")

if __name__ == "__main__":
    main()
