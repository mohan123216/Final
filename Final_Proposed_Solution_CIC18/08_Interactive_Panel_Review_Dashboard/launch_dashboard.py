#!/usr/bin/env python3
"""
========================================================================================
LAUNCHER: INTERACTIVE DEFENSE PANEL REVIEW DASHBOARD
========================================================================================
Project: Hybrid Open-Set Multi-Signal Zero-Day Engine (HOMZ-Engine)
Dataset: CSE-CIC-IDS2018 Benchmark (16,248,642 flows)

Launches an HTTP server and opens the interactive dashboard in your default browser.
========================================================================================
"""

import os
import sys
import webbrowser
import http.server
import socketserver

PORT = 8085
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def main():
    print("=" * 75)
    print(">>> LAUNCHING INTERACTIVE DEFENSE PANEL REVIEW DASHBOARD <<<")
    print(f">>> Dataset: CSE-CIC-IDS2018 (16.2M flows benchmark) <<<")
    print("=" * 75)
    url = f"http://localhost:{PORT}/index.html"
    print(f"\nServing dashboard at: {url}")
    print("Opening in your default browser...")
    webbrowser.open(url)
    print("Press Ctrl+C to terminate the local server.\n")

    try:
        with socketserver.TCPServer(("", PORT), Handler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nServer terminated cleanly.")

if __name__ == "__main__":
    main()
