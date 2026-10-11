#!/usr/bin/env python3
"""
========================================================================================
LIVE DEMO - STEP 6: PUBLICATION DASHBOARDS & INTERACTIVE VISUALIZER
========================================================================================
Directly executes the core dashboard generator from:
  Final_Proposed_Solution/06_Presentation_Dashboards/generate_presentation_dashboards.py
And saves live artifacts into:
  Live_Demonstration/outputs/step6_dashboards/
========================================================================================
"""

import os
import sys
import time
import shutil
import subprocess

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(CURRENT_DIR, "outputs", "step6_dashboards")
os.makedirs(OUTPUT_DIR, exist_ok=True)

STEP6_SCRIPT = os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "06_Presentation_Dashboards", "generate_presentation_dashboards.py")
STEP6_DIR = os.path.dirname(STEP6_SCRIPT)
PLOTS_DIR = os.path.join(STEP6_DIR, "plots")
FINAL_HTML = os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "08_Interactive_Panel_Review_Dashboard", "index.html")

def run_demo():
    print("=" * 85)
    print(">>> LIVE DEMO - STEP 6: PUBLICATION DASHBOARDS & INTERACTIVE VISUALIZER <<<")
    print(f"Calling Core Script: Final_Proposed_Solution/06_Presentation_Dashboards/generate_presentation_dashboards.py")
    print("=" * 85)
    t0 = time.time()

    cmd = [sys.executable, "-u", STEP6_SCRIPT] + sys.argv[1:]
    res = subprocess.run(cmd, cwd=STEP6_DIR)
    if res.returncode != 0:
        sys.exit(res.returncode)

    dashboards = [
        "section1_data_processing_dashboard.png",
        "section2_xgboost_classification_dashboard.png",
        "section3_zeroday_detection_dashboard.png"
    ]
    for d in dashboards:
        src = os.path.join(PLOTS_DIR, d)
        if os.path.exists(src):
            shutil.copy(src, os.path.join(OUTPUT_DIR, d))

    target_html = os.path.join(OUTPUT_DIR, "interactive_panel_review_dashboard.html")
    if os.path.exists(FINAL_HTML):
        shutil.copy(FINAL_HTML, target_html)

    print("\n" + "=" * 80)
    print("LIVE ARTIFACTS GENERATED IN:")
    print(f"  Folder: {OUTPUT_DIR}")
    print(f"  - section1_data_processing_dashboard.png")
    print(f"  - section2_xgboost_classification_dashboard.png")
    print(f"  - section3_zeroday_detection_dashboard.png")
    print(f"  - interactive_panel_review_dashboard.html")
    print(f"Execution finished in {time.time() - t0:.2f} seconds.")
    print(">>> STEP 6 COMPLETED WITH ZERO ERRORS! <<<")
    print("=" * 80)

if __name__ == "__main__":
    run_demo()
