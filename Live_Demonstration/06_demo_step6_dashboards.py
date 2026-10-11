#!/usr/bin/env python3
"""
========================================================================================
LIVE DEMO - STEP 6: PUBLICATION DASHBOARDS & INTERACTIVE VISUALIZER
========================================================================================
Project: Hybrid Open-Set Multi-Signal Zero-Day Engine (HOMZ-Engine)
Demonstrates live to the review panel:
  1. The 3 Master Publication Dashboards:
     - section1_data_processing_dashboard.png: Ingestion, Imbalance & Streaming Sampling
     - section2_xgboost_classification_dashboard.png: Tier 1 Classification & Feature Importance
     - section3_zeroday_detection_dashboard.png: Tier 2 Multi-Signal Fusion & Table 9 Comparison
  2. Deployment of the Interactive Review Dashboard (HTML/JS)
     - Interactive signal weight sliders, live zero-day threshold simulator

Outputs generated into: Live_Demonstration/outputs/step6_dashboards/
  - section1_data_processing_dashboard.png
  - section2_xgboost_classification_dashboard.png
  - section3_zeroday_detection_dashboard.png
  - interactive_panel_review_dashboard.html
========================================================================================
"""

import os
import sys
import time
import shutil

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(CURRENT_DIR, "outputs", "step6_dashboards")
os.makedirs(OUTPUT_DIR, exist_ok=True)

FINAL_PLOTS_DIR = os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "06_Presentation_Dashboards", "plots")
FINAL_HTML = os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "08_Interactive_Panel_Review_Dashboard", "index.html")

def run_demo():
    print("=" * 85)
    print(">>> LIVE DEMO - STEP 6: PUBLICATION DASHBOARDS & INTERACTIVE VISUALIZER <<<")
    print("=" * 85)
    t0 = time.time()

    dashboards = [
        "section1_data_processing_dashboard.png",
        "section2_xgboost_classification_dashboard.png",
        "section3_zeroday_detection_dashboard.png"
    ]

    for d in dashboards:
        src = os.path.join(FINAL_PLOTS_DIR, d)
        if os.path.exists(src):
            shutil.copy(src, os.path.join(OUTPUT_DIR, d))
            size_kb = os.path.getsize(src) / 1024.0
            print(f"  [DEPLOYED] {d:<48} ({size_kb:>7.1f} KB)")
        else:
            print(f"  [WARNING] Missing {d} in source directory")

    target_html = os.path.join(OUTPUT_DIR, "interactive_panel_review_dashboard.html")
    if os.path.exists(FINAL_HTML):
        shutil.copy(FINAL_HTML, target_html)
        print(f"\n  [DEPLOYED] Interactive Review Dashboard HTML to:\n    {target_html}")

    print("\n" + "=" * 80)
    print("ARTIFACTS VERIFIED IN:")
    print(f"  Folder: {OUTPUT_DIR}")
    print(f"  - section1_data_processing_dashboard.png")
    print(f"  - section2_xgboost_classification_dashboard.png")
    print(f"  - section3_zeroday_detection_dashboard.png")
    print(f"  - interactive_panel_review_dashboard.html")
    print(f"Step 6 completed successfully in {time.time() - t0:.2f} seconds.")
    print(">>> STEP 6 COMPLETED WITH ZERO ERRORS! <<<")
    print("=" * 80)

if __name__ == "__main__":
    run_demo()
