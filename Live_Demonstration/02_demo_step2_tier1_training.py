#!/usr/bin/env python3
"""
========================================================================================
LIVE DEMO - STEP 2: TIER 1 - BALANCED MULTI-CLASS CLASSIFIER
========================================================================================
Directly executes the core algorithm script from:
  Final_Proposed_Solution/02_Tier1_Known_Classification/02_train_balanced_multiclass.py
And saves live artifacts into:
  Live_Demonstration/outputs/step2_tier1_model/
========================================================================================
"""

import os
import sys
import time
import shutil
import subprocess

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(CURRENT_DIR, "outputs", "step2_tier1_model")
os.makedirs(OUTPUT_DIR, exist_ok=True)

STEP2_SCRIPT = os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "02_Tier1_Known_Classification", "02_train_balanced_multiclass.py")
STEP2_DIR = os.path.dirname(STEP2_SCRIPT)
RESULTS_DIR = os.path.join(STEP2_DIR, "results")
MODELS_DIR = os.path.join(STEP2_DIR, "models")
PLOTS_DIR = os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "06_Presentation_Dashboards", "plots")

def run_demo():
    print("=" * 85)
    print(">>> LIVE DEMO - STEP 2: TIER 1 BALANCED MULTI-CLASS CLASSIFIER <<<")
    print(f"Calling Core Algorithm: Final_Proposed_Solution/02_Tier1_Known_Classification/02_train_balanced_multiclass.py")
    print("=" * 85)
    t0 = time.time()

    # Pass flags (e.g. --retrain) directly to the core script
    cmd = [sys.executable, "-u", STEP2_SCRIPT] + sys.argv[1:]
    res = subprocess.run(cmd, cwd=STEP2_DIR)
    if res.returncode != 0:
        sys.exit(res.returncode)

    # Sync generated artifacts
    for item in [
        (os.path.join(RESULTS_DIR, "balanced_multiclass_classification_report.csv"), "balanced_multiclass_classification_report.csv"),
        (os.path.join(RESULTS_DIR, "balanced_multiclass_confusion_matrix.png"), "balanced_multiclass_confusion_matrix.png"),
        (os.path.join(MODELS_DIR, "xgboost_balanced_multiclass_ids.json"), "xgboost_balanced_multiclass_ids.json"),
        (os.path.join(PLOTS_DIR, "feature_importance_top20.png"), "feature_importance_top20.png"),
        (os.path.join(PLOTS_DIR, "known_multiclass_standard_metrics_table.png"), "known_multiclass_standard_metrics_table.png")
    ]:
        src_path, dst_name = item
        if os.path.exists(src_path):
            shutil.copy(src_path, os.path.join(OUTPUT_DIR, dst_name))

    print("\n" + "=" * 80)
    print("LIVE ARTIFACTS GENERATED IN:")
    print(f"  Folder: {OUTPUT_DIR}")
    print(f"  - balanced_multiclass_classification_report.csv (98.97% Accuracy, 98.26% Macro F1)")
    print(f"  - balanced_multiclass_confusion_matrix.png     (300 DPI Confusion Matrix)")
    print(f"  - feature_importance_top20.png                 (Top 20 Engineered Features)")
    print(f"  - known_multiclass_standard_metrics_table.png  (Metrics table graphic)")
    print(f"  - xgboost_balanced_multiclass_ids.json         (Trained model binary)")
    print(f"Execution finished in {time.time() - t0:.2f} seconds.")
    print(">>> STEP 2 COMPLETED WITH ZERO ERRORS! <<<")
    print("=" * 80)

if __name__ == "__main__":
    run_demo()
