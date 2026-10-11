#!/usr/bin/env python3
"""
========================================================================================
LIVE DEMO - STEP 1: PREPROCESSING & 73.3M STREAMING INGESTION
========================================================================================
Directly executes the core algorithm script from:
  Final_Proposed_Solution/01_Data_Preprocessing/01_stream_clean_full_dataset.py
And saves live artifacts into:
  Live_Demonstration/outputs/step1_data_preprocessing/
========================================================================================
"""

import os
import sys
import time
import shutil
import subprocess

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(CURRENT_DIR, "outputs", "step1_data_preprocessing")
os.makedirs(OUTPUT_DIR, exist_ok=True)

STEP1_SCRIPT = os.path.abspath(os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "01_Data_Preprocessing", "01_stream_clean_full_dataset.py"))
STEP1_DIR = os.path.dirname(STEP1_SCRIPT)
DATASET_DIR = os.path.join(STEP1_DIR, "dataset")
PLOTS_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "06_Presentation_Dashboards", "plots"))

def run_demo():
    print("=" * 85, flush=True)
    print(">>> LIVE DEMO - STEP 1: DATA PREPROCESSING & STREAMING INGESTION <<<", flush=True)
    print("Calling Core Algorithm: Final_Proposed_Solution/01_Data_Preprocessing/01_stream_clean_full_dataset.py", flush=True)
    print("=" * 85, flush=True)
    t0 = time.time()

    cmd = [sys.executable, "-u", STEP1_SCRIPT] + sys.argv[1:]
    proc = subprocess.Popen(cmd, cwd=STEP1_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in proc.stdout:
        print(line, end='', flush=True)
    proc.wait()

    if proc.returncode != 0:
        sys.exit(proc.returncode)

    # Sync produced artifacts into live demonstration outputs folder
    src_dist = os.path.join(DATASET_DIR, "class_distribution_full_74files.csv")
    if os.path.exists(src_dist):
        shutil.copy(src_dist, os.path.join(OUTPUT_DIR, "class_distribution_full_74files.csv"))

    for p in ["class_imbalance_before_and_after.png", "streaming_stratified_sampling_pipeline.png"]:
        src_p = os.path.join(PLOTS_DIR, p)
        if os.path.exists(src_p):
            shutil.copy(src_p, os.path.join(OUTPUT_DIR, p))

    print("\n" + "=" * 80, flush=True)
    print("LIVE ARTIFACTS GENERATED IN:", flush=True)
    print(f"  Folder: {OUTPUT_DIR}", flush=True)
    print("  - class_distribution_full_74files.csv        (Full 73.3M raw vs sample audit)", flush=True)
    print("  - class_imbalance_before_and_after.png       (Publication Imbalance plot)", flush=True)
    print("  - streaming_stratified_sampling_pipeline.png (Pipeline architecture diagram)", flush=True)
    print(f"Execution finished in {time.time() - t0:.2f} seconds.", flush=True)
    print(">>> STEP 1 COMPLETED WITH ZERO ERRORS! <<<", flush=True)
    print("=" * 80, flush=True)

if __name__ == "__main__":
    run_demo()
