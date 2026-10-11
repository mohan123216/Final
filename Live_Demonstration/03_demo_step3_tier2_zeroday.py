#!/usr/bin/env python3
"""
========================================================================================
LIVE DEMO - STEP 3: TIER 2 - 4-SIGNAL OPEN-SET ZERO-DAY REJECTION ENGINE
========================================================================================
Directly executes the core algorithm script from:
  Final_Proposed_Solution/03_Tier2_ZeroDay_Detection/03_run_zero_day_engine.py
And saves live artifacts into:
  Live_Demonstration/outputs/step3_tier2_zeroday/
========================================================================================
"""

import os
import sys
import time
import shutil
import subprocess
import pandas as pd

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(CURRENT_DIR, "outputs", "step3_tier2_zeroday")
os.makedirs(OUTPUT_DIR, exist_ok=True)

STEP3_SCRIPT = os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "03_Tier2_ZeroDay_Detection", "03_run_zero_day_engine.py")
STEP3_DIR = os.path.dirname(STEP3_SCRIPT)
RESULTS_DIR = os.path.join(STEP3_DIR, "results")

def run_demo():
    print("=" * 85)
    print(">>> LIVE DEMO - STEP 3: TIER 2 MULTI-SIGNAL ZERO-DAY REJECTION ENGINE <<<")
    print(f"Calling Core Algorithm: Final_Proposed_Solution/03_Tier2_ZeroDay_Detection/03_run_zero_day_engine.py")
    print("=" * 85)
    t0 = time.time()

    # Pass flags (e.g. --dynamic-weights) directly to the core script
    cmd = [sys.executable, "-u", STEP3_SCRIPT] + sys.argv[1:]
    res = subprocess.run(cmd, cwd=STEP3_DIR)
    if res.returncode != 0:
        sys.exit(res.returncode)

    # Sync generated artifacts
    for item in [
        (os.path.join(RESULTS_DIR, "zero_day_detection_standard_metrics.csv"), "zero_day_detection_standard_metrics.csv"),
        (os.path.join(RESULTS_DIR, "zero_day_standard_metrics_table_and_chart.png"), "zero_day_standard_metrics_table_and_chart.png"),
        (os.path.join(RESULTS_DIR, "tier2_sample_test_inputs_rejection_trace.csv"), "tier2_sample_test_inputs_rejection_trace.csv")
    ]:
        src_path, dst_name = item
        if os.path.exists(src_path):
            shutil.copy(src_path, os.path.join(OUTPUT_DIR, dst_name))

    # Print Sample Test Inputs Rejection Trace
    trace_path = os.path.join(OUTPUT_DIR, "tier2_sample_test_inputs_rejection_trace.csv")
    if os.path.exists(trace_path):
        df_trace = pd.read_csv(trace_path)
        print("\n" + "=" * 115)
        print(">>> LIVE SAMPLE TEST INPUTS TRACE: 4-SIGNAL SCORING & REJECTION DECISION <<<")
        print("=" * 115)
        print(f"{'Flow ID':<14} | {'Category':<15} | {'Subclass':<18} | {'Truth Type':<22} | {'S_E':<7} | {'S_M':<7} | {'S_L':<7} | {'S_R':<7} | {'S_comp':<7} | {'tau':<7} | {'Decision':<12}")
        print("-" * 135)
        samples_to_show = pd.concat([
            df_trace[df_trace["Traffic_Subcategory"] == "Normal"].head(3),
            df_trace[df_trace["Traffic_Subcategory"] == "HTTP"].head(2),
            df_trace[df_trace["Traffic_Subcategory"] == "OS_Fingerprint"].head(2),
            df_trace[df_trace["Traffic_Subcategory"] == "Data_Exfiltration"].head(4)
        ])
        for _, r in samples_to_show.iterrows():
            dec_short = "ACCEPTED" if "ACCEPTED" in r['Rejection_Decision'] else "REJECTED [!]"
            print(f"{r['Flow_Sample_ID']:<14} | {r['Traffic_Category']:<15} | {r['Traffic_Subcategory']:<18} | {r['Ground_Truth_Type']:<22} | {r['Signal_1_Free_Energy (Z)']:>6.3f} | {r['Signal_2_Mahalanobis (Z)']:>6.3f} | {r['Signal_3_Leaf_Novelty (Z)']:>6.3f} | {r['Signal_4_Margin_Novelty (Z)']:>6.3f} | {r['Composite_Novelty_Score']:>6.3f} | {r['Threshold_Tau']:>6.3f} | {dec_short:<12}")
        print("-" * 135)
        print(f"Total test input sample traces available in: tier2_sample_test_inputs_rejection_trace.csv ({len(df_trace)} flows)")

    print("\n" + "=" * 80)
    print("LIVE ARTIFACTS GENERATED IN:")
    print(f"  Folder: {OUTPUT_DIR}")
    print(f"  - zero_day_detection_standard_metrics.csv       (Rejection benchmarks for all 10 attacks)")
    print(f"  - zero_day_standard_metrics_table_and_chart.png (Official table & bar chart)")
    print(f"  - tier2_sample_test_inputs_rejection_trace.csv  (Per-sample 4-signal decision trace)")
    print(f"Execution finished in {time.time() - t0:.2f} seconds.")
    print(">>> STEP 3 COMPLETED WITH ZERO ERRORS! <<<")
    print("=" * 80)

if __name__ == "__main__":
    run_demo()
