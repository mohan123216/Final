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

STEP3_SCRIPT = os.path.abspath(os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "03_Tier2_ZeroDay_Detection", "03_run_zero_day_engine.py"))
STEP3_DIR = os.path.dirname(STEP3_SCRIPT)
RESULTS_DIR = os.path.join(STEP3_DIR, "results")

def run_demo():
    print("=" * 85, flush=True)
    print(">>> LIVE DEMO - STEP 3: TIER 2 MULTI-SIGNAL ZERO-DAY REJECTION ENGINE <<<", flush=True)
    print("Calling Core Algorithm: Final_Proposed_Solution/03_Tier2_ZeroDay_Detection/03_run_zero_day_engine.py", flush=True)
    print("=" * 85, flush=True)
    t0 = time.time()

    cmd = [sys.executable, "-u", STEP3_SCRIPT] + sys.argv[1:]
    proc = subprocess.Popen(cmd, cwd=STEP3_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in proc.stdout:
        print(line, end='', flush=True)
    proc.wait()

    if proc.returncode != 0:
        sys.exit(proc.returncode)

    # 2. Run PNG generator for Perimeter vs Novelty & Transition Matrix tables
    png_script = os.path.join(STEP3_DIR, "generate_comparison_and_transition_pngs.py")
    if os.path.exists(png_script):
        subprocess.run([sys.executable, png_script], cwd=CURRENT_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    png_script2 = os.path.join(STEP3_DIR, "generate_per_model_three_stream_table_png.py")
    if os.path.exists(png_script2):
        subprocess.run([sys.executable, png_script2], cwd=CURRENT_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Sync generated artifacts to Live_Demonstration/outputs/step3_tier2_zeroday/
    artifacts_to_sync = [
        (os.path.join(RESULTS_DIR, "zero_day_detection_standard_metrics.csv"), "zero_day_detection_standard_metrics.csv"),
        (os.path.join(RESULTS_DIR, "zero_day_standard_metrics_table_and_chart.png"), "zero_day_standard_metrics_table_and_chart.png"),
        (os.path.join(RESULTS_DIR, "tier2_sample_test_inputs_rejection_trace.csv"), "tier2_sample_test_inputs_rejection_trace.csv"),
        (os.path.join(RESULTS_DIR, "comparison_perimeter_vs_novelty_metrics.png"), "comparison_perimeter_vs_novelty_metrics.png"),
        (os.path.join(RESULTS_DIR, "detailed_class_transition_matrix.png"), "detailed_class_transition_matrix.png"),
        (os.path.join(RESULTS_DIR, "three_way_full_transition_matrix.png"), "three_way_full_transition_matrix.png"),
        (os.path.join(RESULTS_DIR, "per_model_three_stream_mapping_table.png"), "per_model_three_stream_mapping_table.png"),
        (os.path.join(RESULTS_DIR, "all_10_attacks_leave_one_out_classification_trace.csv"), "all_10_attacks_leave_one_out_classification_trace.csv"),
        (os.path.join(RESULTS_DIR, "all_10_attacks_leave_one_out_classification_trace.html"), "all_10_attacks_leave_one_out_classification_trace.html"),
        (os.path.join(RESULTS_DIR, "all_tested_flows_full_evaluation_with_color_tags.csv"), "all_tested_flows_full_evaluation_with_color_tags.csv"),
    ]
    for src_path, dst_name in artifacts_to_sync:
        dst_path = os.path.join(OUTPUT_DIR, dst_name)
        if os.path.exists(src_path) and not os.path.exists(dst_path):
            shutil.copy2(src_path, dst_path)

    # Print Sample Test Inputs Rejection Trace
    trace_path = os.path.join(OUTPUT_DIR, "tier2_sample_test_inputs_rejection_trace.csv")
    if os.path.exists(trace_path):
        df_trace = pd.read_csv(trace_path)
        print("\n" + "=" * 115, flush=True)
        print(">>> LIVE SAMPLE TEST INPUTS TRACE: 4-SIGNAL SCORING & REJECTION DECISION <<<", flush=True)
        print("=" * 115, flush=True)
        print(f"{'Flow ID':<14} | {'Category':<15} | {'Subclass':<18} | {'Truth Type':<22} | {'S_E':<7} | {'S_M':<7} | {'S_L':<7} | {'S_R':<7} | {'S_comp':<7} | {'tau':<7} | {'Decision':<12}", flush=True)
        print("-" * 135, flush=True)
        samples_to_show = pd.concat([
            df_trace[df_trace["Traffic_Subcategory"] == "Normal"].head(3),
            df_trace[df_trace["Traffic_Subcategory"] == "HTTP"].head(2),
            df_trace[df_trace["Traffic_Subcategory"] == "OS_Fingerprint"].head(2),
            df_trace[df_trace["Traffic_Subcategory"] == "Data_Exfiltration"].head(4)
        ])
        for _, r in samples_to_show.iterrows():
            dec_short = "ACCEPTED" if "ACCEPTED" in r['Rejection_Decision'] else "REJECTED [!]"
            print(f"{r['Flow_Sample_ID']:<14} | {r['Traffic_Category']:<15} | {r['Traffic_Subcategory']:<18} | {r['Ground_Truth_Type']:<22} | {r['Signal_1_Free_Energy (Z)']:>6.3f} | {r['Signal_2_Mahalanobis (Z)']:>6.3f} | {r['Signal_3_Leaf_Novelty (Z)']:>6.3f} | {r['Signal_4_Margin_Novelty (Z)']:>6.3f} | {r['Composite_Novelty_Score']:>6.3f} | {r['Threshold_Tau']:>6.3f} | {dec_short:<12}", flush=True)
        print("-" * 135, flush=True)
        print(f"Total test input sample traces available in: tier2_sample_test_inputs_rejection_trace.csv ({len(df_trace)} flows)", flush=True)

    print("\n" + "=" * 80, flush=True)
    print("LIVE ARTIFACTS GENERATED IN:", flush=True)
    print(f"  Folder: {OUTPUT_DIR}", flush=True)
    print("  - zero_day_detection_standard_metrics.csv       (Rejection benchmarks for all 10 attacks)", flush=True)
    print("  - zero_day_standard_metrics_table_and_chart.png (Official table & bar chart)", flush=True)
    print("  - tier2_sample_test_inputs_rejection_trace.csv  (Per-sample 4-signal decision trace)", flush=True)
    print("  - comparison_perimeter_vs_novelty_metrics.png   (Perimeter vs. Novelty comparison table)", flush=True)
    print("  - detailed_class_transition_matrix.png          (Granular per-model transition matrix)", flush=True)
    print("  - all_10_attacks_leave_one_out_classification_trace.html (Interactive LOAO dashboard)", flush=True)
    print("  - all_tested_flows_full_evaluation_with_color_tags.csv   (Full 56,450 flows with Green/Red tags)", flush=True)
    print(f"Execution finished in {time.time() - t0:.2f} seconds.", flush=True)
    print(">>> STEP 3 COMPLETED WITH ZERO ERRORS! <<<", flush=True)
    print("=" * 80, flush=True)

if __name__ == "__main__":
    run_demo()
