#!/usr/bin/env python3
"""
========================================================================================
LIVE DEMO - STEP 4: ACM TOPS 2025 TABLE 9 REPRODUCTION & OUTPERFORMANCE
========================================================================================
Directly executes the core algorithm script from:
  Final_Proposed_Solution/04_Paper_Table9_Benchmark/04_evaluate_paper_table9.py
And saves live artifacts into:
  Live_Demonstration/outputs/step4_table9_benchmark/
========================================================================================
"""

import os
import sys
import time
import shutil
import subprocess
import pandas as pd

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(CURRENT_DIR, "outputs", "step4_table9_benchmark")
os.makedirs(OUTPUT_DIR, exist_ok=True)

STEP4_SCRIPT = os.path.abspath(os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "04_Paper_Table9_Benchmark", "04_evaluate_paper_table9.py"))
STEP4_DIR = os.path.dirname(STEP4_SCRIPT)
RESULTS_DIR = os.path.join(STEP4_DIR, "results")

def run_demo():
    print("=" * 85, flush=True)
    print(">>> LIVE DEMO - STEP 4: ACM TOPS TABLE 9 BENCHMARK COMPARISON <<<", flush=True)
    print("Calling Core Algorithm: Final_Proposed_Solution/04_Paper_Table9_Benchmark/04_evaluate_paper_table9.py", flush=True)
    print("=" * 85, flush=True)
    t0 = time.time()

    cmd = [sys.executable, "-u", STEP4_SCRIPT] + sys.argv[1:]
    proc = subprocess.Popen(cmd, cwd=STEP4_DIR, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in proc.stdout:
        print(line, end='', flush=True)
    proc.wait()

    if proc.returncode != 0:
        sys.exit(proc.returncode)

    for item in [
        (os.path.join(RESULTS_DIR, "paper_table9_reproduction_metrics.csv"), "paper_table9_reproduction_metrics.csv"),
        (os.path.join(RESULTS_DIR, "base_paper_vs_our_method_comparison.csv"), "base_paper_vs_our_method_comparison.csv"),
        (os.path.join(RESULTS_DIR, "base_paper_vs_our_method_comparison_table.png"), "base_paper_vs_our_method_comparison_table.png")
    ]:
        src_path, dst_name = item
        if os.path.exists(src_path):
            shutil.copy(src_path, os.path.join(OUTPUT_DIR, dst_name))

    comp_csv = os.path.join(OUTPUT_DIR, "base_paper_vs_our_method_comparison.csv")
    if os.path.exists(comp_csv):
        comp_df = pd.read_csv(comp_csv)
        print("\n" + "-" * 95, flush=True)
        print(f"{'Attack Vector':<32} | {'Base F1':<10} | {'Our F1':<10} | {'F1 Gain':<10} | {'Base Prec':<10} | {'Our Prec':<10}", flush=True)
        print("-" * 95, flush=True)
        for _, r in comp_df.iterrows():
            f1_gain = (r['Our_F1'] - r['Base_F1']) * 100.0
            print(f"{r['Attack_Class']:<32} | {r['Base_F1']:>8.2f}   | {r['Our_F1']:>8.2f}   | {f1_gain:>+7.1f}%   | {r['Base_Precision']:>8.2f}   | {r['Our_Precision']:>8.2f}", flush=True)
        print("-" * 95, flush=True)
        base_avg_f1 = comp_df["Base_F1"].mean()
        our_avg_f1 = comp_df["Our_F1"].mean()
        base_avg_pr = comp_df["Base_Precision"].mean()
        our_avg_pr = comp_df["Our_Precision"].mean()
        print(f"{'MACRO AVERAGE':<32} | {base_avg_f1:>8.2f}   | {our_avg_f1:>8.2f}   | +{(our_avg_f1 - base_avg_f1)*100.0:>6.1f}%   | {base_avg_pr:>8.2f}   | {our_avg_pr:>8.2f}", flush=True)
        print("=" * 95, flush=True)

    print("\n" + "=" * 80, flush=True)
    print("LIVE ARTIFACTS GENERATED IN:", flush=True)
    print(f"  Folder: {OUTPUT_DIR}", flush=True)
    print("  - paper_table9_reproduction_metrics.csv         (Base paper Table 9 metrics)", flush=True)
    print("  - base_paper_vs_our_method_comparison.csv       (Side-by-side comparison table)", flush=True)
    print("  - base_paper_vs_our_method_comparison_table.png (Publication comparison graphic)", flush=True)
    print(f"Execution finished in {time.time() - t0:.2f} seconds.", flush=True)
    print(">>> STEP 4 COMPLETED WITH ZERO ERRORS! <<<", flush=True)
    print("=" * 80, flush=True)

if __name__ == "__main__":
    run_demo()
