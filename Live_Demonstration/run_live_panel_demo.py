#!/usr/bin/env python3
"""
========================================================================================
MASTER CONTROLLER: LIVE DEFENSE PANEL DEMONSTRATION
========================================================================================
Project: Hybrid Open-Set Multi-Signal Zero-Day Intrusion Detection Engine (HOMZ-Engine)
Benchmark: UNSW Bot-IoT Dataset (73.3M flows)
Reference: ACM Transactions on Privacy and Security (ACM TOPS, 2025)

Interactive menu for viva examinations, panel reviews, and live defense demonstrations.
Allows executing each step individually or running all steps end-to-end.
Outputs are cleanly generated step-by-step into: Live_Demonstration/outputs/
========================================================================================
"""

import os
import sys
import time
import subprocess

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

STEPS = {
    "1": {
        "title": "STEP 1: Data Preprocessing & Streaming Reservoir Ingestion",
        "script": "01_demo_step1_preprocessing.py",
        "out_dir": "outputs/step1_data_preprocessing"
    },
    "2": {
        "title": "STEP 2: Tier 1 Balanced Cost-Sensitive XGBoost Training",
        "script": "02_demo_step2_tier1_training.py",
        "out_dir": "outputs/step2_tier1_model"
    },
    "3": {
        "title": "STEP 3: Tier 2 4-Signal Open-Set Zero-Day Rejection Engine",
        "script": "03_demo_step3_tier2_zeroday.py",
        "out_dir": "outputs/step3_tier2_zeroday"
    },
    "4": {
        "title": "STEP 4: ACM TOPS 2025 Table 9 Benchmark Reproduction & Outperformance",
        "script": "04_demo_step4_table9_benchmark.py",
        "out_dir": "outputs/step4_table9_benchmark"
    },
    "5": {
        "title": "STEP 5: Rigorous Data Integrity & Zero-Leakage Assertion Audit",
        "script": "05_demo_step5_integrity_audit.py",
        "out_dir": "outputs/step5_integrity_audit"
    },
    "6": {
        "title": "STEP 6: Publication Figures & Interactive Review Dashboard",
        "script": "06_demo_step6_dashboards.py",
        "out_dir": "outputs/step6_dashboards"
    }
}

def print_banner():
    print("\n" + "=" * 82)
    print("      HOMZ-ENGINE: LIVE DEFENSE PANEL DEMONSTRATION CONTROLLER")
    print("   Hybrid Open-Set Multi-Signal Zero-Day Intrusion Detection System")
    print("=" * 82)
    print("  [1] Step 1: Preprocessing, Imputation & Streaming Ingestion")
    print("  [2] Step 2: Tier 1 Balanced XGBoost Classifier Training (Live)")
    print("  [3] Step 3: Tier 2 Multi-Signal Zero-Day Rejection Engine (Live)")
    print("  [4] Step 4: ACM TOPS Table 9 Academic Benchmark Comparison")
    print("  [5] Step 5: Data Integrity & Zero-Leakage Assertion Audit")
    print("  [6] Step 6: Presentation Dashboards & Interactive Visualizer")
    print("  ----------------------------------------------------------------")
    print("  [A] Run All Steps Sequentially (Complete Live Pipeline in ~40s)")
    print("  [C] Reset / Wipe Output Folders (Clean slate for live review)")
    print("  [Q] Exit")
    print("=" * 82)

def run_step(step_key):
    info = STEPS[step_key]
    script_path = os.path.join(CURRENT_DIR, info["script"])
    print(f"\n>>> Executing {info['title']} <<<\n")
    t0 = time.time()
    res = subprocess.run([sys.executable, script_path], cwd=CURRENT_DIR)
    dur = time.time() - t0
    if res.returncode == 0:
        print(f"\n[SUCCESS] {info['title']} completed in {dur:.2f}s!")
        print(f"Generated artifacts saved in: {info['out_dir']}/\n")
    else:
        print(f"\n[ERROR] Step {step_key} failed with exit code {res.returncode}!\n")

def run_all():
    print("\n" + "#" * 82)
    print(">>> RUNNING COMPLETE END-TO-END DEMONSTRATION (STEPS 1 TO 6) <<<")
    print("#" * 82)
    start_total = time.time()
    for k in ["1", "2", "3", "4", "5", "6"]:
        run_step(k)
    print("#" * 82)
    print(f">>> ALL 6 DEMONSTRATION STEPS COMPLETED IN {time.time() - start_total:.2f} SECONDS! <<<")
    print("#" * 82)

def reset_outputs():
    clean_script = os.path.join(CURRENT_DIR, "clean_outputs.py")
    subprocess.run([sys.executable, clean_script], cwd=CURRENT_DIR)

def main():
    if len(sys.argv) > 1:
        arg = sys.argv[1].upper()
        if arg == "--ALL" or arg == "-A":
            run_all()
            return
        elif arg == "--CLEAN" or arg == "-C":
            reset_outputs()
            return
        elif arg in STEPS:
            run_step(arg)
            return

    while True:
        print_banner()
        choice = input("Enter choice [1-6, A, C, Q]: ").strip().upper()
        if choice == "Q":
            print("\nExiting demonstration controller. Good luck with your defense!\n")
            break
        elif choice in STEPS:
            run_step(choice)
        elif choice == "A":
            run_all()
        elif choice == "C":
            reset_outputs()
        else:
            print(f"\nInvalid choice '{choice}'. Please select from 1-6, A, C, or Q.")

if __name__ == "__main__":
    main()
