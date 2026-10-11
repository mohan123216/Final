#!/usr/bin/env python3
"""
========================================================================================
LIVE DEMONSTRATION RESET SCRIPT
========================================================================================
Wipes all generated demonstration outputs so you can start the viva / panel review
from a completely clean, empty directory and generate outputs live step-by-step.
========================================================================================
"""

import os
import shutil

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUTS_DIR = os.path.join(CURRENT_DIR, "outputs")

SUBDIRS = [
    "step1_data_preprocessing",
    "step2_tier1_model",
    "step3_tier2_zeroday",
    "step4_table9_benchmark",
    "step5_integrity_audit",
    "step6_dashboards"
]

def clean_outputs():
    print("=" * 80)
    print(">>> LIVE DEMONSTRATION: RESETTING OUTPUT DIRECTORIES <<<")
    print("=" * 80)

    if os.path.exists(OUTPUTS_DIR):
        print(f"Purging existing outputs in: {OUTPUTS_DIR}...")
        try:
            shutil.rmtree(OUTPUTS_DIR)
            print("  - Successfully purged previous artifacts.")
        except Exception as e:
            print(f"  - Warning while purging: {e}")

    os.makedirs(OUTPUTS_DIR, exist_ok=True)
    for sub in SUBDIRS:
        sub_path = os.path.join(OUTPUTS_DIR, sub)
        os.makedirs(sub_path, exist_ok=True)
        print(f"  + Prepared clean folder: outputs/{sub}/")

    print("\n>>> All demonstration folders are now 100% EMPTY and READY for live presentation! <<<")
    print("=" * 80)

if __name__ == "__main__":
    clean_outputs()
