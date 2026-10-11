#!/usr/bin/env python3
"""
========================================================================================
RESET ALL DEMONSTRATION OUTPUTS
========================================================================================
Project: Hybrid Open-Set Multi-Signal Zero-Day Engine (HOMZ-Engine)
Purpose: Wipes all generated files and images from the outputs/ directory so you can
         show your panel an initially empty folder and generate outputs live step-by-step.
========================================================================================
"""

import os
import shutil
import stat
import sys

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

def remove_readonly(func, path, excinfo):
    """Handles read-only file attribute locks on Windows."""
    try:
        os.chmod(path, stat.S_IWRITE)
        func(path)
    except Exception:
        pass

def wipe_folder_contents(target_dir):
    """Deletes all files and subdirectories inside target_dir while keeping target_dir itself."""
    if not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)
        return 0

    deleted_count = 0
    for item in os.listdir(target_dir):
        item_path = os.path.join(target_dir, item)
        try:
            if os.path.isfile(item_path) or os.path.islink(item_path):
                os.chmod(item_path, stat.S_IWRITE)
                os.remove(item_path)
                deleted_count += 1
            elif os.path.isdir(item_path):
                shutil.rmtree(item_path, onerror=remove_readonly)
                deleted_count += 1
        except Exception as e:
            print(f"    [Warning] Could not remove {item}: {e}")

    return deleted_count

def reset_all_outputs():
    print("=" * 80)
    print(">>> HOMZ-ENGINE: WIPING ALL DEMONSTRATION OUTPUTS <<<")
    print("=" * 80)

    total_deleted = 0
    os.makedirs(OUTPUTS_DIR, exist_ok=True)

    for sub in SUBDIRS:
        sub_path = os.path.join(OUTPUTS_DIR, sub)
        num_deleted = wipe_folder_contents(sub_path)
        total_deleted += num_deleted
        remaining = len(os.listdir(sub_path))
        status = "[EMPTY - READY]" if remaining == 0 else f"[{remaining} files locked]"
        print(f"  {status:<18} outputs/{sub}/ (Purged {num_deleted} items)")

    print("-" * 80)
    print(f"Total artifacts wiped: {total_deleted}")
    print(">>> STATUS: ALL OUTPUT FOLDERS ARE NOW 100% EMPTY AND READY FOR LIVE DEMO! <<<")
    print("=" * 80)
    print("\nYou can now execute each step one-by-one to generate outputs live in front of the panel:")
    print("  1. python 01_demo_step1_preprocessing.py")
    print("  2. python 02_demo_step2_tier1_training.py")
    print("  3. python 03_demo_step3_tier2_zeroday.py")
    print("  4. python 04_demo_step4_table9_benchmark.py")
    print("  5. python 05_demo_step5_integrity_audit.py")
    print("  6. python 06_demo_step6_dashboards.py")
    print("=" * 80)

if __name__ == "__main__":
    reset_all_outputs()
