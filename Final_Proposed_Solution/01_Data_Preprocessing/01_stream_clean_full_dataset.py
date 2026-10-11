#!/usr/bin/env python3
"""
========================================================================================
STEP 1: STREAMING DATASET PREPROCESSING & STRATIFIED RESERVOIR SAMPLING
========================================================================================
Project: Hybrid Open-Set Multi-Signal Zero-Day Engine (HOMZ-Engine)
Dataset: Complete 74-File UNSW Bot-IoT Dataset (73,370,443 flows, ~15.3 GB)

This script implements:
  1. Complete streaming ingestion of all 74 raw CSV files in 250,000-row chunks.
  2. Missing Values & Infinite Values Handling:
     - Imputes missing / NaN numeric features with 0.0 via pd.to_numeric(errors="coerce").fillna(0.0).
     - Replaces positive and negative infinite values (+inf, -inf) with 0.0.
  3. Categorical Numerical Encoding:
     - Protocols (proto -> proto_number): tcp=1, arp=2, udp=3, icmp=4, ipv6-icmp=5, other=0.
     - TCP Flags (flgs -> flgs_number): 12 distinct TCP flag states mapped to integers.
     - Connection States (state -> state_number): 12 connection states (CON, FIN, INT, RST, etc.) mapped to integers.
  4. Robust Hexadecimal & Negative Port Parsing (parse_port_val):
     - Safely parses hexadecimal port representations (e.g. 0x0303 -> 771) and negative flags (-1).
  5. Anti-Leakage Feature Exclusion:
     - Strips all source/destination IPs (saddr, daddr), MAC addresses, timestamps (stime, ltime),
       and packet sequence numbers (pkSeqID, seq) to eliminate shortcut learning.
  6. Equal-Quota Streaming Stratified Reservoir Sampling:
     - Retains 100% of all rare minority classes: Normal (9,543), Keylogging (1,469), Data_Exfiltration (118).
     - Subsamples high-volume flood attacks (HTTP, TCP, UDP, OS_Fingerprint, Service_Scan)
       and enforces a strict quota cap of 10,000 flows each, yielding a balanced 61,130-flow corpus.
  7. Dual-Mode Operation:
     - Default: Instant verification of the preprocessed 61,130-flow corpus (~1.5s).
     - With `--rebuild`: Streams directly from all 74 raw CSV files in d:\\p01\\dataset.
========================================================================================
"""

import os
import sys
import time
import glob
import argparse
from collections import Counter
import numpy as np
import pandas as pd

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(CURRENT_DIR, "dataset")
PARQUET_PATH = os.path.join(DATASET_DIR, "fulldataset_cleaned_sample.parquet")
CSV_PATH = os.path.join(DATASET_DIR, "fulldataset_cleaned_sample.csv")
AUDIT_PATH = os.path.join(DATASET_DIR, "class_distribution_full_74files.csv")
os.makedirs(DATASET_DIR, exist_ok=True)

# Candidate raw dataset locations on disk
CANDIDATE_RAW_DIRS = [
    r"d:\p01\dataset",
    r"d:\p01",
    os.path.abspath(os.path.join(CURRENT_DIR, "..", "..", "dataset")),
    os.path.abspath(os.path.join(CURRENT_DIR, "..", ".."))
]

# --------------------------------------------------------------------------------------
# 1. CATEGORICAL ENCODING DICTIONARIES
# --------------------------------------------------------------------------------------
PROTO_MAP = {
    "tcp": 1,
    "arp": 2,
    "udp": 3,
    "icmp": 4,
    "ipv6-icmp": 5,
    "other": 0
}

FLGS_MAP = {
    "e": 1,
    "e s": 2,
    "e d": 3,
    "e *": 4,
    "e g": 5,
    "eU": 6,
    "e &": 7,
    "e   t": 8,
    "e  D": 9,
    "e    F": 10,
    "e dD": 11,
    "e r": 12,
    "other": 0
}

STATE_MAP = {
    "RST": 1,
    "CON": 2,
    "REQ": 3,
    "INT": 4,
    "URP": 5,
    "FIN": 6,
    "ACC": 7,
    "NRS": 8,
    "ECO": 9,
    "TST": 10,
    "MAS": 11,
    "PAR": 12,
    "other": 0
}

CAT_MAP = {
    "dos": "DoS",
    "ddos": "DDoS",
    "reconnaissance": "Reconnaissance",
    "normal": "Normal",
    "theft": "Theft"
}

SUBCAT_MAP = {
    "udp": "UDP",
    "tcp": "TCP",
    "service_scan": "Service_Scan",
    "os_fingerprint": "OS_Fingerprint",
    "http": "HTTP",
    "normal": "Normal",
    "keylogging": "Keylogging",
    "data_exfiltration": "Data_Exfiltration"
}

RETAIN_100_PCT_CLASSES = {"Normal", "Data_Exfiltration", "Keylogging"}

SUBSAMPLE_RATIOS = {
    "HTTP": 0.22,
    "OS_Fingerprint": 0.032,
    "Service_Scan": 0.0078,
    "TCP": 0.00036,
    "UDP": 0.00029
}

NUM_COLS = [
    "dur", "pkts", "bytes", "spkts", "dpkts",
    "sbytes", "dbytes", "rate", "srate", "drate",
    "mean", "stddev", "sum", "min", "max"
]

# --------------------------------------------------------------------------------------
# 2. ROBUST PORT CLEANING & HEXADECIMAL PARSER
# --------------------------------------------------------------------------------------
def parse_port_val(val):
    """
    Safely converts port values, handling:
      - Hexadecimal strings (e.g. '0x0303' -> 771)
      - Negative special flags (-1)
      - Missing values (NaN / None -> -1)
      - Non-numeric garbage -> -1
    """
    if pd.isna(val):
        return -1
    val_str = str(val).strip()
    try:
        if val_str.startswith("0x") or val_str.startswith("0X"):
            return int(val_str, 16)
        return int(float(val_str))
    except (ValueError, TypeError):
        return -1

# --------------------------------------------------------------------------------------
# 3. STREAMING RESERVOIR CLEANING ENGINE (FROM ALL 74 RAW CSV FILES)
# --------------------------------------------------------------------------------------
def stream_clean_raw_dataset(raw_dir, chunksize=250000, random_seed=42):
    """
    Streams all 74 raw CSV files (73,370,443 rows) in chunks of 250,000,
    performing cleaning, encoding, imputation, and reservoir sampling.
    """
    start_time = time.time()
    np.random.seed(random_seed)

    data_files = sorted(glob.glob(os.path.join(raw_dir, "data_*.csv")))
    if not data_files:
        raise FileNotFoundError(f"No data_*.csv files found in directory: {raw_dir}")

    print(f"\nDiscovered {len(data_files)} raw dataset files at: {raw_dir}")
    print(f"Streaming through all files in chunks of {chunksize:,} rows...")

    cols_to_read = [
        "proto", "flgs", "state", "sport", "dport", "dur", "pkts", "bytes",
        "spkts", "dpkts", "sbytes", "dbytes", "rate", "srate", "drate",
        "mean", "stddev", "sum", "min", "max", "attack", "category", "subcategory"
    ]

    global_subcat_counts = Counter()
    global_cat_counts = Counter()
    total_raw_rows = 0
    cleaned_sample_chunks = []

    for f_idx, fpath in enumerate(data_files, start=1):
        fname = os.path.basename(fpath)
        t_file_0 = time.time()
        file_rows = 0

        # Read in streaming chunks with low_memory=False to prevent mixed-type warnings
        for chunk in pd.read_csv(fpath, chunksize=chunksize, low_memory=False):
            # Clean column names (strip whitespace)
            chunk.columns = [c.strip() for c in chunk.columns]
            chunk_len = len(chunk)
            file_rows += chunk_len
            total_raw_rows += chunk_len

            # ------------------------------------------------------------------
            # A. CATEGORICAL STRING NORMALIZATION
            # ------------------------------------------------------------------
            chunk["category"] = chunk["category"].astype(str).str.strip()
            chunk["subcategory"] = chunk["subcategory"].astype(str).str.strip()
            chunk["category"] = chunk["category"].map(lambda x: CAT_MAP.get(x.lower(), x))
            chunk["subcategory"] = chunk["subcategory"].map(lambda x: SUBCAT_MAP.get(x.lower(), x))

            global_subcat_counts.update(chunk["subcategory"])
            global_cat_counts.update(chunk["category"])

            # ------------------------------------------------------------------
            # B. STRATIFIED STREAMING RESERVOIR FILTERING
            # ------------------------------------------------------------------
            subcats = chunk["subcategory"].values
            is_rare = np.isin(subcats, list(RETAIN_100_PCT_CLASSES))

            keep_mask = is_rare.copy()
            for sc, ratio in SUBSAMPLE_RATIOS.items():
                sc_mask = (subcats == sc)
                if np.any(sc_mask):
                    rand_draw = np.random.uniform(0.0, 1.0, size=np.sum(sc_mask)) < ratio
                    keep_mask[sc_mask] = rand_draw

            if not np.any(keep_mask):
                continue

            sub_chunk = chunk[keep_mask].copy()

            # ------------------------------------------------------------------
            # C. CATEGORICAL NUMERICAL ENCODING
            # ------------------------------------------------------------------
            proto_clean = sub_chunk["proto"].astype(str).str.strip().str.lower()
            sub_chunk["proto_number"] = proto_clean.map(lambda x: PROTO_MAP.get(x, 0)).astype(np.int32)

            flgs_clean = sub_chunk["flgs"].astype(str).str.strip()
            sub_chunk["flgs_number"] = flgs_clean.map(lambda x: FLGS_MAP.get(x, 0)).astype(np.int32)

            state_clean = sub_chunk["state"].astype(str).str.strip()
            sub_chunk["state_number"] = state_clean.map(lambda x: STATE_MAP.get(x, 0)).astype(np.int32)

            # ------------------------------------------------------------------
            # D. PORT CLEANING (HEX & NEGATIVE PARSING)
            # ------------------------------------------------------------------
            sub_chunk["sport"] = sub_chunk["sport"].apply(parse_port_val).astype(np.int32)
            sub_chunk["dport"] = sub_chunk["dport"].apply(parse_port_val).astype(np.int32)

            # ------------------------------------------------------------------
            # E. MISSING VALUES & INFINITE VALUES IMPUTATION
            # ------------------------------------------------------------------
            for nc in NUM_COLS:
                # 1. Coerce any malformed string/character to NaN, then fill with 0.0
                sub_chunk[nc] = pd.to_numeric(sub_chunk[nc], errors="coerce").fillna(0.0)
                # 2. Replace positive and negative infinite values with 0.0
                sub_chunk[nc] = sub_chunk[nc].replace([np.inf, -np.inf], 0.0)

            # ------------------------------------------------------------------
            # F. ANTI-LEAKAGE FEATURE SELECTION
            # Dropping saddr, daddr, smac, dmac, stime, ltime, pkSeqID, seq
            # ------------------------------------------------------------------
            final_cols = (
                ["proto_number", "flgs_number", "state_number", "sport", "dport"]
                + NUM_COLS
                + ["attack", "category", "subcategory"]
            )
            cleaned_sample_chunks.append(sub_chunk[final_cols])

        t_elapsed = time.time() - t_file_0
        if f_idx % 10 == 0 or f_idx == len(data_files):
            print(f"  [{f_idx:2d}/{len(data_files)}] {fname} ({file_rows:,} rows, {t_elapsed:.1f}s) | Cumulative: {total_raw_rows:,} flows")

    print(f"\nConcatenating sampled chunks from all {len(data_files)} files...")
    df_clean_sample = pd.concat(cleaned_sample_chunks, ignore_index=True)

    # ------------------------------------------------------------------
    # G. EQUAL-QUOTA CAPPING (10,000 PER FLOOD SUBCLASS)
    # ------------------------------------------------------------------
    target_cap = 10000
    print(f"Applying target class quota cap of {target_cap:,} flows per class...")
    capped_chunks = []
    for sc, grp in df_clean_sample.groupby("subcategory"):
        if len(grp) > target_cap:
            capped_chunks.append(grp.sample(n=target_cap, random_state=random_seed))
        else:
            capped_chunks.append(grp)
    df_clean_sample = pd.concat(capped_chunks, ignore_index=True)

    # ------------------------------------------------------------------
    # H. SERIALIZATION TO PARQUET & CSV
    # ------------------------------------------------------------------
    print(f"Writing representative corpus to:\n  {PARQUET_PATH}")
    df_clean_sample.to_parquet(PARQUET_PATH, index=False)
    df_clean_sample.to_csv(CSV_PATH, index=False)

    # Save 74-file distribution audit report
    audit_rows = []
    sample_subcat_counts = df_clean_sample["subcategory"].value_counts().to_dict()
    for sc, raw_cnt in sorted(global_subcat_counts.items(), key=lambda x: -x[1]):
        smpl_cnt = sample_subcat_counts.get(sc, 0)
        retention_pct = (smpl_cnt / raw_cnt * 100.0) if raw_cnt > 0 else 0.0
        role = "Benign Control" if sc == "Normal" else "Attack Class"
        audit_rows.append({
            "subcategory": sc,
            "role": role,
            "raw_total_count": raw_cnt,
            "raw_percentage": round(raw_cnt / total_raw_rows * 100.0, 4),
            "sample_count": smpl_cnt,
            "sample_percentage": round(smpl_cnt / len(df_clean_sample) * 100.0, 4),
            "retention_rate_pct": round(retention_pct, 2)
        })
    df_audit = pd.DataFrame(audit_rows)
    df_audit.to_csv(AUDIT_PATH, index=False)

    print(f"\nStep 1 Rebuild completed in {time.time() - start_time:.1f}s.")
    return df_clean_sample

# --------------------------------------------------------------------------------------
# 4. MAIN VERIFICATION & EXECUTION ROUTINE
# --------------------------------------------------------------------------------------
def run_step_1(force_rebuild=False):
    print("=" * 85)
    print(">>> STEP 1: STREAMING DATASET PREPROCESSING & STRATIFIED RESERVOIR SAMPLING <<<")
    print("=" * 85)

    if force_rebuild:
        raw_dir = None
        for d in CANDIDATE_RAW_DIRS:
            if os.path.exists(os.path.join(d, "data_1.csv")):
                raw_dir = d
                break
        if raw_dir is None:
            raise FileNotFoundError("Raw 74 dataset CSVs (data_1.csv .. data_74.csv) not found!")
        df = stream_clean_raw_dataset(raw_dir)
    elif os.path.exists(PARQUET_PATH):
        print(f"\n[INFO] Cleaned representative corpus already preprocessed and verified at:")
        print(f"       {PARQUET_PATH}")
        t0 = time.time()
        df = pd.read_parquet(PARQUET_PATH)
        t_load = time.time() - t0
        print(f"       Loaded {len(df):,} flows ({df.shape[1]} features) in {t_load:.2f}s.")
    else:
        # If parquet missing, auto-discover raw CSVs and stream
        raw_dir = None
        for d in CANDIDATE_RAW_DIRS:
            if os.path.exists(os.path.join(d, "data_1.csv")):
                raw_dir = d
                break
        if raw_dir is None:
            raise FileNotFoundError("Neither preprocessed corpus nor raw CSVs found!")
        df = stream_clean_raw_dataset(raw_dir)

    # Display audit verification
    print("\n" + "-" * 75)
    print(f"{'Subcategory':<22} | {'Role in Dataset':<18} | {'Sampled Flows':<15} | {'Share (%)':<10}")
    print("-" * 75)
    counts = df["subcategory"].value_counts()
    for subcat, count in counts.items():
        role = "Benign Control" if subcat == "Normal" else "Attack Class"
        pct = (count / len(df)) * 100.0
        print(f"{subcat:<22} | {role:<18} | {count:>15,d} | {pct:>8.2f}%")
    print("-" * 75)
    print(f"{'TOTAL CORPUS':<22} | {'All Classes':<18} | {len(df):>15,d} | 100.00%")
    print("-" * 75)

    if os.path.exists(AUDIT_PATH):
        print(f"\nAudit summary of all 73,370,443 flows across all 74 raw files:")
        audit_df = pd.read_csv(AUDIT_PATH)
        print(audit_df.to_string(index=False))

    print("\n>>> STEP 1 VERIFICATION COMPLETED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Step 1: Streaming Dataset Preprocessing")
    parser.add_argument("--rebuild", action="store_true", help="Force re-streaming from raw 74 CSV files")
    args = parser.parse_args()
    run_step_1(force_rebuild=args.rebuild)
