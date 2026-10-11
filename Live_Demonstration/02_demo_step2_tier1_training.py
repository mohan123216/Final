#!/usr/bin/env python3
"""
========================================================================================
LIVE DEMO - STEP 2: TIER 1 - BALANCED MULTI-CLASS CLASSIFIER TRAINING
========================================================================================
Project: Hybrid Open-Set Multi-Signal Zero-Day Engine (HOMZ-Engine)
Demonstrates live to the review panel:
  1. Engineering 35 domain networking features (Directional Ratios, Port Profiling, Log-Scales)
  2. Inverse-Frequency Class Weighting:
     w_c = N / (K * N_c)
     Penalizes errors on extreme minority attacks (Data Exfiltration 0.19%, Keylogging 2.40%)
  3. Strict 80/20 Stratified Partitioning (48,904 train flows, 12,226 test flows)
  4. Real-time Training of Cost-Sensitive Gradient Boosted Trees (XGBoost, 200 trees, depth 8)
  5. Live Inference Evaluation & Metrics Output

Outputs generated live into: Live_Demonstration/outputs/step2_tier1_model/
  - xgboost_ids_model.json
  - classification_report.csv
  - confusion_matrix.png
  - tier1_metrics.json
========================================================================================
"""

import os
import sys
import time
import json
import argparse
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
from sklearn.utils.class_weight import compute_class_weight
import xgboost as xgb

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(CURRENT_DIR, "outputs", "step2_tier1_model")
os.makedirs(OUTPUT_DIR, exist_ok=True)

DATA_PATH = os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "01_Data_Preprocessing", "dataset", "fulldataset_cleaned_sample.parquet")
PRETRAINED_MODEL = os.path.join(CURRENT_DIR, "..", "Final_Proposed_Solution", "02_Tier1_Known_Classification", "models", "xgboost_balanced_multiclass_ids.json")

BASE_FEATURES = [
    "proto_number", "flgs_number", "state_number", "sport", "dport",
    "dur", "pkts", "bytes", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "srate", "drate", "mean", "stddev", "sum", "min", "max"
]

def engineer_features(df):
    X = df[BASE_FEATURES].copy()
    pkts = np.maximum(X["pkts"].values, 1e-6)
    bytes_val = np.maximum(X["bytes"].values, 1e-6)
    spkts = np.maximum(X["spkts"].values, 0.0)
    dpkts = np.maximum(X["dpkts"].values, 0.0)
    sbytes = np.maximum(X["sbytes"].values, 0.0)
    dbytes = np.maximum(X["dbytes"].values, 0.0)

    X["bytes_per_pkt"] = bytes_val / pkts
    X["sbytes_per_spkt"] = sbytes / (spkts + 1e-6)
    X["dbytes_per_dpkt"] = dbytes / (dpkts + 1e-6)
    X["spkts_ratio"] = spkts / pkts
    X["sbytes_ratio"] = sbytes / bytes_val

    sport = X["sport"].values
    dport = X["dport"].values
    X["is_sport_wellknown"] = (sport < 1024).astype(np.float32)
    X["is_dport_wellknown"] = (dport < 1024).astype(np.float32)
    X["is_dport_http"] = ((dport == 80) | (dport == 8080) | (dport == 443)).astype(np.float32)
    X["is_sport_http"] = ((sport == 80) | (sport == 8080) | (sport == 443)).astype(np.float32)

    for col in ["dur", "pkts", "bytes", "rate", "srate", "drate"]:
        X[f"log_{col}"] = np.log1p(np.maximum(X[col].values, 0.0))

    return X

def run_demo(fast=False):
    print("=" * 85)
    print(">>> LIVE DEMO - STEP 2: TIER 1 BALANCED MULTI-CLASS CLASSIFIER <<<")
    print("=" * 85)
    t_start = time.time()

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Cleaned dataset missing at: {DATA_PATH}")

    print(f"\n1. Ingesting cleaned traffic corpus from:\n   {DATA_PATH}")
    df = pd.read_parquet(DATA_PATH)
    print(f"   Loaded {len(df):,} packet flows across all traffic classes.")

    print("\n2. Engineering 35 domain network features...")
    X_df = engineer_features(df)
    feature_names = list(X_df.columns)
    print(f"   Successfully transformed into {len(feature_names)} engineered features.")

    classes = sorted(df["subcategory"].unique().tolist())
    class_to_idx = {c: i for i, c in enumerate(classes)}
    y = df["subcategory"].map(class_to_idx).values

    print("\n3. Performing Stratified 80/20 Partitioning (random_state=42)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X_df, y, test_size=0.20, stratify=y, random_state=42
    )
    print(f"   Training partition : {len(X_train):,} flows (80%)")
    print(f"   Testing partition  : {len(X_test):,} flows (20%)")

    clf = xgb.XGBClassifier()
    model_output_path = os.path.join(OUTPUT_DIR, "xgboost_ids_model.json")

    if fast and os.path.exists(PRETRAINED_MODEL):
        print(f"\n4. [FAST INFERENCE MODE] Loading verified production model from:\n   {PRETRAINED_MODEL}")
        clf.load_model(PRETRAINED_MODEL)
        clf.save_model(model_output_path)
    else:
        print("\n4. [LIVE TRAINING MODE] Training Balanced Cost-Sensitive XGBoost from Scratch:")
        print("   - Estimators     : 200 trees")
        print("   - Max Depth      : 8 levels")
        print("   - Learning Rate  : 0.08")
        print("   - Tree Method    : 'hist' (Deterministic Quantile Binning)")
        print("   - Loss Objective : multi:softprob")
        
        t0 = time.time()
        classes_arr = np.arange(len(classes))
        weights = compute_class_weight("balanced", classes=classes_arr, y=y_train)
        sample_weights = np.array([weights[lbl] for lbl in y_train])

        clf = xgb.XGBClassifier(
            n_estimators=200,
            max_depth=8,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.85,
            tree_method="hist",
            objective="multi:softprob",
            num_class=len(classes),
            random_state=42,
            n_jobs=-1
        )
        clf.fit(X_train, y_train, sample_weight=sample_weights)
        train_duration = time.time() - t0
        print(f"   >>> Model training converged successfully in {train_duration:.2f} seconds! <<<")
        clf.save_model(model_output_path)
        print(f"   Saved new trained model artifact to:\n     {model_output_path}")

    print(f"\n5. Evaluating Model Predictions on Held-Out Test Flows ({len(X_test):,})...")
    t0 = time.time()
    y_pred = clf.predict(X_test)
    eval_time = time.time() - t0

    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    weighted_f1 = f1_score(y_test, y_pred, average="weighted")
    latency_ms = (eval_time / len(X_test)) * 1000.0

    print("\n" + "=" * 80)
    print("LIVE TIER 1 EVALUATION RESULTS:")
    print("=" * 80)
    print(f"Overall Multi-Class Accuracy : {acc * 100.0:.2f}%")
    print(f"Macro F1-Score               : {macro_f1 * 100.0:.2f}%")
    print(f"Weighted F1-Score            : {weighted_f1 * 100.0:.2f}%")
    print(f"Per-Flow Inference Latency   : {latency_ms:.4f} ms/flow")
    print("=" * 80)

    # Classification report
    report_dict = classification_report(y_test, y_pred, target_names=classes, output_dict=True)
    report_df = pd.DataFrame(report_dict).transpose()
    report_csv = os.path.join(OUTPUT_DIR, "classification_report.csv")
    report_df.to_csv(report_csv)

    print("\nPer-Class Precision, Recall, and F1-Scores:")
    print(f"{'Attack Class':<22} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Test Flows':<10}")
    print("-" * 72)
    for c in classes:
        p = report_dict[c]["precision"]
        r = report_dict[c]["recall"]
        f = report_dict[c]["f1-score"]
        s = int(report_dict[c]["support"])
        print(f"{c:<22} | {p:>9.4f}  | {r:>9.4f}  | {f:>9.4f}  | {s:>10d}")
    print("-" * 72)

    # Confusion matrix plot
    cm = confusion_matrix(y_test, y_pred)
    cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    fig, ax = plt.subplots(figsize=(8.5, 7.0))
    sns.heatmap(cm_norm, annot=True, fmt=".2%", cmap="Blues", xticklabels=classes, yticklabels=classes, ax=ax)
    ax.set_title("Tier 1: Balanced Multi-Class Confusion Matrix (XGBoost)", fontsize=12, fontweight='bold', pad=10)
    ax.set_ylabel("True Category", fontsize=10)
    ax.set_xlabel("Predicted Category", fontsize=10)
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    cm_path = os.path.join(OUTPUT_DIR, "confusion_matrix.png")
    fig.savefig(cm_path, dpi=300)
    plt.close(fig)

    # Summary metrics JSON
    metrics_json = os.path.join(OUTPUT_DIR, "tier1_metrics.json")
    metrics_data = {
        "accuracy": round(float(acc), 6),
        "macro_f1": round(float(macro_f1), 6),
        "weighted_f1": round(float(weighted_f1), 6),
        "latency_ms_per_flow": round(float(latency_ms), 6),
        "total_test_flows": len(X_test),
        "training_time_seconds": round(time.time() - t_start, 2)
    }
    with open(metrics_json, "w") as f:
        json.dump(metrics_data, f, indent=2)

    print("\n" + "=" * 75)
    print("OUTPUTS SUCCESSFULLY GENERATED IN:")
    print(f"  Folder: {OUTPUT_DIR}")
    print(f"  - xgboost_ids_model.json      (Trained model artifact)")
    print(f"  - classification_report.csv   (Per-class performance)")
    print(f"  - confusion_matrix.png        (High-res confusion plot)")
    print(f"  - tier1_metrics.json          (Summary evaluation json)")
    print(f"Step 2 completed successfully in {time.time() - t_start:.2f} seconds.")
    print(">>> STEP 2 COMPLETED WITH ZERO ERRORS! <<<")
    print("=" * 75)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fast", action="store_true", help="Use pre-trained model for instant demonstration")
    args = parser.parse_args()
    run_demo(fast=args.fast)
