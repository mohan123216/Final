#!/usr/bin/env python3
"""
========================================================================================
STEP 2: TIER 1 - BALANCED MULTI-CLASS INTRUSION DETECTION CLASSIFIER
========================================================================================
Project: Hybrid Open-Set Multi-Signal Zero-Day Engine (HOMZ-Engine)
Dataset: CSE-CIC-IDS2018 Benchmark (62,658 curated flows)
Classifier: Cost-Sensitive Gradient Boosted Decision Trees (XGBoost)

Key Technical Components:
  1. Network Domain Feature Engineering (88+ features):
     - Directional payload ratios: spkts_ratio, sbytes_ratio, bytes_per_pkt
     - Asymmetric traffic dynamics: fwd_bytes_per_spkt, bwd_bytes_per_dpkt
     - Service port profiling: is_dport_wellknown, is_dport_http, is_dport_ssh, is_dport_ftp, is_dport_dns
     - Log-manifold volume stabilization: log_flow_duration, log_tot_fwd_pkts, log_tot_bwd_pkts,
       log_totlen_fwd_pkts, log_totlen_bwd_pkts, log_flow_byts_s, log_flow_pkts_s
  2. Inverse-Frequency Class Weighting:
     - Penalizes errors on rare minority classes (SQL Injection, XSS, Web Brute Force, LOIC-UDP)
       via w_c = N / (K * N_c), ensuring rare attacks achieve high recall and precision.
  3. Strict Stratified 80/20 Train/Test Split (50,126 train, 12,532 test flows)
  4. Out-of-the-Box Inference or Fast Re-training:
     - Evaluates the pre-trained production model in ~1.5s
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
DATA_PATH = os.path.join(CURRENT_DIR, "..", "01_Data_Preprocessing", "dataset", "cic18_cleaned_sample.parquet")
MODELS_DIR = os.path.join(CURRENT_DIR, "models")
RESULTS_DIR = os.path.join(CURRENT_DIR, "results")
MODEL_PATH = os.path.join(MODELS_DIR, "xgboost_balanced_multiclass_cic18.json")
MAPPING_PATH = os.path.join(MODELS_DIR, "multiclass_class_mapping.json")

os.makedirs(MODELS_DIR, exist_ok=True)
os.makedirs(RESULTS_DIR, exist_ok=True)

LABEL_COLS = ["Label", "category", "subcategory", "attack", "raw_label"]

def engineer_features(df):
    """Adds domain-specific networking features to enhance classifier discriminative power."""
    feat_cols = [c for c in df.columns if c not in LABEL_COLS]
    X = df[feat_cols].copy()

    # Directional ratios
    fwd_pkts = np.maximum(X["Tot Fwd Pkts"].values if "Tot Fwd Pkts" in X.columns else 0.0, 0.0)
    bwd_pkts = np.maximum(X["Tot Bwd Pkts"].values if "Tot Bwd Pkts" in X.columns else 0.0, 0.0)
    tot_pkts = fwd_pkts + bwd_pkts
    
    fwd_bytes = np.maximum(X["TotLen Fwd Pkts"].values if "TotLen Fwd Pkts" in X.columns else 0.0, 0.0)
    bwd_bytes = np.maximum(X["TotLen Bwd Pkts"].values if "TotLen Bwd Pkts" in X.columns else 0.0, 0.0)
    tot_bytes = fwd_bytes + bwd_bytes

    X["spkts_ratio"] = fwd_pkts / (tot_pkts + 1e-6)
    X["sbytes_ratio"] = fwd_bytes / (tot_bytes + 1e-6)
    X["bytes_per_pkt"] = tot_bytes / (tot_pkts + 1e-6)
    X["fwd_bytes_per_spkt"] = fwd_bytes / (fwd_pkts + 1e-6)
    X["bwd_bytes_per_dpkt"] = bwd_bytes / (bwd_pkts + 1e-6)

    # Port profiling
    dport = X["Dst Port"].values if "Dst Port" in X.columns else np.zeros(len(X))
    X["is_dport_wellknown"] = (dport < 1024).astype(np.float32)
    X["is_dport_http"] = ((dport == 80) | (dport == 8080) | (dport == 443)).astype(np.float32)
    X["is_dport_ssh"] = (dport == 22).astype(np.float32)
    X["is_dport_ftp"] = ((dport == 20) | (dport == 21)).astype(np.float32)
    X["is_dport_dns"] = (dport == 53).astype(np.float32)

    # Log-scaled volume metrics
    for col in ["Flow Duration", "Tot Fwd Pkts", "Tot Bwd Pkts", "TotLen Fwd Pkts", "TotLen Bwd Pkts", "Flow Byts/s", "Flow Pkts/s"]:
        if col in X.columns:
            clean_name = "log_" + col.lower().replace(" ", "_").replace("/", "_")
            X[clean_name] = np.log1p(np.maximum(X[col].values, 0.0))

    # Replace any leftover NaNs or Infs
    X = X.fillna(0.0)
    for c in X.columns:
        vals = X[c].values
        vals[np.isinf(vals)] = 0.0
        X[c] = vals

    return X

def run_step_2(retrain=False):
    print("=" * 85)
    print(">>> STEP 2: TIER 1 - BALANCED MULTI-CLASS INTRUSION DETECTION <<<")
    print(">>> DATASET: CSE-CIC-IDS2018 BENCHMARK <<<")
    print("=" * 85)

    if not os.path.exists(DATA_PATH):
        raise FileNotFoundError(f"Cleaned dataset not found at: {DATA_PATH}")

    print(f"\n1. Loading curated 62,658-flow dataset from:\n   {DATA_PATH}")
    df = pd.read_parquet(DATA_PATH)
    print(f"   Successfully loaded {len(df):,} flows.")

    # Engineer Features
    print(f"\n2. Engineering domain network features (Directional Ratios + Port Profiling + Log Volumes)...")
    X_df = engineer_features(df)
    feature_names = list(X_df.columns)
    print(f"   Total engineered features: {len(feature_names)}")

    # Class mappings
    classes = sorted(df["subcategory"].unique().tolist())
    class_to_idx = {c: i for i, c in enumerate(classes)}
    idx_to_class = {i: c for i, c in enumerate(classes)}
    y = df["subcategory"].map(class_to_idx).values

    # Save class mappings
    with open(MAPPING_PATH, "w") as f:
        json.dump({
            "classes": classes,
            "class_to_idx": class_to_idx,
            "idx_to_class": idx_to_class
        }, f, indent=2)

    # Stratified 80/20 Split
    X_train, X_test, y_train, y_test = train_test_split(
        X_df, y, test_size=0.20, stratify=y, random_state=42
    )
    print(f"\n3. Stratified Partition: Train={len(X_train):,} flows | Test={len(X_test):,} flows")

    clf = xgb.XGBClassifier()
    if os.path.exists(MODEL_PATH) and not retrain:
        print(f"\n4. Loading pre-trained Tier-1 XGBoost model from:\n   {MODEL_PATH}")
        clf.load_model(MODEL_PATH)
    else:
        print(f"\n4. Training Balanced Cost-Sensitive XGBoost Classifier (n_estimators=150, depth=7)...")
        t0 = time.time()
        classes_arr = np.arange(len(classes))
        weights = compute_class_weight("balanced", classes=classes_arr, y=y_train)
        sample_weights = np.array([weights[lbl] for lbl in y_train])

        clf = xgb.XGBClassifier(
            n_estimators=150,
            max_depth=7,
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
        print(f"   Training finished in {time.time() - t0:.2f}s!")
        clf.save_model(MODEL_PATH)

    # Evaluate
    print(f"\n5. Evaluating Model on Held-Out Test Set ({len(X_test):,} flows)...")
    t0 = time.time()
    y_pred = clf.predict(X_test)
    eval_time = time.time() - t0

    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro")
    weighted_f1 = f1_score(y_test, y_pred, average="weighted")

    print("\n" + "=" * 80)
    print(">>> TIER 1 EVALUATION RESULTS <<<")
    print("=" * 80)
    print(f"Overall Multi-Class Accuracy : {acc * 100.0:.2f}%")
    print(f"Macro F1-Score               : {macro_f1 * 100.0:.2f}%")
    print(f"Weighted F1-Score            : {weighted_f1 * 100.0:.2f}%")
    print(f"Inference Latency            : {eval_time / len(X_test) * 1000.0:.4f} ms/flow")
    print("=" * 80)

    # Detailed Per-Class Classification Report
    report_dict = classification_report(y_test, y_pred, target_names=classes, output_dict=True)
    report_df = pd.DataFrame(report_dict).transpose()
    report_csv = os.path.join(RESULTS_DIR, "balanced_multiclass_classification_report.csv")
    report_df.to_csv(report_csv)

    print("\nPer-Class Classification Report:")
    print("-" * 80)
    print(f"{'Attack Subcategory':<22} | {'Precision':<10} | {'Recall':<10} | {'F1-Score':<10} | {'Test Flows':<10}")
    print("-" * 80)
    per_class_metrics = []
    for c in classes:
        p = report_dict[c]["precision"] * 100.0
        r = report_dict[c]["recall"] * 100.0
        f1 = report_dict[c]["f1-score"] * 100.0
        s = int(report_dict[c]["support"])
        print(f"{c:<22} | {p:>9.2f}% | {r:>9.2f}% | {f1:>9.2f}% | {s:>10,d}")
        per_class_metrics.append({
            "Subcategory": c,
            "Precision_pct": round(p, 2),
            "Recall_pct": round(r, 2),
            "F1_Score_pct": round(f1, 2),
            "Test_Support": s
        })
    print("-" * 80)

    metrics_df = pd.DataFrame(per_class_metrics)
    metrics_csv = os.path.join(RESULTS_DIR, "known_attack_multiclass_metrics.csv")
    metrics_df.to_csv(metrics_csv, index=False)

    # Confusion Matrix Heatmap
    cm = confusion_matrix(y_test, y_pred)
    cm_norm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]

    plt.figure(figsize=(14, 11), facecolor="#F8FAFC")
    ax = sns.heatmap(cm_norm, annot=True, fmt=".2f", cmap="Blues",
                     xticklabels=classes, yticklabels=classes,
                     cbar=True, annot_kws={"size": 9})
    plt.title("Tier 1: Normalized Multi-Class Confusion Matrix (CSE-CIC-IDS2018)", fontsize=14, fontweight="bold", pad=15)
    plt.xlabel("Predicted Class", fontsize=11, fontweight="bold")
    plt.ylabel("True Class", fontsize=11, fontweight="bold")
    plt.xticks(rotation=45, ha="right", fontsize=9)
    plt.yticks(rotation=0, fontsize=9)
    plt.tight_layout()
    cm_plot = os.path.join(RESULTS_DIR, "balanced_multiclass_confusion_matrix.png")
    plt.savefig(cm_plot, dpi=300)
    plt.close()
    print(f"\nSaved confusion matrix plot to: {cm_plot}")

    print("\n>>> STEP 2 COMPLETED SUCCESSFULLY! <<<\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--retrain", action="store_true", help="Force retraining of the XGBoost classifier")
    args = parser.parse_args()
    run_step_2(retrain=args.retrain)
