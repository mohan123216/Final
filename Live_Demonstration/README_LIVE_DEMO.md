# LIVE DEFENSE PANEL DEMONSTRATION GUIDE

**Project**: Hybrid Open-Set Multi-Signal Zero-Day Intrusion Detection Engine (HOMZ-Engine)  
**Dataset**: UNSW Bot-IoT Benchmark (73,370,443 flows across 74 raw CSV files)  
**Base Paper**: *"Multi-Stage Enhanced Zero Trust IDS for Unknown Attack Detection in IoT"*, ACM Transactions on Privacy and Security (ACM TOPS, 2025)

---

## 🎯 Quick Start for Viva / Review Panel

You have two ways to demonstrate the project live:

### Option A: Interactive Menu (Recommended)
Open a terminal in `Live_Demonstration/` and run:
```bash
python run_live_panel_demo.py
```
*(Or simply double-click `run_live_demo.bat`)*

You will see:
```text
==================================================================================
      HOMZ-ENGINE: LIVE DEFENSE PANEL DEMONSTRATION CONTROLLER
   Hybrid Open-Set Multi-Signal Zero-Day Intrusion Detection System
==================================================================================
  [1] Step 1: Preprocessing, Imputation & Streaming Ingestion
  [2] Step 2: Tier 1 Balanced XGBoost Classifier Training (Live)
  [3] Step 3: Tier 2 Multi-Signal Zero-Day Rejection Engine (Live)
  [4] Step 4: ACM TOPS Table 9 Academic Benchmark Comparison
  [5] Step 5: Data Integrity & Zero-Leakage Assertion Audit
  [6] Step 6: Presentation Dashboards & Interactive Visualizer
  ----------------------------------------------------------------
  [A] Run All Steps Sequentially (Complete Live Pipeline in ~40s)
  [C] Reset / Wipe Output Folders (Clean slate for live review)
  [Q] Exit
==================================================================================
```

### Option B: Step-by-Step Command Line
You can run each step independently with dedicated commands:

```bash
# 0. Wipe outputs clean so the panel sees empty folders initially
python clean_outputs.py

# 1. Run Step 1: Data Preprocessing
python 01_demo_step1_preprocessing.py

# (Optional: If the panel asks to stream directly from raw data_1.csv)
python 01_demo_step1_preprocessing.py --raw

# 2. Run Step 2: Tier 1 Multi-Class XGBoost Training (Trains live in ~20s)
python 02_demo_step2_tier1_training.py

# 3. Run Step 3: Tier 2 4-Signal Zero-Day Rejection Engine
python 03_demo_step3_tier2_zeroday.py

# 4. Run Step 4: Academic Base Paper Table 9 Benchmark
python 04_demo_step4_table9_benchmark.py

# 5. Run Step 5: Data Leakage & Integrity Audit
python 05_demo_step5_integrity_audit.py

# 6. Run Step 6: Publication Figures & Interactive Dashboard
python 06_demo_step6_dashboards.py
```

---

## 📂 Live Outputs Generated Per Step

As you execute each step, artifacts are generated into `Live_Demonstration/outputs/`:

| Step | Output Folder | Generated Files | What to Show the Panel |
| :--- | :--- | :--- | :--- |
| **Step 1** | `outputs/step1_data_preprocessing/` | • `sample_cleaned_traffic.csv`<br>• `class_distribution_summary.csv`<br>• `cleaning_summary_statistics.json` | Open `sample_cleaned_traffic.csv` to prove infinite rates replaced, non-numeric tokens imputed with 0.0, and IP addresses dropped. |
| **Step 2** | `outputs/step2_tier1_model/` | • `xgboost_ids_model.json`<br>• `classification_report.csv`<br>• `confusion_matrix.png`<br>• `tier1_metrics.json` | Open `confusion_matrix.png` showing 98.97% accuracy, 98.26% Macro F1, and 99.82% Normal specificity. |
| **Step 3** | `outputs/step3_tier2_zeroday/` | • `zero_day_detection_report.csv`<br>• `rejection_threshold_tau.json`<br>• `zeroday_rejection_roc_curve.png` | Open `zeroday_rejection_roc_curve.png` and explain how the 4 signals reject unknown zero-days at $\tau = 0.8407$. |
| **Step 4** | `outputs/step4_table9_benchmark/` | • `table9_benchmark_comparison.csv`<br>• `table9_benchmark_plot.png`<br>• `benchmark_summary.json` | Open `table9_benchmark_plot.png` showing Data Exfiltration F1 jumping from **0.15** (ACM paper) to **0.936** (Our system). |
| **Step 5** | `outputs/step5_integrity_audit/` | • `zero_leakage_assertion_certificate.txt`<br>• `loao_cross_validation_results.csv`<br>• `audit_integrity_summary.json` | Open the signed certificate showing `\|Train ∩ Test\| = 0` (Zero Data Leakage). |
| **Step 6** | `outputs/step6_dashboards/` | • `section1_data_processing.png`<br>• `section2_tier1_performance.png`<br>• `section3_tier2_signals.png`<br>• `interactive_panel_review_dashboard.html` | Double-click `interactive_panel_review_dashboard.html` in your browser for live slider manipulation in front of the panel! |

---

## 🗣️ Viva Defense Talking Points (Per Step)

### Step 1: Preprocessing & Ingestion
- **Q**: *"Why did you drop `saddr`, `daddr`, `pkSeqID`, and `seq`?"*
- **A**: Network address and sequence numbers lead to artificial topology memorization. A real IDS must classify attack traffic based on behavioral telemetry (packet rates, byte ratios, TCP state transitions), not IP addresses.

### Step 2: Tier 1 Classification
- **Q**: *"How did you handle the severe class imbalance (Data Exfiltration is only 0.19%)?"*
- **A**: We formulated cost-sensitive training with inverse-frequency class weights:
  $$w_c = \frac{N}{K \cdot N_c}$$
  This scales minority gradients so the booster penalizes errors on rare attacks just as heavily as high-volume DDoS floods.

### Step 3: Tier 2 Zero-Day Detection
- **Q**: *"Why did you use Logit Free Energy instead of raw Softmax probability?"*
- **A**: Softmax forces probabilities to sum to 1.0 via $\frac{e^{z_k}}{\sum e^{z_j}}$. On alien zero-day traffic, the network is often overconfident on whichever known class has a slightly higher logit. Free Energy:
  $$S_E(x; T) = -T \cdot \ln \sum_{c=1}^K \exp(z_c(x) / T)$$
  measures the total log-partition function of all logits, remaining mathematically unbounded and immune to softmax probability calibration distortion.

### Step 4: Benchmark Comparison
- **Q**: *"How does this outperform ACM TOPS 2025 Table 9?"*
- **A**: In the base paper, Data Exfiltration collapsed to F1 = 0.15 (85% failure) due to severe volume imbalance. Our inverse-frequency weighting and multi-signal rejection elevated Data Exfiltration F1 to 0.936 (+78.6% improvement), with overall Macro F1 exceeding the paper by +15.89%.

### Step 5: Integrity Audit
- **Q**: *"How do you prove no data leakage occurred?"*
- **A**: We enforce strict disjoint row hash tracking ($X_{\text{train}} \cap X_{\text{test}} = \emptyset$), never apply synthetic oversampling (like SMOTE) to test sets, and fit all empirical CDFs and threshold percentiles exclusively on known validation traffic.
