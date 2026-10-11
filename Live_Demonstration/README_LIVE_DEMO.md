# LIVE DEFENSE PANEL DEMONSTRATION GUIDE

**Project**: Hybrid Open-Set Multi-Signal Zero-Day Intrusion Detection Engine (HOMZ-Engine)  
**Dataset**: UNSW Bot-IoT Benchmark (73,370,443 flows across all 74 raw CSV files)  
**Base Paper**: *"Multi-Stage Enhanced Zero Trust IDS for Unknown Attack Detection in IoT"*, ACM Transactions on Privacy and Security (ACM TOPS, 2025)

---

## 🎯 Quick Start for Viva / Review Panel

### Option A: Interactive Menu Controller (Recommended)
Open a terminal in `Live_Demonstration/` and run:
```bash
python run_live_panel_demo.py
```
*(Or simply double-click `run_live_demo.bat`)*

```text
==================================================================================
      HOMZ-ENGINE: LIVE DEFENSE PANEL DEMONSTRATION CONTROLLER
   Hybrid Open-Set Multi-Signal Zero-Day Intrusion Detection System
==================================================================================
  [1] Step 1: Preprocessing & 73.3M Streaming Ingestion Audit
  [2] Step 2: Tier 1 Balanced XGBoost Classifier Training (Live)
  [3] Step 3: Tier 2 Multi-Signal Zero-Day Rejection Engine & Test Trace
  [4] Step 4: ACM TOPS Table 9 Academic Benchmark Comparison
  [5] Step 5: Data Integrity & Zero-Leakage Assertion Audit
  [6] Step 6: Presentation Dashboards & Interactive Visualizer
  ----------------------------------------------------------------
  [A] Run All Steps Sequentially (Complete Live Pipeline in ~40s)
  [C] Reset / Wipe Output Folders (Clean slate for live review)
  [Q] Exit
==================================================================================
```

---

## 📂 Exact Outputs Generated Per Step (Matching `Final_Proposed_Solution`)

| Step | Output Folder | Authentic Artifacts Generated | Description for the Panel |
| :--- | :--- | :--- | :--- |
| **Step 1** | `outputs/step1_data_preprocessing/` | • `class_distribution_full_74files.csv`<br>• `class_imbalance_before_and_after.png`<br>• `streaming_stratified_sampling_pipeline.png` | **Proves full 73.3M streaming scan**: Shows raw 73,370,443 flows tally vs 61,130 balanced evaluation corpus, with 100% retention of Normal & Theft flows. |
| **Step 2** | `outputs/step2_tier1_model/` | • `balanced_multiclass_classification_report.csv`<br>• `balanced_multiclass_confusion_matrix.png`<br>• `feature_importance_top20.png`<br>• `known_multiclass_standard_metrics_table.png`<br>• `xgboost_balanced_multiclass_ids.json` | **Tier 1 Performance**: Accuracy **98.97%**, Macro F1 **98.26%**, Normal Specificity **99.82%** with top 20 engineered feature rankings. |
| **Step 3** | `outputs/step3_tier2_zeroday/` | • `zero_day_detection_standard_metrics.csv`<br>• `zero_day_standard_metrics_table_and_chart.png`<br>• `tier2_sample_test_inputs_rejection_trace.csv` | **Tier 2 Zero-Day Rejection & Test Trace**: Full 10 attack vector metrics AND per-flow test trace showing individual test inputs with their 4 signals and rejection decision. |
| **Step 4** | `outputs/step4_table9_benchmark/` | • `paper_table9_reproduction_metrics.csv`<br>• `base_paper_vs_our_method_comparison.csv`<br>• `base_paper_vs_our_method_comparison_table.png` | **Base Paper Table 9 Outperformance**: Shows Data Exfiltration F1 jumping from **0.15** (Base Paper) to **0.9483** (HOMZ-Engine), +15.89% Macro F1 gain. |
| **Step 5** | `outputs/step5_integrity_audit/` | • `full_dataset_audit_74files.csv`<br>• `zero_leakage_assertion_certificate.txt` | **Integrity & Zero Leakage Audit**: Strict disjointness proof $|X_{\text{train}} \cap X_{\text{test}}| = 0$ across all 74 files with zero address features. |
| **Step 6** | `outputs/step6_dashboards/` | • `section1_data_processing_dashboard.png`<br>• `section2_xgboost_classification_dashboard.png`<br>• `section3_zeroday_detection_dashboard.png`<br>• `interactive_panel_review_dashboard.html` | **Master Presentation Dashboards**: The 3 publication-grade figures and the interactive web visualizer with live sliders. |

---

## 🔍 Critical Panel Questions & Defenses

### 1. "Did you do preprocessing for all 74 million records or only for sampled ones?"
**Answer**:
> *"We preprocessed and audited all 73,370,443 records across all 74 CSV files (~15.3 GB) using streaming chunks of 250,000 flows.*  
> *During this full 73.3M stream, the pipeline cleaned corrupted tokens, replaced zero-duration infinite rates, parsed port hex/strings, mapped categorical protocols, and dropped network address identifiers.*  
> *Because raw traffic is 99.8% DDoS/DoS and only 0.013% Normal (9,543 flows) and 0.0002% Data Exfiltration (118 flows), streaming stratified reservoir sampling was applied to cap redundant floods at 10,000 flows while preserving 100% of all rare Normal and Theft attack flows.*  
> *This created the curated 61,130-flow balanced benchmark corpus for training and open-set evaluation."*

### 2. "How does the Tier 2 rejection mechanism work for individual test inputs?"
**Answer**:
> *"Open `outputs/step3_tier2_zeroday/tier2_sample_test_inputs_rejection_trace.csv`.*  
> *For every incoming packet flow $x$:*  
> 1. *We compute its 4 novelty signals: Free Energy $S_E$, Mahalanobis $S_M$, Leaf Traversal $S_L$, and Margin $S_R$.*  
> 2. *We convert each signal into a percentile rank $Z_i(x) \in [0, 1]$ via empirical CDFs fitted strictly on validation known traffic.*  
> 3. *We combine them: $S_{\text{composite}}(x) = 0.40 Z_E + 0.30 Z_M + 0.15 Z_L + 0.15 Z_R$.*  
> 4. *If $S_{\text{composite}}(x) > \tau$ ($0.8407$), the system REJECTS it as an alien Zero-Day Threat.*  
> *For example, a Normal flow has $S_{\text{comp}} \approx 0.46 \le 0.8407$ (ACCEPTED as Known), while a Zero-Day Data Exfiltration flow has $S_{\text{comp}} \approx 0.936 > 0.8407$ (REJECTED as Zero-Day)."*
