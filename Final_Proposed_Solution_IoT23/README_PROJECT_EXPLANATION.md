# Master Project Guide: Hybrid Multi-Signal Zero-Day Intrusion Detection Engine (HOMZ-Engine)
## Avast / Stratosphere CTU IoT-23 Benchmark (>50 GB across 23 Malware & Benign Scenarios)

> **Complete Step-by-Step Presentation & Technical Architecture Walkthrough**  
> *Evaluated on the 23-Scenario Bro/Zeek IoT Network Traffic Benchmark*  
> *Direct Benchmark against:* **Published SOTA Network Intrusion Detection Literature on IoT-23**

---

## 🎯 What Is This Folder?
This folder (`Final_Proposed_Solution_IoT23`) contains the **complete, clean, reproducible implementation** of our final proposed solution adapted for the **Avast / Stratosphere CTU IoT-23 dataset** located in `c:\Iot_bot\iot-23`. Everything is organized sequentially from **Step 1 to Step 8**, exactly mirroring the architecture of `Final_Proposed_Solution` and `Final_Proposed_Solution_CIC18`.

---

## 🏗️ Master System Architecture

Our solution is a **Two-Tier Hybrid Open-Set Multi-Signal Architecture**:

```
                               Incoming Network Flow Record (35 Features)
                                               │
                                               ▼
             ┌──────────────────────────────────────────────────────────────────┐
             │ TIER 1: Balanced Cost-Sensitive GBDT Classifier                  │
             │ - 35 engineered flow, directional, and protocol features         │
             │ - Inverse-frequency class weighting (wc = N / (K * Nc))          │
             │ - 87.10% Multi-Class Accuracy, 95.95% Macro Recall               │
             │ - 0.0043 ms/flow latency (>234,000 flows/sec throughput)         │
             └─────────────────────────────────┬────────────────────────────────┘
                                               │ Booster Logits + Tree Leaves + Flow Data
                                               ▼
             ┌──────────────────────────────────────────────────────────────────┐
             │ TIER 2: 4-SIGNAL OPEN-SET ZERO-DAY REJECTION ENGINE              │
             │                                                                  │
             │  Signal 1: Logit Free Energy Novelty (S_E)                       │
             │            E(x) = -T * log(sum(exp(f_k(x) / T)))                 │
             │            (Operates on unnormalized booster logits to eliminate │
             │             the Softmax 100%-sum overconfidence fallacy)         │
             │                                                                  │
             │  Signal 2: Log-Manifold Regularized Mahalanobis Distance (S_M)   │
             │            D_M(x) = sqrt((z - μ_c)^T * Σ_c^-1 * (z - μ_c))        │
             │            (Ledoit-Wolf covariance shrinkage on log(1 + x))      │
             │                                                                  │
             │  Signal 3: Tree Leaf-Space Traversal Novelty (S_L)               │
             │            S_leaf = 1.0 - LeafSim(x, c)                          │
             │            (Detects structural anomalies across 100 trees)       │
             │                                                                  │
             │  Signal 4: Relative Margin Distance Ratio (S_R)                  │
             │            R(x) = D_M(pred) / (min_{j≠pred} D_M(j) + ε)           │
             │            (Detects boundary ambiguity between known classes)    │
             │                                                                  │
             │  CALIBRATION: Empirical CDF Percentile Normalizer (searchsorted) │
             │               Z_i(x) = P(S_known <= S_i(x)) in [0.0, 1.0]        │
             │  FUSION:      S_unified = 0.40*Z_E + 0.30*Z_M + 0.15*Z_L + 0.15*Z_R │
             │  THRESHOLD:   tau = percentile(S_val, 95.0) on Known Validation  │
             └─────────────────────────────────┬────────────────────────────────┘
                                               │
                                               ▼
                            Unified Anomaly Score > Threshold (τ)?
                                   ┌───────────┴───────────┐
                                  YES                      NO
                                   │                       │
                                   ▼                       ▼
                         [ ZERO-DAY ATTACK ]      [ KNOWN TRAFFIC ]
                         (Alien Novel Threat)     (Normal or Known Attack)
```

---

## 📂 Step-by-Step Folder Structure & Map

```text
Final_Proposed_Solution_IoT23/
├── 00_run_entire_pipeline.py                 # [Master Runner] Executes Step 1 to 6 in ~15 seconds
├── README_PROJECT_EXPLANATION.md             # [This File] Master narrative & presentation script
│
├── 01_Data_Preprocessing/                    # STEP 1: Ingestion & Stratified Reservoir Sampling
│   ├── README_STEP_1.md                      # Detailed Step 1 documentation
│   ├── 01_stream_clean_full_dataset.py       # Ingestion & Bro/Zeek feature cleaning script
│   └── dataset/
│       ├── iot23_cleaned_sample.parquet      # Cleaned binary research corpus (31,692 flows)
│       ├── iot23_cleaned_sample.csv          # Cleaned CSV sample
│       └── class_distribution_iot23.csv      # Complete class distribution audit
│
├── 02_Tier1_Known_Classification/            # STEP 2: Balanced Multi-Class Classifier
│   ├── README_STEP_2.md                      # Detailed Step 2 documentation
│   ├── 02_train_balanced_multiclass.py       # Tier 1 training & evaluation script
│   ├── models/
│   │   ├── xgboost_balanced_multiclass_iot23.json # Serialized XGBoost model
│   │   └── multiclass_class_mapping.json     # Class mapping metadata
│   └── results/
│       ├── balanced_multiclass_classification_report.csv
│       ├── known_attack_multiclass_metrics.csv
│       └── balanced_multiclass_confusion_matrix.png
│
├── 03_Tier2_ZeroDay_Detection/               # STEP 3: Multi-Signal Zero-Day Engine
│   ├── README_STEP_3.md                      # Detailed Step 3 documentation
│   ├── 03_run_zero_day_engine.py             # 4-Signal novelty isolation script
│   └── results/
│       ├── zero_day_detection_standard_metrics.csv
│       ├── unknown_attack_zeroday_metrics.csv
│       └── zero_day_standard_metrics_table_and_chart.png
│
├── 04_Paper_Table9_Benchmark/                # STEP 4: Leave-One-Attack-Out (LOAO) Benchmark
│   ├── README_STEP_4.md                      # Detailed Step 4 documentation
│   ├── 04_evaluate_paper_table9.py           # 10 LOAO experiments benchmark script
│   └── results/
│       ├── iot23_zeroday_reproduction_metrics.csv
│       ├── base_benchmark_vs_our_method_comparison.csv
│       └── base_benchmark_vs_our_method_comparison_table.png
│
├── 05_Integrity_Audit/                       # STEP 5: Integrity Audit & Dual Evaluation
│   ├── README_STEP_5.md                      # Detailed Step 5 documentation
│   ├── 05_rigorous_dual_evaluation_audit.py  # Zero-leakage mathematical assertion script
│   └── results/
│       ├── full_dataset_audit_iot23.csv
│       └── zero_leakage_assertion_certificate.txt
│
├── 06_Presentation_Dashboards/               # STEP 6: Publication Presentation Dashboards
│   ├── README_STEP_6.md                      # Detailed Step 6 documentation
│   ├── generate_presentation_dashboards.py   # Publication figures generator
│   └── plots/
│       ├── section1_data_processing_dashboard.png
│       ├── section2_xgboost_classification_dashboard.png
│       └── section3_zeroday_detection_dashboard.png
│
├── 07_Final_Reports/                         # STEP 7: Viva Cheat Sheets & Final Technical Reports
│   ├── IOT23_FULL_DATASET_ZERO_DAY_IMPLEMENTATION_REPORT.md
│   └── QUICK_CHEAT_SHEET_FOR_VIVA.md
│
└── 08_Interactive_Panel_Review_Dashboard/    # STEP 8: Interactive Review & Defense Dashboard
    ├── README_STEP_8.md                      # Detailed Step 8 documentation
    └── index.html                            # Standalone Interactive Web Dashboard
```

---

## ⚡ Execution Instructions

To execute the entire pipeline end-to-end:
```bash
python 00_run_entire_pipeline.py
```

To view the interactive defense dashboard:
```bash
python -m http.server 8080 --directory "08_Interactive_Panel_Review_Dashboard"
```
Then open `http://localhost:8080` in your web browser.
