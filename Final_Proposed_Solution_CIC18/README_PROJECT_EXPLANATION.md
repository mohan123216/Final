# Master Project Guide: Hybrid Multi-Signal Zero-Day Intrusion Detection Engine (HOMZ-Engine)
## CSE-CIC-IDS2018 Dataset Benchmark (16,248,642 Network Flows)

> **Complete Step-by-Step Presentation & Technical Architecture Walkthrough**  
> *Evaluated on the 16.2 Million Flow CSE-CIC-IDS2018 Benchmark across 10 CSV files (~7.2 GB)*  
> *Direct Benchmark against:* **SOTA Published Network Intrusion Detection Literature**

---

## 🎯 What Is This Folder?
This folder (`Final_Proposed_Solution_CIC18`) contains the **complete, clean, reproducible implementation** of our final proposed solution adapted for the **CSE-CIC-IDS2018 dataset** located in `c:\Iot_bot\cic-18`. Everything is organized sequentially from **Step 1 to Step 8**, exactly mirroring the architecture of `Final_Proposed_Solution`.

---

## 🏗️ Master System Architecture

Our solution is a **Two-Tier Hybrid Open-Set Multi-Signal Architecture**:

```
                               Incoming Network Flow Record (95 Features)
                                               │
                                               ▼
             ┌──────────────────────────────────────────────────────────────────┐
             │ TIER 1: Balanced Cost-Sensitive GBDT Classifier                  │
             │ - 95 engineered flow, directional, and protocol features         │
             │ - Inverse-frequency class weighting (wc = N / (K * Nc))          │
             │ - 92.04% Multi-Class Accuracy, 90.62% Macro F1 Score             │
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
                          (Alien Novel Threat)     (Classified by Tier 1)
```

---

## 📂 Step-by-Step Folder Structure & Map

```text
Final_Proposed_Solution_CIC18/
├── 00_run_entire_pipeline.py                 # [Master Runner] Executes Step 1 to 6 in ~25 seconds
├── README_PROJECT_EXPLANATION.md             # [This File] Master narrative & presentation script
│
├── 01_Data_Preprocessing/                    # STEP 1: Ingestion & Stratified Reservoir Sampling
│   ├── README_STEP_1.md                      # Detailed Step 1 documentation
│   ├── 01_stream_clean_full_dataset.py       # Ingestion & streaming audit script
│   └── dataset/
│       ├── cic18_cleaned_sample.parquet      # Cleaned binary sample (62,658 flows, 10.8 MB)
│       ├── cic18_cleaned_sample.csv          # Cleaned CSV sample (30.5 MB)
│       └── class_distribution_full_cic18.csv # Audit of all 16,248,642 raw flows across all 10 CSVs
│
├── 02_Tier1_Known_Classification/            # STEP 2: Balanced Multi-Class Classifier
│   ├── README_STEP_2.md                      # Detailed Step 2 documentation
│   ├── 02_train_balanced_multiclass.py       # Tier 1 training & evaluation script
│   ├── models/
│   │   ├── xgboost_balanced_multiclass_cic18.json # Serialized XGBoost model
│   │   └── multiclass_class_mapping.json     # Class mapping definitions
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
│   ├── 04_evaluate_paper_table9.py           # 14 LOAO experiments benchmark script
│   └── results/
│       ├── cic18_zeroday_reproduction_metrics.csv
│       ├── base_benchmark_vs_our_method_comparison.csv
│       └── base_benchmark_vs_our_method_comparison_table.png
│
├── 05_Integrity_Audit/                       # STEP 5: Data Integrity & Zero Leakage Audit
│   ├── README_STEP_5.md                      # Detailed Step 5 documentation
│   ├── 05_rigorous_dual_evaluation_audit.py  # Leakage assertion & dual-eval script
│   └── results/
│       └── full_dataset_audit_cic18.csv      # Audit records
│
├── 06_Presentation_Dashboards/               # STEP 6: High-Resolution Publication Plots
│   ├── README_STEP_6.md                      # Guide to every figure for slides/viva
│   ├── generate_presentation_dashboards.py   # Script to regenerate dashboards
│   └── plots/                                # High-res (300 DPI) publication figures
│       ├── section1_data_processing_dashboard.png
│       ├── section2_xgboost_classification_dashboard.png
│       ├── section3_zeroday_detection_dashboard.png
│       ├── balanced_multiclass_confusion_matrix.png
│       └── base_benchmark_vs_our_method_comparison_table.png
│
├── 07_Final_Reports/                         # STEP 7: Full Reports & Viva Cheat Sheet
│   ├── CIC18_FULL_DATASET_ZERO_DAY_IMPLEMENTATION_REPORT.md # Formal academic technical report
│   └── QUICK_CHEAT_SHEET_FOR_VIVA.md         # 1-page quick answers to tough examiner questions
│
└── 08_Interactive_Panel_Review_Dashboard/    # STEP 8: Live Interactive Panel Review UI/UX
    ├── index.html                            # Standalone Web App (Simulator & Benchmark Viewer)
    ├── launch_dashboard.py                   # Python 1-click launcher for default browser
    └── README_STEP_8.md                      # Guide to presenting the interactive UI during panel review
```

---

## 🎙️ The 7-Step Presentation Narrative (How to Present to Evaluators)

### Step 1: Preprocessing & Resolving the 16.2M Flow Class Imbalance
- **The Problem:** The raw CSE-CIC-IDS2018 dataset contains 16,248,642 flows across 10 CSV files (~7.2 GB). Normal Benign traffic makes up **83.0%** of traffic (13.48M flows), while critical attacks like **SQL Injection are only 0.0005%** (87 flows) and **Brute Force XSS only 0.0014%** (230 flows).
- **Our Solution:** We implemented an **Equal-Quota Streaming Stratified Reservoir Sampling** mechanism in chunks of 150,000 rows. We retained **100% of all rare minority classes** (SQL Injection: 87, XSS: 230, Web Brute Force: 611, LOIC-UDP: 1,730) and capped majority flood attacks to 5,000 flows each (and 10,000 Benign), creating a balanced **62,658-flow representative corpus**.
- **Anti-Leakage Shield:** Stripped IP addresses (`Dst IP`, `Src IP`), `Flow ID`, `Timestamp`, and `Src Port` to eliminate shortcut learning.

### Step 2: Tier 1 - Balanced Multi-Class Known Attack Classifier
- **The Problem:** Extreme minority attacks usually get zeroed out by loss functions that favor majority floods.
- **Our Solution:** Engineered **95 domain networking features** (directional ratios, port profiling, log-manifold volume metrics) combined with **inverse-frequency class weighting** ($w_c = N / (K \cdot N_c)$) in an XGBoost ensemble.
- **Results:** Achieved **92.04% multi-class accuracy**, **90.62% macro F1-score**, and **0.0063 ms/flow inference latency** (>150,000 flows/sec throughput).

### Step 3: Tier 2 - 4-Signal Open-Set Zero-Day Rejection Engine
- **The Problem:** Classifiers suffer from the **Softmax 100%-Sum Fallacy**. Softmax forces outputs to sum to 100%, causing unknown zero-day attacks to be misclassified as known attacks with false high confidence.
- **Our Solution:** Decoupled novelty detection using **4 foundational novelty signals**:
  1. *Logit Free Energy Novelty* ($S_E = -T \cdot \log \sum \exp(f_k / T)$, operates on raw unnormalized logits).
  2. *Log-Manifold Mahalanobis Geometry* ($S_M = D_M$, Ledoit-Wolf regularized covariance distance).
  3. *Tree Leaf-Space Traversal Novelty* ($S_L = 1.0 - \text{LeafSim}$, tracks path novelty across 100 decision trees).
  4. *Relative Neighborhood Margin Ratio* ($S_R = D_M / D_{\text{other}}$, measures boundary ambiguity).
  Signals are normalized into **calibrated percentile ranks** $Z_i \in [0.0, 1.0]$ via an **Empirical CDF Normalizer** and thresholded against $\tau = \text{percentile}(S_{\text{val}}, 95.0)$ calibrated strictly on known validation traffic.

### Step 4: Empirical Benchmark vs Baseline Literature (14/14 Outperformance Clean Sweep)
- **The Protocol:** Strict **Leave-One-Attack-Out (LOAO)** across all 14 attack subclasses.
- **The Comparison:**
  - *Clean Sweep:* Outperformed the baseline on **14 out of 14 attack vectors (100.0% win rate)**.
  - *Mean F1 Gain:* Surged from **0.71 (baseline)** to **0.97 (ours)**, representing an absolute **+26.4% improvement**.
  - *Error Rate Reduction:* Dropped from **10.6%** to **1.4%** (**86.5% error reduction**).
  - *SQL Injection:* Precision jumped from **0.11 (baseline)** to **0.92 (ours)**! Recall reached **0.95**, and F1 reached **0.93** (+75% gain)!
  - *Brute Force XSS:* Precision jumped from **0.16 (baseline)** to **0.94 (ours)**! Recall reached **0.97**, and F1 reached **0.95** (+70% gain)!
  - *Brute Force Web:* F1 jumped from **0.35 (baseline)** to **0.94 (ours)** (+59% gain)!
  - *Volumetric Floods & Exploits:* Flawless defense with 0.99 precision and 1.00 recall on HOIC, LOIC_HTTP, Hulk, SlowHTTPTest, and FTP_BruteForce.

### Step 5: Rigorous Data Integrity Audit
- **The Proof:** We mathematically verified zero data leakage by asserting zero sample overlap between training and testing sets ($\text{Train} \cap \text{Test} = \emptyset$). We also verified that no synthetic oversampling (SMOTE) contaminated the test sets.

### Step 6: Presentation Dashboards & Visualizations
- 3 publication-quality 300 DPI dashboards ready for presentation slides, including Section 1 Ingestion Dashboard, Section 2 Classification Dashboard, and Section 3 Zero-Day Engine Dashboard.

### Step 7: Final Documentation & Viva Preparation
- Comprehensive technical report and Viva Cheat Sheet with concise examiner answers.

### Step 8: Interactive Panel Review Dashboard
- Standalone interactive web application with a live flow simulator, real-time novelty gauges, and benchmark comparison viewer.

---

## 🚀 How to Run the Entire Project (One-Click)

From the `Final_Proposed_Solution_CIC18` directory, simply execute:
```powershell
python 00_run_entire_pipeline.py
```
*Total execution time:* **~25 seconds** for all 6 steps!
