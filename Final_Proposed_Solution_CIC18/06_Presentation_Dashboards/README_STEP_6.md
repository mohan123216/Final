# Step 6: Presentation Dashboards & Visualizations Guide
> **High-Resolution (300 DPI) Publication Figures for Slides, Project Defense, and Viva**

---

## 🎨 Master Visual Dashboards

### 1. `section1_data_processing_dashboard.png`
- **Purpose:** Proves physical benchmark ingestion scale and data hygiene to evaluators.
- **Card 1 (Top-Left):** Raw Benchmark Scale (16.2M flows, 10 CSVs, ~7.2 GB, extreme imbalance).
- **Card 2 (Top-Right):** Data Leakage Shield (IP stripping, timestamp removal, infinity imputation, 100% minority protection).
- **Card 3 (Bottom-Left):** Curated 62,658-Flow Corpus Class Distribution Bar Chart.
- **Card 4 (Bottom-Right):** Complete Preprocessing Pipeline Summary Table.

### 2. `section2_xgboost_classification_dashboard.png`
- **Purpose:** Demonstrates Tier 1 Multi-Class Classification discriminative power.
- **Card 1 (Top-Left):** Model Architecture & Global Metrics (92.04% Accuracy, 90.62% Macro F1, 0.0063 ms latency).
- **Card 2 (Top-Right):** Top 15 Feature Importance (Directional ratios, port profiling, log-manifold volumes).
- **Card 3 (Bottom-Left):** Per-Class F1-Scores across all 15 classes.
- **Card 4 (Bottom-Right):** Held-Out Test Set Confusion Metrics Table.

### 3. `section3_zeroday_detection_dashboard.png`
- **Purpose:** Showcases Tier 2 Four-Signal Open-Set Novelty Rejection Mechanism.
- **Card 1 (Top-Left):** 4 Novelty Equations (Free Energy, Mahalanobis, Leaf-Space, Relative Margin).
- **Card 2 (Top-Right):** Nonparametric Empirical CDF Calibration & Operating Threshold ($\tau$).
- **Card 3 (Bottom-Left):** Zero-Day Detection F1 Comparison vs. SOTA Baseline IDS.
- **Card 4 (Bottom-Right):** Comprehensive LOAO Zero-Day Benchmark Table.
