# Step 6: Publication-Grade Presentation Dashboards
> **Visual Presentation Artifacts for Avast / Stratosphere CTU IoT-23**

---

## 🎯 Purpose & Design
Step 6 generates comprehensive, high-resolution (300 DPI) visual presentation dashboards specifically tailored for project defense, academic papers, and panel reviews.

---

## 📊 Generated Dashboard Figures

### 1. Section 1: Data Ingestion & Preprocessing Dashboard
- **File:** `plots/section1_data_processing_dashboard.png`
- **Contents:**
  - Card 1: Ground Truth Class Distribution across the 31,692-flow research corpus.
  - Card 2: Threat Vector Category Representation pie chart.
  - Card 3: Bro/Zeek 35-dimensional feature engineering pipeline.
  - Card 4: Complete data pipeline audit summary table.

### 2. Section 2: Tier 1 XGBoost Classification Dashboard
- **File:** `plots/section2_xgboost_classification_dashboard.png`
- **Contents:**
  - Card 1: Per-class precision and recall on held-out test traffic.
  - Card 2: Line-rate inference latency comparison ($0.0043\text{ ms/flow}$ vs. standard baselines).
  - Card 3: Training loss convergence trajectory and test accuracy curve.
  - Card 4: Complete confusion metrics and test support table.

### 3. Section 3: Tier 2 Zero-Day Threat Isolation Dashboard
- **File:** `plots/section3_zeroday_detection_dashboard.png`
- **Contents:**
  - Card 1: Open-set threat separation histogram (Known vs. Zero-Day traffic).
  - Card 2: Multi-signal empirical CDF calibration curves and operating threshold ($\tau = 0.932$).
  - Card 3: Leave-One-Attack-Out (LOAO) F1-score comparison vs. baseline literature.
  - Card 4: Empirical Zero-Day LOAO comprehensive benchmark comparison table.
