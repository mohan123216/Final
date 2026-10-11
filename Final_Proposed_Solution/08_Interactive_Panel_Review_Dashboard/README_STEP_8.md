# Step 8: Interactive Panel Review & Zero-Day Rejection Visualizer

## 📌 Executive Summary
This folder contains the **Interactive Presentation & Defense Console** designed specifically for your **Panel Review, Project Defense, and Viva Examination**.

It provides a high-contrast, minimalist **Monochrome (Black & White)** visual user experience to explain every single stage of your project with live mathematical trace audits.

---

## 🖥️ What the Interactive Dashboard Displays

1. **End-to-End Pipeline Architecture (Tab 01):**
   - Full 74 CSV files ingestion (73,370,443 flows, ~15.3 GB).
   - Equal-Quota Streaming Reservoir Sampling (100% Normal retained, 100% Theft retained, 10k flood caps).
   - Strict 70% Train, 15% Validation, 15% Test partition with zero-leakage row-ID assertion proof.
   - Tier 1: 35 domain networking features, balanced XGBoost classifier (98.97% accuracy).
   - Tier 2: 4 Foundational Novelty Signals (Free Energy, Mahalanobis, Leaf-Space, Relative Margin).
   - Percentile Cutoff Rejection Gate ($\tau = 0.8407$).

2. **Live Flow Rejection Simulator (Tab 02):**
   - **Clickable Real Flow Presets:**
     - *Preset 1:* Benign Normal MQTT IoT Flow $\implies$ Accepted as Known ($S_{\text{unified}} = 0.186 \le \tau$).
     - *Preset 2:* Known DDoS TCP Flood $\implies$ Accepted as Known ($S_{\text{unified}} = 0.215 \le \tau$, routed to Tier-1 blocklist).
     - *Preset 3:* Held-Out Zero-Day: Data Exfiltration $\implies$ **REJECTED AS ZERO-DAY NOVEL THREAT** ($S_{\text{unified}} = 0.949 > \tau$).
     - *Preset 4:* Held-Out Zero-Day: Service Scan $\implies$ **REJECTED AS ZERO-DAY NOVEL THREAT** ($S_{\text{unified}} = 0.887 > \tau$).
   - **Live Step-by-Step Mathematical Substitution:**
     - Stage 1: XGBoost Booster Margins & Probabilities.
     - Stage 2: Raw Signals Extraction ($S_E, S_M, S_L, S_R$).
     - Stage 3: Empirical CDF `searchsorted` mapping to Percentile Ranks $Z_i \in [0, 1]$.
     - Stage 4: Multi-Signal Fusion Formula ($w = [0.40, 0.30, 0.15, 0.15]$).
     - Stage 5: Threshold comparison ($S_{\text{unified}} > \tau \implies$ Rejection).
   - **Interactive Sliders:** Allows reviewers to manipulate signal values and watch the decision gate react in real time.

3. **The 4 Novelty Signals & Mathematical Formulations (Tab 03):**
   - Deep dive into Logit Free Energy, Log-Manifold Ledoit-Wolf Mahalanobis, Leaf-Space Traversal, and Relative Ratio.

4. **ECDF Percentile & Threshold Calibration (Tab 04):**
   - Mathematical proof of why Empirical CDF ranks are used.
   - How $\tau = 0.8407$ was chosen at the 95th percentile of known validation traffic.

5. **Academic Table 9 Proof (Tab 05):**
   - Head-to-head outperformance table vs ACM TOPS 2025 across all 10 attack subclasses.
   - Highlights the Data Exfiltration breakthrough ($0.08 \rightarrow 0.97$ Precision).

6. **Panel Defense Q&A Cheat Sheet (Tab 06):**
   - Rapid 1-click answers to the top panel questions.

---

## 🚀 How to Launch the Dashboard

### Option A: Via Python Launcher
From this folder, run:
```powershell
python launch_dashboard.py
```

### Option B: Open Directly in Any Web Browser
Simply double-click [`index.html`](file:///d:/p01/Final_Proposed_Solution/08_Interactive_Panel_Review_Dashboard/index.html) or open it in Chrome, Edge, Brave, or Firefox.  
- **100% Offline & Self-Contained:** Zero dependencies, no internet required, loads instantaneously!
