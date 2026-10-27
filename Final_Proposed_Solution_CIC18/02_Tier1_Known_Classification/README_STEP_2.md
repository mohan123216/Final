# Step 2: Tier 1 - Balanced Multi-Class Intrusion Detection Classifier
> **Cost-Sensitive Gradient Boosted Decision Trees (XGBoost) on CSE-CIC-IDS2018**

---

## 🎯 Objective
To train a high-precision, low-latency Tier 1 classifier capable of accurately distinguishing all 15 network traffic classes (14 attack vectors + 1 Benign normal class), resolving the minority vulnerability where rare attacks (SQL Injection, XSS, Web Brute Force, LOIC-UDP) are typically overwhelmed by majority floods.

---

## 🏗️ Technical Architecture

1. **Domain Feature Engineering (95 Features):**
   - **Directional Traffic Ratios:**
     - Forward-to-Total Packet Ratio: `spkts_ratio = Tot Fwd Pkts / (Tot Pkts + ε)`
     - Forward-to-Total Payload Ratio: `sbytes_ratio = TotLen Fwd Pkts / (Tot Bytes + ε)`
     - Bytes per Packet Asymmetry: `bytes_per_pkt = Tot Bytes / (Tot Pkts + ε)`
     - Forward Byte Density: `fwd_bytes_per_spkt = TotLen Fwd Pkts / (Tot Fwd Pkts + ε)`
     - Backward Byte Density: `bwd_bytes_per_dpkt = TotLen Bwd Pkts / (Tot Bwd Pkts + ε)`
   - **Service Port Profiling:**
     - Well-Known Port Indicator: `is_dport_wellknown` ($< 1024$)
     - Web Services: `is_dport_http` ($80, 8080, 443$)
     - Remote Management: `is_dport_ssh` ($22$), `is_dport_ftp` ($20, 21$)
     - Domain Resolution: `is_dport_dns` ($53$)
   - **Log-Manifold Volume Stabilization:**
     - Natural log transformations $\log(1 + x)$ on heavy-tailed distributions (`Flow Duration`, `Tot Fwd Pkts`, `Tot Bwd Pkts`, `TotLen Fwd Pkts`, `TotLen Bwd Pkts`, `Flow Byts/s`, `Flow Pkts/s`).

2. **Inverse-Frequency Class Weighting:**
   - Standard loss functions prioritize majority flood attacks.
   - We assign sample weights inversely proportional to class frequencies:
     $$w_c = \frac{N}{K \cdot N_c}$$
   - This heavily penalizes misclassifications on extreme minority attacks like SQL Injection ($N_c = 87$) and XSS ($N_c = 230$), ensuring near-perfect recall and precision.

3. **Validation & Evaluation Protocol:**
   - Strict stratified 80% train (50,126 flows) / 20% test (12,532 flows) partition.
   - Evaluates multi-class accuracy, macro F1-score, weighted F1-score, per-class metrics, and confusion matrix.
