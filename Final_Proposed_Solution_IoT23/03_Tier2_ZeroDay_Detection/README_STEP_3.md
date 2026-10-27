# Step 3: Tier 2 Multi-Signal Open-Set Zero-Day Rejection Engine
> **Avast / Stratosphere CTU IoT-23 Benchmark**

---

## 🎯 Architecture & Objectives
Standard machine learning classifiers enforce a **Closed-Set Assumption**: every input flow must be assigned to one of the pre-defined training classes. When presented with an unseen alien attack, the model arbitrarily maps it to a known class with false high confidence (the Softmax 100%-sum fallacy).

Tier 2 implements a **4-Signal Open-Set Rejection Engine**:
1. **Signal 1: Logit Free Energy Novelty ($S_E$):**
   $$E(x) = -T \cdot \log \sum_{k=1}^K \exp(f_k(x) / T)$$
   Computed directly on raw unnormalized booster margins, growing monotonically as inputs deviate from training clusters.
2. **Signal 2: Log-Manifold Ledoit-Wolf Mahalanobis Distance ($S_M$):**
   $$D_M(x) = \min_{c} \sqrt{(z(x) - \mu_c)^T \Sigma_c^{-1} (z(x) - \mu_c)}$$
   Uses regularized covariance shrinkage on log-stabilized volume and rate features.
3. **Signal 3: Tree Leaf-Space Traversal Novelty ($S_L$):**
   $$S_{\text{leaf}}(x) = 1.0 - \text{LeafSim}(x, c)$$
   Quantifies structural tree partitioning novelty across all decision paths.
4. **Signal 4: Relative Margin Distance Ratio ($S_R$):**
   $$R(x) = \frac{D_M(x, c_{\text{nearest}})}{D_M(x, c_{\text{second\_nearest}}) + \epsilon}$$
   Measures boundary ambiguity between known class clusters.

---

## ⚙️ Calibration & Thresholding Protocol
1. **Empirical CDF Calibration:** Non-parametrically maps each raw signal to a uniform percentile rank $Z_i \in [0.0, 1.0]$ using empirical cumulative distribution functions on known validation flows.
2. **Multi-Signal Fusion:**
   $$S_{\text{unified}}(x) = 0.40 \cdot Z_E + 0.30 \cdot Z_M + 0.15 \cdot Z_L + 0.15 \cdot Z_R$$
3. **Calibrated Threshold ($\tau$):** Set at the $95.0^{\text{th}}$ percentile of known validation traffic, ensuring a guaranteed $\le 5\%$ false positive rate on benign normal operations.
4. **Zero-Day Decision Rule:**
   $$\text{Decision}(x) = \begin{cases} \text{REJECT as Zero-Day Novel Threat}, & \text{if } S_{\text{unified}}(x) > \tau \\ \text{ACCEPT as Known Traffic}, & \text{otherwise} \end{cases}$$

---

## 📁 Artifacts Produced
- `results/zero_day_detection_standard_metrics.csv`: Standard binary metrics on held-out zero-day scenarios.
- `results/unknown_attack_zeroday_metrics.csv`: Detailed isolation and neutralization statistics for each held-out threat.
- `results/zero_day_standard_metrics_table_and_chart.png`: 300 DPI publication table and bar chart graphic.
