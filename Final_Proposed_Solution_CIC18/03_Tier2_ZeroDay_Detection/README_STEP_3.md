# Step 3: Tier 2 - 4-Signal Open-Set Zero-Day Rejection Engine
> **Open-Set Rejection & Anomaly Isolation on CSE-CIC-IDS2018**

---

## 🎯 The Core Research Problem
Traditional intrusion detection systems rely on Softmax classification. When an unobserved, alien attack vector (Zero-Day) appears in the network stream:
- The Softmax function is mathematically constrained to sum to $1.0$ ($100\%$).
- This creates the **Softmax Overconfidence Fallacy**, forcing the model to classify an unknown attack as a known class with high confidence.
- Baselines achieve less than 35% detection on novel attack families.

---

## 🔬 The 4 Foundational Novelty Signals

Our Tier 2 engine decouples classification from novelty detection through 4 distinct signals:

### 1. Logit Free Energy Novelty ($S_E$)
$$E(x) = -T \cdot \log \sum_{k=1}^K \exp\left(\frac{f_k(x)}{T}\right)$$
Operates directly on raw, unnormalized XGBoost booster logits ($f_k(x)$), bypassing Softmax normalization. For in-distribution samples, logits for the true class are high, yielding low Free Energy. For alien out-of-distribution zero-day flows, logits across all classes are suppressed, producing a high Free Energy score.

### 2. Log-Manifold Ledoit-Wolf Mahalanobis Distance ($S_M$)
$$D_M(x) = \min_{c} \sqrt{(z(x) - \mu_c)^T \Sigma_c^{-1} (z(x) - \mu_c)}$$
Measures geometric deviation from known class centroids in a normalized log-manifold space using Ledoit-Wolf covariance shrinkage.

### 3. Decision Tree Leaf-Space Traversal Novelty ($S_L$)
$$S_L(x) = 1.0 - \frac{1}{T} \sum_{t=1}^T P_t(\text{LeafID}_t(x) \mid c^*)$$
Evaluates structural pathway novelty across all 100 decision trees in the ensemble. Zero-day attacks trigger rare or previously unseen split combinations.

### 4. Relative Neighborhood Margin Ratio ($S_R$)
$$R(x) = \frac{D_M(x, c^*)}{D_M(x, c_{\text{other}}) + \epsilon}$$
Quantifies boundary ambiguity between the top predicted class and the nearest competitor centroid.

---

## 📐 Non-Parametric Empirical CDF Calibration & Fusion

To combine disparate physical scales without parametric assumptions:
1. **Empirical CDF Calibration:**
   $$Z_i(x) = F_i(S_i(x)) = P(S_{\text{val}} \le S_i(x)) \in [0.0, 1.0]$$
   Computed via `np.searchsorted` fitted strictly on known validation traffic.
2. **Multi-Signal Fusion:**
   $$S_{\text{unified}}(x) = \sum_{i=1}^4 w_i \cdot Z_i(x)$$
   Optimal weights: $w = [0.40 \text{ Energy}, 0.30 \text{ Mahalanobis}, 0.15 \text{ Leaf}, 0.15 \text{ Relative}]$.
3. **Operational Decision Rule:**
   $$\tau = \text{percentile}(S_{\text{val}}, 95.0)$$
   $$\text{Decision}(x) = \begin{cases} \text{REJECT as Zero-Day Attack}, & \text{if } S_{\text{unified}}(x) > \tau \\ \text{ACCEPT as Known Traffic}, & \text{if } S_{\text{unified}}(x) \le \tau \end{cases}$$
