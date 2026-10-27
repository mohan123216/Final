# Quick Cheat Sheet for Viva & Evaluator Examination
> **CSE-CIC-IDS2018 Zero-Day Intrusion Detection System (HOMZ-Engine)**

---

### Q1: What dataset did you use, and what was the raw data challenge?
**Answer:**  
We evaluated on the complete **CSE-CIC-IDS2018 benchmark**, consisting of **10 CSV files totaling 16,248,642 network flows (~7.2 GB)**. The dataset exhibits extreme class imbalance: Benign normal traffic represents 83% of the dataset (13.48M flows), while critical minority attacks like **SQL Injection constitute only 87 flows (0.0005%)** and **Brute Force XSS only 230 flows (0.0014%)**. Naive random sampling would wipe out rare threats completely.

---

### Q2: How did you solve the massive data scale and class imbalance?
**Answer:**  
We implemented an **Equal-Quota Streaming Stratified Reservoir Sampling** mechanism. We streamed the 10 CSVs in chunks of 150,000 rows, retaining **100% of all rare minority classes** (SQL Injection: 87, XSS: 230, Web Brute Force: 611, LOIC-UDP: 1,730) and enforcing a strict quota cap of 5,000 flows each on majority attacks (and 10,000 on Benign), producing a clean, balanced **62,658-flow representative research corpus**. Peak RAM was kept below 1.5 GB.

---

### Q3: How did you prevent Data Leakage?
**Answer:**  
We enforced three strict anti-leakage principles:
1. **Feature Exclusion:** Stripped all IP addresses (`Dst IP`, `Src IP`), `Flow ID`, `Src Port`, and `Timestamp` so the model cannot memorize subnet topologies or temporal patterns.
2. **Mathematical Overlap Assertion:** Assigned immutable integer `row_id` values and proved $\text{Train} \cap \text{Test} = \emptyset$ (zero sample overlap).
3. **No Synthetic Test Contamination:** No SMOTE or synthetic samples were ever added to the test sets.

---

### Q4: What is the "Softmax Overconfidence Fallacy"?
**Answer:**  
Standard deep neural networks and multi-class classifiers use the Softmax function at their output layer:
$$P(y = c \mid x) = \frac{\exp(f_c(x))}{\sum_{k=1}^K \exp(f_k(x))}$$
Because Softmax is mathematically constrained to sum to $1.0$ ($100\%$), when an unobserved, alien attack vector (Zero-Day) appears in the network stream, the model is forced to assign high probability to one of the known classes. This leads to severe false confidence and low zero-day catch rates (<35%).

---

### Q5: How does your Tier 2 Zero-Day Engine catch unknown attacks?
**Answer:**  
We decouple novelty detection from classification using **4 foundational novelty signals**:
1. **Logit Free Energy Novelty ($S_E$):** Computes $E(x) = -T \log \sum \exp(f_k(x) / T)$ on raw unnormalized logits. Alien threats have suppressed logits across all classes, generating high free energy.
2. **Log-Manifold Mahalanobis Distance ($S_M$):** Computes distance to known class centroids using Ledoit-Wolf regularized covariance shrinkage.
3. **Tree Leaf-Space Traversal Novelty ($S_L$):** Tracks path novelty across all 100 decision trees ($1.0 - \text{LeafSim}$).
4. **Relative Neighborhood Margin Ratio ($S_R$):** Detects boundary ambiguity ($D_M / D_{\text{other}}$).
Signals are calibrated into uniform percentile ranks $Z_i \in [0.0, 1.0]$ via an **Empirical CDF Normalizer** and thresholded at $\tau = \text{percentile}(S_{\text{val}}, 95.0)$ calibrated strictly on known validation traffic.

---

### Q6: How did you evaluate Zero-Day detection capability?
**Answer:**  
We enforced the rigorous **Leave-One-Attack-Out (LOAO)** protocol across all 14 attack subclasses. For each test, one attack was held out as completely unobserved, the model was trained on the remaining known classes, and tested on whether the held-out alien attack was rejected as an anomaly when mixed with test Benign Normal traffic.

---

### Q7: What were your benchmark results compared to literature?
**Answer:**  
- **Minority Attack Precision Collapse in Literature (Base Paper Table 11):** In the base paper, precision collapsed catastrophically on minority attacks: FTP Brute Force (**0.001**), SlowHTTPTest (**0.001**), SQL Injection (**0.002**), XSS (**0.005**), Web Brute Force (**0.010**), and LOIC UDP (**0.030**), bringing baseline F1 down to **0.003 - 0.060**!
- **Our Proposed Solution:** Achieved **0.92 - 0.99 precision**, **0.94 - 1.00 recall**, and **0.93 - 0.99 F1-score** across these exact same minority and web attacks.
- **Overall Clean Sweep:** Achieved **14/14 wins**, jumping overall average F1 from **45.2% (base Table 11)** to **97.1% (ours)** (+51.9% absolute jump) and cutting error rate from **3.4%** down to **1.4%**.
- **Tier 1 Classifier:** Achieved **92.04% multi-class accuracy** with **0.0063 ms/flow** latency (>150,000 flows/sec throughput).
