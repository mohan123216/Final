# Quick Viva Cheat Sheet: IoT-23 Zero-Day IDS Defense
> **Fast Answers for Project Examiners, Reviewers, and Viva Panels**

---

### Q1: What dataset did you use and what makes it challenging?
**Answer:**  
We evaluated on the **Avast / Stratosphere CTU IoT-23 benchmark**, comprising over 50 GB of real-world IoT network flow traffic across 23 distinct malware scenarios (Mirai, Okiru, Kenjiro, Torii, Hide and Seek, Muhstik, Hakku, and Honeypot benign traffic). The core challenge is severe class imbalance and the presence of stealthy Command and Control (C&C) beacons and payload downloads hidden within millions of volumetric port scans and floods.

---

### Q2: What is your core architecture?
**Answer:**  
We implemented a **Two-Tier Hybrid Open-Set Multi-Signal Architecture (HOMZ-Engine)**:
- **Tier 1:** Cost-sensitive balanced XGBoost classifier for line-rate routing of known traffic ($0.0043\text{ ms/flow}$ latency).
- **Tier 2:** 4-Signal Open-Set Rejection Engine that combines **Logit Free Energy**, **Log-Manifold Ledoit-Wolf Mahalanobis Distance**, **Tree Leaf Novelty**, and **Margin Distance Ratio** calibrated non-parametrically via empirical CDF percentiles.

---

### Q3: How did you prevent data leakage and shortcut learning?
**Answer:**  
1. **Feature Exclusion:** Permanently stripped IP addresses (`id.orig_h`, `id.resp_h`), flow identifiers (`uid`), timestamps (`ts`), and source ports (`id.orig_p`), forcing the models to learn protocol dynamics rather than memorizing host IP addresses.
2. **Mathematical Overlap Assertion:** Assigned immutable integer `row_id` values and proved $\text{Train} \cap \text{Test} = \emptyset$ (zero sample overlap).
3. **Zero Synthetic Data:** 0% synthetic sample injection (no SMOTE in test sets).

---

### Q4: Why is standard Softmax insufficient for Zero-Day detection?
**Answer:**  
Standard Softmax normalizes logits such that $\sum_{k=1}^K P(k|x) = 1.0$. When presented with an unseen alien threat, the probabilities are forced to sum to 100%, causing the classifier to make high-confidence incorrect predictions (the Softmax 100%-sum overconfidence fallacy). Our Tier 2 uses **Logit Free Energy** and **Mahalanobis geometry** on unnormalized margins, which grow monotonically as inputs deviate from training distributions.

---

### Q5: How did you evaluate Zero-Day detection capability?
**Answer:**  
We enforced the rigorous **Leave-One-Attack-Out (LOAO)** protocol across all 10 attack subclasses. For each test, one attack was held out as completely unobserved, the model was trained on the remaining known classes, and tested on whether the held-out alien attack was rejected as an anomaly when mixed with test Benign Normal traffic.

---

### Q6: What were your benchmark results compared to literature?
**Answer:**  
- **Stealth Attack Resilience:** In baseline literature, C&C beaconing (`C&C-HeartBeat`), modular botnets (`C&C-Torii`), and staging downloads (`FileDownload`) suffer precision collapse down to **0.04 - 0.18** with F1-scores of only **0.07 - 0.26**. Our method achieves **0.91 - 0.99 F1-score**!
- **Overall Clean Sweep:** Achieved **10/10 wins (100% clean sweep)**, jumping overall average F1 from **45.9% (baseline)** to **97.5% (ours)** (+51.6% absolute gain) and cutting error rate from **7.8%** down to **0.3%**.
- **Tier 1 Classifier:** Achieved **87.10% multi-class accuracy** with **0.0043 ms/flow** latency (>234,000 flows/sec throughput).
