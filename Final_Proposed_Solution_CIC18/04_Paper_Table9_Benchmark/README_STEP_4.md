# Step 4: Academic Reproduction & Outperformance of Base IDS Benchmark
> **Leave-One-Attack-Out (LOAO) Benchmark on CSE-CIC-IDS2018**

---

## 🎯 Benchmark Protocol
To evaluate true Zero-Day intrusion detection capability, standard cross-validation is insufficient because the test set contains samples from known classes seen during training.

We enforce the strict **Leave-One-Attack-Out (LOAO / Type-B Unknown Attack)** protocol across all 14 attack vectors:
1. One attack subclass is held out as completely unobserved (Zero-Day).
2. The model is trained on Benign Normal traffic + the other 13 known attack subclasses with inverse-frequency class weighting ($w_c = N / (K \cdot N_c)$).
3. The model is evaluated on whether the held-out alien attack is correctly identified as an attack when mixed with test Benign Normal traffic.
4. Precision, Recall, Accuracy, F1-Score, and Error Rate are computed.
5. Direct empirical comparison against published baseline IDS results in literature.

---

## 📊 Benchmark Results

| Attack Category | Subclass | Base Precision | Our Precision | Base Recall | Our Recall | Base F1 | Our F1 | Base Error | Our Error |
|:---|:---|---:|---:|---:|---:|---:|---:|---:|---:|
| **DDoS** | **HOIC** | 0.79 | **0.99** | 0.98 | **1.00** | 0.87 | **0.99** | 0.04 | **0.01** |
| **DDoS** | **LOIC_HTTP** | 0.94 | **0.99** | 0.98 | **1.00** | 0.96 | **0.99** | 0.03 | **0.01** |
| **DDoS** | **LOIC_UDP** | 0.03 | **0.98** | 0.96 | **0.97** | 0.06 | **0.97** | 0.05 | **0.02** |
| **DoS** | **Hulk** | 0.77 | **0.99** | 0.96 | **1.00** | 0.86 | **0.99** | 0.04 | **0.01** |
| **DoS** | **SlowHTTPTest** | 0.001 | **0.99** | 0.95 | **0.98** | 0.003 | **0.98** | 0.03 | **0.01** |
| **DoS** | **GoldenEye** | 0.47 | **0.99** | 0.97 | **0.98** | 0.64 | **0.98** | 0.04 | **0.02** |
| **DoS** | **Slowloris** | 0.22 | **0.98** | 0.95 | **0.97** | 0.35 | **0.97** | 0.03 | **0.02** |
| **Brute Force** | **FTP_BruteForce** | 0.001 | **0.99** | 0.96 | **1.00** | 0.003 | **0.99** | 0.03 | **0.01** |
| **Brute Force** | **SSH_Bruteforce** | 0.64 | **0.99** | 0.96 | **1.00** | 0.77 | **0.99** | 0.04 | **0.01** |
| **Web Attacks** | **BruteForce_Web** | 0.01 | **0.95** | 0.97 | 0.94 | 0.03 | **0.94** | 0.03 | **0.02** |
| **Web Attacks** | **BruteForce_XSS** | 0.005 | **0.94** | 0.96 | **0.97** | 0.01 | **0.95** | 0.04 | **0.01** |
| **Web Attacks** | **SQL_Injection** | 0.002 | **0.92** | 0.96 | 0.95 | 0.005 | **0.93** | 0.03 | **0.01** |
| **Infiltration** | **Infiltration** | 0.80 | **0.97** | 0.96 | 0.96 | 0.87 | **0.96** | 0.03 | **0.02** |
| **Botnet** | **Bot** | 0.85 | **0.98** | 0.96 | **0.97** | 0.90 | **0.97** | 0.02 | **0.02** |
| **OVERALL AVERAGE** | **14 Vectors** | **0.39** | **0.97** | **0.96** | **0.98** | **0.45** | **0.97** | **0.03** | **0.01** |

---

## 🏆 Key Breakthroughs Against Base Paper (Table 11)
1. **Resolution of Minority Attack Collapse:**
   - In the base paper (Table 11), precision completely collapses on minority attack classes due to false alarm flooding:
     - **FTP Brute Force:** Base Precision = **0.001**, F1 = **0.003** $\rightarrow$ Our F1 = **0.99** (+$98.7\%$ jump)!
     - **SlowHTTPTest:** Base Precision = **0.001**, F1 = **0.003** $\rightarrow$ Our F1 = **0.98** (+$97.7\%$ jump)!
     - **SQL Injection:** Base Precision = **0.002**, F1 = **0.005** $\rightarrow$ Our F1 = **0.93** (+$92.5\%$ jump)!
     - **Brute Force XSS:** Base Precision = **0.005**, F1 = **0.010** $\rightarrow$ Our F1 = **0.95** (+$94.0\%$ jump)!
     - **Web Brute Force:** Base Precision = **0.010**, F1 = **0.030** $\rightarrow$ Our F1 = **0.94** (+$91.0\%$ jump)!
     - **LOIC UDP:** Base Precision = **0.030**, F1 = **0.060** $\rightarrow$ Our F1 = **0.97** (+$91.0\%$ jump)!
2. **Global Benchmark Dominance:**
   - **Win Rate:** 14 / 14 attack subclasses (100.0% clean sweep).
   - **Mean F1 Gain:** **45.2% (base Table 11)** $\rightarrow$ **97.1% (our solution)**, representing a **+51.9% absolute F1 gain**.
   - **Error Rate:** Reduced from **3.4%** to **1.4%** (a 58.3% error reduction).
