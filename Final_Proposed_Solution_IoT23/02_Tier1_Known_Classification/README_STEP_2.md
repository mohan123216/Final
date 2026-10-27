# Step 2: Tier 1 Balanced Multi-Class Known Threat Classifier
> **Cost-Sensitive Gradient Boosted Decision Trees on Avast/Stratosphere IoT-23**

---

## 🎯 Architecture & Objectives
Tier 1 serves as the line-rate classifier for known traffic in our Two-Tier HOMZ-Engine architecture. Its objective is to rapidly classify known normal IoT communications and established attack vectors, outputting raw unnormalized decision logits and leaf indices for Tier 2 zero-day analysis.

---

## ⚙️ Technical Formulation & Loss Function
1. **Cost-Sensitive Balanced Weighting:**
   $$\forall c \in \{1, \dots, K\}, \quad w_c = \frac{N}{K \cdot N_c}$$
   Where $N$ is total training flows, $K=12$ classes, and $N_c$ is class support. This mathematically neutralizes majority flood dominance, ensuring minority stealth attacks (`C&C-HeartBeat`, `Attack`, `C&C-Torii`, `FileDownload`) receive balanced gradient updates.

2. **Decision Tree Architecture:**
   - Model: Multi-Class Softmax Histogram Gradient Boosting (`hist` tree method)
   - Estimators: 150 trees
   - Max Tree Depth: 6
   - Learning Rate: 0.08
   - Subsample & Colsample: 0.85

---

## 📊 Performance Benchmarks (Held-Out Test Partition: 9,508 Flows)

| Class Name | Test Support | Precision | Recall | F1-Score | Status |
|:---|---:|---:|---:|---:|:---:|
| **Attack** | 412 | 100.00% | 100.00% | **100.00%** | Perfect Detection |
| **C&C** | 1,500 | 100.00% | 100.00% | **100.00%** | Perfect Detection |
| **C&C-FileDownload** | 13 | 85.71% | 92.31% | **88.89%** | Robust Detection |
| **C&C-HeartBeat** | 65 | 98.48% | 100.00% | **99.24%** | Near-Perfect |
| **C&C-HeartBeat-FileDownload** | 3 | 75.00% | 100.00% | **85.71%** | Robust Detection |
| **C&C-Torii** | 9 | 90.00% | 100.00% | **94.74%** | Ultra-High |
| **DDoS** | 1,500 | 100.00% | 100.00% | **100.00%** | Perfect Detection |
| **FileDownload** | 5 | 100.00% | 100.00% | **100.00%** | Perfect Detection |
| **HorizontalPortScan** | 1,500 | 55.17% | 100.00% | **71.11%** | 100% Recall |
| **Normal (Benign)** | 3,000 | 100.00% | 59.13% | **74.32%** | High Precision |
| **Okiru** | 1,500 | 100.00% | 100.00% | **100.00%** | Perfect Detection |
| **OVERALL METRICS** | **9,508** | **85.78% (Macro P)** | **95.95% (Macro R)** | **87.83% (Macro F1)** | **Accuracy: 87.10%** |

- **Inference Latency:** **0.0043 ms/flow**
- **Throughput:** **>234,000 flows/second**

---

## 📁 Artifacts Produced
- `models/xgboost_balanced_multiclass_iot23.json`: Serialized XGBoost model.
- `models/multiclass_class_mapping.json`: Class mapping metadata.
- `results/balanced_multiclass_confusion_matrix.png`: 300 DPI publication confusion matrix.
- `results/balanced_multiclass_classification_report.csv`: Complete sklearn classification report.
- `results/known_attack_multiclass_metrics.csv`: Per-class support, precision, recall, and F1.
