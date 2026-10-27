# Step 8: Interactive Review & Defense Dashboard
> **Live Single-Page Web Dashboard for Avast / Stratosphere CTU IoT-23**

---

## 🎯 Purpose & Capabilities
The interactive panel dashboard (`index.html`) is designed for viva presentations, committee demonstrations, and live examiner interactions.

### Features:
1. **Interactive Flow Simulator:** Select any attack subclass (`HorizontalPortScan`, `DDoS`, `Okiru`, `C&C`, `Attack`, `C&C-HeartBeat`, `C&C-Torii`, `FileDownload`, or `Benign Normal`) to watch the live classification handoff through Tier 1 and Tier 2.
2. **KPI Scorecard:** Real-time visibility into Multi-Class Accuracy, Zero-Day F1-Score, Benign Specificity, and Line-Rate Latency.
3. **Academic Benchmark Table:** Side-by-side comparison of baseline literature vs. our HOMZ-Engine across all 10 attack vectors.
4. **Zero-Leakage Certificate Badge:** Displays mathematical proof of partition independence ($\text{Train} \cap \text{Test} = \emptyset$).

---

## 🚀 How to Run the Dashboard
Simply double-click `index.html` or run:
```bash
python -m http.server 8080 --directory "c:\Iot_bot\Final_Proposed_Solution_IoT23\08_Interactive_Panel_Review_Dashboard"
```
Then navigate to `http://localhost:8080` in your web browser.
