# Step 8: Interactive Defense Panel Review Dashboard Guide
> **Interactive Web Application for Project Defense, Live Viva & Panel Review**

---

## 🎯 Overview
This interactive dashboard is a standalone, client-side web application designed to demonstrate the **HOMZ-Engine** during a live evaluation, viva examination, or conference presentation on the **CSE-CIC-IDS2018 benchmark**.

---

## 🚀 How to Launch the Dashboard

### One-Click Launch (Python Launcher):
```powershell
python launch_dashboard.py
```
This automatically starts an HTTP server on port 8085 and opens `http://localhost:8085/index.html` in your default browser.

Or simply double-click `index.html` to open it locally in any modern browser!

---

## 🖥️ Interactive Features for Presenters

1. **Interactive Live Flow Simulator:**
   - Click on any attack subclass (e.g. `SQL_Injection`, `BruteForce_XSS`, `HOIC`, `Hulk`, `Bot`) or `Benign Normal` to see the live classification handoff.
   - Click on **⚠️ Alien Zero-Day Exploit** to watch the 4-signal novelty bars surge past the operating threshold ($\tau = 0.8506$), triggering an immediate **ZERO-DAY REJECTED** quarantine alert!
2. **Leave-One-Attack-Out Academic Benchmark Table:**
   - Displays Precision, Recall, F1-Score, and Error Rate compared directly with published SOTA baselines.
3. **Master System Architecture Diagram:**
   - Walk evaluators through the two-tier decoupled novelty formulation.
4. **Viva Cheat Sheet Tab:**
   - Quick answers to tough examiner questions on data leakage, class imbalance, and the Softmax overconfidence fallacy.
