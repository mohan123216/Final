# Step 1: Streaming Ingestion & Stratified Reservoir Sampling
> **CSE-CIC-IDS2018 Benchmark (16,248,642 Flows across 10 Raw CSV Files, ~7.2 GB)**

---

## 🎯 Objective
To stream the entire massive 10-file CSE-CIC-IDS2018 dataset, resolve its extreme class imbalance without synthetic data distortion, eliminate all sources of data leakage, and produce a balanced, reproducible **62,658-flow research corpus**.

---

## ⚙️ Technical Highlights

1. **Chunked Streaming Pipeline:**
   - Ingests raw CSV files (`02-14-2018.csv` to `03-02-2018.csv`) in memory-bounded blocks of 150,000 rows.
   - Enforces early file termination once targeted quotas are satisfied, reducing I/O latency while reading all 10 dates.
   - Peak RAM usage remains below **1.5 GB**.

2. **Rigorous Data Cleaning & Sanitation:**
   - Detects and drops corrupted header repetition records (`Label == 'Label'`).
   - Coerces non-numeric values to floating point numbers via `pd.to_numeric(errors='coerce').fillna(0.0)`.
   - Resolves the infamous CIC-IDS2018 zero-division bug where `Flow Byts/s` and `Flow Pkts/s` evaluate to `+inf` or `-inf`, replacing infinities with `0.0`.

3. **Anti-Leakage Feature Exclusion Policy:**
   - Drops `Dst IP`, `Src IP`, `Flow ID`, `Src Port`, and `Timestamp`.
   - Guarantees the intrusion detection models cannot memorize network topology or timestamp artifacts (eliminating shortcut learning).

4. **100% Minority Retention & Stratified Quota Sampling:**
   - **100% Retained Rare Attacks:**
     - `SQL Injection`: 87 flows (100% of all occurrences across 16.2M flows)
     - `Brute Force -XSS`: 230 flows (100%)
     - `Brute Force -Web`: 611 flows (100%)
     - `DDOS attack-LOIC-UDP`: 1,730 flows (100%)
   - **Stratified Quota (5,000 flows each):**
     - `HOIC`, `LOIC_HTTP`, `Hulk`, `SlowHTTPTest`, `GoldenEye`, `Slowloris`, `FTP_BruteForce`, `SSH_Bruteforce`, `Infiltration`, `Bot`
   - **Benign Normal Baseline:**
     - 10,000 flows evenly sampled across all 10 capture dates.

---

## 📊 Resulting Curated Research Corpus
- **Total Samples:** 62,658 network flows
- **Feature Space:** 78 numerical flow metrics + 4 ground truth columns (`category`, `subcategory`, `attack`, `raw_label`)
- **Storage:** Binary Apache Parquet (`cic18_cleaned_sample.parquet`) and CSV (`cic18_cleaned_sample.csv`)
