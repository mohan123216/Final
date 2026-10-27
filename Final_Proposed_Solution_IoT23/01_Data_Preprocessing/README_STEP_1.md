# Step 1: Streaming Ingestion & Stratified Reservoir Sampling
> **Avast / Stratosphere CTU IoT-23 Benchmark (23 Malware & Benign Scenarios)**

---

## 🎯 Objective & Engineering Rationale
The **IoT-23** dataset contains over 50 GB of network flow traffic across 23 distinct IoT scenarios (capturing Mirai, Okiru, Kenjiro, Torii, Hide and Seek, Hakku, Muhstik, and Honeypot benign traffic).

Naively training on raw, unbalanced dumps leads to severe shortcut learning:
1. Volumetric PortScan, DDoS, and Okiru floods overwhelm minority stealth attack patterns (such as C&C beaconing, multi-stage Torii C&C, and malware staging downloads).
2. Network identifiers (IP addresses, MAC addresses, flow identifiers, and timestamps) allow machine learning models to memorize specific IP addresses rather than learning genuine protocol anomalies.

Step 1 implements **Streaming Stratified Ingestion & Leakage-Free Preprocessing**:
- **Anti-Leakage Exclusion:** Permanently strips `ts`, `uid`, `id.orig_h`, `id.resp_h`, `id.orig_p`, `local_orig`, `local_resp`, and `tunnel_parents`.
- **Bro/Zeek Flow Sanitation:** Handles Bro/Zeek missing `-` symbols, converting them into valid domain representations.
- **Protocol & Behavioral Feature Engineering:** Derives 35 numeric features including connection duration, payload bytes, packet counts, IP overheads, flow transfer rates, protocol flags, and connection state indicators.
- **Stratified Reservoir Sampling:** Preserves 100% of all rare stealth attacks (`C&C-HeartBeat`, `C&C-Torii`, `C&C-FileDownload`, `FileDownload`, `C&C-HeartBeat-FileDownload`, `Attack`) while capping flood classes at strict balanced quotas, yielding an audited **31,692-flow research corpus**.

---

## 📊 Curated Research Corpus Distribution

| Category | Attack Subclass | Sampled Flows | Nature of Threat |
|:---|:---|---:|:---|
| **Normal** | **Normal (Benign)** | 10,000 | Clean smart-home IoT baseline communication |
| **PortScan** | **HorizontalPortScan** | 5,000 | Mirai / Kenjiro horizontal port enumeration |
| **C&C** | **C&C (Generic)** | 5,000 | Established command & control communication channels |
| **Botnet** | **Okiru** | 5,000 | Okiru / Mirai IoT botnet propagation |
| **DDoS** | **DDoS Flooding** | 5,000 | Volumetric SYN / UDP flood denial of service |
| **Attack** | **Direct Attack / Exploit** | 1,374 | Active vulnerability exploitation attempts |
| **C&C** | **C&C-HeartBeat** | 216 | Periodic botnet keep-alive beaconing |
| **C&C** | **C&C-FileDownload** | 44 | Secondary malware payload staging download |
| **C&C** | **C&C-Torii** | 30 | Multi-stage Torii modular malware C&C |
| **FileDownload** | **FileDownload** | 16 | Direct malicious payload binary download |
| **C&C** | **C&C-HeartBeat-FileDownload** | 11 | Composite beacon and malware retrieval channel |
| **C&C** | **C&C-Mirai** | 1 | High-privilege Mirai controller command |
| **TOTAL** | **11 Attack Subclasses + Benign** | **31,692** | **Balanced, Leakage-Free Ground Truth** |

---

## 📁 Artifacts Produced
- `dataset/iot23_cleaned_sample.parquet`: High-performance serialized binary dataset (35 features, 31,692 flows).
- `dataset/iot23_cleaned_sample.csv`: Standard CSV dataset for external validation.
- `dataset/class_distribution_iot23.csv`: Audited class distribution breakdown.
