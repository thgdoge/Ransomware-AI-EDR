
# AI-Based Continuous Behavioral Monitoring and Adaptive Response for Ransomware Detection

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python Version">
  <img src="https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-0078D4?style=for-the-badge&logo=windows&logoColor=white" alt="Platform">
  <img src="https://img.shields.io/badge/Accuracy-99.65%25-success?style=for-the-badge" alt="Accuracy">
  <img src="https://img.shields.io/badge/Framework-EDR%20%7C%20SOC-red?style=for-the-badge" alt="Framework">
</p>

A multi-layered Endpoint Detection and Response (EDR) and Security Operations Center (SOC) simulation system. This project implements a hybrid defensive architecture combining static structural analysis (pre-execution) and dynamic behavioral tracking (runtime) to detect, classify, and mitigate ransomware threats in real time using an Ensemble Machine Learning approach.

---

## ⚡ Technical Architecture Overview

The system operates on a multi-layer verification model engineered to minimize False Positives (FP) while maintaining a high detection ceiling for zero-day cryptographic threats.

### 🔹 Detection and Mitigation Pipeline
* **Static Layer (Layer 1)**: Inspects inbound Portable Executable (PE) binaries upon creation within monitored directories. It extracts structural header anomalies, section entropies, import address tables (IAT), and string patterns.
* **Behavioral Layer (Layer 2)**: Continuously tracks running processes using Windows API low-level signals and event telemetry (Sysmon). It captures anomalous file I/O operations, mass extension adjustments, registry persistence, and unauthorized system recovery manipulations.

### 🔹 Ensemble Scoring Engine
Instead of relying on a single classifier, the system computes a confidence-based risk score $S(x)$ using an ensemble soft-voting consensus mechanism from supervised classifiers (Random Forest, XGBoost, and LightGBM).

$$
S(x)=\frac{1}{N}\sum_{i=1}^{N}P_{i}(x)
$$

> **Where:**
> * $S(x)$: Final confidence score.
> * $P_i(x)$: Prediction probability of the $i$-th classifier.
> * $N$: Number of classifiers participating in the ensemble ($N=3$).

Additionally, **Isolation Forest** is integrated as an unsupervised anomaly core to detect heavily packed, obfuscated, or previously unseen zero-day ransomware layouts.

### 🔹 Adaptive Feedback Control & Active Learning
When administrators re-classify an event via the SOC management console, the system isolates the sample, appends the calibrated feature vector to the baseline dataset (`data_file.csv`), and executes a live synchronized re-fit of active model matrices in memory without service interruption.

---

## ✨ Key Features

* **📦 Hybrid Multi-Layered Defense**: Combining pre-execution static structure checking with continuous runtime observation and active containment.
* **⏱️ Real-Time Behavioral Triggers**: To catch encryption cycles early without intensive tracing, the module deploys a consecutive alteration counter. If a process exceeds a modification barrier of **3 sequential anomalous file renames**, the trigger is tripped.
* **🛡️ Security Scoring Bypass Line**: Critical registry mutations (e.g., modifying startup run hives to establish persistence) are treated as immediate high-risk alerts, skipping normal cumulative analytical scoring to fire network isolation protocols immediately.
* **🤖 AI Agent Incident Reporting**: Integrates Google's `gemini-2.5-flash` via the `google-genai` SDK to dynamically evaluate threat sub-scores, compile formatted reports, and dispatch professional secure incident emails over SMTP to SOC administrators.

---

## 📁 Repository Structure

```text
.
├── config/
│   ├── ransomware_rules.yar      # YARA static threat signature baselines
│   └── whitelist.txt             # Cryptographic hash exceptions for benign binaries
├── data/
│   ├── processed/
│   │   └── unified_dataset.csv   # Structured feature matrices for model alignments
│   └── raw/
│       ├── data_file.csv         # Layer 1 training data and active learning logs
│       └── ransomset-multiclass-dataset.csv # Multiclass behavior profiling data
├── models/
│   ├── layer1_features.pkl       # Target system structural columns schema
│   ├── layer1_if_model.pkl       # Serialized Isolation Forest anomaly engine
│   ├── layer1_lgbm_model.pkl     # Serialized LightGBM classifier
│   ├── layer1_rf_model.pkl       # Serialized Random Forest classifier
│   ├── layer1_xgb_model.pkl      # Serialized Binary XGBoost classifier
│   ├── layer2_xgb_model.pkl      # Serialized Multiclass Behavioral XGBoost model
│   └── label_encoder.pkl         # Ransomware family label index mappings
├── batch_parser.py               # FP mitigation and structural data synchronizer
├── dashboard.py                  # Streamlit SOC telemetry and active control center
├── demo.py                       # Reactive ransomware behavioral simulator
├── extractor.py                  # Core PE parsing and section entropy analyzer
├── realtime_monitor.py           # Watchdog network sensor, AI agent, and main EDR engine
├── reset.py                      # Features matrix baseline reset utility
├── train_layer1.py               # Training orchestrator for Layer 1 baseline models
├── train_layer2.py               # Retraining orchestrator for Layer 2 behavior arrays
├── requirements.txt              # Application dependency manifests
└── run_system.bat                # Automated operational service initialization script

```

---

## 🚀 Comprehensive Implementation Guide

### 1. Technical Prerequisites

* **Operating System**: Windows 10/11 (Required for native shell sub-processes like ipconfig mitigation handles).
* **Python Environment**: Python 3.10 to 3.13 configuration environments.

### 2. Environment Configuration

Create an environmental variable registry file named `.env` in the project root directory:

```env
GEMINI_API_KEY=your_google_ai_studio_api_key_here
SENDER_EMAIL=your_soc_alert_dispatcher_email@gmail.com
SENDER_PASSWORD=your_gmail_app_restricted_password
RECEIVER_EMAIL=system_administrator_mailbox@gmail.com

```

### 3. Core Dependency Installation

```bash
pip install -r requirements.txt

```

---

## ⚙️ Operational Execution Workflows

### 🛠️ Phase 1: Model Training and Serialization

```bash
python train_layer1.py
python train_layer2.py

```

### 🛠️ Phase 2: System Activation

```bash
run_system.bat

```

*Alternatively, you can manually orchestrate individual terminal operations as follows:*

```bash
# Terminal A: Spin up the continuous file system monitoring loop
python realtime_monitor.py

# Terminal B: Initialize the Streamlit SOC Management Consolidation View
streamlit run dashboard.py

```

### 🛠️ Phase 3: Attack Simulation Testing

```bash
python demo.py

```

---

## 📊 Evaluation Metrics Reference

### 📈 Static Classification Performance Evaluation (Table 4)

The framework was evaluated using an 80:20 training/testing split with 5-fold cross-validation. The proposed Ensemble Model significantly outperforms standalone algorithms:

| Model | Accuracy (%) | Precision (%) | Recall (%) | F1-Score (%) |
| --- | --- | --- | --- | --- |
| Random Forest | 95.80% | 96.10% | 95.50% | 95.80% |
| XGBoost | 96.50% | 96.80% | 96.20% | 96.50% |
| LightGBM | 96.30% | 96.50% | 96.10% | 96.30% |
| **Proposed Ensemble Model** | **🚀 99.65%** | **99.65%** | **99.73%** | **99.69%** |

### 📈 Test Dataset Confusion Matrix Deconstruction (Figure 6)

Evaluated on a validation split containing **12,500 samples**, the confusion matrix metrics show:

* **True Negatives (TN):** `5,401` | Legitimate binaries allowed to execute safely.
* **False Positives (FP):** `25` | Minimal false alarms preventing business downtime.
* **False Negatives (FN):** `19` | Obfuscated samples bypassed and handled by Layer 2 dynamic tracking.
* **True Positives (TP):** `7,055` | Ransomware samples accurately intercepted.

### 📈 Layer 3 Proportional Mitigation Latency & Strategies

The adaptive response module escalates mitigations dynamically by comparing behavioral risk scores against decision thresholds:

$$\text{Response Level} = \begin{cases} L, & \text{if } R < T_1 \\ M, & \text{if } T_1 \le R < T_2 \\ H, & \text{if } T_2 \le R < T_3 \\ C, & \text{if } R \ge T_3 \end{cases}$$

| Threat Severity | Detection Characteristics | Autonomous Response Actions | Success Rate |
| --- | --- | --- | --- |
| **Low ($L$)** | Normal behavior with minor anomalies | Continue monitoring | 100% |
| **Medium ($M$)** | Multiple suspicious behavioral indicators | Alert user & Increase monitoring frequency | 100% |
| **High ($H$)** | Strong evidence of ransomware behavior | Suspend or terminate suspicious process | 98.5% |
| **Critical ($C$)** | Active encryption & recovery manipulation | **Process termination, host isolation, backup protection, incident logging** | **99.2%** |

### 📈 Layer 2 Behavioral Multiclass Classification Report

```text
================== RANSOMWARE CLASSIFICATION REPORT ==================
              precision    recall  f1-score   support

    WannaCry       0.98      0.97      0.98       150
     LockBit       0.96      0.95      0.95       142
      Cerber       0.95      0.96      0.95       135
      Benign       0.99      0.99      0.99       300

    accuracy                           0.97       727
   macro avg       0.97      0.97      0.97       727
weighted avg       0.97      0.97      0.97       727
======================================================================

```

---

## 🔍 Troubleshooting and Operational Recovery

| Issue / Error Signature | Root Cause | Remediation Procedure |
| --- | --- | --- |
| `ValueError: Input y contains NaN` | Missing target class values in `data_file.csv` rows. | Run the automated pre-processing step included in `train_layer1.py` to drop unallocated label blocks. |
| `FileNotFoundError: layer1_features.pkl` | Monitoring loop initialized before training configuration matrices. | Run `python train_layer1.py` or run `python reset.py` to rebuild the 17-column structural layout. |
| `Network Isolation Triggered` | Ransomware mass-renaming signature simulation limit reached. | Open a privileged terminal and run `ipconfig /renew` to re-allocate localized DHCP IP configurations. |

---

## 📝 License

This project is deployed as an open-source technical reference layout for behavioral analysis exploration. All benchmark datasets are included for educational replication and architectural verification purposes.

```

```
