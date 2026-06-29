# AI-Based Continuous Behavioral Monitoring and Adaptive Response for Ransomware Detection

A multi-layered Endpoint Detection and Response (EDR) and Security Operations Center (SOC) simulation system. This project implements a hybrid defensive architecture combining static structural analysis and dynamic behavioral tracking to detect, classify, and mitigate ransomware threats in real time using an Ensemble Machine Learning approach.

---

## Technical Architecture Overview

The system operates on a two-tier verification model engineered to minimize False Positives (FP) while maintaining a high detection ceiling for zero-day cryptographic threats.

### 1. Detection and Mitigation Pipeline
* **Static Layer (Layer 1)**: Inspects inbound Portable Executable (PE) binaries upon creation within monitored directories. It extracts structural anomalies, section entropies, and string patterns.
* **Behavioral Layer (Layer 2)**: Triggers only when Layer 1 flags an anomaly with a high risk factor. It maps dynamic Import Address Table (IAT) actions and API calls to identify the specific ransomware variant family.
* **Ensemble Scoring Matrix**: Instead of relying on a single classifier, the system aggregates risk probabilities from four individual machine learning models using a statically weighted consensus formula:

  $$Final\_Risk = (Score_{RF} \times 0.30) + (Score_{XGB} \times 0.30) + (Score_{IF} \times 0.20) + (Score_{LGBM} \times 0.20)$$

* **Adaptive Feedback Control**: When administrators re-classify an event via the SOC management console, the system isolates the sample, appends the calibrated feature vector to the baseline dataset, and executes a synchronized partial re-fit of the active model matrices in memory without service interruption.

---

## Key Features

* **Hybrid Multi-Layered Defense**:
    * **Layer 1 (Static Analysis)**: Extracts core PE headers, Section Entropies, and string keywords to calculate localized risk metrics.
    * **Layer 2 (Behavioral Analysis)**: Utilizes a multiclass XGBoost model to classify verified threats into specific ransomware families (e.g., WannaCry, LockBit) based on dynamic API call tracking.
* **Ensemble Scoring Engine**: Computes unified threat scores using a weighted combination of four distinct algorithms: Random Forest, XGBoost, LightGBM, and Isolation Forest.
* **Active Learning and Adaptive Re-calibration**: Features a built-in feedback pipeline allowing administrators to retrain operational models live from the SOC interface, effectively eliminating False Positives and updating zero-day detection profiles.
* **AI Agent Incident Reporting**: Integrates Google's gemini-2.5-flash via the modern google-genai SDK to dynamically analyze threat telemetry and draft professional incident response reports for SOC administrators.
* **Automated Threat Mitigation**: Actively monitors critical directory spaces for sequential mass-renaming signatures and enforces proactive network isolation to contain active infections.

---

## Repository Structure

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

## Comprehensive Implementation Guide

### 1. Technical Prerequisites

* **Operating System**: Windows 10/11 (Required for native shell sub-processes like ipconfig mitigation handles).
* **Python Environment**: Python 3.10 to 3.13 configuration environments.

### 2. Environment Configuration

Create an environmental variable registry file named `.env` in the project root directory (`D:\iam\.env`) to securely map sensitive integration tokens:

```env
GEMINI_API_KEY=your_google_ai_studio_api_key_here
SENDER_EMAIL=your_soc_alert_dispatcher_email@gmail.com
SENDER_PASSWORD=your_gmail_app_restricted_password
RECEIVER_EMAIL=system_administrator_mailbox@gmail.com

```

### 3. Core Dependency Installation

Compile the binary processing dependencies and the analytical machine learning libraries:

```bash
pip install -r requirements.txt

```

---

## Operational Execution Workflows

### Phase 1: Model Training and Serialization

Initialize the foundational baseline intelligence structures by compiling the static and behavioral classifiers:

```bash
python train_layer1.py
python train_layer2.py

```

### Phase 2: System Activation

To spin up the continuous sensor loop alongside the interactive logging interface, execute the unified batch controller:

```bash
run_system.bat

```

Alternatively, you can manually orchestrate individual terminal operations as follows:

```bash
# Terminal A: Spin up the continuous file system monitoring loop
python realtime_monitor.py

# Terminal B: Initialize the Streamlit SOC Management Consolidation View
streamlit run dashboard.py

```

### Phase 3: Attack Simulation Testing

Validate the system's runtime defensive mitigation rules by simulating a sequential, multi-stage ransomware renaming and locking attack:

```bash
python demo.py

```

---

## Evaluation Metrics Reference

The internal multi-class framework classifies incoming high-risk binaries against verified training records. Standard performance metrics are exported directly to system logs for reporting reference:

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

## Troubleshooting and Operational Recovery

| Issue / Error Signature | Root Cause | Remediation Procedure |
| --- | --- | --- |
| `ValueError: Input y contains NaN` | Missing target class values in `data_file.csv` rows. | Run the automated pre-processing step included in `train_layer1.py` to drop unallocated label blocks. |
| `FileNotFoundError: layer1_features.pkl` | Monitoring loop initialized before training configuration matrices. | Run `python train_layer1.py` or run `python reset.py` to rebuild the 17-column structural layout. |
| `Network Isolation Triggered` | Ransomware mass-renaming signature simulation limit reached. | Open a privileged terminal and run `ipconfig /renew` to re-allocate localized DHCP IP configurations. |

---

## License

This project is deployed as an open-source technical reference layout for behavioral analysis exploration. All benchmark datasets are included for educational replication and architectural verification purposes.

```
