# AI-Based Continuous Behavioral Monitoring and Adaptive Response for Ransomware Detection

A multi-layered Endpoint Detection and Response (EDR) and Security Operations Center (SOC) simulation system. This project implements a hybrid defensive architecture combining static structural analysis and dynamic behavioral tracking to detect, classify, and mitigate ransomware threats in real time using an Ensemble Machine Learning approach.

---

## Key Features

* **Hybrid Multi-Layered Defense**: 
    * **Layer 1 (Static Analysis)**: Extracts core PE headers, Section Entropies, and string keywords to calculate localized risk metrics.
    * **Layer 2 (Behavioral Analysis)**: Utilizes a multiclass XGBoost model to classify verified threats into specific ransomware families (e.g., WannaCry, LockBit) based on dynamic API call tracking.
* **Ensemble Scoring Engine**: Computes unified threat scores using a weighted combination of four distinct algorithms: Random Forest (30%), XGBoost (30%), LightGBM (20%), and Isolation Forest (20%).
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

Installation and Setup
1. Prerequisites
Ensure you have Python 3.10+ installed on your windows endpoint.

2. Environment Variables Configuration
Create a secure environmental configuration file named .env in your root directory and populate it with your authorization and SMTP credentials:
GEMINI_API_KEY=your_google_ai_studio_api_key_here
SENDER_EMAIL=your_soc_alert_dispatcher_email@gmail.com
SENDER_PASSWORD=your_gmail_app_restricted_password
RECEIVER_EMAIL=system_administrator_mailbox@gmail.com

3. Dependency Installation
Install the mandatory system components and binary analysis libraries:

Bash
pip install -r requirements.txt

Execution Pipelines
Model Baseline Initialization
Before launching the real-time sensor network, compile the analytical logic structures by training the internal detection arrays:

Bash
python train_layer1.py
python train_layer2.py

Starting the EDR and SOC Services
Execute the real-time monitoring interface alongside the interactive telemetry control panel:

Bash
# Launch the main endpoint monitoring sensor loop
python realtime_monitor.py

# Launch the interactive analytical control view
streamlit run dashboard.py
Alternatively, initialize the operational environment seamlessly by executing the pre-configured automation script:

Bash
run_system.bat

Launching Simulation Tests
To validate reactive mitigation capabilities, run the simulation tool to observe automated response measures against mock behavior streams:

Bash
python demo.py

Evaluation Metrics
Layer 2 multiclass models evaluate targeted payload objects against verified profiles. The system outputs standardized classification parameters directly to system logs for reporting reference:

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

License
This project is deployed as an open-source technical reference layout for behavioral analysis exploration. All benchmark datasets are included for educational replication and architectural verification purposes.

