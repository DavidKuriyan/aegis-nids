# Aegis NIDS — AI-Powered Real-Time Intrusion Detection System

Aegis NIDS is a production-style, machine-learning-based Network Intrusion Detection System (NIDS) designed for Windows environments. It captures raw network traffic using Scapy, tracks bidirectional connections, processes them through a Random Forest Classifier trained on key features of the CICIDS2017 dataset, and visualizes security events on a dark-themed glassmorphism SOC dashboard.

---

## Features

- **Multi-threaded Core Architecture**: Distinct threads for packet sniffing, ML prediction, and Flask dashboard server.
- **Stateful Bidirectional Flow Tracking**: Grouping packets into connections (TCP, UDP, ICMP) to extract 14 statistical features.
- **Ensemble ML Classification**: Classification of traffic into 8 categories (BENIGN, PortScan, DDoS, Bot, FTP-Patator, SSH-Patator, Web Attack, Infiltration) using a Random Forest Classifier.
- **Loopback Traffic Sniffing**: Parallel capturing on standard network cards and Windows loopback interfaces.
- **Premium Glassmorphic SOC Interface**: Dynamic Chart.js visualizations, animated KPI counters, ticking clock, row-severity tinted tables, and interactive attack simulations.

---

## Installation & Setup

### Prerequisites

1. **Python 3.8+**: Ensure Python is added to your system's PATH.
2. **Npcap (Critical for Windows)**: 
   - Scapy requires Npcap to capture raw socket traffic on Windows.
   - Download and install [Npcap](https://npcap.com/).
   - **IMPORTANT**: During installation, check the box that says **"Install Npcap with WinPcap API-compatible Mode"**.

---

### Step-by-Step Guide

#### 1. Clone the Repository
Open a terminal and clone the project:
```bash
git clone https://github.com/yourusername/aegis-nids.git
cd "aegis-nids"
```

#### 2. Install Python Dependencies
Install the required packages listed in `requirements.txt`:
```bash
pip install -r requirements.txt
```

#### 3. Generate Simulated Dataset & Train Classifier
Since the official 3GB CICIDS2017 dataset is too large to bundle, Aegis NIDS includes a simulator script that generates 30,000 realistic records for model training.

Generate the dataset and train the Random Forest model:
```bash
python train_model.py
```
This script will:
1. Call `dataset/simulate_dataset.py` to create `dataset/dataset.csv`.
2. Preprocess features, fit preprocessor scalers, split data, and fit the `RandomForestClassifier`.
3. Save preprocessor files (`scaler.joblib`, `label_encoder.joblib`) and the model file (`model.joblib`) into the `models/` directory.
4. Output evaluation metrics (Accuracy, F1-scores, Confusion Matrix).

#### 4. Launch Aegis NIDS Web Dashboard
To capture raw network packets from physical network cards, you **must run the application with Administrator privileges**.

- On Windows, open your terminal (PowerShell or Command Prompt) as **Administrator**.
- Start the server:
```bash
python app.py
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## How to Test and Verify Detections

Aegis NIDS offers two modes to test model and interface functionality via the **Threat Simulator** tab:

### 1. Safe Inject Mode (Software Injection)
- Bypasses raw network adapters.
- Places simulated flow records directly onto the prediction engine's Queue.
- **To run**: Click **Safe Inject** on any card (e.g., Port Scan) in the Threat Simulator tab. Detections will show up in the Dashboard alerts log within 2-3 seconds.

### 2. Live Packet Mode (Network Injection)
- Generates real loopback packets using Scapy and sends them over the wire.
- **To run**:
  1. Go to the dashboard sidebar, select the **Loopback Adapter** (e.g., `\Device\NPF_Loopback` or equivalent) from the dropdown, and click **Start**.
  2. Click **Live Packets** on any card in the Threat Simulator tab.
  3. The capture engine sniffs the loopback packets, aggregates them into flow statistics, and registers them in the alerts database.

### 3. Automated Signature Tests (ICMP Flood)
- To test the ICMP signature engine:
  1. Make sure packet capture is running on your loopback or primary adapter.
  2. Open a command prompt and run:
     ```bash
     ping 127.0.0.1 -n 50
     ```
  3. The NIDS will register the ping sweep and issue a **DDoS (ICMP Flood) — CRITICAL** warning once the ICMP packet count crosses the threshold of 30 packets.

---

## Directory Structure

```
d:\Random Forest IDS/
│
├── dataset/                    # Dataset generation scripts and CSV
│   └── dataset.csv             # Simulated training dataset
│   └── simulate_dataset.py     # Script to generate dataset.csv
├── models/                     # Saved preprocessors and ML model
│   └── scaler.joblib           # StandardScaler metadata
│   └── model.joblib            # Trained RandomForestClassifier
│   └── label_encoder.joblib    # LabelEncoder mapping labels to indices
├── logs/                       # SQLite Database and alerts CSV backup
│   └── ids_database.db         # Database logging all alerts and history
│   └── alerts.csv              # Backup alerts log
├── static/                     # Web dashboard assets
│   ├── css/
│   │   └── style.css           # Premium glassmorphic SOC styling
│   └── js/
│       └── app.js              # SSE/AJAX updates, counters, ticking clock
├── templates/
│   └── index.html              # Dashboard HTML structure
├── app.py                      # Flask orchestration and threading
├── config.py                   # Global directories and feature lists
├── database.py                 # SQLite helper functions
├── packet_capture.py           # Thread capturing raw packets via Scapy
├── predict.py                  # Thread parsing flow queues and executing model
├── feature_extraction.py       # Stateful bidirectional flow tracker
├── preprocess.py               # Preprocessing pipelines (StandardScaler/LabelEncoder)
├── train_model.py              # ML training orchestrator
├── utils.py                    # Network interface helpers and static stats
└── requirements.txt            # Package list
```
